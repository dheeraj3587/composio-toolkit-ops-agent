"""Discovering candidate official pages, and composing discovery providers.

Discovery is the step that turns an app name into URLs, so it is where the "never
trust the provider" rule is applied first: ``include_domains`` is sent as a
provider-side filter for efficiency, but every returned URL is re-validated locally
against the run's ResearchHostPolicy, and the field is OMITTED rather than sent empty
because an empty allowlist would mean "unfiltered" to the provider.

The composite exists so a provider outage degrades depth instead of failing a run: it
tries each configured discovery in order and merges what it gets, recording which
providers were actually used. That is what lets a hundred-app batch keep making
progress while one backend is rate-limited.

The client is always used as an ``async with`` context manager so its httpx client is
closed on the same event loop that created it, because enrichment is invoked with
``asyncio.run`` from sync code and a loop-bound client would otherwise outlive its loop.
"""

from __future__ import annotations

import importlib
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

import httpx
from pydantic import SecretStr, ValidationError

from ops.models import OperationalResearch, validate_https_url
from ops.operational_research import EvidenceDiscovery
from ops.you_cache import ResearchCache, _cached, cache_key
from ops.you_candidates import (
    EvidenceCandidate,
    classify_category,
    deduplicate_and_rank_candidates,
    has_sufficient_coverage,
)
from ops.you_errors import (
    _PROGRAMMING_ERRORS,
    YouProviderError,
    _bounded_retry_config,
    _guard_call,
)
from ops.you_host_policy import ResearchHostPolicy
from ops.you_metrics import _metrics
from ops.you_types import (
    MAX_CANDIDATE_SNIPPETS,
    MAX_SNIPPET_CHARACTERS,
    SEARCH_CACHE_TTL,
    QueryType,
)


# --------------------------------------------------------------------------
# Protocols
# --------------------------------------------------------------------------
class RichEvidenceDiscovery(Protocol):
    """Candidate-returning discovery (superset of the legacy EvidenceDiscovery)."""

    async def discover(
        self,
        *,
        app_name: str,
        p1_record: Mapping[str, object],
        baseline: OperationalResearch,
        official_hosts: tuple[str, ...],
    ) -> tuple[EvidenceCandidate, ...]: ...


# --------------------------------------------------------------------------
# YouSearchDiscovery
# --------------------------------------------------------------------------
class YouSearchDiscovery:
    """Primary discovery provider: You.com Web Search (POST), two bounded queries."""

    def __init__(
        self,
        api_key: SecretStr | str,
        *,
        count: int = 5,
        timeout_seconds: float = 20.0,
        max_calls: int = 2,
        cache: ResearchCache | None = None,
    ) -> None:
        self._api_key = api_key if isinstance(api_key, SecretStr) else SecretStr(api_key)
        self._count = count
        self._timeout_seconds = timeout_seconds
        self._max_calls = max_calls
        self._cache = cache

    async def discover(
        self,
        *,
        app_name: str,
        p1_record: Mapping[str, object],
        baseline: OperationalResearch,
        official_hosts: tuple[str, ...],
    ) -> tuple[EvidenceCandidate, ...]:
        del p1_record, baseline
        if not official_hosts:
            return ()
        policy = ResearchHostPolicy.from_domains(official_hosts)
        provider_domains = policy.provider_include_domains
        queries: tuple[tuple[QueryType, str], ...] = (
            (
                "access",
                f"{app_name} official login sign in signup developer portal developers dashboard",
            ),
            (
                "api_credentials",
                f"{app_name} official API authentication create API key access token "
                "private app OAuth scopes developer settings",
            ),
        )

        discovered: list[EvidenceCandidate] = []
        for query_type, query in queries[: self._max_calls]:
            try:
                candidates = await self._search_query(query, query_type, provider_domains, policy)
            except YouProviderError:
                continue  # one query failing must not fail discovery entirely
            discovered.extend(candidates)
        return deduplicate_and_rank_candidates(discovered)

    async def _search_query(
        self,
        query: str,
        query_type: QueryType,
        provider_domains: tuple[str, ...],
        policy: ResearchHostPolicy,
    ) -> list[EvidenceCandidate]:
        key = cache_key("you-search", query, ",".join(provider_domains), str(self._count))

        def _deserialize(raw: Mapping[str, object]) -> list[EvidenceCandidate] | None:
            items = raw.get("items")
            if not isinstance(items, list):
                return None
            try:
                cached = [EvidenceCandidate.model_validate(item) for item in items]
            except ValidationError:
                return None  # invalid cached payload -> recompute
            # A cached URL is NOT trusted because an older, possibly wider policy
            # accepted it: every hit is re-validated against the CURRENT policy.
            validated: list[EvidenceCandidate] = []
            for candidate in cached:
                try:
                    policy.validate_candidate_url(candidate.source_url)
                except ValueError:
                    continue
                validated.append(candidate)
            if cached and not validated:
                return None  # everything cached is now off-policy -> recompute
            return validated

        def _serialize(value: list[EvidenceCandidate]) -> Mapping[str, object]:
            return {"items": [c.model_dump() for c in value]}

        async def _compute() -> list[EvidenceCandidate]:
            response = await self._search(query=query, provider_domains=provider_domains)
            return self._convert_results(response, query_type=query_type, policy=policy)

        return await _cached(
            self._cache,
            key,
            ttl=SEARCH_CACHE_TTL,
            deserialize=_deserialize,
            serialize=_serialize,
            compute=_compute,
        )

    async def _search(self, *, query: str, provider_domains: tuple[str, ...]) -> object:
        metrics = _metrics()
        started = datetime.now(UTC)

        async def _factory() -> object:
            youdotcom = importlib.import_module("youdotcom")
            safesearch = importlib.import_module("youdotcom.models.safesearch")
            kwargs: dict[str, Any] = {
                "query": query,
                "count": self._count,
                "safesearch": safesearch.SafeSearch.STRICT,
                "retries": _bounded_retry_config(),
                "timeout_ms": int(self._timeout_seconds * 1000),
            }
            # An EMPTY include_domains is not "no filter" to the API — it is an
            # empty allowlist. Omit the field entirely instead (the CLI probe
            # deliberately searches without a domain filter).
            if provider_domains:
                kwargs["include_domains"] = list(provider_domains)
            async with youdotcom.You(api_key_auth=self._api_key.get_secret_value()) as you:
                return await you.search_post_async(**kwargs)

        try:
            response = await _guard_call(
                "you_search", _factory, timeout_seconds=self._timeout_seconds + 5
            )
        finally:
            if metrics is not None:
                metrics.you_search_calls += 1
                metrics.you_search_latency_ms += (
                    datetime.now(UTC) - started
                ).total_seconds() * 1000
        return response

    def _convert_results(
        self, response: object, *, query_type: QueryType, policy: ResearchHostPolicy
    ) -> list[EvidenceCandidate]:
        metrics = _metrics()
        results = getattr(response, "results", None)
        web_results = list(getattr(results, "web", None) or ())
        if metrics is not None:
            metrics.you_search_results_returned += len(web_results)
        candidates: list[EvidenceCandidate] = []
        for rank, item in enumerate(web_results):
            url = getattr(item, "url", None)
            if not isinstance(url, str) or not url:
                continue
            try:
                safe_url = policy.validate_candidate_url(validate_https_url(url))
            except ValueError:
                continue  # off-policy — never trusted just because You.com returned it
            title = (getattr(item, "title", None) or "")[:500]
            raw_snippets = list(getattr(item, "snippets", None) or ())
            description = getattr(item, "description", None)
            if not raw_snippets and description:
                raw_snippets = [description]
            snippets = tuple(
                str(s)[:MAX_SNIPPET_CHARACTERS] for s in raw_snippets[:MAX_CANDIDATE_SNIPPETS]
            )
            candidates.append(
                EvidenceCandidate(
                    source_url=safe_url,
                    title=title,
                    snippets=snippets,
                    provider="you_search",
                    query_type=query_type,
                    rank=rank,
                    # The bounded snippet participates in classification: a URL
                    # and title alone often cannot tell a docs page apart from
                    # the actual credential-creation surface.
                    category=classify_category(safe_url, title, snippets[0] if snippets else ""),
                )
            )
        if metrics is not None:
            metrics.you_search_results_policy_accepted += len(candidates)
        # News results are intentionally ignored for this use case.
        return candidates


# --------------------------------------------------------------------------
# Legacy-protocol adapter + composite discovery
# --------------------------------------------------------------------------
class LegacyDiscoveryAdapter:
    """Adapt an old :class:`EvidenceDiscovery` (URL-only) into RichEvidenceDiscovery."""

    def __init__(
        self, legacy: EvidenceDiscovery, *, provider: Literal["perplexity"] = "perplexity"
    ) -> None:
        self._legacy = legacy
        self._provider = provider

    async def discover(
        self,
        *,
        app_name: str,
        p1_record: Mapping[str, object],
        baseline: OperationalResearch,
        official_hosts: tuple[str, ...],
    ) -> tuple[EvidenceCandidate, ...]:
        del p1_record, baseline
        urls = await self._legacy.discover(app_name=app_name)
        policy = ResearchHostPolicy.from_domains(official_hosts) if official_hosts else None
        candidates: list[EvidenceCandidate] = []
        for rank, url in enumerate(urls):
            try:
                safe_url = (
                    policy.validate_candidate_url(url)
                    if policy is not None
                    else validate_https_url(url)
                )
            except ValueError:
                continue
            candidates.append(
                EvidenceCandidate(
                    source_url=safe_url,
                    provider=self._provider,
                    query_type="baseline",
                    rank=rank,
                    category=classify_category(safe_url),
                )
            )
        return tuple(candidates)


class CompositeEvidenceDiscovery:
    """You.com first; Perplexity (or another provider) only fills coverage gaps.

    A provider that raises an EXPECTED provider/transport error is skipped, never
    fatal. A programming error (TypeError etc.) is NOT caught here — a broken
    integration must be visible, not silently swallowed (section 12).
    """

    def __init__(
        self,
        providers: Sequence[RichEvidenceDiscovery],
        *,
        minimum_candidates_before_stopping: int = 4,
    ) -> None:
        self._providers = tuple(providers)
        self._minimum_candidates_before_stopping = minimum_candidates_before_stopping
        self.last_provider_used: str | None = None

    def _provider_label(self, provider: RichEvidenceDiscovery) -> str:
        if isinstance(provider, YouSearchDiscovery):
            return "you_search"
        if isinstance(provider, LegacyDiscoveryAdapter):
            return "perplexity"
        return type(provider).__name__

    async def discover(
        self,
        *,
        app_name: str,
        p1_record: Mapping[str, object],
        baseline: OperationalResearch,
        official_hosts: tuple[str, ...],
    ) -> tuple[EvidenceCandidate, ...]:
        collected: list[EvidenceCandidate] = []
        used: list[str] = []
        for provider in self._providers:
            try:
                found = await provider.discover(
                    app_name=app_name,
                    p1_record=p1_record,
                    baseline=baseline,
                    official_hosts=official_hosts,
                )
            except _PROGRAMMING_ERRORS:
                raise
            except (YouProviderError, ValueError, OSError, httpx.RequestError):
                continue
            if found:
                used.append(self._provider_label(provider))
            collected.extend(found)
            ranked = deduplicate_and_rank_candidates(collected)
            if has_sufficient_coverage(ranked) and len(ranked) >= min(
                self._minimum_candidates_before_stopping, len(collected)
            ):
                self._record_used(used)
                return ranked
        self._record_used(used)
        return deduplicate_and_rank_candidates(collected)

    def _record_used(self, used: Sequence[str]) -> None:
        label = "+".join(used) or None
        self.last_provider_used = label
        metrics = _metrics()
        if metrics is not None and label is not None:
            metrics.discovery_provider_used = label
