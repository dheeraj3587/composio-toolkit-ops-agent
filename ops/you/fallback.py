"""The bounded You.com Research fallback, used only when cheaper layers fall short.

This is the most expensive path in the research layer, so it is the most constrained.
It runs only when discovery plus content extraction did not produce sufficient
coverage, it is cached for far longer than a search (its answer is a synthesis, not a
volatile result set), and its output is validated against an explicit schema rather
than trusted as prose.

The schema version is part of the cache key material, so changing the requested shape
cannot serve a stale answer in the old shape.

Every URL it returns goes through the same host policy as any other candidate, and a
category outside the reviewed enum is dropped rather than passed through. A provider
that invents a plausible-looking vendor host therefore contributes nothing, which is
the behavior a hundred-app batch needs: a truthful empty result instead of a
fabricated one.
"""

from __future__ import annotations

import contextlib
import importlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from pydantic import SecretStr, ValidationError

from ops.you.cache import ResearchCache, _cached, cache_key
from ops.you.candidates import EvidenceCandidate, canonicalize, classify_category
from ops.you.errors import YouProviderError, _bounded_retry_config, _guard_call
from ops.you.host_policy import ResearchHostPolicy
from ops.you.metrics import _metrics
from ops.you.types import _RESEARCH_CATEGORY_ENUM, RESEARCH_CACHE_TTL

# --------------------------------------------------------------------------
# Optional You Research fallback (disabled by default; SDK research())
# --------------------------------------------------------------------------
YOU_RESEARCH_SCHEMA_VERSION = "candidate_pages_v1"


YOU_RESEARCH_SCHEMA: dict[str, object] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["candidate_pages", "confidence"],
    "properties": {
        "candidate_pages": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["url", "category"],
                "properties": {
                    "url": {"type": "string"},
                    "category": {
                        "type": "string",
                        "enum": sorted(_RESEARCH_CATEGORY_ENUM),
                    },
                },
            },
        },
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
    },
}


@dataclass(frozen=True, slots=True)
class ResearchFallbackResult:
    """Untrusted candidate pages from You Research, ready for You Contents.

    Research NEVER authors an OperationalResearch field — it only points at MORE
    official pages for the SAME canonical Gemini extraction + validation path.
    """

    candidates: tuple[EvidenceCandidate, ...]
    confidence: Literal["high", "medium", "low"]

    @property
    def candidate_urls(self) -> tuple[str, ...]:
        return tuple(c.source_url for c in self.candidates)


class YouResearchFallback:
    """Last-resort discovery: one bounded Research call, at most once per enrichment.

    Uses the SDK ``research_async`` with ``source_control.include_domains`` and a
    minimal ``output_schema`` (candidate pages only). Disabled by default; the
    caller decides (via ``has_sufficient_coverage``) whether to invoke it.
    """

    def __init__(
        self,
        api_key: SecretStr | str,
        *,
        timeout_seconds: float = 60.0,
        cache: ResearchCache | None = None,
    ) -> None:
        self._api_key = api_key if isinstance(api_key, SecretStr) else SecretStr(api_key)
        self._timeout_seconds = timeout_seconds
        self._cache = cache

    async def research(
        self, *, app_name: str, official_hosts: tuple[str, ...], policy: ResearchHostPolicy
    ) -> ResearchFallbackResult | None:
        if not official_hosts:
            return None
        provider_domains = policy.provider_include_domains
        key = cache_key(
            "you-research",
            app_name.casefold(),
            ",".join(provider_domains),
            YOU_RESEARCH_SCHEMA_VERSION,
        )

        def _deserialize(raw: Mapping[str, object]) -> ResearchFallbackResult | None:
            items = raw.get("candidates")
            confidence = raw.get("confidence")
            if not isinstance(items, list) or confidence not in ("high", "medium", "low"):
                return None
            try:
                candidates = tuple(EvidenceCandidate.model_validate(i) for i in items)
            except ValidationError:
                return None
            # Re-validate each cached candidate against the CURRENT policy.
            revalidated = []
            for c in candidates:
                try:
                    policy.validate_candidate_url(c.source_url)
                except ValueError:
                    return None
                revalidated.append(c)
            return ResearchFallbackResult(candidates=tuple(revalidated), confidence=confidence)

        def _serialize(value: ResearchFallbackResult | None) -> Mapping[str, object]:
            # _cached only calls serialize on a non-None result (negative
            # results are never cached), so ``value`` is a real result here.
            assert value is not None
            return {
                "candidates": [c.model_dump() for c in value.candidates],
                "confidence": value.confidence,
            }

        async def _compute() -> ResearchFallbackResult | None:
            return await self._research_call(app_name, provider_domains, policy)

        return await _cached(
            self._cache,
            key,
            ttl=RESEARCH_CACHE_TTL,
            deserialize=_deserialize,
            serialize=_serialize,
            compute=_compute,
        )

    async def _research_call(
        self, app_name: str, provider_domains: tuple[str, ...], policy: ResearchHostPolicy
    ) -> ResearchFallbackResult | None:
        metrics = _metrics()
        started = datetime.now(UTC)

        async def _factory() -> object:
            youdotcom = importlib.import_module("youdotcom")
            researchop = importlib.import_module("youdotcom.models.researchop")
            async with youdotcom.You(api_key_auth=self._api_key.get_secret_value()) as you:
                return await you.research_async(
                    input=(
                        f"Find the official login, signup, developer portal, API credential "
                        f"management, and authentication documentation pages for {app_name}. "
                        "Only cite official first-party pages."
                    ),
                    research_effort=researchop.ResearchEffort.STANDARD,
                    source_control=researchop.SourceControl(include_domains=list(provider_domains)),
                    output_schema=YOU_RESEARCH_SCHEMA,
                    retries=_bounded_retry_config(),
                    timeout_ms=int(self._timeout_seconds * 1000),
                )

        try:
            response = await _guard_call(
                "you_research", _factory, timeout_seconds=self._timeout_seconds + 5
            )
        except YouProviderError:
            return None
        finally:
            if metrics is not None:
                metrics.you_research_calls += 1
                metrics.you_research_latency_ms += (
                    datetime.now(UTC) - started
                ).total_seconds() * 1000

        return self._parse(response, policy)

    def _parse(self, response: object, policy: ResearchHostPolicy) -> ResearchFallbackResult | None:
        output = getattr(response, "output", None)
        if output is None:
            return None
        try:
            dumped = output.model_dump()
        except AttributeError:
            return None
        sources = dumped.get("sources")
        content = dumped.get("content")
        if not isinstance(sources, list):
            return None
        # Compare CANONICAL forms: "…/settings/api/" and "…/settings/api" are the
        # same page, and a case-different host is the same host. Query strings are
        # preserved because they can identify a real documentation page.
        cited: set[str] = set()
        for source in sources:
            if not isinstance(source, Mapping) or not source.get("url"):
                continue
            with contextlib.suppress(ValueError):
                cited.add(canonicalize(str(source.get("url"))))
        # `content` holds the structured object when output_schema is used.
        structured = content if isinstance(content, Mapping) else None
        if structured is None:
            return None
        confidence = structured.get("confidence")
        if confidence not in ("high", "medium", "low"):
            return None

        candidates: list[EvidenceCandidate] = []
        for rank, page in enumerate(structured.get("candidate_pages") or ()):
            if not isinstance(page, Mapping):
                continue
            url = page.get("url")
            category = page.get("category")
            if not isinstance(url, str):
                continue
            try:
                canonical = canonicalize(url)
            except ValueError:
                continue
            if canonical not in cited:
                continue  # every candidate must appear in output.sources
            if category not in _RESEARCH_CATEGORY_ENUM:
                continue
            try:
                safe_url = policy.validate_candidate_url(url)
            except ValueError:
                continue  # off-policy host rejected even if cited
            # The provider-supplied category is metadata only. Coverage decisions
            # use the deterministic, code-owned classification; the provider value
            # is kept only when our own signals are inconclusive.
            derived = classify_category(safe_url)
            candidates.append(
                EvidenceCandidate(
                    source_url=safe_url,
                    provider="you_research",
                    query_type="research_fallback",
                    rank=rank,
                    category=derived if derived != "unknown" else category,
                )
            )
        if not candidates:
            return None
        return ResearchFallbackResult(candidates=tuple(candidates), confidence=confidence)
