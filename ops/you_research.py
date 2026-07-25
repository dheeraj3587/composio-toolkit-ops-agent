"""You.com official-document research: discovery, content extraction, and an
optional bounded Research fallback — layered AHEAD of Perplexity and the
guarded HTTP fetcher in the OperationalResearch pipeline.

Boundary, stated once here because every class in this module exists to
enforce it: You.com is a research/retrieval provider, never a browser
automation provider. It never receives credentials, never selects the browser
provider, and a URL it returns is NEVER trusted just because You.com returned
it — every candidate is re-validated against :class:`ResearchHostPolicy`
(itself built only from already-trusted sources: the verified P1 record, a
verified baseline, and the reviewed static ``browser_host_policy`` dataset),
and :class:`~ops.operational_research.OfficialURLPolicy` remains the final
HTTPS/SSRF authority for anything actually fetched.

SDK contract notes (verified by installing ``youdotcom==2.2.0`` and
inspecting the REAL signatures, not by trusting documentation prose — pinned
by ``tests/test_you_research.py::test_sdk_contract_*``):

* ``you.search.unified_async`` and ``you.contents.generate_async`` are real
  ``async def`` coroutines; no thread-pool wrapping is needed.
* The installed SDK's ``search.unified`` has NO ``include_domains`` /
  ``exclude_domains`` / ``boost_domains`` parameter at all (confirmed absent
  from ``SearchRequest`` itself, by source inspection). Domain trust for
  Search is therefore enforced ENTIRELY downstream, in this module, never at
  the request layer. This is a documented, deliberate limitation of the
  pinned SDK version, not an oversight.
* The installed SDK's ``contents.generate`` has NO ``max_age`` request
  parameter. ``max_age`` here is a local cache-freshness bound only; it is
  never sent to You.com.
* There is no standalone ``you.research(...)`` method in this SDK version;
  the only Research surface is a mismatched ``ResearchTool`` nested inside
  the Agents API, with no ``output_schema`` / ``source_control`` / cited
  ``output.sources`` — none of the guarantees this integration requires.
  :class:`YouResearchFallback` therefore calls the documented REST endpoint
  directly over a guarded ``httpx`` client, the same pattern already used by
  ``OfficialEvidenceFetcher``, rather than inventing a compatibility shim
  around a mismatched SDK object.
* ``YouError`` (the SDK's exception base) exposes ``.status_code``; nothing
  else from a provider exception (``.message``, ``.body``, ``.headers``) is
  ever logged or surfaced — see :func:`map_you_error`.
* The SDK applies NO retry on its own unless a ``RetryConfig`` is explicitly
  supplied (verified from source). This module never supplies one, so the
  bounded retry implemented here (:func:`run_with_bounded_retry`) is the only
  retry layer — no double-retry risk.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import random
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal, Protocol, cast, runtime_checkable
from urllib.parse import urlsplit

import httpx
from pydantic import Field, SecretStr, field_validator

from ops.browser_host_policy import get_browser_policy
from ops.models import OperationalResearch, StrictModel, validate_https_url
from ops.operational_research import (
    MAX_EVIDENCE_DOCUMENTS,
    MAX_EXCERPT_CHARACTERS,
    EvidenceDiscovery,
    EvidenceDocument,
    HostResolver,
    OfficialURLPolicy,
    extract_https_urls,
)

# --------------------------------------------------------------------------
# Bounded constants
# --------------------------------------------------------------------------
MAX_CANDIDATE_SNIPPETS = 3
MAX_SNIPPET_CHARACTERS = 1_000
MAX_YOU_CONTENT_URLS = 10
YOU_MAX_RETRIES = 2
_RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})

QueryType = Literal["baseline", "access", "api_credentials", "research_fallback"]
EvidenceCategory = Literal[
    "login",
    "signup",
    "developer_portal",
    "api_authentication",
    "credential_creation",
    "oauth",
    "scopes",
    "rate_limits",
    "support",
    "general_docs",
    "unknown",
]

# Diversification caps so a result set is not e.g. eight login pages.
_CATEGORY_CAPS: dict[str, int] = {
    "login": 2,
    "signup": 2,
    "developer_portal": 2,
    "api_authentication": 3,
    "credential_creation": 3,
    "oauth": 3,
    "scopes": 1,
    "rate_limits": 1,
}
# Categories that satisfy the composite discovery's "enough coverage" test.
_ACCESS_CATEGORIES = frozenset({"login", "signup"})
_PORTAL_CATEGORIES = frozenset({"developer_portal"})
_CREDENTIAL_CATEGORIES = frozenset({"api_authentication", "credential_creation", "oauth"})


class EvidenceCandidate(StrictModel):
    """A discovered page plus enough metadata to rank and audit it.

    Deliberately NOT a full search-response passthrough: only a URL, a
    bounded title, up to three bounded snippets, and small classification
    metadata ever leave the discovery layer. Nothing here is a trust
    decision — a candidate still has to pass :class:`ResearchHostPolicy`
    before it can become a fetch target.
    """

    source_url: str
    title: str = Field(default="", max_length=500)
    snippets: tuple[Annotated[str, Field(max_length=MAX_SNIPPET_CHARACTERS)], ...] = Field(
        default=(), max_length=MAX_CANDIDATE_SNIPPETS
    )
    provider: Literal["p1", "you_search", "perplexity", "you_research"]
    query_type: QueryType
    rank: int = Field(ge=0)
    category: EvidenceCategory = "unknown"

    _validate_source_url = field_validator("source_url")(validate_https_url)


# --------------------------------------------------------------------------
# Protocols
# --------------------------------------------------------------------------
class RichEvidenceDiscovery(Protocol):
    """The candidate-returning discovery boundary (superset of EvidenceDiscovery).

    Kept as a SEPARATE protocol from :class:`~ops.operational_research.EvidenceDiscovery`
    rather than changing that protocol's call shape, because the old shape is
    depended on directly by ``OperationalResearchEnricher``'s existing code
    path and by its existing tests. Old implementations are adapted forward
    via :class:`LegacyDiscoveryAdapter`, never the reverse.
    """

    async def discover(
        self,
        *,
        app_name: str,
        p1_record: Mapping[str, object],
        baseline: OperationalResearch,
        official_hosts: tuple[str, ...],
    ) -> tuple[EvidenceCandidate, ...]: ...


@runtime_checkable
class EvidenceContentFetcher(Protocol):
    """Fetch bounded evidence documents for a batch of already-policy-checked URLs."""

    async def fetch_many(self, urls: Sequence[str]) -> tuple[EvidenceDocument, ...]: ...


class ResearchCache(Protocol):
    """Provider-neutral cache so identical app research does not re-spend credits."""

    def get(self, key: str) -> Mapping[str, object] | None: ...

    def put(self, key: str, value: Mapping[str, object], *, expires_at: datetime) -> None: ...


# --------------------------------------------------------------------------
# Trusted research-host policy
# --------------------------------------------------------------------------
def _hostname_of(url: str) -> str:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return ""
    if parsed.scheme != "https":
        return ""
    return (parsed.hostname or "").rstrip(".").casefold()


class ResearchHostPolicy:
    """The hosts You.com may be trusted to have discovered official pages on.

    The trusted set comes ONLY from already-reviewed data — never from a
    search result approving its own domain, and never by algorithmically
    widening a host (``developers.vendor.com`` does not imply ``*.vendor.com``
    unless that broader root is already explicitly reviewed in
    :mod:`ops.browser_host_policy`). URL-shape and SSRF enforcement is
    delegated to :class:`~ops.operational_research.OfficialURLPolicy` — this
    class only decides WHICH hosts that policy trusts.
    """

    def __init__(self, hosts: Sequence[str], *, resolver: HostResolver | None = None) -> None:
        normalized = {h.strip().rstrip(".").casefold() for h in hosts if h.strip()}
        exact = {h for h in normalized if not h.startswith("*.")}
        wildcard = {h[2:] for h in normalized if h.startswith("*.") and len(h) > 2}
        self._exact_hosts: frozenset[str] = frozenset(exact)
        self._wildcard_domains: frozenset[str] = frozenset(wildcard)
        all_hosts = exact | wildcard  # OfficialURLPolicy already treats a host as
        # "exact-or-subdomain", so a wildcard root is supplied as its bare domain.
        self._official_policy: OfficialURLPolicy | None = (
            OfficialURLPolicy(sorted(all_hosts), resolver=resolver) if all_hosts else None
        )

    @classmethod
    def build(
        cls,
        *,
        p1_record: Mapping[str, object],
        baseline: OperationalResearch,
        app_slug: str | None = None,
        extra_reviewed_hosts: Sequence[str] = (),
        resolver: HostResolver | None = None,
    ) -> ResearchHostPolicy:
        """Build the trusted set from verified P1 data, baseline, and reviewed policy."""

        hosts: list[str] = []
        primary = p1_record.get("primary_docs_url")
        if isinstance(primary, str):
            hosts.append(_hostname_of(primary))
        evidence = p1_record.get("evidence_urls")
        if isinstance(evidence, list):
            hosts.extend(_hostname_of(value) for value in evidence if isinstance(value, str))
        for value in (baseline.developer_portal_url, baseline.signup_url):
            if isinstance(value, str):
                hosts.append(_hostname_of(value))
        slug = app_slug or (baseline.app_slug or None)
        if slug:
            reviewed = get_browser_policy(slug)
            if reviewed is not None:
                # Reused verbatim: reviewed=False (inactive) apps are still
                # trustworthy for READING public docs; only launching a
                # browser session there is gated separately and unaffected.
                hosts.extend(reviewed.exact_hosts)
                hosts.extend(f"*.{domain}" for domain in reviewed.vendor_wildcard_domains)
        hosts.extend(extra_reviewed_hosts)
        return cls([h for h in hosts if h], resolver=resolver)

    @property
    def include_domains(self) -> tuple[str, ...]:
        """The flat, request-shaped trusted domain list (exact + ``*.``-wildcard)."""

        return tuple(
            sorted({*self._exact_hosts, *(f"*.{domain}" for domain in self._wildcard_domains)})
        )

    @property
    def official_url_policy(self) -> OfficialURLPolicy | None:
        """The underlying HTTPS/SSRF authority, for handing to a content fetcher."""

        return self._official_policy

    def validate_candidate_url(self, url: str) -> str:
        """Shape-validate and canonicalize a candidate URL without network I/O.

        Delegates entirely to :meth:`OfficialURLPolicy.sanitize_candidate` —
        this class never re-implements HTTPS/port/userinfo/query enforcement.
        """

        if self._official_policy is None:
            raise ValueError("no reviewed official host is trusted for this app yet")
        return self._official_policy.sanitize_candidate(url)

    async def validate_for_request(self, url: str) -> str:
        """Shape-validate AND resolve DNS to reject private/special networks."""

        if self._official_policy is None:
            raise ValueError("no reviewed official host is trusted for this app yet")
        return await self._official_policy.validate_for_request(url)

    def __bool__(self) -> bool:
        return self._official_policy is not None


# --------------------------------------------------------------------------
# Sanitized provider-error mapping + bounded retry
# --------------------------------------------------------------------------
def map_you_error(
    exc: Exception, *, capability: Literal["you_search", "you_contents", "you_research"]
) -> str:
    """Map any You.com provider exception to a stable, sanitized reason code.

    Reads ONLY ``exc.status_code`` (the one stable attribute every ``YouError``
    exposes). ``.message``/``.body``/``.headers``/the raw exception text are
    never read here and must never be logged or surfaced by callers.
    """

    if isinstance(exc, TimeoutError | asyncio.TimeoutError):
        return f"{capability}_timeout"
    status = getattr(exc, "status_code", None)
    if status == 401:
        return f"{capability}_unauthorized"
    if status == 402:
        return f"{capability}_credit_exhausted"
    if status == 403:
        return f"{capability}_forbidden"
    if status == 422:
        return (
            f"{capability}_invalid_schema"
            if capability == "you_research"
            else f"{capability}_invalid_request"
        )
    if status == 429:
        return f"{capability}_rate_limited"
    return f"{capability}_failed"


def _is_retryable(exc: Exception) -> bool:
    """Retry only 429, selected transient 5xx, and network connection failures."""

    status = getattr(exc, "status_code", None)
    if status in _RETRYABLE_STATUS_CODES:
        return True
    return status is None and isinstance(exc, httpx.ConnectError | httpx.ConnectTimeout)


def _retry_after_seconds(exc: Exception) -> float | None:
    headers = getattr(exc, "headers", None)
    if headers is None:
        return None
    value = headers.get("retry-after") if hasattr(headers, "get") else None
    if value is None:
        return None
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        return None


# Signals that the INTEGRATION itself is broken (wrong kwarg, renamed/missing
# module, bad attribute access) rather than a provider/network failure. These
# must never be silently retried or swallowed — see section 10's explicit
# "do not swallow programming errors such as TypeError" requirement, applied
# here too since this is where every SDK call actually happens.
_PROGRAMMING_ERRORS: tuple[type[Exception], ...] = (
    TypeError,
    AttributeError,
    NameError,
    ImportError,
    ModuleNotFoundError,
)


async def run_with_bounded_retry(
    call: Callable[[], Awaitable[object]],
    *,
    capability: Literal["you_search", "you_contents", "you_research"],
    max_retries: int = YOU_MAX_RETRIES,
) -> object:
    """Run ``call`` with a bounded, jittered retry — the ONLY retry layer.

    The SDK itself retries nothing by default (verified from source), so this
    is deliberately the single place attempts are bounded. Raises
    :class:`YouProviderError` carrying only a sanitized reason code — never
    the underlying provider exception or its payload. A programming error
    (see :data:`_PROGRAMMING_ERRORS`) is never caught here; it propagates.
    """

    last_reason = f"{capability}_failed"
    for attempt in range(max_retries + 1):
        try:
            return await call()
        except _PROGRAMMING_ERRORS:
            raise
        except Exception as exc:  # provider/network failures only; mapped to a reason code
            last_reason = map_you_error(exc, capability=capability)
            if attempt >= max_retries or not _is_retryable(exc):
                raise YouProviderError(capability=capability, reason_code=last_reason) from None
            retry_after = _retry_after_seconds(exc)
            base_delay = min(retry_after if retry_after is not None else float(2**attempt), 10.0)
            jitter = base_delay * (0.85 + random.random() * 0.3)
            await asyncio.sleep(jitter)
    raise YouProviderError(capability=capability, reason_code=last_reason)  # pragma: no cover


class YouProviderError(RuntimeError):
    """A sanitized You.com failure. Never carries provider payload or the API key."""

    def __init__(self, *, capability: str, reason_code: str) -> None:
        self.capability = capability
        self.reason_code = reason_code
        super().__init__(f"{capability} failed: {reason_code}")


# --------------------------------------------------------------------------
# Candidate classification, scoring, ranking, and diversification
# --------------------------------------------------------------------------
_PATH_WEIGHTS: dict[str, int] = {
    "login": 30,
    "signin": 30,
    "signup": 25,
    "register": 20,
    "developer": 25,
    "developers": 25,
    "api": 30,
    "authentication": 30,
    "auth": 20,
    "oauth": 30,
    "token": 30,
    "private-app": 35,
    "credentials": 30,
    "settings": 15,
    "scopes": 25,
}
_PENALTY_TERMS: tuple[str, ...] = (
    "blog",
    "community",
    "forum",
    "careers",
    "press",
    "status",
    "campaign",
    "case-study",
    "case-studies",
    "webinar",
)
_LOGIN_TERMS = ("login", "signin", "sign-in", "log-in")
_SIGNUP_TERMS = ("signup", "sign-up", "register", "registration")
_PORTAL_TERMS = ("developer", "developers", "dashboard")
_AUTH_TERMS = ("authentication", "auth", "oauth")
_CREDENTIAL_TERMS = (
    "token",
    "api-key",
    "apikey",
    "private-app",
    "credentials",
    "personal-access-token",
)
_SCOPE_TERMS = ("scope", "scopes", "permission", "permissions")
_RATE_LIMIT_TERMS = ("rate-limit", "rate_limit", "ratelimit", "throttl")
_SUPPORT_TERMS = ("support", "help", "contact")
_DOCS_TERMS = ("docs", "documentation", "guide", "guides")


def _tokenize(url: str, title: str) -> str:
    parsed = urlsplit(url)
    # The subdomain often carries the signal for a root path (e.g.
    # ``developers.example.com/``, ``api.example.com/``), so the hostname is
    # part of the haystack too, not just the path and title.
    hostname = (parsed.hostname or "").replace(".", " ")
    return f"{hostname} {parsed.path} {title}".casefold().replace("_", "-")


def classify_category(url: str, title: str = "") -> EvidenceCategory:
    haystack = _tokenize(url, title)
    if any(term in haystack for term in _LOGIN_TERMS):
        return "login"
    if any(term in haystack for term in _SIGNUP_TERMS):
        return "signup"
    if any(term in haystack for term in _CREDENTIAL_TERMS):
        return "credential_creation"
    if "oauth" in haystack:
        return "oauth"
    if any(term in haystack for term in _AUTH_TERMS) and "api" in haystack:
        return "api_authentication"
    if any(term in haystack for term in _SCOPE_TERMS):
        return "scopes"
    if any(term in haystack for term in _RATE_LIMIT_TERMS):
        return "rate_limits"
    if any(term in haystack for term in _PORTAL_TERMS):
        return "developer_portal"
    if any(term in haystack for term in _SUPPORT_TERMS):
        return "support"
    if any(term in haystack for term in _DOCS_TERMS):
        return "general_docs"
    return "unknown"


def _score(url: str, title: str, snippets: Sequence[str]) -> int:
    haystack = _tokenize(url, title)
    score = 0
    for term, weight in _PATH_WEIGHTS.items():
        if term in haystack:
            score += weight
    lowered_title = title.casefold()
    lowered_snippets = " ".join(snippets).casefold()
    for term in _PATH_WEIGHTS:
        if term in lowered_title:
            score += 10
        elif term in lowered_snippets:
            score += 5
    if any(term in haystack for term in _PENALTY_TERMS):
        score -= 20
    return score


def canonicalize(url: str) -> str:
    """Canonical form for cross-provider dedup: lowercase host, no fragment/trailing slash."""

    parsed = urlsplit(url.strip())
    hostname = (parsed.hostname or "").rstrip(".").casefold()
    path = parsed.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/") or "/"
    query = parsed.query
    return f"{parsed.scheme}://{hostname}{path}" + (f"?{query}" if query else "")


def deduplicate_and_rank_candidates(
    candidates: Sequence[EvidenceCandidate],
    *,
    limit: int = MAX_EVIDENCE_DOCUMENTS,
) -> tuple[EvidenceCandidate, ...]:
    """Deduplicate by canonical URL, rank by relevance score, then diversify.

    Ranking is relevance-only; it never substitutes for the security decision
    a domain policy makes elsewhere — a low-scoring candidate that already
    passed :class:`ResearchHostPolicy` is just as safe as a high-scoring one.
    """

    best: dict[str, tuple[int, EvidenceCandidate]] = {}
    for candidate in candidates:
        key = canonicalize(candidate.source_url)
        scored = _score(candidate.source_url, candidate.title, candidate.snippets)
        current = best.get(key)
        if current is None or scored > current[0]:
            best[key] = (scored, candidate)

    ordered = sorted(best.values(), key=lambda pair: pair[0], reverse=True)
    selected: list[EvidenceCandidate] = []
    category_counts: dict[str, int] = {}
    for _score_value, candidate in ordered:
        if len(selected) >= limit:
            break
        cap = _CATEGORY_CAPS.get(candidate.category)
        count = category_counts.get(candidate.category, 0)
        if cap is not None and count >= cap:
            continue
        selected.append(candidate)
        category_counts[candidate.category] = count + 1
    return tuple(selected)


def coverage_categories(candidates: Sequence[EvidenceCandidate]) -> frozenset[str]:
    return frozenset(candidate.category for candidate in candidates)


def has_sufficient_coverage(candidates: Sequence[EvidenceCandidate]) -> bool:
    """True once candidates include an access page, a portal/API page, and a
    credential page — the composite discovery's threshold for skipping the
    next (more expensive, or lower-trust) provider in the chain."""

    categories = coverage_categories(candidates)
    return (
        bool(categories & _ACCESS_CATEGORIES)
        and bool(categories & (_PORTAL_CATEGORIES | _CREDENTIAL_CATEGORIES))
        and bool(categories & _CREDENTIAL_CATEGORIES)
    )


# --------------------------------------------------------------------------
# YouSearchDiscovery
# --------------------------------------------------------------------------
class YouSearchDiscovery:
    """Primary discovery provider: You.com Web Search, two bounded queries."""

    def __init__(
        self,
        api_key: SecretStr | str,
        *,
        count: int = 5,
        timeout_seconds: float = 20.0,
        max_calls: int = 2,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._api_key = api_key if isinstance(api_key, SecretStr) else SecretStr(api_key)
        self._count = count
        self._timeout_seconds = timeout_seconds
        self._max_calls = max_calls
        self._http_client = http_client

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
        policy = ResearchHostPolicy(official_hosts)
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
                response = await self._search(query=query)
            except YouProviderError:
                continue  # one query failing must not fail discovery entirely
            discovered.extend(self._convert_results(response, query_type=query_type, policy=policy))
        return deduplicate_and_rank_candidates(discovered)

    async def _search(self, *, query: str) -> object:
        async def _call() -> object:
            youdotcom = importlib.import_module("youdotcom")
            safesearch_module = importlib.import_module("youdotcom.models.safesearch")
            you = youdotcom.You(api_key_auth=self._api_key.get_secret_value())
            return await asyncio.wait_for(
                you.search.unified_async(
                    query=query,
                    count=self._count,
                    safesearch=safesearch_module.SafeSearch.STRICT,
                    timeout_ms=int(self._timeout_seconds * 1000),
                ),
                timeout=self._timeout_seconds,
            )

        return await run_with_bounded_retry(_call, capability="you_search")

    def _convert_results(
        self, response: object, *, query_type: QueryType, policy: ResearchHostPolicy
    ) -> list[EvidenceCandidate]:
        results = getattr(response, "results", None)
        web_results = list(getattr(results, "web", None) or ())
        candidates: list[EvidenceCandidate] = []
        for rank, item in enumerate(web_results):
            url = getattr(item, "url", None)
            if not isinstance(url, str) or not url:
                continue
            try:
                validated = validate_https_url(url)
                safe_url = policy.validate_candidate_url(validated)
            except ValueError:
                continue  # off-policy or malformed — never trusted just because You.com returned it
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
                    category=classify_category(safe_url, title),
                )
            )
        # News results are intentionally ignored for this use case UNLESS a
        # first-party migration announcement is the only lead — that judgment
        # call is out of scope for an automated pipeline, so news is skipped.
        return candidates


# --------------------------------------------------------------------------
# Legacy-protocol adapter + composite discovery
# --------------------------------------------------------------------------
class LegacyDiscoveryAdapter:
    """Adapt an old :class:`EvidenceDiscovery` (URL-only) into :class:`RichEvidenceDiscovery`.

    Used to fold ``PerplexitySearchDiscovery`` into the same composite chain
    as :class:`YouSearchDiscovery` without changing Perplexity's own call
    shape or touching any test that constructs it directly.
    """

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
        policy = ResearchHostPolicy(official_hosts) if official_hosts else None
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
    """You.com first; Perplexity (or any other provider) only fills gaps.

    A provider that raises is skipped, never fatal to the whole enrichment —
    except a genuine programming error (``TypeError`` etc.), which is not
    caught here and propagates, exactly so a broken integration is visible
    rather than silently swallowed.
    """

    def __init__(
        self,
        providers: Sequence[RichEvidenceDiscovery],
        *,
        minimum_candidates_before_stopping: int = 4,
    ) -> None:
        self._providers = tuple(providers)
        self._minimum_candidates_before_stopping = minimum_candidates_before_stopping
        # Sanitized, in-memory only — which provider actually supplied the
        # candidates used on the most recent call. No secrets, no payload.
        self.last_provider_used: str | None = None

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
                raise  # a broken integration must be visible, never silently swallowed
            except (YouProviderError, ValueError, RuntimeError, OSError):
                continue  # expected provider-shaped failures only
            if found:
                used.append(type(provider).__name__)
            collected.extend(found)
            ranked = deduplicate_and_rank_candidates(collected)
            if has_sufficient_coverage(ranked) and len(ranked) >= min(
                self._minimum_candidates_before_stopping, len(collected)
            ):
                self.last_provider_used = "+".join(used) or None
                return ranked
        self.last_provider_used = "+".join(used) or None
        return deduplicate_and_rank_candidates(collected)


# --------------------------------------------------------------------------
# Content fetchers: You Contents -> guarded HTTP fallback (per URL)
# --------------------------------------------------------------------------
class YouContentsFetcher:
    """Fetch clean Markdown for already policy-approved official URLs, in bounded batches."""

    def __init__(
        self,
        api_key: SecretStr | str,
        *,
        policy: ResearchHostPolicy,
        crawl_timeout: int = 10,
        max_age: int | None = 86_400,
        request_timeout: float = 30.0,
    ) -> None:
        self._api_key = api_key if isinstance(api_key, SecretStr) else SecretStr(api_key)
        self._policy = policy
        self._crawl_timeout = crawl_timeout
        self._max_age = max_age
        self._request_timeout = request_timeout

    async def fetch_many(self, urls: Sequence[str]) -> tuple[EvidenceDocument, ...]:
        bounded = list(dict.fromkeys(urls))[:MAX_YOU_CONTENT_URLS]
        safe_urls: list[str] = []
        for url in bounded:
            try:
                safe_urls.append(await self._policy.validate_for_request(url))
            except ValueError:
                continue  # never sent to You.com if it fails our own policy first
        if not safe_urls:
            return ()

        try:
            responses = await self._generate(safe_urls)
        except YouProviderError:
            return ()

        documents: list[EvidenceDocument] = []
        for page in responses:
            document = self._to_document(page)
            if document is not None:
                documents.append(document)
        return tuple(documents)

    async def _generate(self, urls: list[str]) -> list[object]:
        async def _call() -> object:
            youdotcom = importlib.import_module("youdotcom")
            formats_module = importlib.import_module("youdotcom.models.contentsformats")
            you = youdotcom.You(api_key_auth=self._api_key.get_secret_value())
            return await asyncio.wait_for(
                you.contents.generate_async(
                    urls=urls,
                    formats=[
                        formats_module.ContentsFormats.MARKDOWN,
                        formats_module.ContentsFormats.METADATA,
                    ],
                    crawl_timeout=self._crawl_timeout,
                    timeout_ms=int(self._request_timeout * 1000),
                ),
                timeout=self._request_timeout,
            )

        result = await run_with_bounded_retry(_call, capability="you_contents")
        # The pinned SDK's contents.generate_async is typed to always return a
        # list (verified by the SDK contract test); this is a narrowing cast; it does not assume anything not already verified.
        if result is None:
            return []
        return cast("list[object]", result)

    def _to_document(self, page: object) -> EvidenceDocument | None:
        returned_url = getattr(page, "url", None)
        if not isinstance(returned_url, str) or not returned_url:
            return None
        try:
            # The URL You.com actually fetched must independently pass our
            # policy again — a redirect during crawling must not smuggle in
            # an off-policy host.
            safe_url = self._policy.validate_candidate_url(returned_url)
        except ValueError:
            return None
        markdown = getattr(page, "markdown", None)
        if not isinstance(markdown, str) or not markdown.strip():
            return None  # empty Markdown is rejected, not passed through as evidence
        metadata = getattr(page, "metadata", None)
        title = (
            getattr(page, "title", None)
            or getattr(metadata, "site_name", None)
            or "Official documentation"
        )
        return EvidenceDocument(
            source_url=safe_url,
            title=str(title)[:500],
            relevant_text=_strip_injection_markers(markdown)[:MAX_EXCERPT_CHARACTERS],
        )


_INJECTION_MARKERS = re.compile(
    r"(?im)^\s*(ignore (all|previous) instructions|system prompt|you are now|disregard the above)\b.*$"
)


def _strip_injection_markers(markdown: str) -> str:
    """Cosmetic-only: drop lines shaped like a prompt-injection directive for
    DISPLAY. This is not a trust boundary — fetched text is untrusted evidence
    fed to Gemini's structured extraction regardless, never executed as an
    instruction by anything in this pipeline."""

    return _INJECTION_MARKERS.sub("[removed: instruction-shaped text]", markdown)


class GuardedHTTPEvidenceFetcher:
    """Adapt the existing per-URL ``OfficialEvidenceFetcher`` to the batch protocol."""

    def __init__(self, fetcher: object) -> None:
        self._fetcher = fetcher

    async def fetch_many(self, urls: Sequence[str]) -> tuple[EvidenceDocument, ...]:
        documents: list[EvidenceDocument] = []
        for url in urls:
            try:
                documents.append(await self._fetcher.fetch(url))  # type: ignore[attr-defined]
            except (httpx.HTTPError, OSError, ValueError):
                continue
        return tuple(documents)


class FallbackEvidenceContentFetcher:
    """You Contents first; the guarded HTTP fetcher fills whatever it missed."""

    def __init__(self, primary: EvidenceContentFetcher, fallback: EvidenceContentFetcher) -> None:
        self._primary = primary
        self._fallback = fallback

    async def fetch_many(self, urls: Sequence[str]) -> tuple[EvidenceDocument, ...]:
        primary_documents = await self._primary.fetch_many(urls)
        fetched = {canonicalize(document.source_url) for document in primary_documents}
        missing = [url for url in urls if canonicalize(url) not in fetched]
        fallback_documents = await self._fallback.fetch_many(missing) if missing else ()
        return merge_documents(primary_documents, fallback_documents)


def merge_documents(
    primary: Sequence[EvidenceDocument], fallback: Sequence[EvidenceDocument]
) -> tuple[EvidenceDocument, ...]:
    seen: set[str] = set()
    merged: list[EvidenceDocument] = []
    for document in (*primary, *fallback):
        key = canonicalize(document.source_url)
        if key in seen:
            continue
        seen.add(key)
        merged.append(document)
    return tuple(merged[:MAX_EVIDENCE_DOCUMENTS])


# --------------------------------------------------------------------------
# Optional You Research fallback (disabled by default; direct REST call)
# --------------------------------------------------------------------------
YOU_RESEARCH_SCHEMA: dict[str, object] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "login_url",
        "signup_url",
        "developer_portal_url",
        "credential_management_url",
        "authentication_method",
        "credential_creation_steps",
        "source_urls",
        "confidence",
    ],
    "properties": {
        "login_url": {"type": ["string", "null"]},
        "signup_url": {"type": ["string", "null"]},
        "developer_portal_url": {"type": ["string", "null"]},
        "credential_management_url": {"type": ["string", "null"]},
        "authentication_method": {"type": ["string", "null"]},
        "credential_creation_steps": {"type": "array", "items": {"type": "string"}},
        "source_urls": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
    },
}
_RESEARCH_ENDPOINT = "https://api.you.com/v1/research"


@dataclass(frozen=True, slots=True)
class ResearchFallbackResult:
    """Untrusted candidate source URLs from You Research, ready for You Contents.

    Deliberately does NOT carry ``credential_creation_steps``/``authentication_method``
    prose forward as trusted fact — see the module docstring: Research is only
    ever allowed to point at MORE pages for the SAME canonical Gemini
    extraction + validation path, never to author an ``OperationalResearch``
    field directly.
    """

    candidate_urls: tuple[str, ...]
    confidence: Literal["high", "medium", "low"]


class YouResearchFallback:
    """Last-resort discovery: multi-step Research, called at most once per enrichment.

    Uses the documented REST endpoint directly (see the module docstring for
    why the installed SDK's mismatched ``ResearchTool`` object is not used).
    Disabled by default; the caller decides whether Search + Contents were
    already sufficient before ever constructing/invoking this.
    """

    def __init__(
        self,
        api_key: SecretStr | str,
        *,
        http_client: httpx.AsyncClient,
        timeout_seconds: float = 60.0,
    ) -> None:
        self._api_key = api_key if isinstance(api_key, SecretStr) else SecretStr(api_key)
        self._http_client = http_client
        self._timeout_seconds = timeout_seconds

    async def research(
        self, *, app_name: str, official_hosts: tuple[str, ...], policy: ResearchHostPolicy
    ) -> ResearchFallbackResult | None:
        if not official_hosts:
            return None

        async def _call() -> httpx.Response:
            response = await self._http_client.post(
                _RESEARCH_ENDPOINT,
                json={
                    "input": (
                        f"Find the official login, signup, developer portal, API credential "
                        f"management, and authentication documentation pages for {app_name}. "
                        "Only cite official first-party pages."
                    ),
                    "research_effort": "standard",
                    "source_control": {"include_domains": list(official_hosts)},
                    "output_schema": YOU_RESEARCH_SCHEMA,
                },
                headers={
                    "X-API-Key": self._api_key.get_secret_value(),
                    "Content-Type": "application/json",
                },
                timeout=self._timeout_seconds,
            )
            if response.status_code >= 400:
                raise _HttpStatusError(response.status_code, response.headers)
            return response

        try:
            response = await run_with_bounded_retry(_call, capability="you_research")
        except YouProviderError:
            return None

        try:
            payload = response.json()  # type: ignore[attr-defined]
        except ValueError:
            return None
        return self._validate(payload, policy)

    def _validate(
        self, payload: Mapping[str, object], policy: ResearchHostPolicy
    ) -> ResearchFallbackResult | None:
        output = payload.get("output")
        if not isinstance(output, Mapping):
            return None
        content = output.get("content")
        sources = output.get("sources")
        if not isinstance(content, Mapping) or not isinstance(sources, list):
            return None
        cited_urls = {
            str(source.get("url"))
            for source in sources
            if isinstance(source, Mapping) and source.get("url")
        }

        confidence = content.get("confidence")
        if confidence not in ("high", "medium", "low"):
            return None

        candidate_urls: list[str] = []
        for value in content.get("source_urls") or ():
            if not isinstance(value, str) or value not in cited_urls:
                continue  # every source_url must appear in output.sources
            try:
                # Shape AND host-policy enforcement together: an untrusted
                # Research response cannot smuggle in an off-policy host just
                # because it labeled the URL a "source".
                safe = policy.validate_candidate_url(value)
            except ValueError:
                continue
            candidate_urls.append(safe)
        if not candidate_urls:
            return None
        return ResearchFallbackResult(candidate_urls=tuple(candidate_urls), confidence=confidence)


class _HttpStatusError(Exception):
    """Sanitized stand-in exposing only ``.status_code``/``.headers`` for mapping."""

    def __init__(self, status_code: int, headers: httpx.Headers) -> None:
        self.status_code = status_code
        self.headers = headers
        super().__init__(f"HTTP {status_code}")


# --------------------------------------------------------------------------
# NOTE: ``extract_https_urls`` (documented-evidence URL extraction used for
# operational-URL validation) lives in ``ops.operational_research`` — that
# module is the lower-level base this one builds on, and
# ``OperationalResearchEnricher._validate_extracted_research`` needs the same
# helper without this module importing back into it (which would be
# circular, since this module already imports FROM operational_research).
# --------------------------------------------------------------------------
# In-memory research cache (credit protection)
# --------------------------------------------------------------------------
class InMemoryResearchCache:
    """A simple process-local :class:`ResearchCache`. No secrets are ever cached."""

    def __init__(self) -> None:
        self._store: dict[str, tuple[Mapping[str, object], datetime]] = {}

    def get(self, key: str) -> Mapping[str, object] | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if datetime.now(UTC) >= expires_at:
            del self._store[key]
            return None
        return value

    def put(self, key: str, value: Mapping[str, object], *, expires_at: datetime) -> None:
        self._store[key] = (dict(value), expires_at)


def cache_key(kind: Literal["you-search", "you-contents", "you-research"], *parts: str) -> str:
    digest = hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]
    return f"{kind}:v1:{digest}"


SEARCH_CACHE_TTL = timedelta(hours=24)
CONTENTS_CACHE_TTL = timedelta(hours=24)
RESEARCH_CACHE_TTL = timedelta(days=7)


# --------------------------------------------------------------------------
# Observability (sanitized only)
# --------------------------------------------------------------------------
ProviderHealth = Literal[
    "configured_not_verified",
    "ready",
    "rate_limited",
    "credit_exhausted",
    "not_configured",
    "disabled",
]


@dataclass(slots=True)
class YouResearchMetrics:
    """Sanitized counters for one enrichment attempt. No payload, ever."""

    you_search_calls: int = 0
    you_search_latency_ms: float = 0.0
    you_search_results_returned: int = 0
    you_search_results_policy_accepted: int = 0
    you_contents_calls: int = 0
    you_contents_pages_requested: int = 0
    you_contents_pages_returned: int = 0
    you_contents_latency_ms: float = 0.0
    you_research_calls: int = 0
    you_research_latency_ms: float = 0.0
    research_cache_hits: int = 0
    research_cache_misses: int = 0
    discovery_provider_used: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "you_search_calls": self.you_search_calls,
            "you_search_latency_ms": self.you_search_latency_ms,
            "you_search_results_returned": self.you_search_results_returned,
            "you_search_results_policy_accepted": self.you_search_results_policy_accepted,
            "you_contents_calls": self.you_contents_calls,
            "you_contents_pages_requested": self.you_contents_pages_requested,
            "you_contents_pages_returned": self.you_contents_pages_returned,
            "you_contents_latency_ms": self.you_contents_latency_ms,
            "you_research_calls": self.you_research_calls,
            "you_research_latency_ms": self.you_research_latency_ms,
            "research_cache_hits": self.research_cache_hits,
            "research_cache_misses": self.research_cache_misses,
            "discovery_provider_used": self.discovery_provider_used,
        }


def provider_health_state(
    *, configured: bool, enabled: bool, last_reason_code: str | None = None
) -> ProviderHealth:
    """A LIGHTWEIGHT configuration check — never a live probe. See ``probe-you``
    in ``ops.cli`` for the explicit, opt-in live diagnostic."""

    if not configured:
        return "not_configured"
    if not enabled:
        return "disabled"
    if last_reason_code:
        if last_reason_code.endswith("_rate_limited"):
            return "rate_limited"
        if last_reason_code.endswith("_credit_exhausted"):
            return "credit_exhausted"
    return "configured_not_verified"


__all__ = [
    "MAX_CANDIDATE_SNIPPETS",
    "MAX_SNIPPET_CHARACTERS",
    "MAX_YOU_CONTENT_URLS",
    "YOU_MAX_RETRIES",
    "YOU_RESEARCH_SCHEMA",
    "CompositeEvidenceDiscovery",
    "EvidenceCandidate",
    "EvidenceContentFetcher",
    "FallbackEvidenceContentFetcher",
    "GuardedHTTPEvidenceFetcher",
    "InMemoryResearchCache",
    "LegacyDiscoveryAdapter",
    "ResearchCache",
    "ResearchFallbackResult",
    "ResearchHostPolicy",
    "RichEvidenceDiscovery",
    "YouContentsFetcher",
    "YouProviderError",
    "YouResearchFallback",
    "YouResearchMetrics",
    "YouSearchDiscovery",
    "cache_key",
    "canonicalize",
    "classify_category",
    "coverage_categories",
    "deduplicate_and_rank_candidates",
    "extract_https_urls",
    "has_sufficient_coverage",
    "map_you_error",
    "merge_documents",
    "provider_health_state",
    "run_with_bounded_retry",
]
