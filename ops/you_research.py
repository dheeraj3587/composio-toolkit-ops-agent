"""You.com official-document research: discovery, content extraction, and an
optional bounded Research fallback — layered AHEAD of Perplexity and the
guarded HTTP fetcher in the OperationalResearch pipeline.

Boundary, stated once because every class here enforces it: You.com is a
research/retrieval provider, never a browser automation provider. It never
receives credentials, never selects the browser provider, and a URL it returns
is NEVER trusted just because You.com returned it — every candidate is
re-validated against :class:`ResearchHostPolicy` (built only from already-
trusted sources: the verified P1 record, a verified baseline, and the reviewed
static ``browser_host_policy`` dataset), and the underlying
:class:`~ops.operational_research.OfficialURLPolicy` remains the final
HTTPS/SSRF authority for anything actually fetched.

SDK contract (verified against the version pinned in
``requirements-providers.txt`` — see ``tests/test_you_research.py::TestSdkContract``,
which reads that pin and fails loudly if a future upgrade changes the surface):

* ``search_post_async`` accepts ``include_domains`` as a JSON array of bare
  domains; used as the provider-side first filter, with local policy validation
  as the actual security boundary AFTER results return. The field is OMITTED when
  there is nothing to filter on — an empty array is an empty allowlist, not
  "unfiltered".
* ``contents.generate_async`` accepts ``max_age`` and ``crawl_timeout`` and
  ``formats`` (``markdown``/``html``/``metadata``); we request markdown only.
* ``research_async`` accepts ``source_control`` (include_domains) and
  ``output_schema`` and returns ``output.sources`` — so Research fallback uses
  the SDK directly (no raw REST shim needed at this version).
* Every SDK call auto-retries by default; we pass ONE explicit bounded
  ``RetryConfig`` so retries are deterministic (429/5xx + connection errors,
  bounded elapsed time) and never stack a second custom retry layer on top.
* The ``You`` client is always used as an ``async with`` context manager so its
  httpx client is closed within the same event loop that created it (the app
  invokes enrichment via ``asyncio.run`` from sync code, so a persistent
  loop-bound client would be unsafe).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import importlib
import re
import threading
from collections.abc import Awaitable, Callable, Iterator, Mapping, Sequence
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol, TypeVar, runtime_checkable
from urllib.parse import urlsplit

import httpx
from pydantic import Field, SecretStr, ValidationError, field_validator

from ops.browser_host_policy import get_browser_policy
from ops.models import OperationalResearch, StrictModel, validate_https_url
from ops.operational_research import (
    MAX_EVIDENCE_DOCUMENTS,
    MAX_EXCERPT_CHARACTERS,
    EvidenceDiscovery,
    EvidenceDocument,
    HostResolver,
    OfficialURLPolicy,
)

# --------------------------------------------------------------------------
# Bounded constants
# --------------------------------------------------------------------------
MAX_CANDIDATE_SNIPPETS = 3
MAX_SNIPPET_CHARACTERS = 1_000
MAX_YOU_CONTENT_URLS = 10
# Snippets are untrusted web text, so only a small bounded prefix ever reaches
# the deterministic classifier.
MAX_CLASSIFICATION_SNIPPET_CHARACTERS = 300

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
_ACCESS_CATEGORIES = frozenset({"login", "signup"})
_PORTAL_OR_API_DOCS = frozenset({"developer_portal", "api_authentication"})
_CREDENTIAL_SURFACE = frozenset({"credential_creation", "oauth"})
# Categories a Research candidate page may be classified into (section 19).
_RESEARCH_CATEGORY_ENUM = frozenset(
    {
        "login",
        "signup",
        "developer_portal",
        "api_authentication",
        "credential_creation",
        "oauth",
        "scopes",
        "rate_limits",
        "general_docs",
    }
)

SEARCH_CACHE_TTL = timedelta(hours=24)
RESEARCH_CACHE_TTL = timedelta(days=7)


class EvidenceCandidate(StrictModel):
    """A discovered page plus bounded metadata to rank and audit it.

    Not a full search-response passthrough: only a URL, a bounded title, up to
    three bounded snippets, and small classification metadata leave discovery.
    A candidate is never a trust decision — it must still pass
    :class:`ResearchHostPolicy` before it can become a fetch target.
    """

    source_url: str
    title: str = Field(default="", max_length=500)
    snippets: tuple[str, ...] = Field(default=(), max_length=MAX_CANDIDATE_SNIPPETS)
    provider: Literal["p1", "you_search", "perplexity", "you_research"]
    query_type: QueryType
    rank: int = Field(ge=0)
    category: EvidenceCategory = "unknown"

    _validate_source_url = field_validator("source_url")(validate_https_url)

    @field_validator("snippets")
    @classmethod
    def _bound_snippets(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(s[:MAX_SNIPPET_CHARACTERS] for s in value[:MAX_CANDIDATE_SNIPPETS])


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


@runtime_checkable
class EvidenceContentFetcher(Protocol):
    async def fetch_many(self, urls: Sequence[str]) -> tuple[EvidenceDocument, ...]: ...


class ResearchCache(Protocol):
    """Provider-neutral cache so identical app research does not re-spend credits."""

    def get(self, key: str) -> Mapping[str, object] | None: ...

    def put(self, key: str, value: Mapping[str, object], *, expires_at: datetime) -> None: ...


# --------------------------------------------------------------------------
# Sanitized metrics (one instance per enrichment attempt, via a contextvar)
# --------------------------------------------------------------------------
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

    def as_dict(self) -> dict[str, int | float | str | None]:
        return {
            "you_search_calls": self.you_search_calls,
            "you_search_latency_ms": round(self.you_search_latency_ms, 1),
            "you_search_results_returned": self.you_search_results_returned,
            "you_search_results_policy_accepted": self.you_search_results_policy_accepted,
            "you_contents_calls": self.you_contents_calls,
            "you_contents_pages_requested": self.you_contents_pages_requested,
            "you_contents_pages_returned": self.you_contents_pages_returned,
            "you_contents_latency_ms": round(self.you_contents_latency_ms, 1),
            "you_research_calls": self.you_research_calls,
            "you_research_latency_ms": round(self.you_research_latency_ms, 1),
            "research_cache_hits": self.research_cache_hits,
            "research_cache_misses": self.research_cache_misses,
            "discovery_provider_used": self.discovery_provider_used,
        }


_metrics_var: ContextVar[YouResearchMetrics | None] = ContextVar("you_metrics", default=None)


@contextlib.contextmanager
def use_metrics(metrics: YouResearchMetrics) -> Iterator[YouResearchMetrics]:
    token = _metrics_var.set(metrics)
    try:
        yield metrics
    finally:
        _metrics_var.reset(token)


def _metrics() -> YouResearchMetrics | None:
    return _metrics_var.get()


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

    Trust comes ONLY from already-reviewed data. Hosts are tracked as EXACT
    hosts and WILDCARD domains separately and handed to
    :class:`OfficialURLPolicy` with the explicit exact/wildcard rules — never
    the legacy exact-or-subdomain widening — so ``developers.example.com`` can
    never silently grant ``anything.developers.example.com``.
    """

    def __init__(
        self,
        exact_hosts: Sequence[str] = (),
        wildcard_domains: Sequence[str] = (),
        *,
        resolver: HostResolver | None = None,
    ) -> None:
        self._exact_hosts = frozenset(
            h.strip().rstrip(".").casefold() for h in exact_hosts if h.strip()
        )
        self._wildcard_domains = frozenset(
            d.strip().rstrip(".").removeprefix("*.").casefold()
            for d in wildcard_domains
            if d.strip()
        )
        if self._exact_hosts or self._wildcard_domains:
            self._official_policy: OfficialURLPolicy | None = OfficialURLPolicy(
                exact_hosts=sorted(self._exact_hosts),
                wildcard_domains=sorted(self._wildcard_domains),
                resolver=resolver,
            )
        else:
            self._official_policy = None

    @classmethod
    def from_domains(
        cls, domains: Sequence[str], *, resolver: HostResolver | None = None
    ) -> ResearchHostPolicy:
        """Build from a flat list where ``*.x`` entries are wildcard domains and
        everything else is an exact host (the inverse of ``include_domains``)."""

        return cls(
            exact_hosts=[d for d in domains if not d.startswith("*.")],
            wildcard_domains=[d[2:] for d in domains if d.startswith("*.")],
            resolver=resolver,
        )

    @classmethod
    def build(
        cls,
        *,
        p1_record: Mapping[str, object],
        baseline: OperationalResearch,
        app_slug: str | None = None,
        resolver: HostResolver | None = None,
    ) -> ResearchHostPolicy:
        """Build the trusted set from verified P1 data, baseline, and reviewed policy.

        P1-derived and baseline-derived hosts are treated as EXACT hosts (a
        specific reviewed page's host), never widened. Wildcard breadth comes
        ONLY from the reviewed ``browser_host_policy`` ``vendor_wildcard_domains``.
        """

        exact: list[str] = []
        wildcard: list[str] = []
        primary = p1_record.get("primary_docs_url")
        if isinstance(primary, str):
            exact.append(_hostname_of(primary))
        evidence = p1_record.get("evidence_urls")
        if isinstance(evidence, list):
            exact.extend(_hostname_of(v) for v in evidence if isinstance(v, str))
        for value in (baseline.developer_portal_url, baseline.signup_url):
            if isinstance(value, str):
                exact.append(_hostname_of(value))
        slug = app_slug or (baseline.app_slug or None)
        if slug:
            reviewed = get_browser_policy(slug)
            if reviewed is not None:
                exact.extend(reviewed.exact_hosts)
                wildcard.extend(reviewed.vendor_wildcard_domains)
        return cls(
            exact_hosts=[h for h in exact if h],
            wildcard_domains=[d for d in wildcard if d],
            resolver=resolver,
        )

    @property
    def include_domains(self) -> tuple[str, ...]:
        """Flat trusted domain list for building a policy or a debug view."""

        return tuple(sorted({*self._exact_hosts, *(f"*.{d}" for d in self._wildcard_domains)}))

    @property
    def provider_include_domains(self) -> tuple[str, ...]:
        """Bare domains for You.com's request-level ``include_domains`` filter.

        A reviewed wildcard ``*.pipedrive.com`` is sent as the bare
        ``pipedrive.com`` (the SDK/API expects bare domains, never ``*.``
        notation). This is only a first-pass provider filter; local
        :meth:`validate_candidate_url` still enforces the actual exact/wildcard
        rule on every returned result.
        """

        return tuple(sorted(self._exact_hosts | self._wildcard_domains))

    @property
    def official_url_policy(self) -> OfficialURLPolicy | None:
        return self._official_policy

    def validate_candidate_url(self, url: str) -> str:
        if self._official_policy is None:
            raise ValueError("no reviewed official host is trusted for this app yet")
        return self._official_policy.sanitize_candidate(url)

    async def validate_for_request(self, url: str) -> str:
        if self._official_policy is None:
            raise ValueError("no reviewed official host is trusted for this app yet")
        return await self._official_policy.validate_for_request(url)

    def __bool__(self) -> bool:
        return self._official_policy is not None


# --------------------------------------------------------------------------
# Sanitized provider-error mapping + one bounded SDK retry layer
# --------------------------------------------------------------------------
class YouProviderError(RuntimeError):
    """A sanitized You.com failure. Never carries provider payload or the API key."""

    def __init__(self, *, capability: str, reason_code: str) -> None:
        self.capability = capability
        self.reason_code = reason_code
        super().__init__(f"{capability} failed: {reason_code}")


# Signals the INTEGRATION is broken (wrong kwarg, renamed module, bad attribute)
# rather than a provider/network failure. These are never mapped to a provider
# reason code, never retried, and never degraded to the baseline — they must
# reach monitoring/tests. (Section 12.)
_PROGRAMMING_ERRORS: tuple[type[Exception], ...] = (
    TypeError,
    AttributeError,
    NameError,
    ImportError,
    ModuleNotFoundError,
)

# Transient transport failures worth surfacing as a sanitized transient reason.
# (PoolTimeout is deliberately excluded — it signals local resource pressure.)
_TRANSIENT_TRANSPORT: tuple[type[Exception], ...] = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.RemoteProtocolError,
)
_TIMEOUT_AND_TRANSPORT: tuple[type[Exception], ...] = (TimeoutError, *_TRANSIENT_TRANSPORT)


def map_you_error(
    exc: Exception, *, capability: Literal["you_search", "you_contents", "you_research"]
) -> str:
    """Map a You.com provider exception to a stable, sanitized reason code.

    Reads only ``exc.status_code`` (the one stable attribute every ``YouError``
    exposes). ``.message``/``.body``/``.headers`` and the raw exception text are
    never read for logging or user-facing output.
    """

    if isinstance(exc, TimeoutError):
        return f"{capability}_timeout"
    status = getattr(exc, "status_code", None)
    if status == 400:
        return f"{capability}_invalid_request"
    if status == 401:
        return f"{capability}_unauthorized"
    if status == 402:
        return f"{capability}_credit_exhausted"
    if status == 403:
        return f"{capability}_forbidden"
    if status == 404:
        return f"{capability}_not_found"
    if status == 422:
        return (
            f"{capability}_invalid_schema"
            if capability == "you_research"
            else f"{capability}_invalid_request"
        )
    if status == 429:
        return f"{capability}_rate_limited"
    if isinstance(exc, _TRANSIENT_TRANSPORT):
        return f"{capability}_timeout"
    return f"{capability}_failed"


def _bounded_retry_config() -> object:
    """One explicit, bounded RetryConfig — the SDK's retry layer, made deterministic.

    Only 429 and selected transient 5xx (plus connection errors) retry, with a
    bounded total elapsed time. Client 4xx (400/401/402/403/404/422) are NOT in
    the override set, so they never retry. This is the ONLY retry layer; no
    custom retry loop wraps the SDK call.
    """

    retries = importlib.import_module("youdotcom.utils.retries")
    return retries.RetryConfig(
        strategy="backoff",
        backoff=retries.BackoffStrategy(
            initial_interval=500,
            max_interval=8_000,
            exponent=1.5,
            max_elapsed_time=20_000,
            jitter_ms=250,
        ),
        retry_connection_errors=True,
        status_codes_override=["429", "500", "502", "503", "504"],
    )


def _you_error_types() -> tuple[type[BaseException], ...]:
    """The installed SDK's provider error base class, if it can be imported.

    Imported lazily and tolerantly: this module is importable (and unit-testable)
    without the You.com SDK present.
    """

    try:
        errors = importlib.import_module("youdotcom.errors")
    except Exception:
        return ()
    base = getattr(errors, "YouError", None)
    if isinstance(base, type) and issubclass(base, BaseException):
        return (base,)
    return ()


def _is_provider_failure(exc: BaseException) -> bool:
    """Whether an exception is an EXPECTED provider failure worth sanitizing.

    Either an SDK ``YouError`` or something carrying its one stable attribute, an
    integer ``status_code``. A programming error (``TypeError``, ``NameError``,
    ``AttributeError``), an ``AssertionError``, or a Pydantic contract error has
    no ``status_code`` and therefore is NOT a provider failure — it must surface.
    """

    if isinstance(exc, _you_error_types()):
        return True
    return isinstance(getattr(exc, "status_code", None), int)


async def _guard_call(
    capability: Literal["you_search", "you_contents", "you_research"],
    factory: Any,
    *,
    timeout_seconds: float,
) -> Any:
    """Run one provider coroutine with an outer timeout and sanitized mapping.

    ``factory`` must itself open and close the ``You`` client via ``async with``
    so the client is torn down even on timeout/cancellation. Only timeouts,
    transport failures, and real provider errors become a
    :class:`YouProviderError`; everything else (broken integration, contract
    drift, assertion failures) propagates so it is visible to tests/monitoring
    instead of being reported as a provider outage.
    """

    try:
        return await asyncio.wait_for(factory(), timeout=timeout_seconds)
    except _PROGRAMMING_ERRORS:
        raise
    except _TIMEOUT_AND_TRANSPORT as exc:
        raise YouProviderError(
            capability=capability, reason_code=map_you_error(exc, capability=capability)
        ) from None
    except Exception as exc:
        # Deliberately NOT a catch-all: an unknown exception is re-raised.
        if not _is_provider_failure(exc):
            raise
        raise YouProviderError(
            capability=capability, reason_code=map_you_error(exc, capability=capability)
        ) from None


# --------------------------------------------------------------------------
# Cache helper (single-flight over the persistent cache)
# --------------------------------------------------------------------------
def cache_key(
    kind: Literal["you-search", "you-contents", "you-research", "operational-research"],
    *parts: str,
) -> str:
    digest = hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]
    return f"{kind}:v2:{digest}"


_CacheT = TypeVar("_CacheT")


async def _cached(
    cache: ResearchCache | None,
    key: str,
    *,
    ttl: timedelta,
    deserialize: Callable[[Mapping[str, object]], _CacheT | None],
    serialize: Callable[[_CacheT], Mapping[str, object]],
    compute: Callable[[], Awaitable[_CacheT]],
) -> _CacheT:
    """Return a cached value or compute+store it, single-flighting concurrent
    identical requests via the cache's per-key lock (see research_cache.py)."""

    if cache is None:
        return await compute()

    metrics = _metrics()
    raw = cache.get(key)
    if raw is not None:
        value = deserialize(raw)
        if value is not None:
            if metrics is not None:
                metrics.research_cache_hits += 1
            return value

    lock = getattr(cache, "lock_for", None)
    acquired = lock(key) if callable(lock) else None
    if acquired is not None:
        # A per-key threading.Lock is the right single-flight primitive here (each
        # enrichment runs in its own thread + event loop), but acquiring it must
        # never block the loop while another thread awaits a provider call.
        await asyncio.to_thread(acquired.acquire)
    try:
        raw = cache.get(key)
        if raw is not None:
            value = deserialize(raw)
            if value is not None:
                if metrics is not None:
                    metrics.research_cache_hits += 1
                return value
        if metrics is not None:
            metrics.research_cache_misses += 1
        result = await compute()
        if result is not None:  # negative results (e.g. Research found nothing) are not cached
            with contextlib.suppress(Exception):
                cache.put(key, serialize(result), expires_at=datetime.now(UTC) + ttl)
        return result
    finally:
        if acquired is not None:
            acquired.release()


# --------------------------------------------------------------------------
# Category classification, scoring, ranking, diversification
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
_PENALTY_TERMS = (
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


def _tokenize(url: str, title: str, snippet: str = "") -> str:
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").replace(".", " ")
    bounded_snippet = snippet[:MAX_CLASSIFICATION_SNIPPET_CHARACTERS]
    return f"{hostname} {parsed.path} {title} {bounded_snippet}".casefold().replace("_", "-")


def classify_category(url: str, title: str = "", snippet: str = "") -> EvidenceCategory:
    """Classify a candidate from CODE-OWNED signals only.

    The URL path, the title, and a bounded snippet are the inputs. A category a
    provider or model returned is metadata at best — it never decides coverage on
    its own (see ``YouResearchFallback._parse``, which re-derives the category).
    """

    haystack = _tokenize(url, title, snippet)
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
    parsed = urlsplit(url.strip())
    hostname = (parsed.hostname or "").rstrip(".").casefold()
    path = parsed.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/") or "/"
    query = parsed.query
    return f"{parsed.scheme}://{hostname}{path}" + (f"?{query}" if query else "")


def deduplicate_and_rank_candidates(
    candidates: Sequence[EvidenceCandidate], *, limit: int = MAX_EVIDENCE_DOCUMENTS
) -> tuple[EvidenceCandidate, ...]:
    """Deduplicate by canonical URL, rank by relevance score, then diversify.

    Ranking is relevance-only; it never substitutes for the security decision a
    domain policy makes — a low-scoring candidate that already passed
    :class:`ResearchHostPolicy` is exactly as safe as a high-scoring one.
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


def merge_research_candidates(
    discovered: Sequence[EvidenceCandidate], extra: Sequence[EvidenceCandidate]
) -> tuple[EvidenceCandidate, ...]:
    """Combine discovery candidates with Research-fallback candidates, deduped/ranked."""

    return deduplicate_and_rank_candidates([*discovered, *extra])


def coverage_categories(candidates: Sequence[EvidenceCandidate]) -> frozenset[str]:
    return frozenset(candidate.category for candidate in candidates)


def has_sufficient_coverage(candidates: Sequence[EvidenceCandidate]) -> bool:
    """Sufficient only with an ACCESS page, a PORTAL/API-docs surface, AND a
    CREDENTIAL surface. login+credential alone is NOT sufficient — a developer
    /API documentation surface is required too (section 17)."""

    categories = coverage_categories(candidates)
    has_access = bool(categories & _ACCESS_CATEGORIES)
    has_portal_or_api_docs = bool(categories & _PORTAL_OR_API_DOCS)
    has_credential_surface = bool(categories & _CREDENTIAL_SURFACE)
    return has_access and has_portal_or_api_docs and has_credential_surface


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


# --------------------------------------------------------------------------
# Content fetchers: You Contents -> guarded HTTP fallback (per URL)
# --------------------------------------------------------------------------
# Control characters to strip from fetched Markdown (keep tab/newline/CR).
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def normalize_markdown(text: str) -> str:
    """Normalize fetched Markdown WITHOUT altering its factual content.

    Only removes null/unsafe control characters and normalizes newlines. It does
    NOT delete or rewrite instruction-shaped lines — fetched content is untrusted
    EVIDENCE handed to Gemini as source material (the extraction prompt tells the
    model to never obey instructions inside evidence), so silently editing the
    text would both be a false sense of safety and could corrupt real facts.
    """

    cleaned = text.replace("\r\n", "\n").replace("\r", "\n")
    cleaned = _CONTROL_CHARS.sub("", cleaned)
    return cleaned[:MAX_EXCERPT_CHARACTERS]


class YouContentsFetcher:
    """Fetch clean Markdown for already policy-approved official URLs, in one bounded batch."""

    def __init__(
        self,
        api_key: SecretStr | str,
        *,
        policy: ResearchHostPolicy,
        crawl_timeout: int = 10,
        max_age: int | None = 86_400,
        request_timeout: float = 30.0,
        max_pages: int = 8,
        cache: ResearchCache | None = None,
    ) -> None:
        self._api_key = api_key if isinstance(api_key, SecretStr) else SecretStr(api_key)
        self._policy = policy
        self._crawl_timeout = crawl_timeout
        self._max_age = max_age
        self._request_timeout = request_timeout
        self._max_pages = min(max_pages, MAX_YOU_CONTENT_URLS)
        self._cache = cache

    async def fetch_many(self, urls: Sequence[str]) -> tuple[EvidenceDocument, ...]:
        bounded = list(dict.fromkeys(urls))[: self._max_pages]
        safe_urls: list[str] = []
        for url in bounded:
            try:
                # Host-policy validation (HTTPS/port/host-allowlist/sensitive-query),
                # NOT DNS-resolution SSRF. You.com Contents crawls the page on ITS
                # servers, so our resolver's view is irrelevant to what You.com
                # fetches — the meaningful control here is the reviewed host
                # allowlist. DNS-based SSRF protection remains on the guarded HTTP
                # fallback (GuardedHTTPEvidenceFetcher -> OfficialEvidenceFetcher),
                # where WE perform the fetch.
                safe_urls.append(self._policy.validate_candidate_url(url))
            except ValueError:
                continue  # never sent to You.com if it fails our own host policy first
        if not safe_urls:
            return ()

        key = cache_key("you-contents", "|".join(sorted(safe_urls)), str(self._max_age))

        def _deserialize(raw: Mapping[str, object]) -> tuple[EvidenceDocument, ...] | None:
            items = raw.get("items")
            if not isinstance(items, list):
                return None
            try:
                cached = tuple(EvidenceDocument.model_validate(item) for item in items)
            except ValidationError:
                return None
            # Same rule as a fresh crawl: the cached URL must still pass the
            # current host policy, and empty content is never evidence.
            validated: list[EvidenceDocument] = []
            for document in cached:
                try:
                    self._policy.validate_candidate_url(document.source_url)
                except ValueError:
                    continue
                if not document.relevant_text.strip():
                    continue
                validated.append(document)
            if cached and not validated:
                return None
            return tuple(validated)

        def _serialize(value: tuple[EvidenceDocument, ...]) -> Mapping[str, object]:
            return {"items": [d.model_dump() for d in value]}

        async def _compute() -> tuple[EvidenceDocument, ...]:
            return await self._generate_documents(safe_urls)

        ttl = timedelta(seconds=self._max_age if self._max_age and self._max_age > 0 else 86_400)
        return await _cached(
            self._cache,
            key,
            ttl=ttl,
            deserialize=_deserialize,
            serialize=_serialize,
            compute=_compute,
        )

    async def _generate_documents(self, safe_urls: list[str]) -> tuple[EvidenceDocument, ...]:
        metrics = _metrics()
        started = datetime.now(UTC)

        async def _factory() -> object:
            youdotcom = importlib.import_module("youdotcom")
            formats = importlib.import_module("youdotcom.models.contentsformats")
            async with youdotcom.You(api_key_auth=self._api_key.get_secret_value()) as you:
                return await you.contents.generate_async(
                    urls=safe_urls,
                    formats=[formats.ContentsFormats.MARKDOWN],
                    crawl_timeout=self._crawl_timeout,
                    max_age=self._max_age,
                    retries=_bounded_retry_config(),
                    timeout_ms=int(self._request_timeout * 1000),
                )

        try:
            responses = await _guard_call(
                "you_contents", _factory, timeout_seconds=self._request_timeout + 5
            )
        except YouProviderError:
            return ()
        finally:
            if metrics is not None:
                metrics.you_contents_calls += 1
                metrics.you_contents_pages_requested += len(safe_urls)
                metrics.you_contents_latency_ms += (
                    datetime.now(UTC) - started
                ).total_seconds() * 1000

        pages = list(responses) if isinstance(responses, list) else list(responses or ())
        documents: list[EvidenceDocument] = []
        for page in pages:
            document = self._to_document(page)
            if document is not None:
                documents.append(document)
        if metrics is not None:
            metrics.you_contents_pages_returned += len(documents)
        return tuple(documents)

    def _to_document(self, page: object) -> EvidenceDocument | None:
        returned_url = getattr(page, "url", None)
        if not isinstance(returned_url, str) or not returned_url:
            return None
        try:
            # The URL You.com actually fetched must independently pass policy
            # again — a redirect during crawling must not smuggle an off-policy
            # host into the evidence set.
            safe_url = self._policy.validate_candidate_url(returned_url)
        except ValueError:
            return None
        markdown = getattr(page, "markdown", None)
        if not isinstance(markdown, str) or not markdown.strip():
            return None  # empty Markdown is rejected, not passed through as evidence
        title = getattr(page, "title", None) or "Official documentation"
        return EvidenceDocument(
            source_url=safe_url,
            title=str(title)[:500],
            relevant_text=normalize_markdown(markdown),
        )


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
    """You Contents first; the guarded HTTP fetcher fills whatever it missed (per URL)."""

    def __init__(self, primary: EvidenceContentFetcher, fallback: EvidenceContentFetcher) -> None:
        self._primary = primary
        self._fallback = fallback

    async def fetch_many(self, urls: Sequence[str]) -> tuple[EvidenceDocument, ...]:
        primary_documents = await self._primary.fetch_many(urls)
        fetched = {canonicalize(d.source_url) for d in primary_documents}
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


# --------------------------------------------------------------------------
# In-memory research cache (unit tests only; production uses SqliteResearchCache)
# --------------------------------------------------------------------------
class InMemoryResearchCache:
    """A process-local :class:`ResearchCache` for isolated unit tests. No secrets."""

    def __init__(self) -> None:
        self._store: dict[str, tuple[Mapping[str, object], datetime]] = {}
        self._locks: dict[str, threading.Lock] = {}
        self._guard = threading.Lock()

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

    def lock_for(self, key: str) -> threading.Lock:
        with self._guard:
            lock = self._locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._locks[key] = lock
            return lock


# --------------------------------------------------------------------------
# Observability helper
# --------------------------------------------------------------------------
ProviderHealth = Literal[
    "configured_not_verified",
    "ready",
    "rate_limited",
    "credit_exhausted",
    "not_configured",
    "disabled",
]


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
    "YOU_RESEARCH_SCHEMA",
    "YOU_RESEARCH_SCHEMA_VERSION",
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
    "has_sufficient_coverage",
    "map_you_error",
    "merge_documents",
    "merge_research_candidates",
    "normalize_markdown",
    "provider_health_state",
    "use_metrics",
]
