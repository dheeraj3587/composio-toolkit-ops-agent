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


The implementation now lives in focused modules; this module stays the single import
surface the rest of the application uses, so no caller has to know which piece a name
comes from:

* :mod:`ops.you_types` — bounded constants and the category vocabulary
* :mod:`ops.you_metrics` — per-enrichment counters and provider health
* :mod:`ops.you_errors` — typed, sanitized provider failures and bounded retries
* :mod:`ops.you_host_policy` — the trusted-host boundary
* :mod:`ops.you_candidates` — classification, scoring, dedup and per-category caps
* :mod:`ops.you_cache` — single-flight TTL caching
* :mod:`ops.you_discovery` — search discovery and provider composition
* :mod:`ops.you_contents` — content extraction with a guarded fallback
* :mod:`ops.you_fallback` — the bounded Research fallback
"""

from __future__ import annotations

# Re-exported with the explicit "X as X" form: this module is the declared import
# home for the research layer, and the type checker forbids implicit re-export.
from ops.you_cache import InMemoryResearchCache as InMemoryResearchCache
from ops.you_cache import ResearchCache as ResearchCache
from ops.you_cache import _cached as _cached
from ops.you_cache import cache_key as cache_key
from ops.you_candidates import EvidenceCandidate as EvidenceCandidate
from ops.you_candidates import canonicalize as canonicalize
from ops.you_candidates import classify_category as classify_category
from ops.you_candidates import coverage_categories as coverage_categories
from ops.you_candidates import (
    deduplicate_and_rank_candidates as deduplicate_and_rank_candidates,
)
from ops.you_candidates import has_sufficient_coverage as has_sufficient_coverage
from ops.you_candidates import merge_research_candidates as merge_research_candidates
from ops.you_contents import EvidenceContentFetcher as EvidenceContentFetcher
from ops.you_contents import (
    FallbackEvidenceContentFetcher as FallbackEvidenceContentFetcher,
)
from ops.you_contents import GuardedHTTPEvidenceFetcher as GuardedHTTPEvidenceFetcher
from ops.you_contents import YouContentsFetcher as YouContentsFetcher
from ops.you_contents import merge_documents as merge_documents
from ops.you_contents import normalize_markdown as normalize_markdown
from ops.you_discovery import CompositeEvidenceDiscovery as CompositeEvidenceDiscovery
from ops.you_discovery import LegacyDiscoveryAdapter as LegacyDiscoveryAdapter
from ops.you_discovery import RichEvidenceDiscovery as RichEvidenceDiscovery
from ops.you_discovery import YouSearchDiscovery as YouSearchDiscovery
from ops.you_errors import YouProviderError as YouProviderError
from ops.you_errors import map_you_error as map_you_error
from ops.you_fallback import YOU_RESEARCH_SCHEMA as YOU_RESEARCH_SCHEMA
from ops.you_fallback import YOU_RESEARCH_SCHEMA_VERSION as YOU_RESEARCH_SCHEMA_VERSION
from ops.you_fallback import ResearchFallbackResult as ResearchFallbackResult
from ops.you_fallback import YouResearchFallback as YouResearchFallback
from ops.you_host_policy import ResearchHostPolicy as ResearchHostPolicy
from ops.you_metrics import YouResearchMetrics as YouResearchMetrics
from ops.you_metrics import provider_health_state as provider_health_state
from ops.you_metrics import use_metrics as use_metrics
from ops.you_types import MAX_CANDIDATE_SNIPPETS as MAX_CANDIDATE_SNIPPETS
from ops.you_types import MAX_SNIPPET_CHARACTERS as MAX_SNIPPET_CHARACTERS
from ops.you_types import MAX_YOU_CONTENT_URLS as MAX_YOU_CONTENT_URLS

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
