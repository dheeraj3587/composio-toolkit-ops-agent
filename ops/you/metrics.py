"""Per-enrichment You.com counters, and the health state derived from them.

The counters are held in a ContextVar rather than on a client or a module global,
because one enrichment is driven from sync code via ``asyncio.run`` and several
enrichments may be in flight across threads. A ContextVar scopes the counters to the
enrichment that opened them, so a hundred concurrent app runs cannot mix each other's
numbers, and code that runs outside any ``use_metrics`` block simply records nothing
instead of failing.

Everything recorded here is non-secret and aggregate: call counts, cache hits,
document counts and provider labels. No query text, URL content or credential is
ever stored.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Literal


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
