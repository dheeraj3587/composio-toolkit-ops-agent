"""Classifying, scoring, de-duplicating and capping discovered candidates.

Ranking exists because a hundred apps share one evidence budget. Without it, six
OAuth pages for one vendor would crowd out the login and credential pages another
vendor actually needs, so candidates are scored, de-duplicated by canonical URL, and
then capped PER CATEGORY.

Classification is deliberately keyword-based and deterministic. That means it is
honest rather than clever: a bare root URL with no path keywords (a plain login SPA
at ``https://app.example.com/``) classifies as ``unknown`` even though a human would
recognize it, and that documented limitation is preferred over a model guess that
could not be audited. Only a small bounded prefix of an untrusted snippet is ever fed
to it.

Canonicalization strips the parts that create duplicate evidence without adding
information (fragment, tracking query, trailing slash), so the same page discovered by
two queries is counted once.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator

from ops.models import StrictModel, validate_https_url
from ops.operational_research import MAX_EVIDENCE_DOCUMENTS
from ops.you_types import (
    _ACCESS_CATEGORIES,
    _CATEGORY_CAPS,
    _CREDENTIAL_SURFACE,
    _PORTAL_OR_API_DOCS,
    MAX_CANDIDATE_SNIPPETS,
    MAX_CLASSIFICATION_SNIPPET_CHARACTERS,
    MAX_SNIPPET_CHARACTERS,
    EvidenceCategory,
    QueryType,
)


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
