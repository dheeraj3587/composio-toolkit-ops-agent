"""Bounded constants and category vocabulary for You.com research.

These are the numbers and enums the whole research layer agrees on, kept in a leaf
module so discovery, ranking, content extraction and the fallback can share them
without importing each other.

The bounds are the point. Snippets are untrusted web text, so only a small bounded
prefix ever reaches the deterministic classifier; candidate counts, snippet sizes and
content URLs are all capped so one app's research can never grow unbounded work. The
per-category caps keep a single category (say six OAuth pages) from crowding out the
evidence a run actually needs, which matters when the same budget has to serve a
hundred apps.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Literal

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
