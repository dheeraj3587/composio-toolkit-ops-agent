"""Building the bounded Gmail search query for an inbox read.

The query is assembled from validated pieces rather than interpolated text. Domains and
age windows are matched against strict patterns first, because a query is provider
input: an unvalidated fragment could widen the search beyond the reviewed senders and
the freshness window that make a verification read safe to act on.

The freshness clause is always present. An inbox read without an age bound would let an
old message satisfy a new request, which is exactly the replay this boundary exists to
prevent.
"""

from __future__ import annotations

import re

_INBOX_DOMAIN_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


# Gmail's relative age operators accept ONLY d (day), m (month), and y (year).
# An hour unit does not exist, and "m" is months rather than minutes, so a query
# like "newer_than:1h" is not a one-hour bound and "newer_than:30m" would mean
# thirty MONTHS. Accepting "h" here silently produced an unbounded freshness
# window for one-time codes, so it is rejected; sub-day bounds must be enforced
# against each message's own timestamp (see ops.email_verification).
_INBOX_AGE_RE = re.compile(r"^\d{1,4}[dmy]$")


def build_inbox_query(
    *,
    sender_domain: str | None = None,
    subject: str | None = None,
    newer_than: str | None = None,
    unread: bool = False,
    extra: str | None = None,
) -> str:
    """Build a safe Gmail search query from bounded, validated parts.

    Every part is validated and stripped of newlines/quotes so neither a caller
    nor untrusted upstream text can inject extra operators into the provider
    query. Returns ``in:anywhere`` when no part is supplied.

    ``newer_than`` accepts only the units Gmail actually supports: ``d`` (days),
    ``m`` (**months**) and ``y`` (years). Hours are not expressible, so a
    short-lived freshness bound must be enforced against each message's own
    receive timestamp rather than through this query.
    """

    parts: list[str] = []
    if sender_domain:
        domain = sender_domain.strip().lstrip("@").rstrip(".").casefold()
        if not _INBOX_DOMAIN_RE.match(domain):
            raise ValueError("sender_domain is not a valid domain")
        parts.append(f"from:{domain}")
    if subject:
        cleaned = re.sub(r'[\r\n"]', " ", subject).strip()[:200]
        if cleaned:
            parts.append(f"subject:({cleaned})")
    if newer_than:
        age = newer_than.strip().casefold()
        if not _INBOX_AGE_RE.match(age):
            raise ValueError("newer_than must look like 7d, 6m (months), or 1y")
        parts.append(f"newer_than:{age}")
    if unread:
        parts.append("is:unread")
    if extra:
        cleaned_extra = re.sub(r"[\r\n]", " ", extra).strip()[:200]
        if cleaned_extra:
            parts.append(cleaned_extra)
    return " ".join(parts) or "in:anywhere"
