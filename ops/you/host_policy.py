"""The hosts You.com may be trusted to have discovered official pages on.

This is the security boundary of the whole research layer, so it is deliberately the
smallest module here. A URL is never trusted because You.com returned it: trust comes
only from already-reviewed data (the verified P1 record, a verified baseline, and the
reviewed static browser_host_policy dataset), and every candidate is re-validated
against this policy after results come back.

Exact hosts and wildcard domains are tracked SEPARATELY and handed to
OfficialURLPolicy with explicit exact/wildcard rules rather than the legacy
exact-or-subdomain widening, so ``developers.example.com`` can never silently grant
``anything.developers.example.com``. Provider-side ``include_domains`` is only a
first filter for efficiency; this local validation is the actual boundary.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from urllib.parse import urlsplit

from ops.browser.host_policy import get_browser_policy
from ops.core.models import OperationalResearch
from ops.research.operational_research import HostResolver, OfficialURLPolicy


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
