"""Derive a browser navigation allowlist from an app's already-verified hosts.

The hand-authored policies in :mod:`ops.browser_host_policy` and the reviewed
matrix in :mod:`api.assignment_runtime` cover only the apps that were manually
traced. Every other app in the verified P1 snapshot had no allowlist at all, so a
deterministically ``self_serve`` run could never launch a browser session even
though the snapshot carries verified HTTPS evidence URLs for that app. This module
closes that gap without inventing anything:

* One vendor registrable domain is chosen from the hostnames that already appear
  in the app's verified research (operational claims, reviewed operational URLs,
  or P1 evidence URLs). Hosts outside that domain are dropped, so an evidence URL
  pointing at a third party never widens the allowlist.
* The wildcard is that vendor domain, which is where the app's own
  tenant/login/settings subdomains live.
* Shared domains (code hosts, cloud consoles, social platforms) are never
  wildcarded and are only used at all when the app itself is that vendor — so a
  derived allowlist can hold ``github.com`` for GitHub but never for an unrelated
  app whose evidence happens to cite a GitHub README.

A derived policy is explicitly weaker evidence than a reviewed one: callers must
prefer an active reviewed policy, and an explicitly *inactive* reviewed policy
(a reviewed "no") must always win over derivation.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ops.browser_host_policy import BrowserAllowedHosts, BrowserHostPolicy
from ops.models import OperationalResearch

# ``ops.browser_worker.validate_allowed_domains`` accepts at most twenty patterns.
MAX_ALLOWED_PATTERNS = 20

# Registrable domains shared by many unrelated parties, or shared corporate
# umbrellas. These are NEVER wildcarded, and they are only usable at all when the
# app itself is that vendor (see ``_belongs_to_app``): an evidence URL pointing at
# a GitHub README must not put ``github.com`` in some other app's allowlist.
SHARED_HOST_DOMAINS: frozenset[str] = frozenset(
    {
        "amazon.com",
        "amazonaws.com",
        "apple.com",
        "atlassian.net",
        "azure.com",
        "azurewebsites.net",
        "bitbucket.org",
        "blogspot.com",
        "cloudfront.net",
        "discourse.group",
        "facebook.com",
        "fb.com",
        "gitbook.com",
        "gitbook.io",
        "github.com",
        "github.io",
        "gitlab.com",
        "google.com",
        "googleapis.com",
        "googleusercontent.com",
        "gstatic.com",
        "herokuapp.com",
        "instagram.com",
        "linkedin.com",
        "medium.com",
        "microsoft.com",
        "netlify.app",
        "notion.site",
        "npmjs.com",
        "pages.dev",
        "postman.com",
        "pypi.org",
        "readme.io",
        "reddit.com",
        "stackoverflow.com",
        "substack.com",
        "twitter.com",
        "vercel.app",
        "wikipedia.org",
        "windows.net",
        "wordpress.com",
        "x.com",
        "ycombinator.com",
        "youtube.com",
        "zapier.com",
    }
)

# A deliberately small public-suffix approximation. Only multi-label suffixes that
# actually occur in vendor documentation hosts are listed; anything else falls
# back to the last two labels.
_MULTI_LABEL_SUFFIXES: frozenset[str] = frozenset(
    {
        "ac.uk",
        "co.il",
        "co.in",
        "co.jp",
        "co.kr",
        "co.nz",
        "co.uk",
        "co.za",
        "com.ar",
        "com.au",
        "com.br",
        "com.cn",
        "com.hk",
        "com.mx",
        "com.sg",
        "com.tr",
        "com.tw",
        "gov.uk",
        "ne.jp",
        "net.au",
        "or.jp",
        "org.au",
        "org.uk",
    }
)

# Shortest vendor label that may be matched against an app slug by prefix. Below
# this length a prefix match is noise (for example "up" matching "uptime.com").
_MINIMUM_PREFIX_MATCH = 4


def registrable_domain(hostname: str) -> str | None:
    """Return the registrable domain of a hostname, or ``None`` when unusable."""

    labels = [label for label in hostname.rstrip(".").casefold().split(".") if label]
    if len(labels) < 2:
        return None
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _is_usable_host(hostname: str) -> bool:
    """Reject anything the browser allowlist validator would refuse anyway."""

    host = hostname.rstrip(".").casefold()
    if not host or len(host) > 253 or "*" in host or "." not in host:
        return False
    if host in {"localhost", "localhost.localdomain"}:
        return False
    labels = host.split(".")
    if any(not label or len(label) > 63 for label in labels):
        return False
    # An IP literal is never a vendor documentation host and is refused upstream.
    return not labels[-1].isdigit()


def _ordered_research_hosts(research: OperationalResearch) -> list[str]:
    """Collect verified HTTPS hostnames, most credential-relevant first.

    Ordering matters twice: the first usable host decides the vendor domain, and
    the same order decides which hosts survive the twenty-pattern budget.
    """

    urls: list[object] = [
        *(getattr(claim, "url", None) for claim in research.operational_url_claims or ()),
        research.credential_management_url,
        research.developer_portal_url,
        research.login_url,
        research.signup_url,
        *research.evidence_urls,
        research.api_base_url,
        research.authorization_url,
        research.token_url,
    ]
    hosts: list[str] = []
    for url in urls:
        if not isinstance(url, str) or not url:
            continue
        try:
            parsed = urlsplit(url)
        except ValueError:
            continue
        if parsed.scheme != "https":
            continue
        host = (parsed.hostname or "").rstrip(".").casefold()
        if _is_usable_host(host) and host not in hosts:
            hosts.append(host)
    return hosts


def _belongs_to_app(app_slug: str, domain: str) -> bool:
    """True when a registrable domain is plainly the app's own domain.

    This is what allows a shared domain to be used for the vendor that owns it
    (``github.com`` for the ``github`` app) while still keeping it out of every
    other app's allowlist.
    """

    compact = app_slug.replace("-", "")
    label = domain.split(".")[0]
    if label == compact:
        return True
    return len(label) >= _MINIMUM_PREFIX_MATCH and (
        compact.startswith(label) or label.startswith(compact)
    )


def _vendor_domain(app_slug: str, hosts: list[str]) -> str | None:
    """Pick the one registrable domain that most plausibly belongs to the app."""

    candidates: list[str] = []
    for host in hosts:
        domain = registrable_domain(host)
        if domain is not None and domain not in candidates:
            candidates.append(domain)
    owned = [domain for domain in candidates if _belongs_to_app(app_slug, domain)]
    if owned:
        return owned[0]
    # No name match: trust the ordering instead. The first host comes from the
    # app's own credential/portal/docs URL, which is the vendor in practice. A
    # shared domain is never accepted on ordering alone.
    for domain in candidates:
        if domain not in SHARED_HOST_DOMAINS:
            return domain
    return None


def derive_browser_host_policy(research: OperationalResearch) -> BrowserHostPolicy | None:
    """Build a policy from verified research hosts, or ``None`` when impossible.

    ``None`` means the app carries no verified vendor-owned HTTPS host, so no
    browser session may be launched for it and the caller must fall back to its
    non-browser path (outreach) rather than guessing a target.
    """

    hosts = _ordered_research_hosts(research)
    vendor = _vendor_domain(research.app_slug, hosts)
    if vendor is None:
        return None

    # ``*.vendor.com`` does not match the apex, and sign-in pages frequently live
    # there (``vendor.com/login``), so the apex is always an exact host.
    exact: list[str] = [vendor]
    for host in hosts:
        if host != vendor and host.endswith(f".{vendor}") and host not in exact:
            exact.append(host)

    # A shared domain the app happens to own (github.com) is usable as an exact
    # host but must never be wildcarded.
    wildcards = () if vendor in SHARED_HOST_DOMAINS else (vendor,)
    del exact[MAX_ALLOWED_PATTERNS - len(wildcards) :]

    return BrowserHostPolicy(
        app_slug=research.app_slug,
        active=True,
        exact_hosts=tuple(exact),
        vendor_wildcard_domains=wildcards,
    )


def derive_browser_allowed_hosts(research: OperationalResearch) -> BrowserAllowedHosts | None:
    """Return the derived per-run allowlist, or ``None`` when nothing is derivable."""

    policy = derive_browser_host_policy(research)
    if policy is None:
        return None
    return BrowserAllowedHosts(
        app_slug=policy.app_slug,
        exact_hosts=policy.exact_hosts,
        vendor_wildcard_domains=policy.vendor_wildcard_domains,
    )


__all__ = [
    "MAX_ALLOWED_PATTERNS",
    "SHARED_HOST_DOMAINS",
    "derive_browser_allowed_hosts",
    "derive_browser_host_policy",
    "registrable_domain",
]
