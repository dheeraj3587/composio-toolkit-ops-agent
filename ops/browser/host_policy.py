"""Recipe-backed top-level browser navigation policy.

This is one of two separate security boundaries:

* ``BrowserHostPolicy`` (this module) — exact hosts Playwright may visibly
  navigate to. Authority comes only from a checked-in ``AppRecipe``.
* ``NetworkEndpointPolicy`` (``ops.core.network_endpoint_policy``) — exact API,
  OAuth token-exchange, and credential-validation endpoints that backend HTTP
  clients may call. API/token endpoints are NEVER added here just because they
  belong to the provider; they must be genuinely browser-facing (e.g. an OAuth
  ``/authorize`` page a human visits).

A checked-in recipe is always the preferred authority. When ``BROWSER_DOMAIN_
DISCOVERY_ENABLED`` is set, an app that has no reviewed recipe may instead receive
a policy scoped to the single registrable domain its own verified operational URLs
agree on (see :func:`discovered_policy_from_research`). That lets the agent explore
a vendor's own site — signup, login, developer portal, API-key page — without a
hand-written host list, while still refusing to navigate anywhere off that domain.
Discovery never widens an app that already has a reviewed recipe, and it never
authorizes a domain the app's verified URLs do not support.

Documentation URLs and runtime-supplied hosts still never expand this boundary.
Resource and IdP hosts remain separately reviewed recipe fields and do not become
top-level navigation destinations.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from ops.core.models import OperationalResearch
from ops.recipes.app_recipes import AppRecipe, get_app_recipe

# Access routes for which a browser session may be launched at all.
BROWSER_ROUTES = frozenset({"self_serve", "hybrid"})

# Multi-label public suffixes seen across the reviewed catalog. Kept as an
# explicit, auditable list rather than a bundled public-suffix database: an
# unknown multi-label suffix collapses to a longer (narrower) domain, which fails
# closed by over-restricting rather than granting a whole second-level zone.
_MULTI_LABEL_SUFFIXES: frozenset[str] = frozenset(
    {
        "co.uk",
        "org.uk",
        "ac.uk",
        "co.jp",
        "co.nz",
        "co.za",
        "co.in",
        "com.au",
        "com.br",
        "com.sg",
        "com.mx",
        "com.tr",
    }
)


# The reviewed research/profile fields that can become a TOP-LEVEL navigation
# target. Documentation and evidence URLs are deliberately absent: they are
# evidence, never a destination.
NAVIGATION_TARGET_FIELDS: tuple[str, ...] = (
    "login_url",
    "signup_url",
    "credential_management_url",
    "developer_portal_url",
)

# One serialized allow-list is a small, reviewed list; a longer one is a bug or an
# attempt to widen the boundary, and is refused rather than truncated.
MAX_ALLOWED_HOST_PATTERNS = 32

# An allow-list entry is either an exact host or a single left-edge wildcard.
_ALLOWED_HOST_PATTERN = re.compile(
    r"^(?:\*\.)?[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$"
)


def registrable_domain(hostname: str) -> str | None:
    """The narrowest domain a vendor can be said to own, or ``None`` if unclear.

    Deliberately conservative: an unrecognized multi-label suffix yields a longer
    domain, which restricts navigation further instead of opening a public zone.
    """

    host = (hostname or "").strip().rstrip(".").casefold()
    if not host or "/" in host or ":" in host:
        return None
    labels = host.split(".")
    if len(labels) < 2 or any(not label for label in labels):
        return None
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


@dataclass(frozen=True, slots=True)
class BrowserHostPolicy:
    """An explicit, reviewed per-app browser navigation policy.

    ``active`` gates whether Playwright may run for the app at all.
    """

    app_slug: str
    active: bool
    exact_hosts: tuple[str, ...] = ()
    # Retained in the serialized effect shape for legacy-read compatibility. New
    # recipes are exact-host only and always leave this empty.
    vendor_wildcard_domains: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class BrowserAllowedHosts:
    """The resolved, per-run browser allowlist and its flat matcher patterns."""

    app_slug: str
    exact_hosts: tuple[str, ...]
    vendor_wildcard_domains: tuple[str, ...]

    def patterns(self) -> tuple[str, ...]:
        return (*self.exact_hosts, *(f"*.{domain}" for domain in self.vendor_wildcard_domains))

    def as_report(self) -> dict[str, object]:
        return {
            "app_slug": self.app_slug,
            "exact_hosts": list(self.exact_hosts),
            "vendor_wildcard_domains": list(self.vendor_wildcard_domains),
        }


@dataclass(frozen=True, slots=True)
class BrowserHostDecision:
    """Result of checking one URL against a run's browser allowlist (no secrets)."""

    allowed: bool
    current_url: str
    blocked_hostname: str | None
    allowed_hosts: tuple[str, ...]
    reason_code: str
    backend_policy_update_required: bool


class BrowserPolicyInactiveError(RuntimeError):
    """Raised when an app has no active browser policy; navigation is refused."""

    def __init__(self, app_slug: str, reason_code: str) -> None:
        self.app_slug = app_slug
        self.reason_code = reason_code
        super().__init__(f"browser navigation is not permitted for {app_slug}: {reason_code}")


def get_browser_policy(app_slug: str) -> BrowserHostPolicy | None:
    """Return top-level navigation authority from a checked-in recipe only.

    Exact, IdP and static-resource hosts are distinct in AppRecipe review. They
    are combined only at this browser egress boundary; no URL or documentation
    page is inspected to invent an allowlist.
    """

    recipe = get_app_recipe(app_slug)
    return browser_policy_from_recipe(recipe) if recipe is not None else None


def browser_policy_from_recipe(recipe: AppRecipe) -> BrowserHostPolicy | None:
    """Build navigation authority from an already-bound immutable recipe."""

    if recipe.route_kind != "playwright":
        return None
    browser = recipe.browser
    if browser is None:
        return BrowserHostPolicy(app_slug=recipe.app_slug, active=False)
    return BrowserHostPolicy(
        app_slug=recipe.app_slug,
        active=True,
        # Navigation authority is deliberately narrower than resource egress:
        # IdP and static-resource hosts never become top-level destinations.
        exact_hosts=browser.exact_hosts,
        vendor_wildcard_domains=(),
    )


def navigation_target_urls(research: object) -> tuple[str, ...]:
    """The URLs in a research/profile view that may become a navigation target.

    Accepts either an ``OperationalResearch`` model or its already-serialized
    mapping, so the API caller and the browser container read the SAME field set
    rather than each deciding for itself what counts as a destination.
    """

    targets: list[str] = []
    for field_name in NAVIGATION_TARGET_FIELDS:
        value = (
            research.get(field_name)
            if isinstance(research, Mapping)
            else getattr(research, field_name, None)
        )
        if isinstance(value, str) and value:
            targets.append(value)
    return tuple(targets)


def discovered_policy_from_research(
    app_slug: str,
    research: OperationalResearch,
) -> BrowserHostPolicy | None:
    """Derive a single-domain policy from the app's OWN verified operational URLs.

    The app's reviewed login, signup, developer-portal and credential-management
    URLs must all resolve to one registrable domain. That agreement is the evidence:
    it proves the domain belongs to the vendor rather than to a page some search
    result pointed at. Any disagreement (or no URLs at all) yields ``None`` and the
    caller fails closed.

    The result is a wildcard over that one domain, so the agent may discover any
    subdomain the vendor actually uses (``app.``, ``developers.``, ``console.``)
    and nothing outside it.
    """

    candidates = navigation_target_urls(research)
    domains: set[str] = set()
    for url in candidates:
        if not url:
            continue
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname:
            continue
        domain = registrable_domain(parsed.hostname)
        if domain is not None:
            domains.add(domain)
    if len(domains) != 1:
        # No evidence, or the app's own URLs disagree about who owns it.
        return None
    domain = domains.pop()
    # Both forms are required. ``host_matches_patterns`` treats ``*.example.com``
    # as strictly a subdomain match (``host != parent``), so the wildcard alone
    # would allow ``app.example.com`` while refusing the apex ``example.com`` —
    # and apex login pages (``vercel.com/login``, ``coda.io/signin``) are common.
    return BrowserHostPolicy(
        app_slug=app_slug,
        active=True,
        exact_hosts=(domain,),
        vendor_wildcard_domains=(domain,),
    )


def build_browser_allowed_hosts(
    app_slug: str,
    research: OperationalResearch,
    *,
    access_route: str | None = None,
    self_host_runtime_host: str | None = None,
    recipe: AppRecipe | None = None,
    allow_domain_discovery: bool | None = None,
) -> BrowserAllowedHosts:
    """Build the per-run browser allowlist, failing closed for inactive apps.

    * The app's route must be a browser route (``self_serve``/``hybrid``) when
      ``access_route`` is provided.
    * A reviewed recipe policy is always preferred and is never widened.
    * With domain discovery enabled, an app WITHOUT a reviewed recipe may instead
      be scoped to the one registrable domain its own verified URLs agree on.
      Without it, an unknown app still receives no allowlist at all.
    """

    del self_host_runtime_host
    if access_route is not None and access_route not in BROWSER_ROUTES:
        raise BrowserPolicyInactiveError(app_slug, "route_is_not_a_browser_route")

    if recipe is not None and recipe.app_slug != app_slug:
        raise BrowserPolicyInactiveError(app_slug, "immutable_recipe_app_mismatch")
    policy = (
        browser_policy_from_recipe(recipe) if recipe is not None else get_browser_policy(app_slug)
    )
    if policy is None:
        if allow_domain_discovery is None:
            from ops.core.config import Settings

            allow_domain_discovery = bool(
                getattr(Settings.from_env(), "browser_domain_discovery_enabled", False)
            )
        if not allow_domain_discovery:
            # A research URL is evidence, never browser authority. Unknown apps do
            # not receive an allowlist until a reviewed recipe is checked in.
            raise BrowserPolicyInactiveError(app_slug, "reviewed_browser_policy_required")
        policy = discovered_policy_from_research(app_slug, research)
        if policy is None:
            raise BrowserPolicyInactiveError(app_slug, "discovery_domain_unproven")

    if not policy.active:
        raise BrowserPolicyInactiveError(app_slug, "browser_policy_inactive_for_app")

    return BrowserAllowedHosts(
        app_slug=app_slug,
        exact_hosts=tuple(dict.fromkeys(policy.exact_hosts)),
        vendor_wildcard_domains=policy.vendor_wildcard_domains,
    )


def allowed_hosts_from_patterns(app_slug: str, patterns: Iterable[str]) -> BrowserAllowedHosts:
    """Rebuild a run allow-list from the flat pattern list it was serialized as.

    The wire form is exactly what :meth:`BrowserAllowedHosts.patterns` produces,
    plus the app slug, so an allow-list can cross the RPC boundary into the browser
    container without anyone inventing an ad-hoc host string on either side.

    Fails closed with ``ValueError``: an empty, oversized, or malformed list yields
    no allow-list at all rather than a partial one. A wildcard is admitted only
    over its own registrable domain, so ``*.example.com`` is rebuildable and
    ``*.com`` is not — the boundary can never be widened in transit.
    """

    exact_hosts: list[str] = []
    wildcard_domains: list[str] = []
    seen: set[str] = set()
    for raw in patterns:
        if not isinstance(raw, str):
            raise ValueError("allow-list pattern must be a string")
        pattern = raw.strip().rstrip(".").casefold()
        if pattern in seen:
            continue
        seen.add(pattern)
        if len(seen) > MAX_ALLOWED_HOST_PATTERNS:
            raise ValueError("allow-list is larger than the reviewed bound")
        if _ALLOWED_HOST_PATTERN.fullmatch(pattern) is None:
            raise ValueError("allow-list pattern is malformed")
        if pattern.startswith("*."):
            domain = pattern[2:]
            # ``registrable_domain`` treats a bare multi-label public suffix such as
            # ``co.uk`` as its own registrable domain, so that check alone would let
            # ``*.co.uk`` through and open a whole public zone. Refuse the suffix
            # itself as well.
            if registrable_domain(domain) != domain or domain in _MULTI_LABEL_SUFFIXES:
                raise ValueError("wildcard is wider than one registrable domain")
            wildcard_domains.append(domain)
        else:
            if registrable_domain(pattern) is None:
                raise ValueError("exact host has no registrable domain")
            exact_hosts.append(pattern)
    if not exact_hosts and not wildcard_domains:
        raise ValueError("allow-list is empty")
    return BrowserAllowedHosts(
        app_slug=app_slug,
        exact_hosts=tuple(exact_hosts),
        vendor_wildcard_domains=tuple(wildcard_domains),
    )


def first_denied_navigation(
    urls: Iterable[str], allowed: BrowserAllowedHosts
) -> BrowserHostDecision | None:
    """The first URL in ``urls`` the allow-list refuses, or ``None`` if all pass.

    A convenience over :func:`evaluate_navigation` for the places that must check a
    whole set of candidate destinations before acting on any of them. The host
    check itself lives in one function only.
    """

    for url in urls:
        decision = evaluate_navigation(url, allowed)
        if not decision.allowed:
            return decision
    return None


def host_matches_patterns(hostname: str, patterns: tuple[str, ...]) -> bool:
    """Match a hostname against exact and left-edge ``*.parent`` patterns."""

    host = hostname.rstrip(".").casefold()
    for pattern in patterns:
        if pattern.startswith("*."):
            parent = pattern[2:]
            if host != parent and host.endswith(f".{parent}"):
                return True
        elif host == pattern:
            return True
    return False


def evaluate_navigation(url: str, allowed: BrowserAllowedHosts) -> BrowserHostDecision:
    """Check a target/current URL against the run's browser allowlist, fail-closed."""

    patterns = allowed.patterns()
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        return BrowserHostDecision(
            allowed=False,
            current_url=url,
            blocked_hostname=parsed.hostname,
            allowed_hosts=patterns,
            reason_code="browser_url_not_https_or_malformed",
            backend_policy_update_required=False,
        )
    host = parsed.hostname.rstrip(".").casefold()
    if host_matches_patterns(host, patterns):
        return BrowserHostDecision(
            allowed=True,
            current_url=url,
            blocked_hostname=None,
            allowed_hosts=patterns,
            reason_code="host_in_app_policy",
            backend_policy_update_required=False,
        )
    return BrowserHostDecision(
        allowed=False,
        current_url=url,
        blocked_hostname=host,
        allowed_hosts=patterns,
        reason_code="browser_host_not_in_app_policy",
        backend_policy_update_required=True,
    )


__all__ = [
    "BROWSER_ROUTES",
    "MAX_ALLOWED_HOST_PATTERNS",
    "NAVIGATION_TARGET_FIELDS",
    "BrowserAllowedHosts",
    "BrowserHostDecision",
    "BrowserHostPolicy",
    "BrowserPolicyInactiveError",
    "allowed_hosts_from_patterns",
    "build_browser_allowed_hosts",
    "evaluate_navigation",
    "first_denied_navigation",
    "get_browser_policy",
    "host_matches_patterns",
    "navigation_target_urls",
]
