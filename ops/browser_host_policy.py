"""Recipe-backed top-level browser navigation policy.

This is one of two separate security boundaries:

* ``BrowserHostPolicy`` (this module) — exact hosts Playwright may visibly
  navigate to. Authority comes only from a checked-in ``AppRecipe``.
* ``NetworkEndpointPolicy`` (``ops.network_endpoint_policy``) — exact API,
  OAuth token-exchange, and credential-validation endpoints that backend HTTP
  clients may call. API/token endpoints are NEVER added here just because they
  belong to the provider; they must be genuinely browser-facing (e.g. an OAuth
  ``/authorize`` page a human visits).

Research URLs, documentation URLs, and runtime-supplied hosts never expand this
boundary. Resource and IdP hosts remain separately reviewed recipe fields and do
not become top-level navigation destinations.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from ops.app_recipes import AppRecipe, get_app_recipe
from ops.models import OperationalResearch

# Access routes for which a browser session may be launched at all.
BROWSER_ROUTES = frozenset({"self_serve", "hybrid"})


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


def build_browser_allowed_hosts(
    app_slug: str,
    research: OperationalResearch,
    *,
    access_route: str | None = None,
    self_host_runtime_host: str | None = None,
    recipe: AppRecipe | None = None,
) -> BrowserAllowedHosts:
    """Build the per-run browser allowlist, failing closed for inactive apps.

    * The app's route must be a browser route (``self_serve``/``hybrid``) when
      ``access_route`` is provided.
    * The app's reviewed policy must be ``active``.
    * Research and runtime values cannot create or expand a policy.
    """

    del research, self_host_runtime_host
    if access_route is not None and access_route not in BROWSER_ROUTES:
        raise BrowserPolicyInactiveError(app_slug, "route_is_not_a_browser_route")

    if recipe is not None and recipe.app_slug != app_slug:
        raise BrowserPolicyInactiveError(app_slug, "immutable_recipe_app_mismatch")
    policy = (
        browser_policy_from_recipe(recipe) if recipe is not None else get_browser_policy(app_slug)
    )
    if policy is None:
        # A research URL is evidence, never browser authority. Unknown apps do not
        # receive an allowlist until a reviewed recipe/policy is checked in.
        raise BrowserPolicyInactiveError(app_slug, "reviewed_browser_policy_required")

    if not policy.active:
        raise BrowserPolicyInactiveError(app_slug, "browser_policy_inactive_for_app")

    return BrowserAllowedHosts(
        app_slug=app_slug,
        exact_hosts=tuple(dict.fromkeys(policy.exact_hosts)),
        vendor_wildcard_domains=policy.vendor_wildcard_domains,
    )


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
    "BrowserAllowedHosts",
    "BrowserHostDecision",
    "BrowserHostPolicy",
    "BrowserPolicyInactiveError",
    "build_browser_allowed_hosts",
    "evaluate_navigation",
    "get_browser_policy",
    "host_matches_patterns",
]
