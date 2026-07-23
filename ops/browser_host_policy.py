"""Per-run BROWSER navigation host policy (visible Browser Use navigation only).

This is one of two separate security boundaries:

* ``BrowserHostPolicy`` (this module) — hosts Browser Use may visibly navigate
  to. It is activated only after deterministic routing selects an actual browser
  route (``self_serve``/``hybrid`` with a permitted fallback), and only for apps
  whose policy is explicitly marked active.
* ``NetworkEndpointPolicy`` (``ops.network_endpoint_policy``) — exact API,
  OAuth token-exchange, and credential-validation endpoints that backend HTTP
  clients may call. API/token endpoints are NEVER added here just because they
  belong to the provider; they must be genuinely browser-facing (e.g. an OAuth
  ``/authorize`` page a human visits).

Wildcards are granted only for vendor-owned, non-shared registrable domains, and
only where account/customer subdomains genuinely vary. Shared corporate domains
(google.com, facebook.com) and code hosts (github.com) are never wildcarded.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from ops.models import OperationalResearch

# Access routes for which a browser session may be launched at all.
BROWSER_ROUTES = frozenset({"self_serve", "hybrid"})


@dataclass(frozen=True, slots=True)
class BrowserHostPolicy:
    """An explicit, reviewed per-app browser navigation policy.

    ``active`` gates whether Browser Use may run for the app at all. Inactive
    policies exist as reviewed metadata (for documentation and future review)
    but never produce an allowlist and never reach a Browser Use session.
    """

    app_slug: str
    active: bool
    exact_hosts: tuple[str, ...] = ()
    # Vendor-owned, non-shared registrable domains whose subdomains are trusted
    # (e.g. customer-specific ``<company>.pipedrive.com``). Never a shared host.
    vendor_wildcard_domains: tuple[str, ...] = ()
    # True when a self-hosted deployment must supply an exact runtime host via
    # verified configuration (Twenty). Cloud hosts alone are otherwise used.
    allows_configured_runtime_host: bool = False


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


# Explicit, reviewed per-app browser policies. ONLY Pipedrive and Twenty are
# active in the current 10-app matrix (the only deterministic browser routes).
# Every other app is inactive reviewed metadata and never launches Browser Use.
_BROWSER_POLICIES: dict[str, BrowserHostPolicy] = {
    # --- Active browser-fallback / self-serve routes ---
    "pipedrive": BrowserHostPolicy(
        app_slug="pipedrive",
        active=True,
        exact_hosts=("developers.pipedrive.com", "app.pipedrive.com", "oauth.pipedrive.com"),
        # Customer accounts live on <company>.pipedrive.com.
        vendor_wildcard_domains=("pipedrive.com",),
    ),
    "twenty": BrowserHostPolicy(
        app_slug="twenty",
        active=True,
        # Cloud hosts only; no wildcard. Self-hosted runtime host must be supplied
        # explicitly through verified configuration (see build kwarg).
        exact_hosts=("api.twenty.com", "app.twenty.com", "docs.twenty.com"),
        allows_configured_runtime_host=True,
    ),
    # --- Inactive reviewed metadata (never launches Browser Use) ---
    "hubspot": BrowserHostPolicy(
        app_slug="hubspot",
        active=False,
        exact_hosts=("developers.hubspot.com", "app.hubspot.com"),
    ),
    "attio": BrowserHostPolicy(
        app_slug="attio",
        active=False,
        exact_hosts=("docs.attio.com", "app.attio.com", "build.attio.com"),
    ),
    "zendesk": BrowserHostPolicy(
        app_slug="zendesk",
        active=False,
        vendor_wildcard_domains=("zendesk.com",),
    ),
    "google-ads": BrowserHostPolicy(
        app_slug="google-ads",
        active=False,
        exact_hosts=(
            "developers.google.com",
            "ads.google.com",
            "console.cloud.google.com",
            "accounts.google.com",
        ),
    ),
    "whatsapp-business": BrowserHostPolicy(app_slug="whatsapp-business", active=False),
    "salesforce": BrowserHostPolicy(
        app_slug="salesforce",
        active=False,
        exact_hosts=("login.salesforce.com", "test.salesforce.com"),
    ),
    "close": BrowserHostPolicy(
        app_slug="close",
        active=False,
        exact_hosts=("app.close.com", "developer.close.com"),
    ),
    "sherlock": BrowserHostPolicy(app_slug="sherlock", active=False),
}


def get_browser_policy(app_slug: str) -> BrowserHostPolicy | None:
    """Return the reviewed browser policy (active or inactive) for an app."""

    return _BROWSER_POLICIES.get(app_slug)


def _research_hostnames(research: OperationalResearch) -> list[str]:
    urls = [
        research.developer_portal_url,
        research.signup_url,
        research.api_base_url,
        research.authorization_url,
        research.token_url,
        *research.evidence_urls,
    ]
    hosts: list[str] = []
    for url in urls:
        if not isinstance(url, str) or not url:
            continue
        parsed = urlsplit(url)
        if parsed.scheme != "https":
            continue
        hostname = (parsed.hostname or "").rstrip(".").casefold()
        if hostname and hostname not in hosts:
            hosts.append(hostname)
    return hosts


def _is_valid_runtime_host(value: str) -> bool:
    parsed = urlsplit(value if "://" in value else f"https://{value}")
    host = (parsed.hostname or "").rstrip(".").casefold()
    return bool(host) and "." in host and " " not in host


def build_browser_allowed_hosts(
    app_slug: str,
    research: OperationalResearch,
    *,
    access_route: str | None = None,
    self_host_runtime_host: str | None = None,
) -> BrowserAllowedHosts:
    """Build the per-run browser allowlist, failing closed for inactive apps.

    * The app's route must be a browser route (``self_serve``/``hybrid``) when
      ``access_route`` is provided.
    * The app's reviewed policy must be ``active``.
    * Unknown apps fail closed to their exact verified research hostnames only
      (no wildcard, no auth host, no API/token host expansion).
    """

    if access_route is not None and access_route not in BROWSER_ROUTES:
        raise BrowserPolicyInactiveError(app_slug, "route_is_not_a_browser_route")

    policy = _BROWSER_POLICIES.get(app_slug)
    if policy is None:
        # Unknown app: fail closed to exact verified research hostnames only.
        unknown_hosts = tuple(dict.fromkeys(_research_hostnames(research)))
        if not unknown_hosts:
            raise BrowserPolicyInactiveError(app_slug, "no_verified_host_for_unknown_app")
        return BrowserAllowedHosts(app_slug, exact_hosts=unknown_hosts, vendor_wildcard_domains=())

    if not policy.active:
        raise BrowserPolicyInactiveError(app_slug, "browser_policy_inactive_for_app")

    exact_hosts: list[str] = list(policy.exact_hosts)
    if policy.allows_configured_runtime_host and self_host_runtime_host:
        host = urlsplit(
            self_host_runtime_host
            if "://" in self_host_runtime_host
            else f"https://{self_host_runtime_host}"
        ).hostname
        if host and _is_valid_runtime_host(host):
            normalized = host.rstrip(".").casefold()
            if normalized not in exact_hosts:
                exact_hosts.append(normalized)
    return BrowserAllowedHosts(
        app_slug=app_slug,
        exact_hosts=tuple(dict.fromkeys(exact_hosts)),
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
