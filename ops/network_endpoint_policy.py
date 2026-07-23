"""Exact backend network-endpoint policy (server-side HTTP clients only).

This is the second security boundary, separate from ``BrowserHostPolicy``. It
lists the exact API, OAuth token-exchange, and credential-validation endpoints
that backend HTTP clients may call. Entries are exact HTTPS endpoints (no query
string, no fragment, standard port). These endpoints are never added to the
browser navigation allowlist merely because they belong to the provider.

Only endpoints the backend actually calls (or is reviewed to call) are listed.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


class NetworkEndpointError(ValueError):
    """Raised when an endpoint is not an exact, well-formed HTTPS endpoint."""


def normalize_endpoint(url: str) -> str:
    """Canonicalize an exact HTTPS endpoint or raise ``NetworkEndpointError``."""

    parsed = urlsplit(url.strip())
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise NetworkEndpointError("network endpoints must be HTTPS without credentials")
    if parsed.query or parsed.fragment:
        raise NetworkEndpointError("network endpoints cannot contain a query string or fragment")
    if parsed.port not in (None, 443):
        raise NetworkEndpointError("network endpoints must use the standard HTTPS port")
    hostname = parsed.hostname.rstrip(".").casefold()
    return urlunsplit(("https", hostname, parsed.path or "/", "", ""))


@dataclass(frozen=True, slots=True)
class NetworkEndpoint:
    """A single reviewed backend endpoint and its purpose."""

    url: str
    purpose: str  # "credential_validation" | "oauth_token" | "api"


@dataclass(frozen=True, slots=True)
class NetworkEndpointPolicy:
    """The reviewed set of exact endpoints a backend client may call for an app."""

    app_slug: str
    endpoints: tuple[NetworkEndpoint, ...]

    def allowed_urls(self) -> tuple[str, ...]:
        return tuple(normalize_endpoint(endpoint.url) for endpoint in self.endpoints)

    def endpoint_for(self, purpose: str) -> str | None:
        for endpoint in self.endpoints:
            if endpoint.purpose == purpose:
                return normalize_endpoint(endpoint.url)
        return None


# Reviewed exact endpoints. Credential validation is what the backend actively
# calls today (HubSpot, Pipedrive); token endpoints are reviewed metadata for
# the documented OAuth flows. Providers the backend does not call have no entry.
_NETWORK_POLICIES: dict[str, NetworkEndpointPolicy] = {
    "hubspot": NetworkEndpointPolicy(
        app_slug="hubspot",
        endpoints=(
            NetworkEndpoint(
                "https://api.hubapi.com/account-info/2026-03/details", "credential_validation"
            ),
            NetworkEndpoint("https://api.hubapi.com/oauth/v3/token", "oauth_token"),
        ),
    ),
    "pipedrive": NetworkEndpointPolicy(
        app_slug="pipedrive",
        endpoints=(
            NetworkEndpoint("https://api.pipedrive.com/v1/users/me", "credential_validation"),
            NetworkEndpoint("https://oauth.pipedrive.com/oauth/token", "oauth_token"),
        ),
    ),
}


def get_network_policy(app_slug: str) -> NetworkEndpointPolicy | None:
    return _NETWORK_POLICIES.get(app_slug)


def validation_endpoint(app_slug: str) -> str | None:
    """Return the reviewed read-only credential-validation endpoint for an app."""

    policy = _NETWORK_POLICIES.get(app_slug)
    return policy.endpoint_for("credential_validation") if policy is not None else None


def is_allowed_network_endpoint(app_slug: str, url: str) -> bool:
    """True only when ``url`` is an exact reviewed HTTPS endpoint for the app."""

    policy = _NETWORK_POLICIES.get(app_slug)
    if policy is None:
        return False
    try:
        candidate = normalize_endpoint(url)
    except NetworkEndpointError:
        return False
    return candidate in policy.allowed_urls()


__all__ = [
    "NetworkEndpoint",
    "NetworkEndpointError",
    "NetworkEndpointPolicy",
    "get_network_policy",
    "is_allowed_network_endpoint",
    "normalize_endpoint",
    "validation_endpoint",
]
