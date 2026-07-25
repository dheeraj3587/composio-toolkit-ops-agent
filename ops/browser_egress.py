"""Staged browser egress policy.

Which hosts may be contacted, for which resource kind, at which point in the
run. Host sets come ONLY from reviewed static configuration (the per-app
``browser_host_policy`` plus explicitly reviewed identity-provider/asset lists).
They are NEVER derived from LLM output, page HTML, redirect history, JavaScript,
or You.com results.

Stages tighten monotonically:

* ``PRE_AUTH`` — before any credential exists in the DOM. Vendor navigation +
  reviewed active API/script hosts, plus render-only assets from reviewed asset
  hosts.
* ``AUTHENTICATING`` — a login/IdP flow is in progress. Adds reviewed
  identity-provider hosts (an IdP legitimately needs its own scripts/XHR).
* ``AUTHENTICATED`` — a session exists. IdP hosts are dropped again; only
  vendor + reviewed post-auth hosts remain.
* ``CREDENTIAL_SURFACE`` — a credential is (or may be) rendered. Nothing
  off-allowlist may leave, for ANY resource kind, including images/fonts/CSS —
  closing pixel/CSS/font beacon channels.

Unknown resource kinds fail CLOSED at every stage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from urllib.parse import urlsplit

from ops.browser_host_policy import host_matches_patterns


class EgressStage(StrEnum):
    PRE_AUTH = "pre_auth"
    AUTHENTICATING = "authenticating"
    AUTHENTICATED = "authenticated"
    CREDENTIAL_SURFACE = "credential_surface"


# Resource kinds Playwright reports. Anything NOT listed here is unknown and
# fails closed.
_ACTIVE_KINDS = frozenset(
    {"document", "xhr", "fetch", "websocket", "eventsource", "manifest", "script"}
)
_PASSIVE_KINDS = frozenset({"image", "font", "stylesheet", "media"})
KNOWN_KINDS = _ACTIVE_KINDS | _PASSIVE_KINDS


@dataclass(frozen=True, slots=True)
class BrowserEgressPolicy:
    """Reviewed host sets per capability. All lists are static, reviewed data."""

    vendor_navigation_hosts: tuple[str, ...] = ()
    identity_provider_hosts: tuple[str, ...] = ()
    active_api_hosts: tuple[str, ...] = ()
    active_script_hosts: tuple[str, ...] = ()
    passive_asset_hosts: tuple[str, ...] = ()
    post_auth_hosts: tuple[str, ...] = ()

    def allowed_patterns(self, stage: EgressStage, kind: str) -> tuple[str, ...]:
        """The host patterns permitted for ``kind`` at ``stage`` (may be empty)."""

        vendor = self.vendor_navigation_hosts
        if stage is EgressStage.CREDENTIAL_SURFACE:
            # Nothing but the vendor itself, for any kind.
            return vendor

        if stage is EgressStage.AUTHENTICATED:
            base = (*vendor, *self.post_auth_hosts)
            if kind in _PASSIVE_KINDS:
                return (*base, *self.passive_asset_hosts)
            if kind == "script":
                return (*base, *self.active_script_hosts)
            if kind in _ACTIVE_KINDS:
                return (*base, *self.active_api_hosts)
            return ()  # unknown kind -> fail closed

        if stage is EgressStage.AUTHENTICATING:
            base = (*vendor, *self.identity_provider_hosts)
            if kind in _PASSIVE_KINDS:
                return (*base, *self.passive_asset_hosts)
            if kind == "script":
                return (*base, *self.active_script_hosts)
            if kind in _ACTIVE_KINDS:
                return (*base, *self.active_api_hosts)
            return ()

        # PRE_AUTH
        if kind in _PASSIVE_KINDS:
            return (*vendor, *self.passive_asset_hosts)
        if kind == "script":
            return (*vendor, *self.active_script_hosts)
        if kind in _ACTIVE_KINDS:
            return (*vendor, *self.active_api_hosts)
        return ()

    def permits(self, *, url: str, kind: str, stage: EgressStage) -> bool:
        """True only when this exact (url, kind, stage) combination is reviewed."""

        if kind not in KNOWN_KINDS:
            return False  # unknown resource kind fails closed
        parsed = urlsplit(url)
        if parsed.scheme != "https":
            return False
        host = (parsed.hostname or "").rstrip(".").casefold()
        if not host:
            return False
        patterns = self.allowed_patterns(stage, kind)
        if not patterns:
            return False
        return host_matches_patterns(host, tuple(patterns))


@dataclass(slots=True)
class EgressStageTracker:
    """Monotonic stage state for one session (it never loosens)."""

    stage: EgressStage = EgressStage.PRE_AUTH
    _order: dict[EgressStage, int] = field(
        default_factory=lambda: {
            EgressStage.PRE_AUTH: 0,
            EgressStage.AUTHENTICATING: 1,
            EgressStage.AUTHENTICATED: 2,
            EgressStage.CREDENTIAL_SURFACE: 3,
        }
    )

    def advance_to(self, stage: EgressStage) -> EgressStage:
        """Move forward to ``stage``; a request to loosen is ignored."""

        if self._order[stage] > self._order[self.stage]:
            self.stage = stage
        return self.stage


def build_egress_policy(
    vendor_patterns: tuple[str, ...],
    *,
    identity_provider_hosts: tuple[str, ...] = (),
    active_api_hosts: tuple[str, ...] = (),
    active_script_hosts: tuple[str, ...] = (),
    passive_asset_hosts: tuple[str, ...] = (),
    post_auth_hosts: tuple[str, ...] = (),
) -> BrowserEgressPolicy:
    """Build a policy from the app's REVIEWED vendor patterns plus reviewed extras."""

    return BrowserEgressPolicy(
        vendor_navigation_hosts=tuple(vendor_patterns),
        identity_provider_hosts=tuple(identity_provider_hosts),
        active_api_hosts=tuple(active_api_hosts),
        active_script_hosts=tuple(active_script_hosts),
        passive_asset_hosts=tuple(passive_asset_hosts),
        post_auth_hosts=tuple(post_auth_hosts),
    )


__all__ = [
    "KNOWN_KINDS",
    "BrowserEgressPolicy",
    "EgressStage",
    "EgressStageTracker",
    "build_egress_policy",
]
