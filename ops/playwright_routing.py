"""Staged network egress: what the browser is allowed to fetch, and when.

The stage model exists because credentials are typed into the DOM, so "who may the
page talk to" has to tighten as the run progresses:

* pre_auth — reviewed vendor hosts, plus reviewed passive asset hosts for
  render-only resources (image/font/stylesheet/media). Every ACTIVE request kind
  (document, fetch/XHR, WebSocket, EventSource, script, unknown) must be on the
  vendor allowlist, because those kinds can EXFILTRATE rather than merely render.
* post_auth — once credentials are injected or a credential-bearing page is
  reached, every off-allowlist request is aborted regardless of kind, including
  images, fonts, stylesheets and media. That closes the pixel/CSS/font beacon
  channels a compromised page could otherwise use to leak a credential.

Two fail-closed rules hold throughout: an unknown resource kind is refused, and a
stage-provider error is treated as the STRICTEST stage rather than the most
permissive. A blocked finding is logged once per (host, kind, stage) and bounded, so
a hostile page cannot flood the log.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from typing import Any
from urllib.parse import urlsplit

from ops.browser_egress import BrowserEgressPolicy, EgressStage
from ops.browser_link_log import log_event
from ops.browser_target_selection import AccountState, select_browser_target
from ops.browser_worker import (
    BrowserObservation,
    is_allowed_browser_url,
    sanitize_browser_url,
)


def navigation_allowed(url: str, patterns: tuple[str, ...]) -> bool:
    """True when ``url`` is an https URL whose host is inside the allowlist."""

    return is_allowed_browser_url(url, patterns)


def select_initial_target(
    research: Any,
    trace: Any,
    patterns: Sequence[str],
    *,
    account_state: AccountState = "unknown",
) -> str | None:
    """Choose the shared account-aware reviewed starting URL for Playwright.

    The shared selector preserves Playwright's conservative compatibility fallback:
    an unverified developer-portal field is considered only when this app has no
    reviewed trace.  Field-level claims, trace host validation, and strict URL
    rejection are centralized with the Browser Use implementation.
    """

    return select_browser_target(
        research=research,
        trace=trace,
        allowed_domains=patterns,
        account_state=account_state,
        is_allowed_url=is_allowed_browser_url,
        fallback_mode="playwright",
    )


def make_egress_route_handler(
    *,
    policy: BrowserEgressPolicy,
    stage_provider: Callable[[], EgressStage],
) -> Callable[[Any], Awaitable[None]]:
    """Build the route handler that makes ``BrowserEgressPolicy`` the authority.

    The four-stage policy already existed but was never installed: the context
    route used the older two-stage string handler, so per-kind and per-stage host
    sets (reviewed IdP hosts, post-auth hosts, credential-surface tightening) had
    no effect on the network.

    Unknown resource kinds fail closed inside ``policy.permits``. A stage-provider
    error is treated as the STRICTEST stage rather than the most permissive.
    """

    blocked_seen: set[tuple[str, str, str]] = set()

    async def _handler(route: Any) -> None:
        request = route.request
        try:
            kind = str(request.resource_type or "").casefold()
            url = str(request.url)
        except Exception:
            await route.abort(error_code="blockedbyclient")
            return

        try:
            stage = stage_provider()
        except Exception:
            stage = EgressStage.CREDENTIAL_SURFACE  # fail closed: tightest stage

        if policy.permits(url=url, kind=kind, stage=stage):
            await route.continue_()
        else:
            host = (urlsplit(url).hostname or "").casefold()
            finding = (host, kind, stage.value)
            if host and finding not in blocked_seen and len(blocked_seen) < 32:
                blocked_seen.add(finding)
                log_event(
                    "playwright.egress.blocked",
                    blocked_host=host,
                    resource_kind=kind,
                    stage=stage.value,
                )
            await route.abort(error_code="blockedbyclient")

    return _handler


# Request kinds that can EXFILTRATE data (send it somewhere) as opposed to merely
# rendering the page. These are blocked off-allowlist even though they are not
# top-level navigations, because credentials are typed into the DOM and a
# compromised third-party script could otherwise beacon them out.
_ACTIVE_RESOURCE_TYPES = frozenset(
    {"document", "xhr", "fetch", "websocket", "eventsource", "manifest", "other"}
)


# Passive render-only asset kinds: allowed off-allowlist so real pages still work.
_PASSIVE_RESOURCE_TYPES = frozenset({"image", "font", "stylesheet", "media"})


def make_route_handler(
    patterns: tuple[str, ...],
    *,
    stage_provider: Any = None,
    asset_hosts: tuple[str, ...] = (),
) -> Any:
    """Build a Playwright route handler enforcing STAGED egress (item 6).

    Stage ``pre_auth`` — reviewed vendor hosts plus reviewed passive asset hosts may
    serve render-only resources (image/font/stylesheet/media); every ACTIVE request
    kind (document, fetch/XHR, WebSocket, EventSource, script, unknown) must be on
    the vendor allowlist.

    Stage ``post_auth`` — once credentials have been injected or a credential-bearing
    page is reached, EVERY off-allowlist request is aborted regardless of kind,
    including images, fonts, stylesheets and media. That closes the pixel/CSS/font
    beacon channels a compromised page could use to exfiltrate a credential.

    ``stage_provider`` is a zero-arg callable returning the current stage, so one
    installed route reflects later tightening. Unknown kinds fail CLOSED, and a
    stage_provider error is treated as post_auth (the stricter stage).
    """

    async def _handler(route: Any) -> None:
        request = route.request
        try:
            resource_type = str(request.resource_type or "other")
            url = str(request.url)
        except Exception:
            await route.abort()
            return

        if navigation_allowed(url, patterns):
            await route.continue_()
            return

        stage = "pre_auth"
        if callable(stage_provider):
            try:
                stage = str(stage_provider() or "pre_auth")
            except Exception:
                stage = "post_auth"  # fail closed
        if stage != "pre_auth":
            # Authenticated / credential-bearing: nothing off-allowlist may leave.
            await route.abort()
            return

        if resource_type in _PASSIVE_RESOURCE_TYPES and (
            not asset_hosts or is_allowed_browser_url(url, asset_hosts)
        ):
            await route.continue_()
            return
        await route.abort()

    return _handler


def _blocked(url: str) -> BrowserObservation:
    parsed = urlsplit(url)
    host = parsed.hostname or "unknown"
    return BrowserObservation(
        status="blocked",
        current_url=sanitize_browser_url(url),
        page_title=f"Navigation blocked by host policy ({host})"[:500],
        non_secret_notes=("Target was outside the reviewed host allowlist.",),
    )
