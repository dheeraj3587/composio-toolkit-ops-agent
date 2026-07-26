"""Token-gated noVNC surface, served by THIS service rather than websockify.

Interactive HITL needs a real remote-control surface (a screenshot cannot solve a
CAPTCHA or an account chooser). The obvious build is ``websockify --token-plugin``
in front of x11vnc, but its plugin contract makes the Phase 3 security
requirements unachievable — verified against the websockify sources, not assumed:

* ``auth_plugins.BasePlugin.authenticate(self, headers, target_host,
  target_port)`` receives ONLY headers. The URL ``?token=`` never reaches an auth
  plugin, so a signed session-bound grant token cannot be validated there.
* ``token_plugins.BasePlugin.lookup(token)`` returns a ``host:port`` target. It is
  a routing hook, not an authorizer: returning a target IS the authorization, and
  a failed lookup is logged verbatim as ``"Token '%s' not found" % token`` —
  which violates "never include the token in logs".
* ``--web-auth`` gates static files through the same headers-only plugin.

So websockify would leave either an unauthenticated noVNC or a token in logs.
Instead the WebSocket relay lives here, behind the SAME verification the RPC
endpoints use:

1. the grant token must verify (HMAC signature, bound session id, bound owner,
   unexpired) — see ``ops.browser_live_view.verify_live_view_token``,
2. the session must exist, be ``ACTIVE``, be awaiting HITL, and be owned by the caller,
3. only then is a TCP connection opened to x11vnc on **loopback inside this
   container**, which is the only place the VNC port is reachable.

The container publishes no port (``compose.playwright.sandbox.yaml`` has no
``ports:``), so this surface is reachable only on the private Compose network,
and every open/close is audited without the token or the URL.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

LOGGER = logging.getLogger("browser_service.novnc")

# One RFB frame chunk. Large enough for smooth screen updates, bounded so a
# hostile peer cannot force unbounded buffering.
_RELAY_CHUNK_BYTES = 64 * 1024

# Time budget for reaching x11vnc on loopback. It is either up or it is not.
_VNC_CONNECT_TIMEOUT_SECONDS = 5.0


class LiveViewDenied(RuntimeError):
    """Access refused. Carries a reason code, never the token."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class VncTarget:
    """Where x11vnc listens. Loopback only — never a caller-supplied address."""

    host: str = "127.0.0.1"
    port: int = 5900

    def is_loopback(self) -> bool:
        """Guard against ever relaying to a non-local target."""

        return self.host in {"127.0.0.1", "::1", "localhost"}


def authorize_live_view(
    *,
    token: str,
    session_id: str,
    caller_owner: str,
    secret: str,
    session_owner: str | None,
    session_lifecycle: str | None,
    interactive_enabled: bool,
    hitl_pending: bool = False,
) -> str:
    """Authorize one interactive attachment, or raise ``LiveViewDenied``.

    Fail-closed ordering: the feature flag, then the signed grant, then the live
    session's own ownership. Every check must pass; none is skipped when another
    already succeeded.
    """

    from ops.browser_live_view import LiveViewTokenError, verify_live_view_token

    if not interactive_enabled:
        raise LiveViewDenied("interactive_hitl_disabled")
    if not secret:
        raise LiveViewDenied("live_view_secret_missing")
    try:
        verify_live_view_token(
            token,
            secret=secret,
            expected_session_id=session_id,
            expected_owner=caller_owner,
        )
    except LiveViewTokenError as exc:
        # Reason code only: the token itself is never echoed or logged.
        raise LiveViewDenied(exc.reason_code) from None
    if session_owner is None:
        raise LiveViewDenied("session_not_found")
    # A validly signed token for a session someone else owns is still refused.
    if session_owner != caller_owner:
        raise LiveViewDenied("session_not_found")
    if session_lifecycle != "ACTIVE":
        raise LiveViewDenied("session_closing")
    if not hitl_pending:
        raise LiveViewDenied("hitl_not_pending")
    return "live_view_authorized"


async def relay_websocket_to_vnc(
    *,
    receive: Callable[[], Awaitable[bytes | None]],
    send: Callable[[bytes], Awaitable[None]],
    target: VncTarget,
) -> str:
    """Pump bytes both ways between an authorized WebSocket and x11vnc.

    ``receive`` returns ``None`` at end-of-stream. The relay is byte-transparent:
    it neither parses nor logs RFB traffic (frames can show credential surfaces).
    """

    if not target.is_loopback():
        # Defence in depth: this relay must never become an SSRF primitive.
        raise LiveViewDenied("vnc_target_not_loopback")
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target.host, target.port),
            timeout=_VNC_CONNECT_TIMEOUT_SECONDS,
        )
    except (OSError, TimeoutError):
        raise LiveViewDenied("vnc_unavailable") from None

    async def _client_to_vnc() -> None:
        while True:
            chunk = await receive()
            if not chunk:
                return
            writer.write(chunk)
            await writer.drain()

    async def _vnc_to_client() -> None:
        while True:
            chunk = await reader.read(_RELAY_CHUNK_BYTES)
            if not chunk:
                return
            await send(chunk)

    tasks = [asyncio.create_task(_client_to_vnc()), asyncio.create_task(_vnc_to_client())]
    try:
        # Either direction closing ends the attachment.
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            exc = task.exception()
            if exc is not None and not isinstance(exc, OSError | asyncio.CancelledError):
                raise exc
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return "live_view_closed"


__all__ = [
    "LiveViewDenied",
    "VncTarget",
    "authorize_live_view",
    "relay_websocket_to_vnc",
]
