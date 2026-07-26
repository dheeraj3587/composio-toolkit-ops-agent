"""The isolated browser service: FastAPI over the Playwright harness.

Chromium runs in THIS process, so an API restart no longer kills a live browser
session and a Chromium crash no longer threatens the control plane.

Every route is under ``/internal``, requires the shared browser-service token,
and enforces session ownership. Nothing is published publicly (see
``compose.playwright.sandbox.yaml``: no ``ports:``). Responses are sanitized
observations — never cookies, storage state, credential values, or the token.

The Phase 1/2 safety logic is REUSED, not re-implemented: this service drives
``ops.playwright_worker.PlaywrightBrowserWorker``, so the reviewed host policy,
candidate policy, risk policy, staged egress, dialog/popup/download guards and
DLP boundary all still apply exactly as tested.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, cast

from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket, status
from fastapi.responses import JSONResponse

from browser_service import __version__
from browser_service.auth import AuthContext, assert_session_owner, token_dependency
from browser_service.models import (
    CaptureCredentialsResponse,
    CreateSessionRequest,
    HealthResponse,
    LiveViewGrant,
    NavigateRequest,
    ObservationResponse,
    ProviderHealthState,
    ResumeRequest,
    SessionSummary,
)
from browser_service.novnc import LiveViewDenied, VncTarget, authorize_live_view
from browser_service.session_manager import ManagedSession, SessionManager, SessionUnavailable
from browser_service.settings import BrowserServiceSettings
from ops.provider_errors import ProviderOperationError

LOGGER = logging.getLogger("browser_service")

_LIVE_VIEW_QUERY = re.compile(
    r"(?P<path>/internal/browser/live-view/novnc)\?[^\s\"']*",
    flags=re.IGNORECASE,
)
_TOKEN_QUERY_VALUE = re.compile(r"(?i)(token=)[^&\s\"']+")
_SAFE_LOG_IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]{1,180}$")


def _safe_log_identifier(value: str) -> str:
    """Return only a bounded identifier that cannot smuggle a token into logs."""

    return value if _SAFE_LOG_IDENTIFIER.fullmatch(value) is not None else "-"


def _redact_uvicorn_log_value(value: Any) -> Any:
    """Remove bearer query material while preserving logging interpolation."""

    if isinstance(value, str):
        without_live_query = _LIVE_VIEW_QUERY.sub(r"\g<path>", value)
        return _TOKEN_QUERY_VALUE.sub(r"\1[REDACTED]", without_live_query)
    if isinstance(value, tuple):
        return tuple(_redact_uvicorn_log_value(item) for item in value)
    if isinstance(value, list):
        return [_redact_uvicorn_log_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact_uvicorn_log_value(item) for key, item in value.items()}
    return value


class UvicornWebSocketLogFilter(logging.Filter):
    """Strip noVNC grant queries from Uvicorn handshake/denial records.

    Uvicorn's websocket protocol logger uses ``uvicorn.error`` rather than the
    HTTP access logger, so ``--no-access-log`` alone cannot protect a query-string
    bearer token. This filter handles both the format string and its arguments.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = _redact_uvicorn_log_value(record.msg)
        record.args = _redact_uvicorn_log_value(record.args)
        return True


def install_uvicorn_websocket_log_filter() -> UvicornWebSocketLogFilter:
    """Attach the filter after Uvicorn configured logging, idempotently."""

    logger = logging.getLogger("uvicorn.error")
    existing = next(
        (item for item in logger.filters if isinstance(item, UvicornWebSocketLogFilter)),
        None,
    )
    redacting_filter = existing or UvicornWebSocketLogFilter()
    if existing is None:
        logger.addFilter(redacting_filter)
    for handler in logger.handlers:
        if not any(isinstance(item, UvicornWebSocketLogFilter) for item in handler.filters):
            handler.addFilter(redacting_filter)
    return redacting_filter


# Uvicorn configures its loggers before importing ``browser_service.main:app``.
# Installing at module import therefore protects websocket accept/deny records.
_UVICORN_WEBSOCKET_LOG_FILTER = install_uvicorn_websocket_log_filter()

_JANITOR_INTERVAL_SECONDS = 60.0

# Only these reasons mean the SAVED authentication state is no longer valid. A
# generic failure (timeout, model error, popup, transient outage) must not discard
# a working session.
_AUTH_STATE_INVALIDATION_REASONS = frozenset(
    {"authentication_failed", "session_expired", "logout_detected", "storage_state_rejected"}
)

# Module-level dependency singleton: FastAPI resolves this per request, and
# defining it once avoids a function call in an argument default (ruff B008).
_AUTH: AuthContext = Depends(token_dependency)


def _sanitized_error(exc: SessionUnavailable) -> HTTPException:
    code = {
        "session_not_found": status.HTTP_404_NOT_FOUND,
        "session_closing": status.HTTP_409_CONFLICT,
        "capacity_exhausted": status.HTTP_429_TOO_MANY_REQUESTS,
    }.get(exc.reason_code, status.HTTP_400_BAD_REQUEST)
    return HTTPException(status_code=code, detail=exc.reason_code)


# How long a cached Chromium readiness result stays fresh. The probe launches a
# browser, so it must not run per request.
_READINESS_TTL_SECONDS = 300.0


@dataclass
class _ReadinessCache:
    """One cached readiness result, refreshed under a single lock."""

    chromium_installed: bool = False
    context_launch_ok: bool = False
    reason_code: str = "readiness_not_probed"
    detail: str = ""
    checked_at: float | None = None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def is_stale(self) -> bool:
        if self.checked_at is None:
            return True
        return (time.monotonic() - self.checked_at) >= _READINESS_TTL_SECONDS

    def update(
        self, *, chromium_installed: bool, context_launch_ok: bool, reason_code: str, detail: str
    ) -> None:
        self.chromium_installed = chromium_installed
        self.context_launch_ok = context_launch_ok
        self.reason_code = reason_code
        self.detail = detail
        self.checked_at = time.monotonic()


def _storage_binding(payload: CreateSessionRequest, owner: str) -> Any:
    """The (app, account, owner) triple stored state is bound to."""

    from ops.browser_storage_state import StorageStateBinding

    return StorageStateBinding(
        app_slug=payload.app_slug,
        # An opaque reference, never a raw email address.
        account_ref=payload.account_ref or payload.profile_id or "default",
        owner=owner,
    )


def _state_store(settings: BrowserServiceSettings) -> Any:
    from ops.browser_storage_state import EncryptedStorageStateStore

    key = settings.storage_state_key.get_secret_value() if settings.storage_state_key else None
    return EncryptedStorageStateStore(settings.storage_state_dir, key)


def _load_storage_state(
    payload: CreateSessionRequest, owner: str, settings: BrowserServiceSettings
) -> dict[str, object] | None:
    """Decrypt previously saved authenticated state for this exact binding.

    Returns None when persistence is disabled, nothing is stored, or the blob is
    expired/undecryptable — the caller then simply performs a fresh login. The
    request only ever names an app and an opaque account reference, never a path.
    """

    if not payload.use_storage_state:
        return None
    store = _state_store(settings)
    if not store.enabled:
        return None
    try:
        return cast("dict[str, object] | None", store.load(_storage_binding(payload, owner)))
    except Exception:
        # A binding mismatch or corrupt blob must never block session creation.
        return None


def make_session_closer(
    worker_factory: Callable[[], Any],
    *,
    attachment_drainer: Callable[[str], Awaitable[bool]] | None = None,
) -> Callable[[ManagedSession], Awaitable[None]]:
    """Build the manager's unified live-view and browser-session closer.

    Previously the closer walked ``session.context``/``browser``/``playwright``,
    none of which were ever populated — so the janitor and service shutdown closed
    nothing and leaked Chromium. Ownership is now explicit: the manager holds the
    worker-side ``BrowserSessionContext`` and stops it through the worker.
    """

    async def _close(session: ManagedSession) -> None:
        # Revoke grants first, then stop every relay before Chromium is closed or
        # the single-display capacity can be reused by another run.
        session.hitl_pending = False
        if attachment_drainer is not None and not await attachment_drainer(session.session_id):
            raise RuntimeError("live_attachment_drain_failed")
        context = session.worker_context
        if context is None:
            return
        worker = worker_factory()
        if worker is None:
            raise RuntimeError("browser_worker_missing_during_close")
        await worker.stop(context)
        session.worker_context = None

    return _close


def create_app(settings: BrowserServiceSettings | None = None) -> FastAPI:
    """Build the browser-service app (factory so tests can inject settings)."""

    resolved = settings or BrowserServiceSettings.from_env()

    manager = SessionManager(
        max_sessions=resolved.max_sessions,
        inactivity_seconds=resolved.inactivity_seconds,
        maximum_age_seconds=resolved.maximum_age_seconds,
        drain_seconds=resolved.drain_seconds,
    )

    @contextlib.asynccontextmanager
    async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
        janitor = asyncio.create_task(manager.run_janitor(_JANITOR_INTERVAL_SECONDS))
        app.state.janitor_task = janitor
        # One readiness probe at startup, so the first health call is already
        # answered from cache rather than launching a browser inline.
        with contextlib.suppress(Exception):
            await _refresh_readiness(force=True)
        try:
            yield
        finally:
            janitor.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await janitor
            await manager.close_all()

    app = FastAPI(
        title="Composio Ops browser service",
        version=__version__,
        # No public docs surface on an internal service.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=_lifespan,
    )
    app.state.settings = resolved
    app.state.manager = manager
    # The worker is created lazily: importing Playwright must not be required for
    # /internal/health to answer "chromium not installed".
    app.state.worker = None
    app.state.readiness = _ReadinessCache()
    # Open interactive attachments are process-local and deliberately never
    # persisted. Resume drains this registry before autonomous browser work starts.
    live_attachments: dict[str, dict[asyncio.Task[Any], WebSocket]] = {}
    app.state.live_attachments = live_attachments

    async def _drain_live_attachments(
        session_id: str, *, close_reason: str = "hitl_resumed"
    ) -> bool:
        attached = list(live_attachments.get(session_id, {}).items())
        if not attached:
            return True
        for _task, socket in attached:
            with contextlib.suppress(Exception):
                await socket.close(code=1001, reason=close_reason)
        tasks = [task for task, _socket in attached if not task.done()]
        if tasks:
            _done, pending = await asyncio.wait(
                tasks,
                timeout=min(resolved.drain_seconds, 5.0),
            )
            for task in pending:
                task.cancel()
            if pending:
                with contextlib.suppress(Exception):
                    await asyncio.gather(*pending, return_exceptions=True)
        await asyncio.sleep(0)
        return not live_attachments.get(session_id)

    def _worker() -> Any:
        if app.state.worker is None:
            # ``api.main`` and this isolated service are different processes. The
            # assignment host matrix therefore has to be installed here too;
            # otherwise HubSpot remains inactive in the Playwright process and
            # its first frame is a real white ``about:blank`` page.
            from api.assignment_runtime import install_assignment_browser_policies
            from ops.config import Settings
            from ops.playwright_worker import PlaywrightBrowserWorker

            install_assignment_browser_policies()
            app.state.worker = PlaywrightBrowserWorker(
                settings=Settings.from_env(dotenv_path=None),
                # Headed ONLY when interactive HITL is enabled: a headless browser
                # renders nothing on the VNC desktop, so the previous hard-coded
                # headless launch made interactive HITL structurally impossible.
                headless=not resolved.interactive_hitl_enabled,
                # The service manager owns capacity and TTL; two independent
                # limits and two janitors would disagree.
                service_mode=True,
            )
        return app.state.worker

    # The idle sweep must be able to see a human attached to the interactive
    # relay; without this a waiting_for_hitl session is "idle" by definition and
    # could be reaped while someone is using it.
    manager.set_attachment_probe(lambda session_id: bool(live_attachments.get(session_id)))

    # Attach the real worker-backed closer now that the factory exists.
    manager.set_closer(
        make_session_closer(
            lambda: app.state.worker,
            attachment_drainer=lambda session_id: _drain_live_attachments(
                session_id, close_reason="session_closed"
            ),
        )
    )

    # ---------------------------------------------------------------- sessions
    @app.post(
        "/internal/browser/sessions",
        response_model=SessionSummary,
        status_code=status.HTTP_201_CREATED,
    )
    async def create_session(
        payload: CreateSessionRequest, auth: AuthContext = _AUTH
    ) -> SessionSummary:
        try:
            session = manager.create(
                owner=auth.owner,
                app_slug=payload.app_slug,
                live_view_mode=payload.live_view_mode,
            )
        except SessionUnavailable as exc:
            raise _sanitized_error(exc) from None

        # Launch the real browser for this session.
        try:
            worker = _worker()
            storage_state = _load_storage_state(payload, auth.owner, resolved)
            context = await worker.start(
                payload.profile_id,
                storage_state=storage_state if payload.use_storage_state else None,
            )
            # EXPLICIT ownership: the manager can now close the real session, and
            # nothing reaches into the worker's private session dictionary.
            session.worker_context = context
            session.reason_code = "session_started"
            session.current_page_id = context.session_id
            # Bind the run scope and account so one-time login references can only be
            # consumed for the matching run.
            session.secret_scope = payload.secret_scope
            session.account_ref = payload.account_ref
            # A screenshot is NOT available until one is actually captured — a
            # launched browser is not the same as a current, non-sensitive frame.
            session.screenshot_available = False
            # Interactive readiness is an explicit deployment capability. It is
            # never inferred from a screenshot or a run state.
            session.interactive_ready = resolved.interactive_hitl_enabled
            if payload.use_storage_state:
                session.storage_binding = _storage_binding(payload, auth.owner)
        except Exception as exc:  # sanitized: never surface provider text
            await manager.close(session.session_id, reason_code="browser_launch_failed")
            # Log the provider's OWN sanitized reason code, not just the exception
            # class. "browser launch failed: ProviderOperationError" told an
            # operator nothing, so a launch failure could not be diagnosed from the
            # service logs at all.
            reason = str(getattr(exc, "reason_code", "") or "unknown")
            LOGGER.warning("browser launch failed: reason=%s error=%s", reason, type(exc).__name__)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="browser_launch_failed"
            ) from None
        return session.summary()

    @app.get("/internal/browser/sessions/{session_id}/status", response_model=SessionSummary)
    async def session_status(session_id: str, auth: AuthContext = _AUTH) -> SessionSummary:
        session = manager.get_if_present(session_id)
        if session is None:
            # 404 is the authoritative answer the API's restart reconciliation
            # relies on: a persisted id is NEVER trusted without this check.
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session_not_found")
        assert_session_owner(session_owner=session.owner, caller_owner=auth.owner)
        return session.summary()

    @app.post(
        "/internal/browser/sessions/{session_id}/navigate", response_model=ObservationResponse
    )
    async def navigate(
        session_id: str,
        payload: NavigateRequest,
        auth: AuthContext = _AUTH,
    ) -> ObservationResponse:
        session = manager.get_if_present(session_id)
        if session is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session_not_found")
        assert_session_owner(session_owner=session.owner, caller_owner=auth.owner)
        try:
            with manager.lease(session_id) as leased:
                return await _drive(
                    _worker(),
                    leased,
                    payload.research,
                    payload.credential_refs,
                    resolved,
                    resume_signal=None,
                    account_creation_requested=payload.account_creation_requested,
                    credential_creation_policy=payload.credential_creation_policy,
                )
        except SessionUnavailable as exc:
            raise _sanitized_error(exc) from None

    @app.post("/internal/browser/sessions/{session_id}/resume", response_model=ObservationResponse)
    async def resume(
        session_id: str,
        payload: ResumeRequest,
        auth: AuthContext = _AUTH,
    ) -> ObservationResponse:
        session = manager.get_if_present(session_id)
        if session is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session_not_found")
        assert_session_owner(session_owner=session.owner, caller_owner=auth.owner)
        if not session.hitl_pending:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="hitl_not_pending")
        # Revoke stale grants before closing attachments. A socket racing this
        # transition will fail its handshake because HITL is no longer pending.
        session.hitl_pending = False
        if not await _drain_live_attachments(session_id):
            # The operator must be able to retry Resume after the stale socket
            # finally closes. Leaving this false would strand the run forever.
            session.hitl_pending = True
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="live_attachment_drain_failed",
            )
        try:
            with manager.lease(session_id) as leased:
                return await _drive(
                    _worker(),
                    leased,
                    payload.research or {},
                    payload.credential_refs,
                    resolved,
                    resume_signal=payload.signal,
                    credential_creation_policy=payload.credential_creation_policy,
                )
        except SessionUnavailable as exc:
            raise _sanitized_error(exc) from None

    @app.post(
        "/internal/browser/sessions/{session_id}/capture-credentials",
        response_model=CaptureCredentialsResponse,
    )
    async def capture_credentials(
        session_id: str,
        auth: AuthContext = _AUTH,
    ) -> CaptureCredentialsResponse:
        """Capture a reviewed credential into the shared vault, returning refs only."""

        session = manager.get_if_present(session_id)
        if session is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session_not_found")
        assert_session_owner(session_owner=session.owner, caller_owner=auth.owner)
        try:
            store = _credential_capture_store()
        except ProviderOperationError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=exc.reason_code,
            ) from None
        try:
            with manager.lease(session_id) as leased:
                captured = await asyncio.wait_for(
                    _worker().auto_capture_credentials(
                        leased.current_page_id,
                        leased.app_slug,
                        store,
                    ),
                    timeout=resolved.operation_timeout_seconds,
                )
                leased.touch()
        except TimeoutError:
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="credential_capture_timeout",
            ) from None
        except SessionUnavailable as exc:
            raise _sanitized_error(exc) from None
        except (TypeError, AttributeError, AssertionError, NameError):
            raise
        except Exception:
            # Never include exception/page text: it could contain the credential.
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="credential_capture_failed",
            ) from None
        return CaptureCredentialsResponse(credential_refs=captured or {})

    @app.get("/internal/browser/sessions/{session_id}/screenshot")
    async def screenshot(session_id: str, auth: AuthContext = _AUTH) -> Response:
        session = manager.get_if_present(session_id)
        if session is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session_not_found")
        assert_session_owner(session_owner=session.owner, caller_owner=auth.owner)
        worker = _worker()
        data: bytes | None = None
        if session.worker_context is not None:
            # PUBLIC contract only — never the worker's private _sessions dict.
            with contextlib.suppress(Exception):
                data = await worker.refresh_session_screenshot(session.worker_context)
        session.screenshot_available = bool(data)
        if not data:
            # No frame is available (or capture is disabled because the page is
            # credential-bearing): say so rather than serving a STALE frame from
            # a previous page.
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="screenshot_unavailable"
            )
        return Response(content=data, media_type="image/png")

    @app.post("/internal/browser/sessions/{session_id}/live-view", response_model=LiveViewGrant)
    async def live_view(session_id: str, auth: AuthContext = _AUTH) -> LiveViewGrant:
        """Issue a short-lived, session-bound interactive grant (never persisted)."""

        session = manager.get_if_present(session_id)
        if session is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session_not_found")
        assert_session_owner(session_owner=session.owner, caller_owner=auth.owner)
        if not resolved.interactive_hitl_enabled:
            return LiveViewGrant(mode="screenshot", url=None, session_id=session_id)
        if not session.hitl_pending:
            return LiveViewGrant(mode="screenshot", url=None, session_id=session_id)
        from ops.browser_live_view import (
            LiveViewAudit,
            build_interactive_url,
            issue_live_view_token,
        )

        secret = resolved.service_token.get_secret_value() if resolved.service_token else ""
        token, expires_at = issue_live_view_token(
            session_id=session_id,
            owner=auth.owner,
            secret=secret,
            ttl_seconds=resolved.live_view_token_seconds,
        )
        # The noVNC page is served by THIS service on the private network, so the
        # relay is gated by the same grant (see browser_service.novnc for why
        # websockify cannot enforce this).
        url = build_interactive_url(
            base_url=f"{resolved.novnc_base_url}/internal/browser/live-view/novnc",
            token=token,
            session_id=session_id,
        )
        audit = LiveViewAudit.record(
            session_id=session_id,
            owner=auth.owner,
            event="opened",
            reason_code="grant_issued",
        )
        # Audited WITHOUT the token or the URL, and the URL is never persisted.
        LOGGER.info(
            "live view grant issued session=%s owner=%s event=%s reason=%s",
            _safe_log_identifier(audit.session_id),
            _safe_log_identifier(audit.owner),
            audit.event,
            audit.reason_code,
        )
        return LiveViewGrant(
            mode="interactive_remote",
            url=url,
            expires_at=expires_at.isoformat(),
            session_id=session_id,
        )

    # -------------------------------------------------------- interactive HITL
    @app.websocket("/internal/browser/live-view/novnc")
    async def novnc_relay(websocket: WebSocket) -> None:
        """Relay an AUTHORIZED noVNC client to x11vnc on container loopback.

        The grant token arrives as a query parameter because that is the only
        channel a browser-based noVNC client can use; it is verified before the
        socket is accepted, is never logged, and authorizes exactly one session.
        """

        session_id = websocket.query_params.get("session", "")
        token = websocket.query_params.get("token", "")
        owner = websocket.headers.get("x-browser-session-owner", "")
        session = manager.get_if_present(session_id)
        # Log only canonical state, never attacker-controlled query/header text.
        log_session_id = _safe_log_identifier(session.session_id) if session else "-"
        log_owner = _safe_log_identifier(session.owner) if session else "-"
        secret = resolved.service_token.get_secret_value() if resolved.service_token else ""
        try:
            authorize_live_view(
                token=token,
                session_id=session_id,
                caller_owner=owner,
                secret=secret,
                session_owner=session.owner if session else None,
                session_lifecycle=session.lifecycle if session else None,
                interactive_enabled=resolved.interactive_hitl_enabled,
                hitl_pending=session.hitl_pending if session else False,
            )
        except LiveViewDenied as exc:
            # Refuse BEFORE accepting: an unauthorized client never gets a socket.
            LOGGER.warning("live view denied session=%s reason=%s", log_session_id, exc.reason_code)
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason=exc.reason_code)
            return

        # Reserve the attachment BEFORE the first post-authorization await. Resume
        # can now always see and drain an authorized handshake, even if WebSocket
        # acceptance is slow. This closes the authorize -> accept -> register race
        # that could otherwise overlap a newly resumed autonomous browser drive.
        attachment_task = asyncio.current_task()
        if attachment_task is None:  # pragma: no cover - ASGI always owns a task
            raise RuntimeError("websocket_task_missing")
        live_attachments.setdefault(session_id, {})[attachment_task] = websocket

        reason = "live_view_accept_failed"
        try:
            # RFB payloads remain binary frames, but noVNC does not need to request
            # a WebSocket subprotocol named "binary". Accepting one it did not offer
            # makes standards-compliant browser clients refuse the connection.
            await websocket.accept()
            reason = "live_view_closed"
            LOGGER.info("live view opened session=%s owner=%s", log_session_id, log_owner)

            async def _receive() -> bytes | None:
                from starlette.websockets import WebSocketDisconnect

                try:
                    message = await websocket.receive()
                except (WebSocketDisconnect, RuntimeError):
                    return None
                if message.get("type") == "websocket.disconnect":
                    return None
                data = message.get("bytes")
                if isinstance(data, bytes):
                    return data
                text = message.get("text")
                return text.encode() if isinstance(text, str) else b""

            from browser_service.novnc import relay_websocket_to_vnc

            reason = await relay_websocket_to_vnc(
                receive=_receive,
                send=websocket.send_bytes,
                target=VncTarget(port=resolved.vnc_port),
            )
        except LiveViewDenied as exc:
            reason = exc.reason_code
            with contextlib.suppress(Exception):
                await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason=exc.reason_code)
        finally:
            session_attachments = live_attachments.get(session_id)
            if session_attachments is not None:
                session_attachments.pop(attachment_task, None)
                if not session_attachments:
                    live_attachments.pop(session_id, None)
            with contextlib.suppress(Exception):
                await websocket.close()
            # Close is audited too, so an interactive attachment is never silent.
            LOGGER.info(
                "live view closed session=%s owner=%s reason=%s",
                log_session_id,
                log_owner,
                reason,
            )

    @app.delete("/internal/browser/sessions/{session_id}")
    async def delete_session(session_id: str, auth: AuthContext = _AUTH) -> JSONResponse:
        session = manager.get_if_present(session_id)
        if session is None:
            # Idempotent delete: already gone is success.
            return JSONResponse({"reason_code": "session_not_found"})
        assert_session_owner(session_owner=session.owner, caller_owner=auth.owner)
        # ONE teardown path: manager.close() runs the worker-backed closer, which
        # stops the real session. This endpoint used to stop the browser itself AND
        # then close the manager session, so with a working closer the browser was
        # stopped twice — and the janitor path stopped it zero times.
        reason = await manager.close(session_id, reason_code="closed_by_api")
        return JSONResponse({"reason_code": reason})

    # ------------------------------------------------------------------ health
    async def _refresh_readiness(*, force: bool = False) -> None:
        """Probe Chromium at most once per interval, under a single lock.

        The probe LAUNCHES a browser, so running it per request (as the Docker
        healthcheck does, every 60s, forever) burned a Chromium start each time and
        could exhaust resources. One cached result is refreshed in the background.
        """

        cache: _ReadinessCache = app.state.readiness
        if not force and not cache.is_stale():
            return
        async with cache.lock:
            if not force and not cache.is_stale():
                return
            try:
                from ops.browser_readiness import probe_playwright

                readiness = await probe_playwright(timeout_seconds=25.0)
                cache.update(
                    chromium_installed=readiness.reason_code != "playwright_not_installed",
                    context_launch_ok=readiness.ok,
                    reason_code=(
                        "chromium_launch_verified" if readiness.ok else readiness.reason_code
                    ),
                    detail=readiness.detail[:200] if not readiness.ok else "",
                )
            except Exception as exc:  # pragma: no cover - defensive
                cache.update(
                    chromium_installed=False,
                    context_launch_ok=False,
                    reason_code=f"probe_failed:{type(exc).__name__}",
                    detail="",
                )

    def _health_from_cache() -> HealthResponse:
        cache: _ReadinessCache = app.state.readiness
        state: ProviderHealthState
        if not resolved.token_configured:
            # Fail closed: with no token the service refuses every RPC, so it is not
            # merely unverified — it is unconfigured.
            state, reason = "not_configured", "token_missing"
        elif cache.checked_at is None:
            state, reason = "configured_not_verified", "readiness_not_probed"
        elif cache.context_launch_ok:
            state, reason = "ready", cache.reason_code
        else:
            state, reason = "degraded", cache.reason_code

        if manager.capacity_in_use >= manager.capacity_total and state == "ready":
            state, reason = "capacity_exhausted", "all_session_slots_in_use"

        return HealthResponse(
            state=state,
            reason_code=reason,
            version=__version__,
            chromium_installed=cache.chromium_installed,
            context_launch_ok=cache.context_launch_ok,
            capacity_total=manager.capacity_total,
            capacity_in_use=manager.capacity_in_use,
            janitor_running=manager.janitor_running,
            detail=cache.detail,
        )

    @app.get("/internal/live")
    async def live() -> JSONResponse:
        """Cheap liveness: the process and event loop are responsive.

        Launches nothing. This is what a frequent container healthcheck should call.
        """

        return JSONResponse({"status": "live", "version": __version__})

    @app.get("/internal/ready", response_model=HealthResponse)
    async def ready() -> HealthResponse:
        """Cached Chromium readiness plus capacity and janitor state."""

        await _refresh_readiness()
        return _health_from_cache()

    @app.get("/internal/health", response_model=HealthResponse)
    async def health(request: Request) -> HealthResponse:
        """Provider-aware health. Deliberately UNAUTHENTICATED but secret-free.

        Reports only capability state (never a session id, URL, or token) so a
        container healthcheck can call it without holding the RPC token. Backed by
        the CACHED readiness result rather than a fresh Chromium launch.
        """

        del request
        await _refresh_readiness()
        return _health_from_cache()

    return app


async def _save_storage_state(worker: Any, session: ManagedSession, store: Any) -> None:
    """Capture and encrypt the browser's authenticated state, best effort.

    Exports through the worker's PUBLIC ``export_storage_state`` contract rather than
    reaching into its private ``_sessions`` dict. A failure here must not fail the
    run: the next run simply logs in again.
    """

    if session.worker_context is None or not getattr(store, "enabled", False):
        return
    try:
        state = await worker.export_storage_state(session.worker_context)
    except Exception:
        return
    if isinstance(state, dict) and session.storage_binding is not None:
        with contextlib.suppress(Exception):
            store.save(session.storage_binding, state)


async def _drive(
    worker: Any,
    session: ManagedSession,
    research_payload: dict[str, object],
    credential_refs: dict[str, str],
    settings: BrowserServiceSettings,
    *,
    resume_signal: str | None,
    account_creation_requested: bool = False,
    credential_creation_policy: str = "reuse_only",
) -> ObservationResponse:
    """Run one navigate/resume operation and project a sanitized observation.

    Credential REFERENCES are resolved to values inside this service (never sent
    over RPC and never returned), so a value cannot cross a process boundary in
    either direction.
    """

    from ops.browser_worker import BrowserSessionContext
    from ops.models import OperationalResearch

    try:
        research = OperationalResearch.model_validate(research_payload)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="invalid_research_payload"
        ) from None

    handle = session.current_page_id
    context = BrowserSessionContext(
        profile_id=handle,
        session_id=handle,
        live_view_available=True,
        allowed_domains=(),
        created_at=session.created_at.isoformat(),
        inactivity_expires_at=session.maximum_expires_at.isoformat(),
        maximum_expires_at=session.maximum_expires_at.isoformat(),
    )
    try:
        sensitive = _resolve_credential_refs(
            session=session, credential_refs=credential_refs, settings=settings
        )
    except ProviderOperationError as exc:
        # A shared-vault misconfiguration is a deployment error, surfaced as a
        # sanitized 502 with the typed reason rather than an unhandled 500.
        session.reason_code = exc.reason_code
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail=exc.reason_code
        ) from None
    try:
        if resume_signal is None:
            navigate_kwargs: dict[str, object] = {
                "sensitive_data": sensitive,
                "credential_creation_policy": credential_creation_policy,
            }
            if account_creation_requested:
                navigate_kwargs["account_creation_requested"] = True
            observation = await asyncio.wait_for(
                worker.navigate_onboarding(context, research, **navigate_kwargs),
                timeout=settings.operation_timeout_seconds,
            )
        else:
            observation = await asyncio.wait_for(
                worker.resume_after_hitl(
                    context,
                    resume_signal,
                    research,
                    sensitive_data=sensitive,
                    credential_creation_policy=credential_creation_policy,
                ),
                timeout=settings.operation_timeout_seconds,
            )
    except TimeoutError:
        session.reason_code = "operation_timeout"
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT, detail="operation_timeout"
        ) from None
    except (TypeError, AttributeError, AssertionError, NameError):
        raise  # a programming error must surface, never be masked as provider failure
    except Exception as exc:
        session.reason_code = f"provider_error:{type(exc).__name__}"
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="browser_operation_failed"
        ) from None
    finally:
        sensitive.clear()  # drop credential values immediately

    session.hitl_pending = observation.status == "human_action_required"
    session.current_url_path = _url_path(observation.current_url)
    session.touch()

    # Persist authenticated state ONLY after a reviewed success, and invalidate it
    # the moment authentication fails. Storage state is bearer credential material,
    # so it is encrypted at rest and never logged.
    if session.storage_binding is not None:
        store = _state_store(settings)
        if observation.status == "credential_page_ready":
            await _save_storage_state(worker, session, store)
        elif observation.reason_code in _AUTH_STATE_INVALIDATION_REASONS:
            # Invalidate saved authentication state ONLY for explicit auth reasons.
            # Previously ANY failed observation invalidated it, so a navigation
            # timeout, model failure, popup failure or transient outage wrongly
            # discarded a still-valid session and forced a needless re-login.
            with contextlib.suppress(Exception):
                store.invalidate(session.storage_binding, reason_code=observation.reason_code)
    return ObservationResponse(
        status=observation.status,
        current_url=observation.current_url,
        page_title=observation.page_title,
        developer_app_id=observation.developer_app_id,
        human_action_type=observation.human_action_type,
        human_instruction=observation.human_instruction,
        credential_field_labels=tuple(observation.credential_field_labels),
        non_secret_notes=tuple(observation.non_secret_notes),
        reason_code=observation.reason_code,
        session=session.summary(),
    )


def _credential_capture_store() -> Any:
    """Build the service-local view of the shared encrypted credential vault."""

    from ops.config import Settings
    from ops.secret_store import SQLiteSecretStore

    app_settings = Settings.from_env(dotenv_path=None)
    if app_settings.secret_vault_key is None:
        raise ProviderOperationError(
            capability="browser service vault",
            reason_code="secret_vault_not_configured",
        )
    return SQLiteSecretStore(
        app_settings.secret_vault_db_path,
        app_settings.secret_vault_key.get_secret_value(),
    )


def _resolve_credential_refs(
    *,
    session: ManagedSession,
    credential_refs: dict[str, str],
    settings: BrowserServiceSettings,
) -> dict[str, str]:
    """Consume the run's ONE-TIME vault references to values INSIDE this service.

    A raw credential value never crosses the RPC boundary; the API sends only
    ``vault://`` references and the service consumes them here, bound to this
    session's app and run scope. A missing shared vault is an EXPLICIT error
    (secret_vault_not_configured) rather than a silent empty mapping, because the
    latter turned a deployment mistake into an unexplained login failure.
    """

    del settings
    if not credential_refs:
        return {}

    from ops.config import Settings
    from ops.secret_store import SQLiteSecretStore, TransientSecretError

    app_settings = Settings.from_env(dotenv_path=None)
    if app_settings.secret_vault_key is None:
        raise ProviderOperationError(
            capability="browser service vault",
            reason_code="secret_vault_not_configured",
        )
    store = SQLiteSecretStore(
        app_settings.secret_vault_db_path,
        app_settings.secret_vault_key.get_secret_value(),
    )
    resolved: dict[str, str] = {}
    for field_name, reference in credential_refs.items():
        if not isinstance(reference, str) or not reference.startswith("vault://"):
            continue
        expected_kind = f"browser_login_{field_name}"
        try:
            # Consume once, bound to this session's app and this run's scope. A
            # mismatch or expiry is a typed reason, never a raw value or a probe of
            # another app's secrets.
            value = store.consume_transient(
                reference,
                expected_app_slug=session.app_slug,
                expected_kind=expected_kind,
                expected_scope_id=session.secret_scope,
            )
        except TransientSecretError:
            continue
        if isinstance(value, str) and value:
            resolved[field_name] = value
    return resolved


def _url_path(url: str) -> str:
    from urllib.parse import urlsplit

    with contextlib.suppress(ValueError):
        return urlsplit(url).path or "/"
    return "/"


# The ASGI application Uvicorn serves (see Dockerfile.browser CMD).
app = create_app()

__all__ = ["app", "create_app"]
