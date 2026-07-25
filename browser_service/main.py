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
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, cast

from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket, status
from fastapi.responses import JSONResponse

from browser_service import __version__
from browser_service.auth import AuthContext, assert_session_owner, token_dependency
from browser_service.models import (
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

LOGGER = logging.getLogger("browser_service")

_JANITOR_INTERVAL_SECONDS = 60.0

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


def make_session_closer(worker_factory: Any) -> Any:
    """Build the manager's closer, which stops the REAL worker session.

    Previously the closer walked ``session.context``/``browser``/``playwright``,
    none of which were ever populated — so the janitor and service shutdown closed
    nothing and leaked Chromium. Ownership is now explicit: the manager holds the
    worker-side ``BrowserSessionContext`` and stops it through the worker.
    """

    async def _close(session: ManagedSession) -> None:
        context = session.worker_context
        if context is None:
            return
        worker = worker_factory()
        if worker is None:
            return
        with contextlib.suppress(Exception):
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

    def _worker() -> Any:
        if app.state.worker is None:
            from ops.config import Settings
            from ops.playwright_worker import PlaywrightBrowserWorker

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

    # Attach the real worker-backed closer now that the factory exists.
    manager.set_closer(make_session_closer(lambda: app.state.worker))

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
            session.screenshot_available = True
            if payload.use_storage_state:
                session.storage_binding = _storage_binding(payload, auth.owner)
        except Exception as exc:  # sanitized: never surface provider text
            await manager.close(session.session_id, reason_code="browser_launch_failed")
            LOGGER.warning("browser launch failed: %s", type(exc).__name__)
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
        try:
            with manager.lease(session_id) as leased:
                return await _drive(
                    _worker(),
                    leased,
                    payload.research or {},
                    payload.credential_refs,
                    resolved,
                    resume_signal=payload.signal,
                )
        except SessionUnavailable as exc:
            raise _sanitized_error(exc) from None

    @app.get("/internal/browser/sessions/{session_id}/screenshot")
    async def screenshot(session_id: str, auth: AuthContext = _AUTH) -> Response:
        session = manager.get_if_present(session_id)
        if session is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session_not_found")
        assert_session_owner(session_owner=session.owner, caller_owner=auth.owner)
        worker = _worker()
        handle = session.current_page_id
        data: bytes | None = None
        worker_session = getattr(worker, "_sessions", {}).get(handle)
        if worker_session is not None:
            with contextlib.suppress(Exception):
                await worker.refresh_live_view(worker_session)
                data = getattr(worker_session, "screenshot", None)
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
            audit.session_id,
            audit.owner,
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
            )
        except LiveViewDenied as exc:
            # Refuse BEFORE accepting: an unauthorized client never gets a socket.
            LOGGER.warning(
                "live view denied session=%s reason=%s", session_id or "-", exc.reason_code
            )
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason=exc.reason_code)
            return

        await websocket.accept(subprotocol="binary")
        LOGGER.info("live view opened session=%s owner=%s", session_id, owner)

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

        reason = "live_view_closed"
        try:
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
            with contextlib.suppress(Exception):
                await websocket.close()
            # Close is audited too, so an interactive attachment is never silent.
            LOGGER.info("live view closed session=%s owner=%s reason=%s", session_id, owner, reason)

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

    Uses the WORKER's own context rather than reaching for Playwright objects the
    manager never held. A failure here must not fail the run: the next run simply
    logs in again.
    """

    if session.worker_context is None or not getattr(store, "enabled", False):
        return
    handle = session.current_page_id
    pw_session = getattr(worker, "_sessions", {}).get(handle)
    context = getattr(pw_session, "context", None)
    if context is None:
        return
    try:
        state = await context.storage_state()
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
    sensitive = _resolve_credential_refs(credential_refs, settings)
    try:
        if resume_signal is None:
            observation = await asyncio.wait_for(
                worker.navigate_onboarding(context, research, sensitive_data=sensitive),
                timeout=settings.operation_timeout_seconds,
            )
        else:
            observation = await asyncio.wait_for(
                worker.resume_after_hitl(
                    context, resume_signal, research, sensitive_data=sensitive
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
        if observation.status in {"credential_page_ready", "succeeded"}:
            await _save_storage_state(worker, session, store)
        elif observation.status == "failed":
            with contextlib.suppress(Exception):
                store.invalidate(session.storage_binding, reason_code="authentication_failed")
    return ObservationResponse(
        status=observation.status,
        current_url=observation.current_url,
        page_title=observation.page_title,
        developer_app_id=observation.developer_app_id,
        human_action_type=observation.human_action_type,
        human_instruction=observation.human_instruction,
        credential_field_labels=tuple(observation.credential_field_labels),
        non_secret_notes=tuple(observation.non_secret_notes),
        session=session.summary(),
    )


def _resolve_credential_refs(
    credential_refs: dict[str, str], settings: BrowserServiceSettings
) -> dict[str, str]:
    """Resolve vault references to values INSIDE this service.

    A raw credential value never crosses the RPC boundary; the API sends only
    ``vault://`` references and the service reads the vault itself.
    """

    del settings
    if not credential_refs:
        return {}
    resolved: dict[str, str] = {}
    try:
        from ops.config import Settings
        from ops.secret_store import SQLiteSecretStore

        app_settings = Settings.from_env(dotenv_path=None)
        if app_settings.secret_vault_key is None:
            return {}
        store = SQLiteSecretStore(
            app_settings.secret_vault_db_path,
            app_settings.secret_vault_key.get_secret_value(),
        )
    except Exception:
        return {}
    for field_name, reference in credential_refs.items():
        if not isinstance(reference, str) or not reference.startswith("vault://"):
            continue
        with contextlib.suppress(Exception):
            value = store.get(reference)
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
