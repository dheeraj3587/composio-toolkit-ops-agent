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
from collections.abc import AsyncIterator
from typing import Any

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


async def _close_session_resources(session: ManagedSession) -> None:
    """Close Playwright objects in dependency order, best effort."""

    for closer in (
        getattr(session.context, "close", None),
        getattr(session.browser, "close", None),
        getattr(session.playwright, "stop", None),
    ):
        if callable(closer):
            with contextlib.suppress(Exception):
                await closer()


def create_app(settings: BrowserServiceSettings | None = None) -> FastAPI:
    """Build the browser-service app (factory so tests can inject settings)."""

    resolved = settings or BrowserServiceSettings.from_env()

    manager = SessionManager(
        max_sessions=resolved.max_sessions,
        inactivity_seconds=resolved.inactivity_seconds,
        maximum_age_seconds=resolved.maximum_age_seconds,
        drain_seconds=resolved.drain_seconds,
        closer=_close_session_resources,
    )

    @contextlib.asynccontextmanager
    async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
        janitor = asyncio.create_task(manager.run_janitor(_JANITOR_INTERVAL_SECONDS))
        app.state.janitor_task = janitor
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

    def _worker() -> Any:
        if app.state.worker is None:
            from ops.config import Settings
            from ops.playwright_worker import PlaywrightBrowserWorker

            app.state.worker = PlaywrightBrowserWorker(settings=Settings.from_env(dotenv_path=None))
        return app.state.worker

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
            context = await worker.start(payload.profile_id)
            session.page = getattr(worker, "_sessions", {}).get(context.session_id)
            session.reason_code = "session_started"
            # Remember the worker-side handle so operations address the same browser.
            session.current_page_id = context.session_id
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
        worker = _worker()
        handle = session.current_page_id
        worker_session = getattr(worker, "_sessions", {}).get(handle)
        if worker_session is not None:
            with contextlib.suppress(Exception):
                from ops.browser_worker import BrowserSessionContext

                await worker.stop(
                    BrowserSessionContext(
                        profile_id=handle,
                        session_id=handle,
                        live_view_available=False,
                        allowed_domains=(),
                        created_at=session.created_at.isoformat(),
                        inactivity_expires_at=session.maximum_expires_at.isoformat(),
                        maximum_expires_at=session.maximum_expires_at.isoformat(),
                    )
                )
        reason = await manager.close(session_id, reason_code="closed_by_api")
        return JSONResponse({"reason_code": reason})

    # ------------------------------------------------------------------ health
    @app.get("/internal/health", response_model=HealthResponse)
    async def health(request: Request) -> HealthResponse:
        """Provider-aware health. Deliberately UNAUTHENTICATED but secret-free.

        It reports only capability state (never a session id, URL, or token) so a
        container healthcheck can call it without holding the RPC token.
        """

        del request
        state: ProviderHealthState = "configured_not_verified"
        reason = "token_configured" if resolved.token_configured else "token_missing"
        chromium_installed = False
        context_ok = False
        detail = ""

        if not resolved.token_configured:
            state = "not_configured"
        else:
            try:
                from ops.browser_readiness import probe_playwright

                readiness = await probe_playwright(timeout_seconds=25.0)
                chromium_installed = readiness.reason_code != "playwright_not_installed"
                context_ok = readiness.ok
                if readiness.ok:
                    state = "ready"
                    reason = "chromium_launch_verified"
                else:
                    state = "degraded"
                    reason = readiness.reason_code
                    detail = readiness.detail[:200]
            except Exception as exc:  # pragma: no cover - defensive
                state = "degraded"
                reason = f"probe_failed:{type(exc).__name__}"

        if manager.capacity_in_use >= manager.capacity_total and state == "ready":
            state = "capacity_exhausted"
            reason = "all_session_slots_in_use"

        return HealthResponse(
            state=state,
            reason_code=reason,
            version=__version__,
            chromium_installed=chromium_installed,
            context_launch_ok=context_ok,
            capacity_total=manager.capacity_total,
            capacity_in_use=manager.capacity_in_use,
            janitor_running=manager.janitor_running,
            detail=detail,
        )

    return app


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
