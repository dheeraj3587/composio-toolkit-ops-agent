"""The isolated browser service: FastAPI over the Playwright harness.

Chromium runs in THIS process, so an API restart no longer kills a live browser
session and a Chromium crash no longer threatens the control plane.

Every route is under ``/internal``, requires the shared browser-service token,
and enforces session ownership. The browser worker publishes no host port in
``compose.prod.yaml``. Responses are sanitized
observations — never cookies, storage state, credential values, or the token.

The Phase 1/2 safety logic is REUSED, not re-implemented: this service drives
``ops.playwright.worker.PlaywrightBrowserWorker``, so the reviewed host policy,
candidate policy, risk policy, staged egress, dialog/popup/download guards and
DLP boundary all still apply exactly as tested.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import socket
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Literal, cast

from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket, status
from fastapi.responses import JSONResponse

from browser_service import __version__
from browser_service.auth import (
    AuthContext,
    assert_session_access,
    require_session_capability,
    require_session_capability_value,
    token_dependency,
)
from browser_service.display_pool import DisplayPool, DisplayUnavailable
from browser_service.models import (
    CaptureCredentialsRequest,
    CaptureCredentialsResponse,
    CreateSessionRequest,
    DrainStatus,
    HealthResponse,
    LiveViewGrant,
    NavigateRequest,
    ObservationResponse,
    ProviderHealthState,
    ReconcileSessionsRequest,
    ReconcileSessionsResponse,
    ResumeRequest,
    SessionSummary,
)
from browser_service.novnc import LiveViewDenied, VncTarget, authorize_live_view
from browser_service.secret_broker import BrokerCaptureStore, BrowserSecretBrokerClient
from browser_service.session_manager import ManagedSession, SessionManager, SessionUnavailable
from browser_service.settings import BrowserServiceSettings
from ops.browser.host_policy import (
    allowed_hosts_from_patterns,
    first_denied_navigation,
    navigation_target_urls,
)
from ops.browser.process_hardening import harden_browser_service_process
from ops.core.redaction import install_redacting_filter
from ops.providers.errors import ProviderOperationError

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


def install_browser_service_log_filters() -> None:
    """Install general value redaction plus the live-view query scrubber.

    Uvicorn owns several non-propagating loggers and may attach its handlers after
    application modules are first imported. Calling this at import and again from
    lifespan is therefore intentional and idempotent: the latter is the
    after-Uvicorn-configuration enforcement point.
    """

    for logger in (
        logging.getLogger(),
        LOGGER,
        logging.getLogger("browser_service.novnc"),
        logging.getLogger("uvicorn"),
        logging.getLogger("uvicorn.error"),
        logging.getLogger("uvicorn.access"),
    ):
        install_redacting_filter(logger)
    install_uvicorn_websocket_log_filter()


# Uvicorn configures its loggers before importing ``browser_service.main:app``.
# Install immediately for websocket accept/deny records, then again from lifespan
# in case an embedding server attached or replaced handlers after this import.
install_browser_service_log_filters()

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
        "service_draining": status.HTTP_503_SERVICE_UNAVAILABLE,
    }.get(exc.reason_code, status.HTTP_400_BAD_REQUEST)
    return HTTPException(status_code=code, detail=exc.reason_code)


# How long a cached Chromium readiness result stays fresh. The probe launches a
# browser, so it must not run per request.
_READINESS_TTL_SECONDS = 300.0


def _interactive_stack_ready(display_pool: DisplayPool) -> bool:
    """Verify every configured control/view VNC listener is reachable locally."""

    for slot in display_pool.slots():
        for port in (slot.vnc_port, slot.view_vnc_port):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                    pass
            except OSError:
                return False
    return True


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

    from ops.browser.storage_state import StorageStateBinding

    if payload.account_ref is None:
        raise ValueError("browser account reference is required")

    return StorageStateBinding(
        app_slug=payload.app_slug,
        # An opaque reference, never a raw email address.
        account_ref=payload.account_ref,
        owner=owner,
    )


def _state_store(settings: BrowserServiceSettings) -> Any:
    from ops.browser.storage_state import EncryptedStorageStateStore

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
    display_pool: DisplayPool | None = None,
) -> Callable[[ManagedSession], Awaitable[None]]:
    """Build the manager's unified live-view and browser-session closer.

    Previously the closer walked ``session.context``/``browser``/``playwright``,
    none of which were ever populated — so the janitor and service shutdown closed
    nothing and leaked Chromium. Ownership is now explicit: the manager holds the
    worker-side ``BrowserSessionContext`` and stops it through the worker.
    """

    async def _close(session: ManagedSession) -> None:
        # Revoke grants first, then stop every relay before Chromium is closed or
        # this session's display slot can be leased by another run.
        _set_hitl_pending(session, False)
        if attachment_drainer is not None and not await attachment_drainer(session.session_id):
            raise RuntimeError("live_attachment_drain_failed")
        context = session.worker_context
        if context is None:
            # No browser was ever attached, but a display may still have been
            # leased by a create that failed before launch. Return it or the slot
            # leaks and interactive capacity shrinks permanently.
            _release_display(session)
            return
        worker = worker_factory()
        if worker is None:
            raise RuntimeError("browser_worker_missing_during_close")
        await worker.stop(context)
        session.worker_context = None
        # Released only AFTER Chromium is actually gone. Handing the display to a
        # new session while the old browser still renders to it would put two
        # sessions on one desktop, which is exactly the leak per-session displays
        # exist to prevent.
        _release_display(session)

    def _release_display(session: ManagedSession) -> None:
        if display_pool is None:
            return
        display_pool.release(session.display_slot)
        session.display_slot = None

    return _close


def _set_hitl_pending(session: ManagedSession, pending: bool) -> None:
    """Cross a HITL boundary while revoking grants from earlier pauses."""

    if pending and not session.hitl_pending:
        session.hitl_generation += 1
    session.hitl_pending = pending


def create_app(settings: BrowserServiceSettings | None = None) -> FastAPI:
    """Build the browser-service app (factory so tests can inject settings)."""

    resolved = settings or BrowserServiceSettings.from_env()

    manager = SessionManager(
        max_sessions=resolved.max_sessions,
        inactivity_seconds=resolved.inactivity_seconds,
        maximum_age_seconds=resolved.maximum_age_seconds,
        drain_seconds=resolved.drain_seconds,
    )
    # One private X display per session slot. Inert (zero slots) when interactive
    # HITL is off, so a headless deployment allocates nothing.
    display_pool = DisplayPool(
        slots=resolved.display_slots,
        display_base=resolved.display_num_base,
        vnc_port_base=resolved.vnc_port_base,
        view_vnc_port_base=resolved.view_vnc_port_base,
    )

    @contextlib.asynccontextmanager
    async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
        harden_browser_service_process()
        install_browser_service_log_filters()
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
            broker = app.state.secret_broker
            if broker is not None:
                broker.close()

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
    app.state.display_pool = display_pool
    # The worker is created lazily: importing Playwright must not be required for
    # /internal/health to answer "chromium not installed".
    app.state.worker = None
    app.state.secret_broker = None
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
        for _task, attached_socket in attached:
            with contextlib.suppress(Exception):
                await attached_socket.close(code=1001, reason=close_reason)
        tasks = [task for task, _attached_socket in attached if not task.done()]
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

    async def _enter_secret_capture_boundary(session: ManagedSession) -> None:
        """Revoke every live pixel capability before automatic reveal/capture.

        Signed grants are stateless, so revocation is enforced through the live
        session flag consulted on every WebSocket authorization. Existing relays
        are then closed and drained. Capture is impossible unless both that drain
        and the browser-context document-start mask are proven.
        """

        # Revoke FIRST. A socket racing the drain now fails authorization, and the
        # screenshot endpoint also consults this monotonic flag.
        session.live_view_allowed = False
        _set_hitl_pending(session, False)
        session.screenshot_available = False
        if not session.live_pixel_mask_installed:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="live_pixel_mask_not_installed",
            )
        if not await _drain_live_attachments(
            session.session_id,
            close_reason="secret_capture_boundary",
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="live_attachment_drain_failed",
            )
        session.secret_capture_boundary_entered = True

    def _worker() -> Any:
        if app.state.worker is None:
            from ops.core.config import Settings
            from ops.playwright.worker import PlaywrightBrowserWorker

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

    def _secret_broker() -> BrowserSecretBrokerClient:
        if app.state.secret_broker is not None:
            return cast(BrowserSecretBrokerClient, app.state.secret_broker)
        if resolved.secret_broker_token is None:
            raise ProviderOperationError(
                capability="browser secret broker",
                reason_code="browser_secret_broker_unavailable",
            )
        app.state.secret_broker = BrowserSecretBrokerClient(
            base_url=resolved.secret_broker_url,
            token=resolved.secret_broker_token,
            timeout_seconds=resolved.secret_broker_timeout_seconds,
        )
        return cast(BrowserSecretBrokerClient, app.state.secret_broker)

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
            display_pool=display_pool,
        )
    )

    # ------------------------------------------------------------ release drain
    def _drain_status() -> DrainStatus:
        accepting, in_use, total = manager.drain_status()
        return DrainStatus(
            accepting_new_sessions=accepting,
            capacity_in_use=in_use,
            capacity_total=total,
        )

    @app.get("/internal/drain", response_model=DrainStatus)
    async def drain_status(auth: AuthContext = _AUTH) -> DrainStatus:
        # The regular token+owner dependency authenticates release tooling. A
        # run capability is intentionally irrelevant: drain is service-wide and
        # never grants access to any session.
        del auth
        return _drain_status()

    @app.post("/internal/drain", response_model=DrainStatus)
    async def begin_drain(auth: AuthContext = _AUTH) -> DrainStatus:
        del auth
        manager.begin_drain()
        return _drain_status()

    @app.delete("/internal/drain", response_model=DrainStatus)
    async def undrain(auth: AuthContext = _AUTH) -> DrainStatus:
        del auth
        manager.undrain()
        return _drain_status()

    # ---------------------------------------------------------------- sessions
    @app.post(
        "/internal/browser/sessions",
        response_model=SessionSummary,
        status_code=status.HTTP_201_CREATED,
    )
    async def create_session(
        payload: CreateSessionRequest, auth: AuthContext = _AUTH
    ) -> SessionSummary:
        session_capability_digest = require_session_capability(auth)
        recipe = _validated_recipe_snapshot(
            payload.recipe_snapshot,
            expected_app_slug=payload.app_slug,
        )
        if recipe is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="recipe_snapshot_required",
            )
        # Rebuild the run's allow-list from its serialized patterns rather than
        # trusting loose strings later. A malformed list is refused outright: a
        # partially understood allow-list is not confinement.
        allowed_hosts = None
        if payload.allowed_host_patterns:
            try:
                allowed_hosts = allowed_hosts_from_patterns(
                    payload.app_slug, payload.allowed_host_patterns
                )
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail="browser_allow_list_invalid",
                ) from None
        try:
            session = manager.create(
                owner=auth.owner,
                app_slug=payload.app_slug,
                live_view_mode=payload.live_view_mode,
                session_capability_digest=session_capability_digest,
                secret_scope=payload.secret_scope,
                account_ref=payload.account_ref,
                run_id=payload.run_id,
                allowed_hosts=allowed_hosts,
            )
        except SessionUnavailable as exc:
            raise _sanitized_error(exc) from None

        # Lease this session's PRIVATE display before anything launches. Recorded
        # on the session immediately so a failed launch still releases it via the
        # closer rather than leaking interactive capacity.
        try:
            session.display_slot = display_pool.acquire()
        except DisplayUnavailable as exc:
            await manager.close(session.session_id, reason_code=exc.reason_code)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=exc.reason_code
            ) from None

        # Launch the real browser for this session.
        try:
            worker = _worker()
            storage_state = _load_storage_state(payload, auth.owner, resolved)
            context = await worker.start(
                payload.profile_id,
                recipe=recipe,
                storage_state=storage_state if payload.use_storage_state else None,
                # Headful Chromium renders to THIS session's display only. None in a
                # headless deployment, where the worker inherits the process env.
                display=session.display_slot.display if session.display_slot else None,
            )
            # EXPLICIT ownership: the manager can now close the real session, and
            # nothing reaches into the worker's private session dictionary.
            session.worker_context = context
            masker = getattr(worker, "install_live_pixel_mask", None)
            if not callable(masker) or not await masker(
                context,
                payload.app_slug,
                recipe=recipe,
            ):
                raise ProviderOperationError(
                    capability="Playwright live view",
                    reason_code="live_pixel_mask_install_failed",
                )
            # The service, not the frontend, owns this fact. Interactive readiness
            # is never published until the actual browser context has the recipe's
            # document-start mask.
            session.live_pixel_mask_installed = True
            session.reason_code = "session_started"
            session.current_page_id = context.session_id
            # The run/account binding was attached atomically when the manager
            # admitted the session, before Chromium launch. That makes a response-
            # loss orphan discoverable without widening the search.
            # A screenshot is NOT available until one is actually captured — a
            # launched browser is not the same as a current, non-sensitive frame.
            session.screenshot_available = False
            # Interactive readiness is an explicit deployment capability. It is
            # never inferred from a screenshot or a run state. It additionally
            # requires an actually-leased private display: without one there is no
            # desktop to relay, and claiming otherwise would hand out a grant that
            # cannot resolve to a VNC target.
            session.interactive_ready = (
                resolved.interactive_hitl_enabled and session.display_slot is not None
            )
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

    @app.post(
        "/internal/browser/sessions/reconcile",
        response_model=ReconcileSessionsResponse,
    )
    async def reconcile_sessions(
        payload: ReconcileSessionsRequest,
        auth: AuthContext = _AUTH,
    ) -> ReconcileSessionsResponse:
        session_capability_digest = require_session_capability(auth)
        return ReconcileSessionsResponse(
            session_ids=manager.find_bound_sessions(
                owner=auth.owner,
                session_capability_digest=session_capability_digest,
                app_slug=payload.app_slug,
                secret_scope=payload.secret_scope,
                account_ref=payload.account_ref,
                run_id=payload.run_id,
            )
        )

    @app.get("/internal/browser/sessions/{session_id}/status", response_model=SessionSummary)
    async def session_status(session_id: str, auth: AuthContext = _AUTH) -> SessionSummary:
        caller_capability_digest = require_session_capability(auth)
        session = manager.get_if_present(session_id)
        if session is None:
            # 404 is the authoritative answer the API's restart reconciliation
            # relies on: a persisted id is NEVER trusted without this check.
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session_not_found")
        assert_session_access(
            session_owner=session.owner,
            caller_owner=auth.owner,
            session_capability_digest=session.session_capability_digest,
            caller_capability_digest=caller_capability_digest,
        )
        return session.summary()

    @app.post(
        "/internal/browser/sessions/{session_id}/navigate", response_model=ObservationResponse
    )
    async def navigate(
        session_id: str,
        payload: NavigateRequest,
        auth: AuthContext = _AUTH,
    ) -> ObservationResponse:
        caller_capability_digest = require_session_capability(auth)
        session = manager.get_if_present(session_id)
        if session is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session_not_found")
        assert_session_access(
            session_owner=session.owner,
            caller_owner=auth.owner,
            session_capability_digest=session.session_capability_digest,
            caller_capability_digest=caller_capability_digest,
        )
        caller_capability = require_session_capability_value(auth)
        try:
            with manager.lease(session_id) as leased:
                observation = await _drive(
                    _worker(),
                    leased,
                    payload.research,
                    payload.recipe_snapshot,
                    payload.credential_refs,
                    payload.secret_grants,
                    resolved,
                    secret_broker_factory=_secret_broker,
                    broker_owner=auth.owner,
                    broker_capability=caller_capability,
                    resume_signal=None,
                    account_creation_requested=payload.account_creation_requested,
                    signup_fields=payload.signup_fields,
                    credential_creation_policy=payload.credential_creation_policy,
                )
                if observation.status == "credential_page_ready":
                    leased.credential_surface_ready = True
                    await _enter_secret_capture_boundary(leased)
                    observation = observation.model_copy(update={"session": leased.summary()})
                return observation
        except SessionUnavailable as exc:
            raise _sanitized_error(exc) from None

    @app.post("/internal/browser/sessions/{session_id}/resume", response_model=ObservationResponse)
    async def resume(
        session_id: str,
        payload: ResumeRequest,
        auth: AuthContext = _AUTH,
    ) -> ObservationResponse:
        caller_capability_digest = require_session_capability(auth)
        session = manager.get_if_present(session_id)
        if session is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session_not_found")
        assert_session_access(
            session_owner=session.owner,
            caller_owner=auth.owner,
            session_capability_digest=session.session_capability_digest,
            caller_capability_digest=caller_capability_digest,
        )
        caller_capability = require_session_capability_value(auth)
        if not session.hitl_pending:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="hitl_not_pending")
        # Revoke stale grants before closing attachments. A socket racing this
        # transition will fail its handshake because HITL is no longer pending.
        _set_hitl_pending(session, False)
        if not await _drain_live_attachments(session_id):
            # The operator must be able to retry Resume after the stale socket
            # finally closes. Leaving this false would strand the run forever.
            _set_hitl_pending(session, True)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="live_attachment_drain_failed",
            )
        try:
            with manager.lease(session_id) as leased:
                observation = await _drive(
                    _worker(),
                    leased,
                    payload.research or {},
                    payload.recipe_snapshot,
                    payload.credential_refs,
                    payload.secret_grants,
                    resolved,
                    secret_broker_factory=_secret_broker,
                    broker_owner=auth.owner,
                    broker_capability=caller_capability,
                    resume_signal=payload.signal,
                    account_creation_requested=payload.account_creation_requested,
                    signup_fields=payload.signup_fields,
                    credential_creation_policy=payload.credential_creation_policy,
                )
                if observation.status == "credential_page_ready":
                    leased.credential_surface_ready = True
                    await _enter_secret_capture_boundary(leased)
                    observation = observation.model_copy(update={"session": leased.summary()})
                return observation
        except HTTPException as exc:
            detail = str(exc.detail)
            definite_pre_action = bool(
                exc.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
                or detail.startswith("browser_secret_")
            )
            if definite_pre_action and session.lifecycle == "ACTIVE":
                # No Playwright action ran, so the owner may safely retry this
                # same gate after correcting the transient/broker condition.
                _set_hitl_pending(session, True)
            else:
                # The operation may have clicked or submitted before its response
                # was lost. Never turn that ambiguity into an automatic replay.
                session.reason_code = "browser_resume_outcome_unknown"
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="browser_resume_outcome_unknown",
                ) from None
            raise
        except SessionUnavailable as exc:
            if session.lifecycle == "ACTIVE":
                _set_hitl_pending(session, True)
            raise _sanitized_error(exc) from None

    @app.post(
        "/internal/browser/sessions/{session_id}/capture-credentials",
        response_model=CaptureCredentialsResponse,
    )
    async def capture_credentials(
        session_id: str,
        payload: CaptureCredentialsRequest,
        auth: AuthContext = _AUTH,
    ) -> CaptureCredentialsResponse:
        """Write a reviewed credential through the broker, returning refs only."""

        caller_capability_digest = require_session_capability(auth)
        session = manager.get_if_present(session_id)
        if session is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session_not_found")
        assert_session_access(
            session_owner=session.owner,
            caller_owner=auth.owner,
            session_capability_digest=session.session_capability_digest,
            caller_capability_digest=caller_capability_digest,
        )
        caller_capability = require_session_capability_value(auth)
        try:
            with manager.lease(session_id) as leased:
                if not leased.credential_surface_ready:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="credential_surface_not_ready",
                    )
                # Idempotent when navigation already entered the boundary. This
                # second enforcement prevents a direct RPC caller from bypassing
                # revocation before an automatic reveal/capture implementation.
                await _enter_secret_capture_boundary(leased)
                recipe = _validated_recipe_snapshot(
                    payload.recipe_snapshot,
                    expected_app_slug=leased.app_slug,
                )
                store = _credential_capture_store(
                    session=leased,
                    broker=_secret_broker(),
                    grant=payload.broker_grant,
                    owner=auth.owner,
                    capability=caller_capability,
                )
                capture_kwargs: dict[str, object] = {}
                if recipe is not None:
                    capture_kwargs["recipe"] = recipe
                captured = await asyncio.wait_for(
                    _worker().auto_capture_credentials(
                        leased.current_page_id,
                        leased.app_slug,
                        store,
                        **capture_kwargs,
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
        except HTTPException:
            raise
        except ProviderOperationError as exc:
            broker_unavailable = exc.reason_code in {
                "browser_secret_broker_unavailable",
                "browser_secret_broker_unreachable",
            }
            raise HTTPException(
                status_code=(
                    status.HTTP_503_SERVICE_UNAVAILABLE
                    if broker_unavailable
                    else status.HTTP_502_BAD_GATEWAY
                ),
                detail=exc.reason_code,
            ) from None
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
        caller_capability_digest = require_session_capability(auth)
        session = manager.get_if_present(session_id)
        if session is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session_not_found")
        assert_session_access(
            session_owner=session.owner,
            caller_owner=auth.owner,
            session_capability_digest=session.session_capability_digest,
            caller_capability_digest=caller_capability_digest,
        )
        if not session.live_view_allowed:
            session.screenshot_available = False
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="live_view_revoked",
            )
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
        """Issue a short-lived view/control grant for an active session.

        A running autonomous session gets ``view``. A session paused at HITL gets
        ``control``. The capability is signed into the token and the WebSocket
        relay independently chooses a server-side view-only/control VNC listener.
        """

        caller_capability_digest = require_session_capability(auth)
        session = manager.get_if_present(session_id)
        if session is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session_not_found")
        assert_session_access(
            session_owner=session.owner,
            caller_owner=auth.owner,
            session_capability_digest=session.session_capability_digest,
            caller_capability_digest=caller_capability_digest,
        )
        if (
            not resolved.interactive_hitl_enabled
            or not session.interactive_ready
            or not session.live_view_allowed
        ):
            return LiveViewGrant(
                mode="screenshot",
                url=None,
                session_id=session_id,
                view_allowed=False,
                control_allowed=False,
            )
        from ops.browser.live_view import (
            LiveViewAudit,
            build_interactive_url,
            issue_live_view_token,
        )

        secret = resolved.service_token.get_secret_value() if resolved.service_token else ""
        access: Literal["view", "control"] = "control" if session.hitl_pending else "view"
        token, expires_at = issue_live_view_token(
            session_id=session_id,
            owner=auth.owner,
            secret=secret,
            access=access,
            hitl_generation=session.hitl_generation,
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
            view_allowed=True,
            control_allowed=access == "control",
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
            access = authorize_live_view(
                token=token,
                session_id=session_id,
                caller_owner=owner,
                secret=secret,
                session_owner=session.owner if session else None,
                session_lifecycle=session.lifecycle if session else None,
                interactive_enabled=resolved.interactive_hitl_enabled,
                view_allowed=(
                    session.interactive_ready and session.live_view_allowed if session else False
                ),
                hitl_pending=session.hitl_pending if session else False,
                hitl_generation=session.hitl_generation if session else 0,
            )
        except LiveViewDenied as exc:
            # Refuse BEFORE accepting: an unauthorized client never gets a socket.
            LOGGER.warning("live view denied session=%s reason=%s", log_session_id, exc.reason_code)
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason=exc.reason_code)
            return

        # Authorization proved WHO may attach; the leased display decides WHERE the
        # relay may connect. Fail closed when the session holds no display rather
        # than falling back to a shared or default port.
        slot = session.display_slot if session else None
        if slot is None:
            LOGGER.warning(
                "live view denied session=%s reason=%s", log_session_id, "display_slot_missing"
            )
            await websocket.close(
                code=status.WS_1008_POLICY_VIOLATION, reason="display_slot_missing"
            )
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

            # The target is derived from the session's OWN leased display and the
            # SIGNED capability, never from caller input. View grants terminate at
            # an x11vnc process launched with -viewonly, so client-side changes to
            # noVNC cannot inject input. The slot binding also means a grant for
            # session A can only ever reach A's private desktop.
            target_port = slot.vnc_port if access == "control" else slot.view_vnc_port
            reason = await relay_websocket_to_vnc(
                receive=_receive,
                send=websocket.send_bytes,
                target=VncTarget(port=target_port),
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
        caller_capability_digest = require_session_capability(auth)
        session = manager.get_if_present(session_id)
        if session is None:
            # Idempotent delete: already gone is success.
            return JSONResponse({"reason_code": "session_not_found"})
        assert_session_access(
            session_owner=session.owner,
            caller_owner=auth.owner,
            session_capability_digest=session.session_capability_digest,
            caller_capability_digest=caller_capability_digest,
        )
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
        # A headed probe uses the same display stack as real sessions. Never
        # introduce a probe window onto an operator's active private desktop;
        # retain the last verified cache until capacity is idle.
        if not force and manager.capacity_in_use:
            return
        if not force and not cache.is_stale():
            return
        async with cache.lock:
            if not force and not cache.is_stale():
                return
            try:
                from ops.browser.readiness import probe_playwright

                readiness = await probe_playwright(timeout_seconds=25.0)
                interactive_ready = _interactive_stack_ready(display_pool)
                launch_ok = readiness.ok and interactive_ready
                cache.update(
                    chromium_installed=readiness.reason_code != "playwright_not_installed",
                    context_launch_ok=launch_ok,
                    reason_code=(
                        "chromium_launch_verified"
                        if launch_ok
                        else "interactive_display_stack_unavailable"
                        if readiness.ok
                        else readiness.reason_code
                    ),
                    detail=(
                        "An interactive display listener is unavailable."
                        if readiness.ok and not interactive_ready
                        else readiness.detail[:200]
                        if not readiness.ok
                        else ""
                    ),
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
        """Fast cache-only provider health; unauthenticated but secret-free.

        Reports only capability state (never a session id, URL, or token) so a
        caller can inspect it without holding the RPC token. This endpoint never
        acquires the readiness lock or launches Chromium; ``/internal/ready`` is
        the sole HTTP refresh owner.
        """

        del request
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


def _validated_recipe_snapshot(
    payload: dict[str, object] | None,
    *,
    expected_app_slug: str,
) -> Any:
    """Validate a caller-bound recipe without consulting this service's catalog."""

    if payload is None:
        return None
    from ops.recipes.app_recipes import AppRecipe

    try:
        recipe = AppRecipe.model_validate(payload)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="invalid_recipe_snapshot",
        ) from None
    if recipe.app_slug != expected_app_slug or recipe.route_kind != "playwright":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="recipe_app_mismatch",
        )
    return recipe


async def _drive(
    worker: Any,
    session: ManagedSession,
    research_payload: dict[str, object],
    recipe_payload: dict[str, object] | None,
    credential_refs: dict[str, str],
    secret_grants: dict[str, str],
    settings: BrowserServiceSettings,
    secret_broker_factory: Callable[[], BrowserSecretBrokerClient],
    broker_owner: str,
    broker_capability: str,
    *,
    resume_signal: str | None,
    account_creation_requested: bool = False,
    signup_fields: dict[str, str] | None = None,
    credential_creation_policy: str = "reuse_only",
) -> ObservationResponse:
    """Run one navigate/resume operation and project a sanitized observation.

    The control-plane RPC carries references only. This process redeems each
    exact transient reference through the private broker immediately before use;
    the value is never returned on the control RPC or persisted by this service.
    """

    from ops.browser.worker import BrowserSessionContext
    from ops.core.models import OperationalResearch

    try:
        research = OperationalResearch.model_validate(research_payload)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="invalid_research_payload"
        ) from None
    recipe = _validated_recipe_snapshot(
        recipe_payload,
        expected_app_slug=session.app_slug,
    )
    if research.app_slug != session.app_slug:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="research_app_mismatch",
        )
    # Confinement is enforced HERE for a session that carries a run allow-list.
    # Every URL this payload could turn into a top-level destination is checked
    # before the worker is driven, so a caller that skipped its own check (or was
    # steered by page content) still cannot leave the provider's domain.
    run_allowed_hosts = session.allowed_hosts
    if run_allowed_hosts is not None:
        denial = first_denied_navigation(navigation_target_urls(research), run_allowed_hosts)
        if denial is not None:
            session.reason_code = denial.reason_code
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=denial.reason_code)

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
            session=session,
            credential_refs=credential_refs,
            secret_grants=secret_grants,
            broker=(secret_broker_factory() if credential_refs else None),
            owner=broker_owner,
            capability=broker_capability,
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
            if recipe is not None:
                navigate_kwargs["recipe"] = recipe
            if account_creation_requested:
                navigate_kwargs["account_creation_requested"] = True
                navigate_kwargs["signup_fields"] = signup_fields or {}
            observation = await asyncio.wait_for(
                worker.navigate_onboarding(context, research, **navigate_kwargs),
                timeout=settings.operation_timeout_seconds,
            )
        else:
            resume_kwargs: dict[str, object] = {
                "sensitive_data": sensitive,
                "credential_creation_policy": credential_creation_policy,
            }
            if recipe is not None:
                resume_kwargs["recipe"] = recipe
            if account_creation_requested:
                resume_kwargs["account_creation_requested"] = True
                resume_kwargs["signup_fields"] = signup_fields or {}
            observation = await asyncio.wait_for(
                worker.resume_after_hitl(context, resume_signal, research, **resume_kwargs),
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

    # Where the browser actually ENDED UP, not only where it was asked to go: a
    # provider redirect can drift off the run's allow-list without any navigation
    # being requested. Refuse rather than report the page, and do not persist
    # authenticated state for an off-allow-list surface. A failed observation is
    # exempt because it carries a placeholder URL, not a real destination.
    if run_allowed_hosts is not None and observation.status != "failed":
        drift = session.authorize_navigation(observation.current_url)
        if not drift.allowed:
            session.reason_code = drift.reason_code
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=drift.reason_code)

    _set_hitl_pending(session, observation.status == "human_action_required")
    session.current_url_path = _url_path(observation.current_url)
    session.touch()

    # Persist encrypted state at reviewed authentication checkpoints, not just the
    # final credential page. An email-verification or account-selection handoff
    # often happens after the vendor has already issued short-lived signup/session
    # cookies; retaining them is what lets an API restart continue the same flow.
    # CAPTCHA and generic human gates are excluded because they do not prove any
    # authentication progress.
    if session.storage_binding is not None:
        store = _state_store(settings)
        authenticated_checkpoint = bool(
            observation.status == "credential_page_ready"
            or (
                observation.status == "human_action_required"
                and observation.human_action_type in {"email_otp", "account_selection"}
            )
        )
        if authenticated_checkpoint:
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


def _credential_capture_store(
    *,
    session: ManagedSession,
    broker: BrowserSecretBrokerClient,
    grant: str,
    owner: str,
    capability: str,
) -> BrokerCaptureStore:
    """Return a write-only broker adapter bound to one leased browser session."""

    return BrokerCaptureStore(
        broker=broker,
        grant=grant,
        app_slug=session.app_slug,
        scope_id=session.secret_scope,
        session_id=session.session_id,
        owner=owner,
        capability=capability,
    )


def _resolve_credential_refs(
    *,
    session: ManagedSession,
    credential_refs: dict[str, str],
    secret_grants: dict[str, str],
    broker: BrowserSecretBrokerClient | None,
    owner: str,
    capability: str,
) -> dict[str, str]:
    """Consume exact ONE-TIME references through the API-owned broker.

    The browser process has no vault database or encryption key.  The only raw
    value it can receive is the transient value whose app/kind/scope all match
    this session; the API atomically deletes that row during the handoff.
    """

    if not credential_refs:
        if secret_grants:
            raise ProviderOperationError(
                capability="browser secret broker",
                reason_code="browser_secret_grant_invalid",
            )
        return {}
    if set(secret_grants) != set(credential_refs):
        raise ProviderOperationError(
            capability="browser secret broker",
            reason_code="browser_secret_grant_invalid",
        )
    if broker is None:
        raise ProviderOperationError(
            capability="browser secret broker",
            reason_code="browser_secret_broker_unavailable",
        )
    resolved: dict[str, str] = {}
    for field_name, reference in credential_refs.items():
        if not isinstance(reference, str) or not reference.startswith("vault://"):
            raise ProviderOperationError(
                capability="browser secret broker",
                reason_code="browser_secret_reference_invalid",
            )
        expected_kind = f"browser_login_{field_name}"
        # Every advertised reference is part of one exact handoff. Continuing
        # after one consume fails could type a partial login and turn a definite
        # pre-action broker failure into an ambiguous vendor-side effect. Surface
        # the typed error instead; resume restores HITL and canonical retry can
        # mint a fresh run-scoped transient from its encrypted stage.
        value = broker.consume(
            grant=secret_grants[field_name],
            reference=reference,
            app_slug=session.app_slug,
            kind=expected_kind,
            scope_id=session.secret_scope,
            session_id=session.session_id,
            owner=owner,
            capability=capability,
        )
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
