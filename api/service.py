"""Injectable API service and Phase 0/1 adapter over the existing local ledger."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Literal, Protocol

from pydantic import SecretStr
from starlette.concurrency import run_in_threadpool

from api.browser_ui import project_browser_ui, session_lost_recorded
from api.models import (
    ActionReceipt,
    AppCatalogResponse,
    AppResearchResponse,
    AppSearchResponse,
    AppSummary,
    BrowserLoginInput,
    BrowserUiState,
    CreateRunRequest,
    CredentialSubmissionRequest,
    HealthCheck,
    HealthResponse,
    HitlRequestView,
    LiveViewResponse,
    PhaseState,
    ProviderState,
    RevealCredentialsResponse,
    RouteDecisionView,
    RunDetailResponse,
    RunListResponse,
    RunOutputResponse,
    RunSummary,
    SecurityState,
    SnapshotHealth,
    TimelineEvent,
    TimelineResponse,
)
from ops.browser_readiness import browser_configuration_state
from ops.config import Settings, load_settings
from ops.models import CompanyProfile, OperationalResearch, OperationsRequest
from ops.run_service import CredentialSubmissionError
from ops.run_service import RunService as CoreRunService
from ops.state import BrowserProvider


class RunNotFoundError(LookupError):
    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        super().__init__("run was not found")


class AppNotFoundError(LookupError):
    def __init__(self, app_slug: str) -> None:
        self.app_slug = app_slug
        super().__init__("app was not found")


class PhaseUnavailableError(RuntimeError):
    def __init__(
        self,
        *,
        run_id: str,
        action: str,
        available_in: tuple[str, ...],
        error: str = "phase_unavailable",
        message: str = "Action is unavailable in the current runtime configuration.",
    ) -> None:
        self.run_id = run_id
        self.action = action
        self.available_in = available_in
        self.error = error
        self.safe_message = message
        super().__init__(message)


class RunService(Protocol):
    """Stable orchestration boundary implemented by local and future Phase 2 services."""

    async def startup(self) -> None: ...

    async def shutdown(self) -> None: ...

    async def create_run(
        self,
        request: CreateRunRequest,
        *,
        idempotency_key: str | None = None,
    ) -> RunDetailResponse: ...

    async def submit_credentials(
        self,
        run_id: str,
        request: CredentialSubmissionRequest,
    ) -> RunDetailResponse: ...

    async def list_runs(self, *, limit: int, offset: int) -> RunListResponse: ...

    async def get_run(self, run_id: str) -> RunDetailResponse: ...

    async def get_timeline(self, run_id: str) -> TimelineResponse: ...

    async def resume(
        self,
        run_id: str,
        *,
        browser_login: BrowserLoginInput | None = None,
        signal: str = "completed",
    ) -> ActionReceipt: ...

    async def get_live_view(self, run_id: str) -> LiveViewResponse: ...

    async def get_live_screenshot(self, run_id: str) -> tuple[bytes, str]: ...

    async def poll_email(self, run_id: str) -> ActionReceipt: ...

    async def get_output(self, run_id: str) -> RunOutputResponse: ...

    async def reveal_credentials(self, run_id: str) -> RevealCredentialsResponse: ...

    async def retry(self, run_id: str, capability: str) -> ActionReceipt: ...

    async def search_apps(self, query: str) -> AppSearchResponse: ...

    async def list_apps(self) -> AppCatalogResponse: ...

    async def get_app_research(self, app_slug: str) -> AppResearchResponse: ...

    async def health(self) -> HealthResponse: ...


_EVENT_SUMMARIES = {
    "dry_run_created": "Local dry-run ledger entry created.",
    "run_created": "Executable run ledger entry created.",
    "operational_research_started": "Deterministic operational research started.",
    "p1_snapshot_loaded": "Verified P1 research loaded.",
    "p1_snapshot_not_found": "App was not found in the verified P1 snapshot.",
    "operational_research_built": "Provider-agnostic operational research built.",
    "reviewed_operational_baseline_applied": "Reviewed versioned provider baseline applied.",
    "route_pending": "Access route remains unknown; one bounded enrichment probe is available.",
    "route_selected": "Access route selected.",
    "composio_capability_evaluated": "Composio toolkit capability evaluated.",
    "browser_session_started": "Controlled browser session started.",
    "browser_navigation_completed": "Browser navigation to the official setup page completed.",
    "credential_page_ready": "Official credential/developer setup page reached.",
    "browser_hitl_required": "Human action required in the live browser.",
    "hitl_requested": "Human action requested.",
    "hitl_resumed": "Human action completed; run resumed.",
    "hitl_cancelled": "Human action cancelled; run blocked and browser released.",
    "outreach_sent": "Provider outreach sent.",
    "reply_received": "Provider reply received and sanitized.",
    "credential_stored": "Credential material stored behind a vault reference.",
    "credential_validated": "Credential validation completed.",
    "credential_capture_started": "Deterministic credential capture started.",
    "credentials_stored": "Captured credentials stored behind vault references.",
    "credential_validation_started": "Read-only credential validation started.",
    "credentials_validated": "Credential validation completed.",
    "integrator_bundle_generated": "Reference-only IntegratorBundle generated.",
    "credentials_ready": "Validated credential references are ready.",
    "run_completed": "Run completed.",
    "completed": "Run completed.",
}


class LocalRunService:
    """Leak-resistant HTTP adapter over the Phase 2 application service."""

    def __init__(
        self,
        db_path: str | Path | None = None,
        *,
        core_service: CoreRunService | None = None,
        settings: Settings | None = None,
    ) -> None:
        self._settings = settings or load_settings()
        resolved_path = Path(db_path) if db_path is not None else self._settings.ops_db_path
        self._service = core_service or CoreRunService.from_paths(
            db_path=resolved_path,
            settings=self._settings,
        )
        self._started = False

    async def startup(self) -> None:
        await run_in_threadpool(self._service.startup)
        self._started = True

    async def shutdown(self) -> None:
        self._started = False
        await run_in_threadpool(self._service.shutdown)

    def _require_started(self) -> None:
        if not self._started:
            raise RuntimeError("API service lifespan has not started")

    @staticmethod
    def _summary(record: dict[str, object]) -> RunSummary:
        return RunSummary(
            run_id=str(record["run_id"]),
            thread_id=str(record["thread_id"]),
            app_name=str(record["app_name"]),
            app_slug=str(record["app_slug"]),
            status=record["status"],  # type: ignore[arg-type]
            access_route=record.get("access_route"),  # type: ignore[arg-type]
            created_at=str(record["created_at"]),
            updated_at=str(record["updated_at"]),
            execution_mode=record.get("execution_mode", "plan_only"),  # type: ignore[arg-type]
            browser_provider=record.get("browser_provider", "browser_use"),  # type: ignore[arg-type]
            credential_creation_policy=record.get("credential_creation_policy", "reuse_only"),  # type: ignore[arg-type]
            external_actions=bool(record.get("external_actions", False)),
        )

    def _provider_states(self) -> list[ProviderState]:
        settings = self._settings

        def state(
            provider: str,
            *,
            configured: bool,
            enabled: bool = True,
            detail: str,
        ) -> ProviderState:
            if not enabled:
                status = "disabled"
            elif configured:
                status = "configured_not_verified"
            else:
                status = "not_configured"
            return ProviderState(provider=provider, status=status, detail=detail)  # type: ignore[arg-type]

        live_browser_enabled = bool(getattr(settings, "allow_live_browser", False))
        gmail_configured = bool(
            settings.composio_api_key is not None and settings.composio_gmail_connected_account_id
        )
        return [
            state(
                "langgraph",
                configured=settings.langgraph_aes_key is not None,
                detail="Encrypted workflow checkpoints require a dedicated AES key.",
            ),
            state(
                "vault",
                configured=settings.secret_vault_key is not None,
                detail="The credential vault requires a separate Fernet key.",
            ),
            state(
                "perplexity",
                configured=settings.perplexity_api_key is not None,
                detail="Search is used only for bounded official-document discovery.",
            ),
            state(
                "gemini",
                configured=settings.google_genai_api_key is not None,
                detail="Structured extraction runs only against fetched official evidence.",
            ),
            state(
                "composio",
                configured=gmail_configured,
                enabled=settings.allow_live_vendor_email,
                detail=(
                    "Live Gmail is policy-disabled."
                    if not settings.allow_live_vendor_email
                    else "Gmail configuration has not been verified against the pinned schema."
                ),
            ),
            state(
                "playwright",
                configured=browser_configuration_state(settings, "playwright"),
                enabled=live_browser_enabled,
                detail=self._browser_provider_detail(
                    provider="playwright",
                    settings=settings,
                    live_enabled=live_browser_enabled,
                ),
            ),
            state(
                "browser_use",
                configured=browser_configuration_state(settings, "browser_use"),
                enabled=live_browser_enabled,
                detail=self._browser_provider_detail(
                    provider="browser_use",
                    settings=settings,
                    live_enabled=live_browser_enabled,
                ),
            ),
        ]

    @staticmethod
    def _browser_provider_detail(*, provider: str, settings: Settings, live_enabled: bool) -> str:
        """Provider health detail. Never launches a browser from the API path."""

        if not live_enabled:
            return "Live browser execution is policy-disabled."
        if provider != "playwright":
            if settings.browser_use_api_key is None:
                return "Browser Use requires BROWSER_USE_API_KEY."
            return "Browser configuration is present but has not been verified."
        if getattr(settings, "playwright_in_process_sandbox", False):
            return (
                "In-process Playwright sandbox is enabled (tests and local debugging "
                "only); Chromium runs inside this process rather than the browser service."
            )
        if not settings.browser_service_url or settings.browser_service_token is None:
            return (
                "The Playwright provider requires BROWSER_SERVICE_URL and "
                "BROWSER_SERVICE_TOKEN, or the explicit in-process sandbox flag."
            )
        return (
            "Chromium runs in the isolated browser service; its readiness is reported "
            "by that service's own cached probe rather than by this image."
        )

    @staticmethod
    def _browser_phase_detail(*, provider: str, configured: bool) -> str:
        """Describe the SELECTED browser provider's state in its own terms."""

        if provider == "playwright":
            if not configured:
                return (
                    "The self-hosted browser harness requires the ALLOW_LIVE_BROWSER policy "
                    "opt-in. No Browser Use key is needed for this provider."
                )
            return (
                "The self-hosted harness enforces the host allowlist in-process via request "
                "interception, and Chromium runs in the separate browser service so an API "
                "restart does not end a live session. Readiness is proven by that service's "
                "own health probe rather than by this image."
            )
        if not configured:
            return "A Browser Use key and ALLOW_LIVE_BROWSER policy opt-in are required."
        return (
            "Browser Use v3 agent navigation fails closed because the installed SDK cannot "
            "prove the mandatory domain allowlist. Trusted adapter-owned Playwright capture "
            "remains a separate deterministic boundary."
        )

    def _phases(
        self,
        research: OperationalResearch | None,
        record: dict[str, object],
    ) -> list[PhaseState]:
        research_phase = (
            PhaseState(
                key="research",
                name="Research",
                phase="2",
                status="ready",
                detail="Verified P1 research and deterministic access routing are available.",
                available=True,
            )
            if research is not None
            else PhaseState(
                key="research",
                name="Research",
                phase="2",
                status="waiting",
                detail=(
                    "The app is absent from the verified P1 snapshot. One bounded enrichment "
                    "probe remains pending and requires configured discovery plus structured extraction."
                ),
                available=False,
            )
        )
        has_checkpoint_key = self._settings.langgraph_aes_key is not None
        # Provider-aware: a Playwright deployment needs no Browser Use key.
        browser_provider: BrowserProvider = (
            "playwright" if record.get("browser_provider") == "playwright" else "browser_use"
        )
        has_browser_configuration = browser_configuration_state(
            self._settings,
            browser_provider,
        )
        # The detail text must describe the SELECTED provider. Reporting Browser Use's
        # v3 allowlist limitation on a Playwright deployment would be simply false:
        # the self-hosted harness enforces the host allowlist itself via route
        # interception, which is the reason it exists.
        browser_detail = self._browser_phase_detail(
            provider=browser_provider, configured=has_browser_configuration
        )
        has_email_configuration = bool(
            self._settings.composio_api_key is not None
            and self._settings.composio_gmail_connected_account_id
            and self._settings.allow_live_vendor_email
        )
        bundle_ready = record.get("integrator_bundle") is not None
        return [
            research_phase,
            PhaseState(
                key="browser",
                name="Browser",
                phase="5/6",
                status="unavailable" if has_browser_configuration else "configuration_required",
                detail=browser_detail,
                available=False,
            ),
            PhaseState(
                key="hitl",
                name="HITL",
                phase="3",
                status="ready" if has_checkpoint_key else "configuration_required",
                detail=(
                    "Encrypted durable interrupts are available when a run requests human action."
                    if has_checkpoint_key
                    else "LANGGRAPH_AES_KEY is required for durable interrupt and resume."
                ),
                available=has_checkpoint_key,
            ),
            PhaseState(
                key="email",
                name="Email",
                phase="4",
                status="ready" if has_email_configuration else "configuration_required",
                detail=(
                    "Pinned, least-privilege Gmail execution is configured but runs only on an "
                    "explicit action."
                    if has_email_configuration
                    else "Composio Gmail account configuration and live-email policy opt-in are required."
                ),
                available=has_email_configuration,
            ),
            PhaseState(
                key="output",
                name="Output",
                phase="3+",
                status="complete" if bundle_ready else "waiting",
                detail=(
                    "A sanitized IntegratorBundle is available."
                    if bundle_ready
                    else "No IntegratorBundle exists until credential validation reaches a terminal state."
                ),
                available=bundle_ready,
            ),
        ]

    @staticmethod
    def _hitl_view(record: dict[str, object]) -> HitlRequestView | None:
        if record.get("status") != "waiting_for_hitl":
            return None
        hitl = record.get("hitl_request")
        if not isinstance(hitl, dict):
            return None
        action_type = str(hitl.get("type") or hitl.get("action_type") or "provider_verification")
        message = str(hitl.get("message") or "A human action is required in the live browser.")
        signal = str(
            hitl.get("expected_completion_signal") or "The required action has been completed."
        )
        return HitlRequestView(
            action_type=action_type,
            message=message,
            expected_completion_signal=signal,
            resumable=True,
        )

    def _browser_ui(
        self, record: dict[str, object], hitl: HitlRequestView | None
    ) -> BrowserUiState:
        """Project explicit browser permissions from backend-owned facts only."""

        run_id = str(record.get("run_id") or "")
        try:
            events = self._service.get_timeline(run_id)
        except Exception:
            # A timeline read failure must not fabricate progress: with no trusted
            # events, nothing is verified and every mutation stays disabled.
            events = []
        event_types = {str(event.get("event_type")) for event in events}
        run_status = str(record.get("status") or "")
        session_id = record.get("browser_session_id")
        session_id = session_id if isinstance(session_id, str) and session_id else None
        # Rule 8: ask the worker whether a real frame exists, and only when a live
        # session could plausibly have one.
        screenshot_present = False
        if session_id is not None and run_status in {"browser_running", "waiting_for_hitl"}:
            try:
                screenshot_present = self._service.get_browser_screenshot(run_id) is not None
            except Exception:
                screenshot_present = False
        return project_browser_ui(
            settings=self._settings,
            browser_provider=record.get("browser_provider", "browser_use"),  # type: ignore[arg-type]
            run_status=run_status,
            event_types=event_types,
            browser_session_id=session_id,
            hitl=hitl,
            screenshot_present=screenshot_present,
            session_lost=session_lost_recorded(events),
            plan_only=str(record.get("execution_mode") or "") == "local_dry_run",
        )

    def _detail(self, summary: RunSummary) -> RunDetailResponse:
        research = self._service.get_research(summary.run_id)
        record = self._service.storage.get_run(summary.run_id)
        if record is None:  # pragma: no cover - summary came from the same record
            raise RunNotFoundError(summary.run_id)
        owner_only = self._storage_permissions_are_owner_only()
        route_reason_code = record.get("route_reason_code")
        route_explanation = record.get("route_explanation")
        hitl_view = self._hitl_view(record)
        return RunDetailResponse(
            run=summary,
            research=research,
            phases=self._phases(research, record),
            security=SecurityState(
                secret_vault=(
                    "configured_not_verified"
                    if self._settings.secret_vault_key is not None
                    else "not_configured"
                ),
                owner_only_storage=("verified_owner_only" if owner_only else "verification_failed"),
                checkpoint_encryption=(
                    "ready" if self._settings.langgraph_aes_key is not None else "not_configured"
                ),
                live_vendor_email=(
                    "enabled" if self._settings.allow_live_vendor_email else "disabled"
                ),
                live_browser=(
                    "enabled"
                    if getattr(self._settings, "allow_live_browser", False)
                    else "disabled"
                ),
                external_actions=bool(record.get("external_actions", False)),
                notes=[
                    "API responses exclude provider sessions and raw audit payloads.",
                    "Vault values and provider capability URLs are never exposed by this API.",
                ],
            ),
            route_decision=(
                RouteDecisionView(
                    route=summary.access_route or "unknown",
                    reason_code=str(route_reason_code),
                    explanation=str(route_explanation),
                    is_final=summary.status != "researching",
                )
                if route_reason_code is not None and route_explanation is not None
                else None
            ),
            missing_fields=[str(item) for item in record.get("missing_fields", [])],
            provider_states=self._provider_states(),
            hitl_request=hitl_view,
            browser=self._browser_ui(record, hitl_view),
        )

    def _create_sync(
        self,
        operation: OperationsRequest,
        idempotency_key: str | None,
        execution_mode: Literal["plan_only", "execute_when_configured"],
        browser_login: Mapping[str, SecretStr] | None = None,
    ) -> RunDetailResponse:
        record = self._service.create_run(
            operation,
            idempotency_key=idempotency_key,
            execution_mode=execution_mode,
            browser_login=browser_login,
        )
        return self._detail(self._summary(record))

    def _list_sync(self, *, limit: int, offset: int) -> RunListResponse:
        records, total = self._service.list_runs(limit=limit, offset=offset)
        items = [self._summary(record) for record in records]
        return RunListResponse(items=items, total=total, limit=limit, offset=offset)

    def _get_sync(self, run_id: str) -> RunDetailResponse:
        record = self._service.get_run(run_id)
        if record is None:
            raise RunNotFoundError(run_id)
        return self._detail(self._summary(record))

    def _timeline_sync(self, run_id: str) -> TimelineResponse:
        if self._service.get_run(run_id) is None:
            raise RunNotFoundError(run_id)
        raw_events = self._service.get_timeline(run_id)
        items = [
            TimelineEvent(
                event_id=int(event.get("id") or 0),
                event_type=(
                    str(event.get("event_type"))
                    if event.get("event_type") in _EVENT_SUMMARIES
                    else "run_updated"
                ),
                summary=_EVENT_SUMMARIES.get(
                    str(event.get("event_type")),
                    "Run state updated.",
                ),
                status="recorded",
                created_at=str(event.get("created_at") or "unknown"),
            )
            for event in raw_events
        ]
        return TimelineResponse(run_id=run_id, items=items)

    def _storage_permissions_are_owner_only(self) -> bool:
        database_path = self._service.storage.db_path
        try:
            parent_info = database_path.parent.lstat()
            file_info = database_path.lstat()
        except OSError:
            return False
        current_user = os.getuid()
        return bool(
            stat.S_ISDIR(parent_info.st_mode)
            and not stat.S_ISLNK(parent_info.st_mode)
            and parent_info.st_uid == current_user
            and stat.S_IMODE(parent_info.st_mode) & 0o077 == 0
            and stat.S_ISREG(file_info.st_mode)
            and not stat.S_ISLNK(file_info.st_mode)
            and file_info.st_uid == current_user
            and stat.S_IMODE(file_info.st_mode) & 0o077 == 0
        )

    def _storage_is_readable(self) -> bool:
        try:
            count = self._service.storage.count_runs()
            sample = self._service.storage.list_runs(limit=1, offset=0)
        except Exception:
            return False
        return count >= len(sample)

    def _health_sync(self) -> HealthResponse:
        storage_readable = self._storage_is_readable()
        storage_owner_only = self._storage_permissions_are_owner_only()
        try:
            provenance = self._service.snapshot_provenance()
        except Exception:
            snapshot = SnapshotHealth(verified=False)
            snapshot_verified = False
        else:
            snapshot = SnapshotHealth(
                verified=True,
                source_repository=provenance.source_repository,
                source_commit=provenance.source_commit,
                copied_at=provenance.copied_at,
                results_sha256=provenance.results_sha256,
                coverage_sha256=provenance.coverage_sha256,
            )
            snapshot_verified = True
        checks = [
            HealthCheck(
                name="operations_storage_read",
                status="pass" if storage_readable else "fail",
            ),
            HealthCheck(
                name="operations_storage_owner_only",
                status="pass" if storage_owner_only else "fail",
            ),
            HealthCheck(
                name="p1_snapshot_integrity",
                status="pass" if snapshot_verified else "fail",
            ),
        ]
        return HealthResponse(
            status="healthy" if all(check.status == "pass" for check in checks) else "degraded",
            snapshot=snapshot,
            checks=checks,
            providers=self._provider_states(),
        )

    def _search_apps_sync(self, query: str) -> AppSearchResponse:
        items = [AppSummary.model_validate(item) for item in self._service.search_apps(query)]
        return AppSearchResponse(query=query, items=items, total=len(items))

    def _list_apps_sync(self) -> AppCatalogResponse:
        items = [AppSummary.model_validate(item) for item in self._service.list_apps()]
        return AppCatalogResponse(items=items, total=len(items))

    def _get_app_research_sync(self, app_slug: str) -> AppResearchResponse:
        result = self._service.get_app_research(app_slug)
        if result is None:
            raise AppNotFoundError(app_slug)
        summary, research = result
        provenance = self._service.snapshot_provenance()
        return AppResearchResponse(
            app=AppSummary.model_validate(summary),
            research=research,
            provenance=SnapshotHealth(
                verified=True,
                source_repository=provenance.source_repository,
                source_commit=provenance.source_commit,
                copied_at=provenance.copied_at,
                results_sha256=provenance.results_sha256,
                coverage_sha256=provenance.coverage_sha256,
            ),
        )

    async def create_run(
        self,
        request: CreateRunRequest,
        *,
        idempotency_key: str | None = None,
    ) -> RunDetailResponse:
        self._require_started()
        company = CompanyProfile(
            legal_name=request.company.legal_name,
            website=request.company.website,
            work_email_ref=request.company.work_email_ref,
            use_case=request.company.use_case,
            expected_volume=request.company.expected_volume,
            callback_urls=request.company.callback_urls,
        )
        operation = OperationsRequest(
            app_name=request.app_name,
            company=company,
            requested_scope_policy=request.requested_scope_policy,
            browser_provider=request.browser_provider,
            credential_creation_policy=request.credential_creation_policy,
            dry_run=True,
            outreach_recipient_override=request.outreach_recipient_override,
        )
        # Autonomous sign-in credentials (if provided) are mapped to the Browser
        # Use secure-placeholder key names and injected at session creation. The
        # raw values never enter run state, checkpoints, the ledger, or logs.
        browser_login: dict[str, SecretStr] | None = None
        if request.browser_login is not None:
            browser_login = {
                "login_email": request.browser_login.email,
                "login_password": request.browser_login.password,
            }
        return await run_in_threadpool(
            self._create_sync,
            operation,
            idempotency_key,
            request.execution_mode,
            browser_login,
        )

    def _submit_credentials_sync(
        self,
        run_id: str,
        request: CredentialSubmissionRequest,
    ) -> RunDetailResponse:
        company = CompanyProfile(
            legal_name=request.company.legal_name,
            website=request.company.website,
            work_email_ref=request.company.work_email_ref,
            use_case=request.company.use_case,
            expected_volume=request.company.expected_volume,
            callback_urls=request.company.callback_urls,
        )
        try:
            record = self._service.submit_owner_credentials(
                run_id,
                company=company,
                fields=dict(request.credentials),
            )
        except KeyError:
            raise RunNotFoundError(run_id) from None
        return self._detail(self._summary(record))

    async def submit_credentials(
        self,
        run_id: str,
        request: CredentialSubmissionRequest,
    ) -> RunDetailResponse:
        self._require_started()
        return await run_in_threadpool(self._submit_credentials_sync, run_id, request)

    async def list_runs(self, *, limit: int, offset: int) -> RunListResponse:
        self._require_started()
        return await run_in_threadpool(self._list_sync, limit=limit, offset=offset)

    async def get_run(self, run_id: str) -> RunDetailResponse:
        self._require_started()
        return await run_in_threadpool(self._get_sync, run_id)

    async def get_timeline(self, run_id: str) -> TimelineResponse:
        self._require_started()
        return await run_in_threadpool(self._timeline_sync, run_id)

    def _resume_sync(
        self,
        run_id: str,
        *,
        browser_login: Mapping[str, SecretStr] | None = None,
        signal: str = "completed",
    ) -> ActionReceipt:
        try:
            record = self._service.resume_run(run_id, signal=signal, browser_login=browser_login)
        except KeyError:
            raise RunNotFoundError(run_id) from None
        except CredentialSubmissionError:
            # Run is not waiting for human action, or the workflow is unconfigured.
            return ActionReceipt(
                run_id=run_id,
                action="resume",
                status="no_change",
                detail="Run is not waiting for a human action.",
            )
        status = str(record.get("status"))
        logged_in = browser_login is not None
        detail = (
            (
                "Logged in autonomously with the submitted credentials; the credential page "
                "is ready."
                if logged_in
                else "Resumed on the same browser session; the credential page is ready."
            )
            if status == "browser_running"
            else "Resumed on the same browser session; another human action is required."
            if status == "waiting_for_hitl"
            else f"Run resumed (status: {status})."
        )
        return ActionReceipt(run_id=run_id, action="resume", status="accepted", detail=detail)

    async def resume(
        self,
        run_id: str,
        *,
        browser_login: BrowserLoginInput | None = None,
        signal: str = "completed",
    ) -> ActionReceipt:
        await self.get_run(run_id)
        if self._settings.langgraph_aes_key is None:
            raise PhaseUnavailableError(
                run_id=run_id,
                action="resume",
                available_in=("phase_3",),
                error="configuration_required",
            )
        # Map the owner login input onto the Browser Use secure-placeholder names.
        # SecretStr keeps values wrapped until the core service resolves them in
        # memory for the single resume call.
        login_map: dict[str, SecretStr] | None = None
        if browser_login is not None:
            login_map = {
                "login_email": browser_login.email,
                "login_password": browser_login.password,
            }
        return await run_in_threadpool(
            self._resume_sync, run_id, browser_login=login_map, signal=signal
        )

    def _live_view_sync(self, run_id: str) -> LiveViewResponse:
        record = self._service.get_run(run_id)
        if record is None:
            raise RunNotFoundError(run_id)
        provider = record.get("browser_provider", "browser_use")
        # Browser Use keeps its exact existing behavior: a signed hosted URL the
        # owner can interact with directly.
        live_url = self._service.get_browser_live_url(run_id)
        if live_url is not None:
            return LiveViewResponse(
                run_id=run_id,
                provider="browser_use",
                available=True,
                mode="hosted_url",
                live_url=live_url,
                interaction_available=True,
                reason_code="hosted_session_live",
            )
        # Interactive Playwright grants are minted only while this immutable run
        # is paused for HITL. The private URL is transient: the Next server validates
        # and converts it to the reviewed same-origin WebSocket path immediately.
        grant_getter = getattr(self._service, "get_browser_interactive_grant", None)
        grant = grant_getter(run_id) if callable(grant_getter) else None
        if provider == "playwright" and grant is not None:
            _, interactive_url, _expires_at = grant
            return LiveViewResponse(
                run_id=run_id,
                provider="playwright",
                available=True,
                mode="interactive_remote",
                interactive_url=interactive_url,
                interaction_available=True,
                reason_code="interactive_session_live",
            )
        # Self-hosted Playwright has no hosted URL; the client polls masked frames.
        # Frames are viewable but not drivable, so interaction is not advertised.
        shot = self._service.get_browser_screenshot(run_id)
        if shot is not None:
            _, captured_at = shot
            return LiveViewResponse(
                run_id=run_id,
                provider="playwright",
                available=True,
                mode="screenshot",
                screenshot_url=f"/api/runs/{run_id}/live-view/screenshot",
                captured_at=captured_at,
                interaction_available=False,
                reason_code="screenshot_frames_available",
            )
        return LiveViewResponse(
            run_id=run_id,
            # Report the configured backend truthfully even with no live session.
            provider=provider,
            available=False,
            mode="unavailable",
            interaction_available=False,
            reason_code="no_active_browser_session",
        )

    async def get_live_view(self, run_id: str) -> LiveViewResponse:
        self._require_started()
        return await run_in_threadpool(self._live_view_sync, run_id)

    def _live_screenshot_sync(self, run_id: str) -> tuple[bytes, str]:
        if self._service.get_run(run_id) is None:
            raise RunNotFoundError(run_id)
        shot = self._service.get_browser_screenshot(run_id)
        if shot is None:
            raise PhaseUnavailableError(
                run_id=run_id,
                action="live_view_screenshot",
                available_in=("phase_5",),
                error="configuration_required",
            )
        return shot

    async def get_live_screenshot(self, run_id: str) -> tuple[bytes, str]:
        """Return the newest masked PNG frame for this run's browser session."""

        self._require_started()
        return await run_in_threadpool(self._live_screenshot_sync, run_id)

    async def poll_email(self, run_id: str) -> ActionReceipt:
        await self.get_run(run_id)
        if not (
            self._settings.composio_api_key
            and self._settings.composio_gmail_connected_account_id
            and self._settings.outreach_recipient_override
        ):
            raise PhaseUnavailableError(
                run_id=run_id,
                action="poll_email",
                available_in=("phase_4",),
                error="configuration_required",
            )
        return await run_in_threadpool(self._poll_email_sync, run_id)

    def _poll_email_sync(self, run_id: str) -> ActionReceipt:
        try:
            record = self._service.poll_email(run_id)
        except KeyError:
            raise RunNotFoundError(run_id) from None
        except CredentialSubmissionError as exc:
            return ActionReceipt(
                run_id=run_id,
                action="poll_email",
                status="no_change",
                detail=f"No reply action taken ({exc.reason_code.replace('_', ' ')}).",
            )
        status = str(record.get("status"))
        reply_class = str(record.get("latest_reply_class") or "no_reply")
        detail = (
            "Provider reply received and classified as "
            f"{reply_class.replace('_', ' ')}; run status: {status.replace('_', ' ')}."
        )
        return ActionReceipt(
            run_id=run_id,
            action="poll_email",
            status="no_change" if reply_class == "no_reply" else "accepted",
            detail=detail,
        )

    async def retry(self, run_id: str, capability: str) -> ActionReceipt:
        detail = await self.get_run(run_id)
        requirements = {
            "research": bool(
                self._settings.perplexity_api_key and self._settings.google_genai_api_key
            ),
            # Provider-aware retry eligibility (no Browser Use key for Playwright).
            "browser": browser_configuration_state(
                self._settings,
                detail.run.browser_provider,
            ),
            "email": bool(
                self._settings.composio_api_key
                and self._settings.composio_gmail_connected_account_id
                and self._settings.allow_live_vendor_email
            ),
            "validation": self._settings.secret_vault_key is not None,
        }
        if not requirements.get(capability, False):
            return ActionReceipt(
                run_id=run_id,
                action="retry",
                status="configuration_required",
                detail="Required provider configuration or policy opt-in is missing.",
            )
        return ActionReceipt(
            run_id=run_id,
            action="retry",
            status="no_change",
            detail="No retryable failed operation is recorded for this run.",
        )

    async def search_apps(self, query: str) -> AppSearchResponse:
        self._require_started()
        return await run_in_threadpool(self._search_apps_sync, query)

    async def list_apps(self) -> AppCatalogResponse:
        self._require_started()
        return await run_in_threadpool(self._list_apps_sync)

    async def get_app_research(self, app_slug: str) -> AppResearchResponse:
        self._require_started()
        return await run_in_threadpool(self._get_app_research_sync, app_slug)

    async def get_output(self, run_id: str) -> RunOutputResponse:
        await self.get_run(run_id)
        output = await run_in_threadpool(self._service.get_output, run_id)
        if output:
            return RunOutputResponse(run_id=run_id, integrator_bundle=output)  # type: ignore[arg-type]
        raise PhaseUnavailableError(
            run_id=run_id,
            action="output",
            available_in=("output",),
        )

    def _reveal_credentials_sync(self, run_id: str) -> RevealCredentialsResponse:
        revealed = self._service.reveal_credentials(run_id)
        if revealed is None:
            raise RunNotFoundError(run_id)
        if not revealed:
            raise PhaseUnavailableError(
                run_id=run_id,
                action="reveal_credentials",
                available_in=("output",),
            )
        return RevealCredentialsResponse(run_id=run_id, credentials=dict(revealed))

    async def reveal_credentials(self, run_id: str) -> RevealCredentialsResponse:
        self._require_started()
        return await run_in_threadpool(self._reveal_credentials_sync, run_id)

    async def health(self) -> HealthResponse:
        self._require_started()
        return await run_in_threadpool(self._health_sync)
