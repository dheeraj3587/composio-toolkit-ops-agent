"""Injectable API service and Phase 0/1 adapter over the existing local ledger."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Literal, Protocol

from starlette.concurrency import run_in_threadpool

from api.models import (
    ActionReceipt,
    AppResearchResponse,
    AppSearchResponse,
    AppSummary,
    CreateRunRequest,
    CredentialSubmissionRequest,
    HealthCheck,
    HealthResponse,
    PhaseState,
    ProviderState,
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
from ops.config import Settings, load_settings
from ops.models import CompanyProfile, OperationalResearch, OperationsRequest
from ops.run_service import CredentialSubmissionError
from ops.run_service import RunService as CoreRunService


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

    async def resume(self, run_id: str) -> ActionReceipt: ...

    async def poll_email(self, run_id: str) -> ActionReceipt: ...

    async def get_output(self, run_id: str) -> RunOutputResponse: ...

    async def retry(self, run_id: str, capability: str) -> ActionReceipt: ...

    async def search_apps(self, query: str) -> AppSearchResponse: ...

    async def get_app_research(self, app_slug: str) -> AppResearchResponse: ...

    async def health(self) -> HealthResponse: ...


_EVENT_SUMMARIES = {
    "dry_run_created": "Local dry-run ledger entry created.",
    "p1_snapshot_loaded": "Verified P1 research loaded.",
    "p1_snapshot_not_found": "App was not found in the verified P1 snapshot.",
    "operational_research_built": "Provider-agnostic operational research built.",
    "route_pending": "Access route remains unknown; one bounded enrichment probe is available.",
    "route_selected": "Access route selected.",
    "composio_capability_evaluated": "Composio toolkit capability evaluated.",
    "browser_session_started": "Controlled browser session started.",
    "browser_navigation_completed": "Browser navigation to the official setup page completed.",
    "credential_page_ready": "Official credential/developer setup page reached.",
    "browser_hitl_required": "Human action required in the live browser.",
    "hitl_requested": "Human action requested.",
    "hitl_resumed": "Human action completed; run resumed.",
    "outreach_sent": "Provider outreach sent.",
    "reply_received": "Provider reply received and sanitized.",
    "credential_stored": "Credential material stored behind a vault reference.",
    "credential_validated": "Credential validation completed.",
    "credential_capture_started": "Deterministic credential capture started.",
    "credentials_stored": "Captured credentials stored behind vault references.",
    "credential_validation_started": "Read-only credential validation started.",
    "credentials_validated": "Credential validation completed.",
    "integrator_bundle_generated": "Reference-only IntegratorBundle generated.",
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
                "browser_use",
                configured=settings.browser_use_api_key is not None,
                enabled=live_browser_enabled,
                detail=(
                    "Live browser execution is policy-disabled."
                    if not live_browser_enabled
                    else "Browser configuration is present but has not been verified."
                ),
            ),
        ]

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
        has_browser_configuration = bool(
            self._settings.browser_use_api_key is not None
            and getattr(self._settings, "allow_live_browser", False)
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
                detail=(
                    "Browser Use v3 agent navigation fails closed because the installed SDK cannot "
                    "prove the mandatory domain allowlist. Trusted adapter-owned Playwright capture "
                    "remains a separate deterministic boundary."
                    if has_browser_configuration
                    else "A Browser Use key and ALLOW_LIVE_BROWSER policy opt-in are required."
                ),
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

    def _detail(self, summary: RunSummary) -> RunDetailResponse:
        research = self._service.get_research(summary.run_id)
        record = self._service.storage.get_run(summary.run_id)
        if record is None:  # pragma: no cover - summary came from the same record
            raise RunNotFoundError(summary.run_id)
        owner_only = self._storage_permissions_are_owner_only()
        route_reason_code = record.get("route_reason_code")
        route_explanation = record.get("route_explanation")
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
            hitl_request=None,
        )

    def _create_sync(
        self,
        operation: OperationsRequest,
        idempotency_key: str | None,
        execution_mode: Literal["plan_only", "execute_when_configured"],
    ) -> RunDetailResponse:
        record = self._service.create_run(
            operation,
            idempotency_key=idempotency_key,
            execution_mode=execution_mode,
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
            dry_run=True,
            outreach_recipient_override=request.outreach_recipient_override,
        )
        return await run_in_threadpool(
            self._create_sync,
            operation,
            idempotency_key,
            request.execution_mode,
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

    async def resume(self, run_id: str) -> ActionReceipt:
        await self.get_run(run_id)
        if self._settings.langgraph_aes_key is None:
            raise PhaseUnavailableError(
                run_id=run_id,
                action="resume",
                available_in=("phase_3",),
                error="configuration_required",
            )
        raise PhaseUnavailableError(run_id=run_id, action="resume", available_in=("hitl",))

    async def poll_email(self, run_id: str) -> ActionReceipt:
        await self.get_run(run_id)
        if not (
            self._settings.composio_api_key
            and self._settings.composio_gmail_connected_account_id
            and self._settings.allow_live_vendor_email
        ):
            raise PhaseUnavailableError(
                run_id=run_id,
                action="poll_email",
                available_in=("phase_4",),
                error="configuration_required",
            )
        raise PhaseUnavailableError(run_id=run_id, action="poll_email", available_in=("email",))

    async def retry(self, run_id: str, capability: str) -> ActionReceipt:
        await self.get_run(run_id)
        requirements = {
            "research": bool(
                self._settings.perplexity_api_key and self._settings.google_genai_api_key
            ),
            "browser": bool(
                self._settings.browser_use_api_key
                and getattr(self._settings, "allow_live_browser", False)
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

    async def health(self) -> HealthResponse:
        self._require_started()
        return await run_in_threadpool(self._health_sync)
