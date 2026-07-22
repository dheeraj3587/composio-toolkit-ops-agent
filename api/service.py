"""Injectable API service and Phase 0/1 adapter over the existing local ledger."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Protocol

from starlette.concurrency import run_in_threadpool

from api.models import (
    ActionReceipt,
    CreateRunRequest,
    HealthCheck,
    HealthResponse,
    PhaseState,
    RunDetailResponse,
    RunListResponse,
    RunOutputResponse,
    RunSummary,
    SecurityState,
    SnapshotHealth,
    TimelineEvent,
    TimelineResponse,
)
from ops.config import load_settings
from ops.models import CompanyProfile, OperationalResearch, OperationsRequest
from ops.run_service import RunService as CoreRunService


class RunNotFoundError(LookupError):
    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        super().__init__("run was not found")


class PhaseUnavailableError(RuntimeError):
    def __init__(self, *, run_id: str, action: str, available_in: tuple[str, ...]) -> None:
        self.run_id = run_id
        self.action = action
        self.available_in = available_in
        super().__init__("action is unavailable in the current implementation phase")


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

    async def list_runs(self, *, limit: int, offset: int) -> RunListResponse: ...

    async def get_run(self, run_id: str) -> RunDetailResponse: ...

    async def get_timeline(self, run_id: str) -> TimelineResponse: ...

    async def resume(self, run_id: str) -> ActionReceipt: ...

    async def poll_email(self, run_id: str) -> ActionReceipt: ...

    async def get_output(self, run_id: str) -> RunOutputResponse: ...

    async def health(self) -> HealthResponse: ...


_EVENT_SUMMARIES = {
    "dry_run_created": "Local dry-run ledger entry created.",
    "p1_snapshot_loaded": "Verified P1 research loaded.",
    "p1_snapshot_not_found": "App was not found in the verified P1 snapshot.",
    "operational_research_built": "Provider-agnostic operational research built.",
    "route_pending": "Access route remains unknown; one bounded enrichment probe is available.",
    "route_selected": "Access route selected.",
    "hitl_requested": "Human action requested.",
    "hitl_resumed": "Human action completed; run resumed.",
    "outreach_sent": "Provider outreach sent.",
    "reply_received": "Provider reply received and sanitized.",
    "credential_stored": "Credential material stored behind a vault reference.",
    "credential_validated": "Credential validation completed.",
    "completed": "Run completed.",
}


class LocalRunService:
    """Leak-resistant HTTP adapter over the Phase 2 application service."""

    def __init__(
        self,
        db_path: str | Path | None = None,
        *,
        core_service: CoreRunService | None = None,
    ) -> None:
        resolved_path = Path(db_path) if db_path is not None else load_settings().ops_db_path
        self._service = core_service or CoreRunService.from_paths(db_path=resolved_path)
        self._started = False

    async def startup(self) -> None:
        await run_in_threadpool(self._service.initialize)
        self._started = True

    async def shutdown(self) -> None:
        self._started = False

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
            execution_mode="local_dry_run",
            external_actions=False,
        )

    @staticmethod
    def _phases(research: OperationalResearch | None) -> list[PhaseState]:
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
                    "The app is absent from the verified P1 snapshot. A bounded enrichment "
                    "probe remains pending; no external provider was called."
                ),
                available=False,
            )
        )
        return [
            research_phase,
            PhaseState(
                key="browser",
                name="Browser",
                phase="5/6",
                status="unavailable",
                detail="Browser onboarding and deterministic credential capture are not enabled.",
                available=False,
            ),
            PhaseState(
                key="hitl",
                name="HITL",
                phase="3",
                status="unavailable",
                detail="Durable human-in-the-loop resume is not enabled.",
                available=False,
            ),
            PhaseState(
                key="email",
                name="Email",
                phase="4",
                status="unavailable",
                detail="Provider email operations are not enabled.",
                available=False,
            ),
            PhaseState(
                key="output",
                name="Output",
                phase="3+",
                status="unavailable",
                detail="No IntegratorBundle is available for Phase 2 runs.",
                available=False,
            ),
        ]

    def _detail(self, summary: RunSummary) -> RunDetailResponse:
        research = self._service.get_research(summary.run_id)
        owner_only = self._storage_permissions_are_owner_only()
        return RunDetailResponse(
            run=summary,
            research=research,
            phases=self._phases(research),
            security=SecurityState(
                owner_only_storage=("verified_owner_only" if owner_only else "verification_failed"),
                notes=[
                    "API responses exclude provider sessions and raw audit payloads.",
                    "The secret vault is not initialized or exposed by this API.",
                ],
            ),
        )

    def _create_sync(
        self,
        operation: OperationsRequest,
        idempotency_key: str | None,
    ) -> RunDetailResponse:
        record = self._service.create_run(operation, idempotency_key=idempotency_key)
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
        return await run_in_threadpool(self._create_sync, operation, idempotency_key)

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
        raise PhaseUnavailableError(run_id=run_id, action="resume", available_in=("phase_3",))

    async def poll_email(self, run_id: str) -> ActionReceipt:
        await self.get_run(run_id)
        raise PhaseUnavailableError(run_id=run_id, action="poll_email", available_in=("phase_4",))

    async def get_output(self, run_id: str) -> RunOutputResponse:
        await self.get_run(run_id)
        raise PhaseUnavailableError(
            run_id=run_id,
            action="output",
            available_in=("phase_3_plus",),
        )

    async def health(self) -> HealthResponse:
        self._require_started()
        return await run_in_threadpool(self._health_sync)
