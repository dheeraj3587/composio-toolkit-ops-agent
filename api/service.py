"""Injectable API boundary over the canonical run ledger and legacy reader."""

from __future__ import annotations

import os
import re
import stat
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, Protocol, cast

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
    BrowserServiceHealthView,
    BrowserUiState,
    BrowserVerificationInput,
    CreateRunRequest,
    CredentialSubmissionRequest,
    HealthCheck,
    HealthResponse,
    HitlRequestView,
    LiveViewResponse,
    ManagedConnectionResponse,
    PhaseState,
    PrimaryAction,
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
from ops.app_recipes import (
    get_app_recipe,
    get_app_recipe_for_name,
    load_app_recipe_catalog,
    recipe_to_operational_research,
)
from ops.browser_readiness import browser_configuration_state
from ops.browser_service_client import BrowserServiceClient, BrowserServiceHealth
from ops.composio_managed_auth import managed_auth_configuration_is_valid
from ops.config import Settings, load_settings
from ops.deploy_acceptance import deployment_is_accepted
from ops.gmail_worker import GmailSignupPreflight
from ops.models import AccountMode, CompanyProfile, OperationalResearch, OperationsRequest
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


@dataclass(frozen=True, slots=True)
class _CachedGmailSignupPreflight:
    result: GmailSignupPreflight
    expires_monotonic: float
    checked_at: str
    expires_at: str


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
    """Stable orchestration boundary shared by API implementations."""

    async def startup(self) -> None: ...

    async def shutdown(self) -> None: ...

    def deployment_mutations_allowed(self) -> bool: ...

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
        browser_verification: BrowserVerificationInput | None = None,
        signal: str = "completed",
    ) -> ActionReceipt: ...

    async def get_live_view(self, run_id: str) -> LiveViewResponse: ...

    async def get_live_screenshot(self, run_id: str) -> tuple[bytes, str]: ...

    async def poll_email(self, run_id: str) -> ActionReceipt: ...

    async def connect_managed(self, run_id: str) -> ManagedConnectionResponse: ...

    async def poll_managed_connection(self, run_id: str) -> ManagedConnectionResponse: ...

    async def send_gated_outreach(self, run_id: str) -> ActionReceipt: ...

    async def get_output(self, run_id: str) -> RunOutputResponse: ...

    async def retry(self, run_id: str, capability: str) -> ActionReceipt: ...

    async def search_apps(self, query: str) -> AppSearchResponse: ...

    async def list_apps(self) -> AppCatalogResponse: ...

    async def get_app_research(self, app_slug: str) -> AppResearchResponse: ...

    async def signup_readiness(self) -> ProviderState: ...

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


def _work_email_ref_for_app(app_name: str, *, app_slug: str | None = None) -> str:
    """Return a non-secret, deterministic work-email vault reference.

    Catalog slugs are preferred so punctuation-heavy display names such as
    ``Monday.com`` resolve to the exact same reference everywhere. The fallback
    is only for the conservative research-only path and remains inside the
    strict vault-reference alphabet.
    """

    resolved_slug = app_slug
    if resolved_slug is None:
        recipe = get_app_recipe_for_name(app_name) or get_app_recipe(app_name)
        resolved_slug = recipe.app_slug if recipe is not None else None
    if resolved_slug is None:
        resolved_slug = re.sub(r"[^a-z0-9]+", "-", app_name.strip().casefold()).strip("-")
    return f"vault://company/work_email/{resolved_slug or 'app'}"


class LocalRunService:
    """Leak-resistant HTTP adapter over the canonical application service."""

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
        self._gmail_preflight_lock = threading.Lock()
        self._gmail_preflight_cache: _CachedGmailSignupPreflight | None = None

    async def startup(self) -> None:
        await run_in_threadpool(self._service.startup)
        self._started = True

    async def shutdown(self) -> None:
        self._started = False
        await run_in_threadpool(self._service.shutdown)

    def deployment_mutations_allowed(self) -> bool:
        """Keep production writes inert until this exact release is accepted.

        Local and test runtimes do not enable startup automation and therefore
        need no deploy marker. Production enables it in Compose; the same exact
        revision+nonce marker that unlocks background maintenance also unlocks
        operator and browser-broker mutations. Reading the small owner-only
        marker for every write avoids a stale in-memory acceptance decision
        during rollback.
        """

        if not self._settings.ops_startup_automation_enabled:
            return True
        return deployment_is_accepted(self._settings)

    def _require_started(self) -> None:
        if not self._started:
            raise RuntimeError("API service lifespan has not started")

    @staticmethod
    def _summary(record: dict[str, object]) -> RunSummary:
        raw_attempt = record.get("attempt", 0)
        attempt = int(raw_attempt) if isinstance(raw_attempt, int | str) else 0
        stored_request = record.get("request")
        raw_account_mode = record.get("account_mode")
        if raw_account_mode is None and isinstance(stored_request, Mapping):
            raw_account_mode = stored_request.get("account_mode")
        account_mode = (
            cast(AccountMode, raw_account_mode)
            if raw_account_mode in {"existing_account", "create_account"}
            else None
        )
        return RunSummary(
            run_id=str(record["run_id"]),
            thread_id=str(record["thread_id"]),
            app_name=str(record["app_name"]),
            app_slug=str(record["app_slug"]),
            account_mode=account_mode,
            status=record["status"],  # type: ignore[arg-type]
            access_route=record.get("access_route"),  # type: ignore[arg-type]
            created_at=str(record["created_at"]),
            updated_at=str(record["updated_at"]),
            execution_mode=record.get("execution_mode", "plan_only"),  # type: ignore[arg-type]
            browser_provider=record.get("browser_provider", "browser_use"),  # type: ignore[arg-type]
            credential_creation_policy=record.get("credential_creation_policy", "reuse_only"),  # type: ignore[arg-type]
            recipe_version=(
                str(record["recipe_version"]) if record.get("recipe_version") else None
            ),
            route_kind=record.get("route_kind"),  # type: ignore[arg-type]
            readiness_tier=record.get("readiness_tier"),  # type: ignore[arg-type]
            attempt=attempt,
            phase=str(record.get("phase") or "legacy"),
            reason_code=(str(record["reason_code"]) if record.get("reason_code") else None),
            state_engine=record.get("state_engine", "legacy"),  # type: ignore[arg-type]
            external_actions=bool(record.get("external_actions", False)),
        )

    def _primary_action(self, record: Mapping[str, object], summary: RunSummary) -> PrimaryAction:
        if summary.status == "completed":
            return PrimaryAction(kind="none", enabled=False, reason_code="run_completed")
        if summary.execution_mode == "plan_only":
            return PrimaryAction(kind="none", enabled=False, reason_code="plan_only_run_read_only")
        if summary.status == "credentials_ready":
            return PrimaryAction(
                kind="none",
                enabled=False,
                reason_code="credential_stored_validation_not_reviewed",
            )
        if summary.route_kind == "managed_auth":
            managed_enabled = managed_auth_configuration_is_valid(self._settings)
            if record.get("connection_request_id"):
                return PrimaryAction(
                    kind="poll_connection",
                    enabled=managed_enabled,
                    reason_code=(
                        "managed_connection_pending"
                        if managed_enabled
                        else "composio_managed_auth_not_configured"
                    ),
                )
            return PrimaryAction(
                kind="connect_account",
                enabled=managed_enabled,
                reason_code=(
                    "managed_connection_required"
                    if managed_enabled
                    else "composio_managed_auth_not_configured"
                ),
            )
        if summary.route_kind == "playwright":
            if summary.phase in {"credential_ready", "entry_reached"}:
                owner_actions_enabled = self._settings.allow_local_credential_submission
                return PrimaryAction(
                    kind="submit_credentials",
                    enabled=owner_actions_enabled,
                    reason_code=(
                        "owner_credential_submission_disabled"
                        if not owner_actions_enabled
                        else "owner_credential_submission_required"
                        if summary.phase == "credential_ready"
                        else "owner_credential_submission_available"
                    ),
                )
            return PrimaryAction(
                kind="open_browser",
                enabled=summary.status in {"browser_running", "waiting_for_hitl"},
                reason_code=(
                    "playwright_session_live"
                    if summary.status in {"browser_running", "waiting_for_hitl"}
                    else "playwright_session_not_live"
                ),
            )
        if summary.route_kind == "gated":
            if summary.status in {"outreach_sent", "waiting_for_reply"}:
                return PrimaryAction(
                    kind="poll_reply",
                    enabled=True,
                    reason_code="outreach_reply_pending",
                )
            controlled_outreach_enabled = bool(
                self._settings.composio_gmail_api_key is not None
                and self._settings.composio_gmail_connected_account_id
                and self._settings.outreach_recipient_override
            )
            outreach_ready = summary.readiness_tier == "outreach_ready"
            return PrimaryAction(
                kind="review_outreach",
                enabled=outreach_ready and controlled_outreach_enabled,
                reason_code=(
                    "outreach_contact_review_required"
                    if not outreach_ready
                    else "controlled_outreach_not_configured"
                    if not controlled_outreach_enabled
                    else "controlled_outreach_ready"
                ),
            )
        return PrimaryAction(kind="none", enabled=False, reason_code="legacy_run_read_only")

    def _cached_gmail_preflight(
        self,
        *,
        refresh: bool,
        force: bool = False,
    ) -> _CachedGmailSignupPreflight | None:
        """Return one bounded, value-free Gmail readiness result.

        Success is cached for one minute and failure for ten seconds. The lock is
        also the single-flight boundary: concurrent health requests cannot fan
        out into multiple provider reads.
        """

        settings = self._settings
        configured = bool(
            settings.composio_gmail_api_key is not None
            and settings.composio_gmail_connected_account_id
            and settings.gmail_signup_address is not None
        )
        if not configured:
            return None
        with self._gmail_preflight_lock:
            now_monotonic = time.monotonic()
            cached = self._gmail_preflight_cache
            if not force and cached is not None and cached.expires_monotonic > now_monotonic:
                return cached
            if not refresh:
                return None
            try:
                result = self._service.gmail_signup_preflight(
                    timeout_seconds=settings.gmail_signup_preflight_timeout_seconds
                )
            except Exception:
                result = GmailSignupPreflight(
                    status="unavailable",
                    reason_code="gmail_signup_preflight_failed",
                    provider_read_attempted=False,
                )
            ttl_seconds = 60 if result.ready else 10
            checked = datetime.now(UTC)
            entry = _CachedGmailSignupPreflight(
                result=result,
                expires_monotonic=time.monotonic() + ttl_seconds,
                checked_at=checked.isoformat(),
                expires_at=(checked + timedelta(seconds=ttl_seconds)).isoformat(),
            )
            self._gmail_preflight_cache = entry
            return entry

    def _provider_states(
        self,
        *,
        gmail_preflight: _CachedGmailSignupPreflight | None = None,
        browser_health: BrowserServiceHealth | None = None,
    ) -> list[ProviderState]:
        settings = self._settings

        def state(
            provider: str,
            *,
            configured: bool,
            enabled: bool = True,
            ready: bool = False,
            detail: str,
            reason_code: str | None = None,
            checked_at: str | None = None,
            expires_at: str | None = None,
        ) -> ProviderState:
            if not enabled:
                status = "disabled"
            elif ready:
                status = "ready"
            elif configured:
                status = "configured_not_verified"
            else:
                status = "not_configured"
            return ProviderState.model_validate(
                {
                    "provider": provider,
                    "status": status,
                    "detail": detail,
                    "reason_code": reason_code,
                    "checked_at": checked_at,
                    "expires_at": expires_at,
                }
            )

        live_browser_enabled = bool(getattr(settings, "allow_live_browser", False))
        gmail_inbox_configured = bool(
            settings.composio_gmail_api_key is not None
            and settings.composio_gmail_connected_account_id
        )
        gmail_outreach_configured = bool(
            gmail_inbox_configured and settings.outreach_recipient_override
        )
        if gmail_preflight is None:
            gmail_preflight = self._cached_gmail_preflight(refresh=False)
        gmail_signup_ready = bool(
            gmail_preflight is not None
            and gmail_preflight.result.ready
            and settings.gmail_signup_address is not None
        )
        managed_configured = managed_auth_configuration_is_valid(settings)
        browser_use_enabled = bool(
            live_browser_enabled and settings.browser_use_compatibility_enabled
        )
        playwright_configured = browser_configuration_state(settings, "playwright")
        if browser_health is None:
            playwright_state = state(
                "playwright",
                configured=playwright_configured,
                enabled=live_browser_enabled,
                detail=self._browser_provider_detail(
                    provider="playwright",
                    settings=settings,
                    live_enabled=live_browser_enabled,
                ),
            )
        else:
            browser_ready = bool(
                browser_health.state in {"ready", "capacity_exhausted"}
                and browser_health.chromium_installed
                and browser_health.context_launch_ok
                and browser_health.janitor_running
            )
            playwright_state = ProviderState.model_validate(
                {
                    "provider": "playwright",
                    "status": "ready" if browser_ready else "configured_not_verified",
                    "detail": (
                        f"Cached browser service state={browser_health.state}; "
                        f"version={browser_health.version}; "
                        f"chromium_installed={str(browser_health.chromium_installed).lower()}; "
                        f"context_launch_ok={str(browser_health.context_launch_ok).lower()}; "
                        f"janitor_running={str(browser_health.janitor_running).lower()}; "
                        f"capacity={browser_health.capacity_in_use}/"
                        f"{browser_health.capacity_total}."
                    ),
                    "reason_code": browser_health.reason_code,
                }
            )
        return [
            state(
                "recipes",
                configured=True,
                ready=len(load_app_recipe_catalog().apps) == 50,
                detail="The reviewed 50-app recipe catalog passed startup validation.",
            ),
            state(
                "vault",
                configured=settings.secret_vault_key is not None,
                detail="The credential vault requires a separate Fernet key.",
            ),
            state(
                "composio_managed_auth",
                configured=managed_configured,
                detail=(
                    "Managed connection links are configured; live status is checked only on an owner action."
                    if managed_configured
                    else "Managed auth requires COMPOSIO_API_KEY and a valid public HTTPS "
                    "MANAGED_AUTH_CALLBACK_BASE_URL origin."
                ),
            ),
            state(
                "gmail",
                configured=gmail_inbox_configured,
                enabled=gmail_inbox_configured,
                ready=gmail_signup_ready,
                detail=(
                    "A bounded inbox read succeeded; Gmail signup verification is ready."
                    if gmail_signup_ready
                    else "Gmail signup inbox verification failed its latest bounded read."
                    if gmail_preflight is not None
                    else "Gmail inbox verification and controlled outreach are configured but not yet verified."
                    if gmail_outreach_configured and settings.gmail_signup_address
                    else "Gmail inbox verification is configured; new-account signup still needs GMAIL_SIGNUP_ADDRESS."
                    if gmail_inbox_configured and not settings.gmail_signup_address
                    else "Gmail inbox verification is configured; outreach remains disabled."
                    if gmail_inbox_configured
                    else "Gmail verification requires Composio and a connected Gmail account."
                ),
                reason_code=(
                    gmail_preflight.result.reason_code
                    if gmail_preflight is not None
                    else "gmail_signup_address_missing"
                    if gmail_inbox_configured and settings.gmail_signup_address is None
                    else "gmail_signup_preflight_not_run"
                    if gmail_inbox_configured
                    else "gmail_signup_not_configured"
                ),
                checked_at=(gmail_preflight.checked_at if gmail_preflight is not None else None),
                expires_at=(gmail_preflight.expires_at if gmail_preflight is not None else None),
            ),
            playwright_state,
            state(
                "browser_use",
                configured=(
                    browser_use_enabled and browser_configuration_state(settings, "browser_use")
                ),
                enabled=browser_use_enabled,
                detail=self._browser_provider_detail(
                    provider="browser_use",
                    settings=settings,
                    live_enabled=browser_use_enabled,
                ),
            ),
        ]

    @staticmethod
    def _browser_provider_detail(*, provider: str, settings: Settings, live_enabled: bool) -> str:
        """Provider health detail. Never launches a browser from the API path."""

        if not live_enabled:
            if provider == "browser_use" and not settings.browser_use_compatibility_enabled:
                return "Browser Use compatibility execution is disabled for this rollout."
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
        route_kind = str(record.get("route_kind") or "")
        run_status = str(record.get("status") or "")
        run_phase = str(record.get("phase") or "")
        browser_provider: BrowserProvider = (
            "playwright" if record.get("browser_provider") == "playwright" else "browser_use"
        )
        has_browser_configuration = browser_configuration_state(
            self._settings,
            browser_provider,
        )
        browser_detail = self._browser_phase_detail(
            provider=browser_provider, configured=has_browser_configuration
        )
        has_email_inbox_configuration = bool(
            self._settings.composio_gmail_api_key is not None
            and self._settings.composio_gmail_connected_account_id
        )
        has_outreach_configuration = bool(
            has_email_inbox_configuration and self._settings.outreach_recipient_override
        )
        bundle_ready = record.get("integrator_bundle") is not None

        if route_kind != "playwright":
            browser_phase = PhaseState(
                key="browser",
                name="Browser",
                phase="browser",
                status="unavailable",
                detail="This recipe does not use browser automation.",
                available=False,
            )
            hitl_phase = PhaseState(
                key="hitl",
                name="HITL",
                phase="hitl",
                status="unavailable",
                detail="No browser handoff is part of this route.",
                available=False,
            )
        else:
            if run_status == "waiting_for_hitl":
                browser_status = "waiting"
            elif run_status == "browser_running" and run_phase in {
                "credential_ready",
                "entry_reached",
            }:
                browser_status = "ready"
            elif run_status == "browser_running":
                browser_status = "running"
            elif run_status in {"failed", "blocked", "configuration_required"}:
                browser_status = run_status
            else:
                browser_status = "ready" if has_browser_configuration else "configuration_required"
            browser_phase = PhaseState(
                key="browser",
                name="Browser",
                phase="browser",
                status=browser_status,  # type: ignore[arg-type]
                detail=browser_detail,
                available=has_browser_configuration,
            )
            hitl_phase = PhaseState(
                key="hitl",
                name="HITL",
                phase="hitl",
                status=(
                    "waiting"
                    if run_status == "waiting_for_hitl"
                    else "ready"
                    if has_browser_configuration
                    else "configuration_required"
                ),
                detail=(
                    "The same Playwright session is paused for owner control."
                    if run_status == "waiting_for_hitl"
                    else "HITL state is persisted in the canonical SQLite run record."
                ),
                available=has_browser_configuration,
            )

        hitl_request = record.get("hitl_request")
        waiting_for_email_verification = bool(
            run_status == "waiting_for_hitl"
            and isinstance(hitl_request, dict)
            and (
                hitl_request.get("type") == "email_otp"
                or hitl_request.get("action_type") == "email_otp"
            )
        )
        if route_kind == "playwright":
            email_phase = PhaseState(
                key="email",
                name="Email verification",
                phase="verification",
                status=(
                    "waiting"
                    if waiting_for_email_verification
                    else "ready"
                    if has_email_inbox_configuration
                    else "configuration_required"
                ),
                detail=(
                    "Waiting for a fresh, correctly addressed code or verification link."
                    if waiting_for_email_verification
                    else "The connected Gmail inbox can resolve signup and login verification."
                    if has_email_inbox_configuration
                    else "Connect Gmail to enable automatic signup and login verification."
                ),
                available=has_email_inbox_configuration,
            )
        elif route_kind != "gated":
            email_phase = PhaseState(
                key="email",
                name="Email",
                phase="outreach",
                status="unavailable",
                detail="This recipe does not use controlled outreach.",
                available=False,
            )
        elif record.get("readiness_tier") == "outreach_review_required":
            email_phase = PhaseState(
                key="email",
                name="Email",
                phase="outreach",
                status="unavailable",
                detail="A reviewed vendor contact is required before outreach can be enabled.",
                available=False,
            )
        else:
            email_phase = PhaseState(
                key="email",
                name="Email",
                phase="outreach",
                status=(
                    "waiting"
                    if run_status in {"outreach_sent", "waiting_for_reply"}
                    else "ready"
                    if has_outreach_configuration
                    else "configuration_required"
                ),
                detail="Outreach is bounded to the configured controlled sink.",
                available=has_outreach_configuration,
            )
        return [
            research_phase,
            browser_phase,
            hitl_phase,
            email_phase,
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
            owner_submission_ready=(
                record.get("readiness_tier") == "owner_submit_ready"
                and record.get("phase") == "entry_reached"
            ),
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
                operational_state_storage="sqlite_not_app_encrypted",
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
                    (
                        "Canonical run state and effect receipts use ordinary SQLite; they are "
                        "not application-layer encrypted. Owner-only permissions are reported "
                        "separately."
                    ),
                    "Reusable credential payloads are separately Fernet-encrypted in the vault.",
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
            primary_action=self._primary_action(record, summary),
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

    def _health_sync(
        self,
        *,
        browser_health: BrowserServiceHealth | None = None,
        browser_service_expected: bool = False,
    ) -> HealthResponse:
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
        browser_service_healthy = bool(
            browser_health is not None
            and browser_health.state in {"ready", "capacity_exhausted"}
            and browser_health.chromium_installed
            and browser_health.context_launch_ok
            and browser_health.janitor_running
            and browser_health.capacity_total >= 1
        )
        if browser_service_expected:
            checks.append(
                HealthCheck(
                    name="browser_service_cached_readiness",
                    status="pass" if browser_service_healthy else "fail",
                )
            )
        browser_view = (
            BrowserServiceHealthView(
                state=browser_health.state,
                reason_code=browser_health.reason_code,
                version=browser_health.version,
                chromium_installed=browser_health.chromium_installed,
                context_launch_ok=browser_health.context_launch_ok,
                capacity_total=browser_health.capacity_total,
                capacity_in_use=browser_health.capacity_in_use,
                janitor_running=browser_health.janitor_running,
            )
            if browser_health is not None
            else None
        )
        return HealthResponse(
            status="healthy" if all(check.status == "pass" for check in checks) else "degraded",
            snapshot=snapshot,
            checks=checks,
            # Liveness is intentionally provider-I/O-free. A cached readiness
            # result may be projected, but only the dedicated owner-facing
            # endpoint refreshes Gmail.
            providers=self._provider_states(browser_health=browser_health),
            browser_service=browser_view,
        )

    def _search_apps_sync(self, query: str) -> AppSearchResponse:
        items = [AppSummary.model_validate(item) for item in self._service.search_apps(query)]
        return AppSearchResponse(query=query, items=items, total=len(items))

    def _list_apps_sync(self) -> AppCatalogResponse:
        items = [AppSummary.model_validate(item) for item in self._service.list_apps()]
        return AppCatalogResponse(items=items, total=len(items))

    def _get_app_research_sync(self, app_slug: str) -> AppResearchResponse:
        recipe = get_app_recipe(app_slug)
        if recipe is None:
            raise AppNotFoundError(app_slug)
        result = self._service.get_app_research(app_slug)
        if result is None:
            raise AppNotFoundError(app_slug)
        summary, _snapshot_research = result
        # Runtime capabilities must come from the reviewed recipe, not from a
        # broader evidence snapshot. In particular, only a recipe-owned signup
        # URL may enable account creation in the operator UI.
        research = recipe_to_operational_research(recipe)
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
        recipe = get_app_recipe_for_name(request.app_name) or get_app_recipe(
            request.app_name.strip().casefold()
        )
        if recipe is None:
            # Canonical runs are bound to the reviewed recipe matrix. Reject an
            # unknown display name at the API boundary instead of letting a
            # KeyError escape as a misleading 500 after the operator submits.
            raise AppNotFoundError("unknown")
        work_email_ref = request.company.work_email_ref or _work_email_ref_for_app(request.app_name)
        company = CompanyProfile(
            legal_name=request.company.legal_name,
            website=request.company.website,
            work_email_ref=work_email_ref,
            use_case=request.company.use_case,
            expected_volume=request.company.expected_volume,
            callback_urls=request.company.callback_urls,
        )
        operation = OperationsRequest(
            app_name=request.app_name,
            company=company,
            account_mode=request.account_mode,
            requested_scope_policy=request.requested_scope_policy,
            browser_provider=request.browser_provider,
            credential_creation_policy=request.credential_creation_policy,
            dry_run=True,
            account_creation_requested=request.account_mode == "create_account",
        )
        # Autonomous sign-in credentials (if provided) are mapped to the Browser
        # Use secure-placeholder key names and injected at session creation. The
        # raw values never enter run state, checkpoints, or logs. Reusable pairs
        # may be retained only in the encrypted account-scoped vault.
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
        record = self._service.storage.get_run(run_id)
        if record is None:
            raise RunNotFoundError(run_id)
        work_email_ref = request.company.work_email_ref
        if work_email_ref is None:
            stored_request = record.get("request")
            stored_company = (
                stored_request.get("company") if isinstance(stored_request, Mapping) else None
            )
            stored_ref = (
                stored_company.get("work_email_ref")
                if isinstance(stored_company, Mapping)
                else None
            )
            if isinstance(stored_ref, str):
                work_email_ref = stored_ref
            else:
                work_email_ref = _work_email_ref_for_app(
                    str(record.get("app_name") or "app"),
                    app_slug=(str(record["app_slug"]) if record.get("app_slug") else None),
                )
        company = CompanyProfile(
            legal_name=request.company.legal_name,
            website=request.company.website,
            work_email_ref=work_email_ref,
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
        injected_fields = frozenset(browser_login or {})
        logged_in = bool({"login_email", "login_password"} & injected_fields)
        verification_submitted = bool({"login_otp", "login_verification_url"} & injected_fields)
        detail = (
            (
                "Logged in autonomously with the submitted credentials; the credential page "
                "is ready."
                if logged_in
                else "Submitted the one-time email verification; the credential page is ready."
                if verification_submitted
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
        browser_verification: BrowserVerificationInput | None = None,
        signal: str = "completed",
    ) -> ActionReceipt:
        detail = await self.get_run(run_id)
        if detail.run.state_engine != "canonical_v1":
            raise PhaseUnavailableError(
                run_id=run_id,
                action="resume",
                available_in=("canonical_v1",),
                error="phase_unavailable",
            )
        if detail.run.execution_mode == "plan_only" or detail.run.status != "waiting_for_hitl":
            raise PhaseUnavailableError(
                run_id=run_id,
                action="resume",
                available_in=("waiting_for_hitl",),
                error="phase_unavailable",
                message="Resume is available only while a canonical run is waiting for HITL.",
            )
        if browser_verification is not None and (
            detail.hitl_request is None or detail.hitl_request.action_type != "email_otp"
        ):
            raise PhaseUnavailableError(
                run_id=run_id,
                action="resume",
                available_in=("email_otp",),
                error="phase_unavailable",
                message="Email verification can be submitted only at its matching gate.",
            )
        # Map owner input onto the provider-neutral secret boundary names.
        # SecretStr keeps values wrapped until the core service resolves them in
        # memory for the single resume call.
        login_map: dict[str, SecretStr] | None = None
        if browser_login is not None:
            login_map = {
                "login_email": browser_login.email,
                "login_password": browser_login.password,
            }
        elif browser_verification is not None:
            if browser_verification.code is not None:
                login_map = {"login_otp": browser_verification.code}
            elif browser_verification.url is not None:
                login_map = {
                    "login_verification_url": browser_verification.url,
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
        # Playwright grants are minted for both autonomous viewing and HITL. The
        # browser service signs the capability: autonomous grants are view-only;
        # a live HITL pause may receive control. The private URL remains transient.
        grant_getter = getattr(self._service, "get_browser_interactive_grant", None)
        grant = grant_getter(run_id) if callable(grant_getter) else None
        if provider == "playwright" and grant is not None:
            _, interactive_url, _expires_at, control_allowed = grant
            return LiveViewResponse(
                run_id=run_id,
                provider="playwright",
                available=True,
                mode="interactive_remote",
                interactive_url=interactive_url,
                interaction_available=control_allowed,
                reason_code=(
                    "interactive_control_live" if control_allowed else "interactive_view_only_live"
                ),
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
        detail = await self.get_run(run_id)
        verification_wait = bool(
            detail.run.status == "waiting_for_hitl"
            and detail.hitl_request is not None
            and detail.hitl_request.action_type == "email_otp"
        )
        outreach_wait = bool(
            detail.run.route_kind == "gated"
            and detail.run.status
            in {
                "outreach_sent",
                "waiting_for_reply",
            }
        )
        if not verification_wait and not outreach_wait:
            raise PhaseUnavailableError(
                run_id=run_id,
                action="poll_email",
                available_in=("waiting_for_hitl", "outreach_sent", "waiting_for_reply"),
                error="phase_unavailable",
                message="Email checking is available for a pending verification or outreach reply.",
            )
        if verification_wait:
            if not (
                self._settings.composio_gmail_api_key
                and self._settings.composio_gmail_connected_account_id
            ):
                raise PhaseUnavailableError(
                    run_id=run_id,
                    action="poll_email",
                    available_in=("waiting_for_hitl",),
                    error="configuration_required",
                    message="Gmail verification is not configured.",
                )
            return await run_in_threadpool(self._poll_verification_sync, run_id)
        if detail.run.route_kind != "gated" or detail.run.status not in {
            "outreach_sent",
            "waiting_for_reply",
        }:
            raise PhaseUnavailableError(
                run_id=run_id,
                action="poll_email",
                available_in=("outreach_sent", "waiting_for_reply"),
                error="phase_unavailable",
                message="Email polling is available only after controlled outreach.",
            )
        if not (
            self._settings.composio_gmail_api_key
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

    def _poll_verification_sync(self, run_id: str) -> ActionReceipt:
        try:
            record = self._service.resolve_email_otp(run_id)
        except KeyError:
            raise RunNotFoundError(run_id) from None
        if record is None:
            return ActionReceipt(
                run_id=run_id,
                action="poll_email",
                status="no_change",
                detail="No fresh, correctly addressed verification email was found yet.",
            )
        return ActionReceipt(
            run_id=run_id,
            action="poll_email",
            status="accepted",
            detail="Verification email accepted and the same browser session resumed.",
        )

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

    @staticmethod
    def _managed_response(payload: Mapping[str, object]) -> ManagedConnectionResponse:
        run = payload.get("run")
        if not isinstance(run, dict):
            raise RuntimeError("managed connection response is missing its run")
        return ManagedConnectionResponse(
            run=LocalRunService._summary(run),
            connection_request_id=str(payload.get("connection_request_id") or ""),
            state=payload.get("state", "pending"),  # type: ignore[arg-type]
            redirect_url=(
                str(payload["redirect_url"]) if payload.get("redirect_url") is not None else None
            ),
            replayed=bool(payload.get("replayed", False)),
        )

    def _connect_managed_sync(self, run_id: str) -> ManagedConnectionResponse:
        try:
            return self._managed_response(self._service.connect_managed_run(run_id))
        except KeyError:
            raise RunNotFoundError(run_id) from None

    async def connect_managed(self, run_id: str) -> ManagedConnectionResponse:
        self._require_started()
        return await run_in_threadpool(self._connect_managed_sync, run_id)

    def _poll_managed_sync(self, run_id: str) -> ManagedConnectionResponse:
        try:
            return self._managed_response(self._service.poll_managed_connection(run_id))
        except KeyError:
            raise RunNotFoundError(run_id) from None

    async def poll_managed_connection(self, run_id: str) -> ManagedConnectionResponse:
        self._require_started()
        return await run_in_threadpool(self._poll_managed_sync, run_id)

    def _send_gated_outreach_sync(self, run_id: str) -> ActionReceipt:
        try:
            record = self._service.send_gated_outreach(run_id)
        except KeyError:
            raise RunNotFoundError(run_id) from None
        return ActionReceipt(
            run_id=run_id,
            action="send_outreach",
            status="accepted",
            detail=(
                "Controlled-sink outreach was recorded; run status: "
                f"{str(record.get('status') or 'unknown').replace('_', ' ')}."
            ),
        )

    async def send_gated_outreach(self, run_id: str) -> ActionReceipt:
        self._require_started()
        return await run_in_threadpool(self._send_gated_outreach_sync, run_id)

    async def retry(self, run_id: str, capability: str) -> ActionReceipt:
        detail = await self.get_run(run_id)
        if detail.run.execution_mode == "plan_only":
            raise PhaseUnavailableError(
                run_id=run_id,
                action="retry",
                available_in=("execute_when_configured",),
                error="phase_unavailable",
                message="Plan-only runs are immutable.",
            )
        if capability == "browser":
            if detail.run.route_kind != "playwright" or detail.run.browser_provider != "playwright":
                raise PhaseUnavailableError(
                    run_id=run_id,
                    action="retry",
                    available_in=("failed_playwright_run",),
                    error="phase_unavailable",
                )
            if not browser_configuration_state(self._settings, "playwright"):
                return ActionReceipt(
                    run_id=run_id,
                    action="retry",
                    status="configuration_required",
                    detail="Required provider configuration or policy opt-in is missing.",
                )
            try:
                retried = await run_in_threadpool(self._service.retry_browser_run, run_id)
            except KeyError:
                raise RunNotFoundError(run_id) from None
            return ActionReceipt(
                run_id=run_id,
                action="retry",
                status="accepted",
                detail=(
                    "A new Playwright attempt started with the run's approved account policy "
                    f"(attempt {int(retried.get('attempt', 0) or 0)})."
                ),
            )
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
                self._settings.composio_gmail_api_key
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

    def _signup_readiness_sync(self) -> ProviderState:
        gmail_preflight = self._cached_gmail_preflight(refresh=True)
        return next(
            state
            for state in self._provider_states(gmail_preflight=gmail_preflight)
            if state.provider == "gmail"
        )

    async def signup_readiness(self) -> ProviderState:
        self._require_started()
        return await run_in_threadpool(self._signup_readiness_sync)

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

    def _expects_browser_service_health(self) -> bool:
        settings = self._settings
        return bool(
            settings.allow_live_browser
            and not settings.playwright_in_process_sandbox
            and browser_configuration_state(settings, "playwright")
        )

    async def _cached_browser_service_health(self) -> BrowserServiceHealth | None:
        """Fetch the worker's cache-only endpoint within the API health budget."""

        if not self._expects_browser_service_health():
            return None
        settings = self._settings
        if (
            not settings.browser_service_url
            or settings.browser_service_token is None
            or settings.browser_session_capability_key is None
        ):
            return BrowserServiceHealth(
                state="not_configured",
                reason_code="browser_service_configuration_required",
            )
        client = BrowserServiceClient(
            base_url=settings.browser_service_url,
            token=settings.browser_service_token,
            owner=settings.browser_service_owner,
            capability_key=settings.browser_session_capability_key,
            # Operations may run for minutes; health must never inherit that
            # budget. BrowserServiceClient.health applies its own <=5s cap.
            timeout_seconds=2.0,
        )
        return await client.health(timeout_seconds=2.0)

    async def health(self) -> HealthResponse:
        self._require_started()
        browser_service_expected = self._expects_browser_service_health()
        browser_health = await self._cached_browser_service_health()
        return await run_in_threadpool(
            self._health_sync,
            browser_health=browser_health,
            browser_service_expected=browser_service_expected,
        )
