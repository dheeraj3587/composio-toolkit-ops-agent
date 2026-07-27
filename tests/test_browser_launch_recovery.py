"""Regressions for the Playwright create-run failure.

Two defects made a Pipedrive Playwright run impossible to create:

1. The browser image ran headful Chromium with ``HOME`` on the read-only root
   filesystem, so every real session crashed at launch while the headless
   readiness probe stayed green.
2. A failed pre-created session raised straight out of ``create_run``, so the API
   answered 500 and persisted NOTHING — the operator saw "the operations API is
   unavailable" with no run in the ledger and no recorded reason.
"""

from __future__ import annotations

import re
from pathlib import Path
from types import MethodType
from typing import Any
from unittest.mock import patch

from ops.browser_worker import BrowserSessionContext
from ops.composio_capability import ComposioCapabilityReport
from ops.config import Settings
from ops.models import CapabilityAvailability, CompanyProfile, OperationsRequest
from ops.operational_research import ResearchEnrichmentOutcome
from ops.provider_errors import ProviderOperationError
from ops.run_service import RunService

_REPO = Path(__file__).resolve().parents[1]
_ENTRYPOINT = _REPO / "docker" / "browser-entrypoint.sh"


# --- 1. the browser image must give Chromium a writable HOME ------------------
def test_browser_entrypoint_exports_a_writable_home() -> None:
    """Headful Chromium touches ``$HOME``; the image WORKDIR is read-only.

    Without this, ``chromium.launch(headless=False)`` dies immediately with
    SIGTRAP and the browser service answers ``browser_launch_failed`` for every
    session, even though the headless readiness probe reports ready.
    """

    script = _ENTRYPOINT.read_text(encoding="utf-8")

    assert 'BROWSER_HOME="${BROWSER_HOME:-/tmp/browser-home}"' in script
    assert 'HOME="${BROWSER_HOME}"' in script
    # HOME must be exported so the exec'd server (and its Chromium children) see it.
    export = re.search(r"^export .*\bHOME\b.*$", script, re.MULTILINE)
    assert export is not None, "HOME is never exported to the server process"
    # The directories live on tmpfs, so they must be created at runtime.
    assert "mkdir -p" in script and "XDG_CACHE_HOME" in script
    assert "XDG_CONFIG_HOME" in script and "XDG_RUNTIME_DIR" in script
    # The writable HOME must be applied for headless too, not only inside the
    # interactive branch: the same crash appears whenever Chromium runs headful.
    home_index = script.index('BROWSER_HOME="${BROWSER_HOME:-/tmp/browser-home}"')
    interactive_index = script.index('if is_enabled "${BROWSER_INTERACTIVE_HITL_ENABLED:-false}"')
    assert home_index < interactive_index


def test_browser_home_is_not_the_read_only_workdir() -> None:
    dockerfile = (_REPO / "Dockerfile.browser").read_text(encoding="utf-8")
    workdir = re.search(r"^WORKDIR\s+(\S+)", dockerfile, re.MULTILINE)
    assert workdir is not None
    script = _ENTRYPOINT.read_text(encoding="utf-8")
    # /app is on the read-only rootfs; HOME must not point there.
    assert f'HOME="{workdir.group(1)}"' not in script


# --- 2. a failed pre-created session must still persist the run ---------------
class _FallbackPreflight:
    async def evaluate(self, *, app_name: str, app_slug: str) -> ComposioCapabilityReport:
        del app_name
        return ComposioCapabilityReport(
            app_slug=app_slug,
            toolkit_available=False,
            toolkit_slug=None,
            required_auth_schemes=(),
            managed_auth_available=False,
            active_connected_account=False,
            required_tools_present=False,
            capability_state="toolkit_unavailable",
            reason_code="toolkit_unavailable",
            detail="No managed toolkit is available; use the verified fallback.",
        )


class _FallbackWorkflow:
    def start(self, *args: Any, **kwargs: Any) -> dict[str, str]:
        del args, kwargs
        return {
            "status": "configuration_required",
            "access_route": "self_serve",
            "route_reason_code": "browser_launch_failed",
            "route_reason": "The browser provider could not create a session.",
        }

    def close(self) -> None:
        return None


class _FailingWorker:
    """A browser worker whose session creation fails the way the service did."""

    provider_name = "playwright"
    supports_restart_reattach = True

    def __init__(self) -> None:
        self.start_calls = 0

    async def start(self, profile_id: str | None, **kwargs: Any) -> BrowserSessionContext:
        del profile_id, kwargs
        self.start_calls += 1
        raise ProviderOperationError(
            capability="browser service", reason_code="browser_launch_failed"
        )

    async def navigate_onboarding(self, *args: Any, **kwargs: Any) -> Any:
        raise ProviderOperationError(
            capability="browser service", reason_code="browser_launch_failed"
        )

    async def resume_after_hitl(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover
        raise ProviderOperationError(
            capability="browser service", reason_code="browser_launch_failed"
        )

    def provider_session_id(self, handle: str) -> str | None:
        return handle or None

    def live_url(self, session_id: str) -> str | None:
        return None


def _request() -> OperationsRequest:
    return OperationsRequest(
        app_name="Pipedrive",
        company=CompanyProfile(
            legal_name="Example Labs, Inc.",
            website="https://example.com",
            work_email_ref="vault://company/work_email/profile_1",
            use_case="Authorized integration via the provider developer API.",
        ),
        browser_provider="playwright",
    )


def _service(tmp_path: Path, worker: _FailingWorker) -> RunService:
    settings = Settings(
        allow_live_browser=True,
        browser_provider="playwright",
        playwright_in_process_sandbox=True,
        ops_db_path=tmp_path / "ops.db",
        checkpoint_db_path=tmp_path / "checkpoints.db",
        secret_vault_db_path=tmp_path / "vault.db",
        provider_effects_db_path=tmp_path / "effects.db",
    )
    service = RunService.from_paths(db_path=tmp_path / "ops.db", settings=settings)
    service.startup()
    # Inject the failing provider for the Playwright route only.
    service._workflow = _FallbackWorkflow()  # type: ignore[assignment]
    service._browser_workers = {"playwright": worker}  # type: ignore[attr-defined, dict-item]
    service._browser_worker = worker  # type: ignore[assignment]
    service._capability_preflight = _FallbackPreflight()  # type: ignore[assignment]
    service._async_browser_enabled = True  # type: ignore[attr-defined]

    # The verified P1 baseline intentionally omits operational login/settings URLs.
    # Supply a bounded reviewed enrichment so this regression actually enters the
    # pre-created-session branch instead of merely asserting that a run was stored.
    def _reviewed_enrichment(
        _self: RunService, _record: Any, baseline: Any
    ) -> ResearchEnrichmentOutcome:
        research = baseline.model_copy(
            update={
                "login_url": "https://app.pipedrive.com/auth/login",
                "credential_management_url": "https://app.pipedrive.com/settings/api",
            }
        )
        return ResearchEnrichmentOutcome(
            research=research,
            capability=CapabilityAvailability(
                capability="operational_research",
                status="ready",
                reason_code="reviewed_test_evidence",
                detail="Reviewed Pipedrive operational URLs are available.",
            ),
            missing_fields=[],
            documents_fetched=1,
        )

    service._enricher = object()  # type: ignore[assignment]
    service._run_enrichment_probe = MethodType(  # type: ignore[method-assign]
        _reviewed_enrichment, service
    )
    return service


def test_failed_precreated_session_still_persists_the_run(tmp_path: Path) -> None:
    worker = _FailingWorker()
    service = _service(tmp_path, worker)
    try:
        # Patched where create_run RESOLVES the name. A shim re-exported from
        # ops.run_service would make this patch silently ineffective rather than
        # failing, so the target has to follow the implementation.
        with patch("ops.run_creation.get_browser_api_trace", return_value=object()):
            record = service.create_run(_request(), execution_mode="execute_when_configured")
        rows, total = service.list_runs(limit=10, offset=0)
    finally:
        service.shutdown()

    # The failing provider was actually called, and the request still produced
    # exactly one durable ledger row.
    assert worker.start_calls >= 1
    assert total == 1
    assert [row["run_id"] for row in rows] == [record["run_id"]]
    run_id = str(record["run_id"])
    assert run_id.startswith("run_")
    assert record["status"] in {"configuration_required", "failed", "blocked", "route_selected"}
    assert record["status"] != "browser_running"
    assert worker.start_calls >= 1


def test_a_failed_session_does_not_raise_out_of_create_run(tmp_path: Path) -> None:
    """create_run must not turn a provider outage into an unhandled 500."""

    worker = _FailingWorker()
    service = _service(tmp_path, worker)
    try:
        # No exception: the previous behaviour raised ProviderOperationError here.
        record = service.create_run(_request(), execution_mode="execute_when_configured")
        stored = service.get_run(str(record["run_id"]))
    finally:
        service.shutdown()

    assert stored is not None
    assert str(stored["run_id"]) == str(record["run_id"])


# --- 3. the service must log WHY a launch failed ------------------------------
def test_browser_service_logs_the_provider_reason_code() -> None:
    source = (_REPO / "browser_service" / "main.py").read_text(encoding="utf-8")
    marker = source.index("browser launch failed")
    window = source[marker - 500 : marker + 400]
    # The sanitized provider reason code, not just the exception class name.
    assert 'getattr(exc, "reason_code"' in window
    assert "reason=%s" in window
