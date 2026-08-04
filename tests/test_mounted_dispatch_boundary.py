"""The dispatch boundary between the legacy fast path and the mounted seam.

A profile-onboarding run must reach ``MountedOnboardingRuntime`` with no browser
session in existence. Thirteen of the fourteen reviewed Playwright recipes declare
no static signup URL, so before this boundary existed they were dispatched straight
into ``_start_playwright`` and the mounted seam never saw them.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ops.core.config import Settings
from ops.core.models import CompanyProfile, OperationsRequest
from ops.onboarding.runtime import _is_mounted_request
from ops.runs.errors import ProviderReadinessError
from ops.runs.service import RunService


class _NeverStartedPlaywright:
    """Any call proves the run was dispatched when it should not have been."""

    provider_name = "playwright"

    async def start(self, profile_id: str | None, **_kwargs: object) -> object:
        raise AssertionError("a profile-onboarding run must not start a browser session")

    async def stop(self, context: object) -> None:
        del context


def _company() -> CompanyProfile:
    return CompanyProfile(
        legal_name="Example Labs, Inc.",
        website="https://example.com",
        work_email_ref="vault://company/work_email/profile_1",
        use_case="Connect the authorized integration.",
    )


def _service(tmp_path: Path) -> RunService:
    service = RunService.from_paths(
        db_path=tmp_path / "private" / "ops.db",
        settings=Settings(),
    )
    browser = _NeverStartedPlaywright()
    service._browser_workers = {"playwright": browser}  # type: ignore[assignment]
    service._browser_worker = browser  # type: ignore[assignment]
    return service


def _onboarding_request(app_name: str) -> OperationsRequest:
    return OperationsRequest(
        app_name=app_name,
        company=_company(),
        account_mode="create_account",
        account_creation_requested=True,
        onboarding=True,
        browser_provider="playwright",
    )


def test_profile_onboarding_run_is_not_dispatched_to_the_browser(tmp_path: Path) -> None:
    """Telegram declares no static signup URL, so it belongs to the mounted seam."""

    service = _service(tmp_path)
    run = service.create_run(
        _onboarding_request("Telegram"),
        execution_mode="execute_when_configured",
    )
    for thread in service._browser_threads:
        thread.join(timeout=5)

    stored = service.storage.get_run(str(run["run_id"]))
    assert stored is not None
    assert stored["execution_path"] == "profile_mounted"
    assert stored["status"] != "browser_running"
    assert stored["phase"] == "research"


def test_the_mounted_seam_claims_the_run_by_resolved_path(tmp_path: Path) -> None:
    """``_is_mounted_request`` reads the resolved path, not the client's hint."""

    service = _service(tmp_path)
    run = service.create_run(
        _onboarding_request("Telegram"),
        execution_mode="execute_when_configured",
    )
    for thread in service._browser_threads:
        thread.join(timeout=5)

    stored = service.storage.get_run(str(run["run_id"]))
    assert stored is not None
    assert _is_mounted_request(stored) is True


def test_a_stranded_mounted_run_is_reconcilable_from_the_ledger(tmp_path: Path) -> None:
    """A crash leaves the run in ``research``; the sweep must still find it.

    Post-commit onboarding work used to run only inside the creating request, so
    nothing carried the run forward afterwards.
    """

    service = _service(tmp_path)
    run = service.create_run(
        _onboarding_request("Telegram"),
        execution_mode="execute_when_configured",
    )
    for thread in service._browser_threads:
        thread.join(timeout=5)
    run_id = str(run["run_id"])

    assert run_id in service.storage.stranded_mounted_run_ids(limit=100)

    # A legacy run is never claimed by the mounted sweep.
    legacy = service.create_run(
        OperationsRequest(
            app_name="Notion",
            company=_company(),
            account_mode="existing_account",
        ),
        execution_mode="plan_only",
    )
    assert str(legacy["run_id"]) not in service.storage.stranded_mounted_run_ids(limit=100)


def test_a_static_signup_recipe_keeps_the_legacy_path(tmp_path: Path) -> None:
    """Pipedrive declares a static signup URL, so it must not be mounted.

    Its readiness gate is what rejects the run here; reaching that gate at all is
    the proof that the run stayed on the legacy path.
    """

    service = _service(tmp_path)
    with pytest.raises(ProviderReadinessError):
        service.create_run(
            _onboarding_request("Pipedrive"),
            execution_mode="execute_when_configured",
        )
