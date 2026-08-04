"""A run that fails before it has a profile must still reach a durable boundary.

Research is the phase where a profile digest first exists, so a failure *inside*
research has none to carry. Before this was handled, `drive_run` raised
`PhaseNotDrivable` at the transition, the run was left with no committed
`blocked` boundary, and `_onboarding_state` returned nothing — which cost the
console its reset and retry controls and made the run unrecoverable. Every
mounted onboarding run took that path, so none could be created over the API.

The empty digest is the module's existing convention for "no profile was ever
built" (`AutonomyOutcome.__post_init__`, `RecoveryPlan.__post_init__`, and
`drive_run`'s own outcome construction). These tests pin that the WRITE boundary
now agrees with it, and — just as importantly — that it still refuses the empty
digest anywhere a profile must exist.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from ops.core.config import Settings
from ops.core.models import CompanyProfile, OperationsRequest
from ops.onboarding.driver import _committed_profile_digest
from ops.onboarding.runtime import MountedOnboardingRuntime
from ops.runs.service import RunService

_REAL_DIGEST = "a" * 64


class _NeverStartedPlaywright:
    provider_name = "playwright"

    async def start(self, profile_id: str | None, **_kwargs: object) -> object:
        raise AssertionError("a pre-profile failure must not open a browser session")

    async def stop(self, context: object) -> None:
        del context


def _service(tmp_path: Path) -> RunService:
    service = RunService.from_paths(
        db_path=tmp_path / "private" / "ops.db",
        settings=Settings(),
    )
    browser = _NeverStartedPlaywright()
    service._browser_workers = {"playwright": browser}  # type: ignore[assignment]
    service._browser_worker = browser  # type: ignore[assignment]
    return service


def _request(app_name: str, hint_url: str | None = None) -> OperationsRequest:
    return OperationsRequest(
        app_name=app_name,
        company=CompanyProfile(
            legal_name="Example Labs, Inc.",
            website="https://example.com",
            work_email_ref="vault://company/work_email/profile_1",
            use_case="Connect the authorized integration.",
        ),
        account_mode="create_account",
        account_creation_requested=True,
        onboarding=True,
        browser_provider="playwright",
        provider_hint_url=hint_url,
    )


class TestCommittedProfileDigest:
    """The validator that decides which boundaries may carry no digest."""

    @pytest.mark.parametrize("to_phase", ["blocked", "cancelled"])
    def test_a_pre_profile_terminal_phase_admits_the_empty_digest(self, to_phase: str) -> None:
        assert _committed_profile_digest("", to_phase=to_phase) == ""  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "to_phase",
        [
            # Reached only WITH a committed profile, so a missing digest here is a
            # wiring defect and must stay loud.
            "vault_check",
            "awaiting_admission",
            "route_selected_signup",
            "signup",
            # A run that produced a credential built a profile on the way to it.
            "completed",
        ],
    )
    def test_every_other_phase_still_requires_a_real_digest(self, to_phase: str) -> None:
        with pytest.raises(ValueError, match="sha256 hex digest"):
            _committed_profile_digest("", to_phase=to_phase)  # type: ignore[arg-type]

    def test_a_malformed_digest_is_refused_even_on_a_terminal_phase(self) -> None:
        """The exemption is for ABSENCE, not for a wrong content address."""

        with pytest.raises(ValueError, match="sha256 hex digest"):
            _committed_profile_digest("not-a-digest", to_phase="blocked")

    def test_a_real_digest_passes_through_unchanged(self) -> None:
        assert _committed_profile_digest(_REAL_DIGEST, to_phase="vault_check") == _REAL_DIGEST


def _advance(service: RunService, tmp_path: Path, request: OperationsRequest) -> dict[str, object]:
    run = service.create_run(request, execution_mode="execute_when_configured")
    for thread in service._browser_threads:
        thread.join(timeout=5)
    run_id = str(run["run_id"])
    runtime = MountedOnboardingRuntime(Settings(), ledger_path=str(tmp_path / "private" / "ops.db"))
    # No network is reachable in the offline gate, so research fails — which is
    # exactly the pre-profile failure under test.
    asyncio.run(runtime.advance(run_id))
    record = service.storage.get_run(run_id)
    assert record is not None
    history = runtime.ports.phases.history(run_id=run_id)
    return {"record": record, "history": history, "run_id": run_id}


@pytest.mark.parametrize(
    ("app_name", "hint_url"),
    [
        pytest.param("Telegram", None, id="on_catalog"),
        pytest.param(
            "Unreviewed Vendor",
            "https://unreviewed-vendor.com/signup",
            id="off_catalog",
        ),
    ],
)
def test_a_research_failure_commits_a_blocked_boundary(
    tmp_path: Path,
    app_name: str,
    hint_url: str | None,
) -> None:
    """The regression this fixes: advance() used to raise instead of committing."""

    service = _service(tmp_path)
    result = _advance(service, tmp_path, _request(app_name, hint_url))
    record = result["record"]
    history = result["history"]
    assert isinstance(record, dict)
    assert isinstance(history, tuple | list)

    # The run is durably blocked rather than crashed mid-walk...
    assert record["status"] == "blocked"
    assert record["phase"] == "blocked"
    # ...and the boundary exists, which is what the console reads to offer reset.
    assert len(history) >= 1
    boundary = history[-1]
    assert boundary.to_phase == "blocked"
    assert boundary.from_phase == "research"
    # Recorded under the documented empty digest: no profile was ever built.
    assert boundary.profile_digest == ""
    # The reason names what actually failed, drawn from the closed vocabulary.
    assert boundary.reason_code.startswith("research_")


def test_the_blocked_run_is_not_left_looking_alive(tmp_path: Path) -> None:
    """A committed terminal boundary is what stops the run being a silent stall."""

    service = _service(tmp_path)
    result = _advance(service, tmp_path, _request("Telegram"))
    run_id = result["run_id"]
    assert isinstance(run_id, str)

    # ``blocked`` is terminal, so the mounted sweep must not keep re-claiming it.
    assert run_id not in service.storage.stranded_mounted_run_ids(limit=100)
