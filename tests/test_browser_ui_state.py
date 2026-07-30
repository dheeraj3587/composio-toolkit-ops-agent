"""Provider-aware browser UI projection.

The invariant under test: the interface receives explicit backend decisions, so a
capability is true only on positive backend evidence — never because a run happens
to be in ``browser_running``, and never because Browser Use would have been able
to do it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import SecretStr

from api.browser_ui import project_browser_ui
from api.models import HitlRequestView
from ops.core.config import Settings

_PLAYWRIGHT = Settings(
    allow_live_browser=True,
    browser_provider="playwright",
    browser_service_url="http://browser-worker:8081",
    browser_service_token=SecretStr("service-token-" + ("s" * 32)),
    browser_session_capability_key=SecretStr("c" * 32),
    allow_local_credential_submission=True,
)
_PLAYWRIGHT_INTERACTIVE = _PLAYWRIGHT.model_copy(update={"browser_interactive_hitl_enabled": True})
_BROWSER_USE = Settings(
    allow_live_browser=True,
    browser_use_api_key=SecretStr("bu-key"),
    browser_use_compatibility_enabled=True,
    allow_local_credential_submission=True,
)


# --- provider configuration is never judged by the other provider's key -------
def test_playwright_is_configured_without_a_browser_use_key() -> None:
    assert _PLAYWRIGHT.browser_use_api_key is None

    state = project_browser_ui(
        settings=_PLAYWRIGHT,
        run_status="browser_running",
        event_types={"browser_session_started"},
        browser_session_id="pw_1",
        screenshot_present=True,
    )

    assert state.provider == "playwright"
    assert state.lifecycle == "running"
    assert state.live_view_mode == "screenshot"
    assert state.live_view_available is True
    # Rule 9: masked frames are never drivable.
    assert state.interaction_available is False
    assert state.screenshot_available is True


def test_browser_use_still_requires_its_own_key() -> None:
    unconfigured = Settings(allow_live_browser=True)

    state = project_browser_ui(settings=unconfigured, run_status="created", event_types=set())

    assert state.provider == "browser_use"
    assert state.lifecycle == "unavailable"
    assert state.reason_code == "browser_not_configured"
    assert state.live_view_available is False

    configured = project_browser_ui(
        settings=_BROWSER_USE,
        run_status="browser_running",
        event_types={"browser_session_started"},
        browser_session_id="bu_1",
    )
    assert configured.lifecycle == "running"
    assert configured.live_view_mode == "hosted_url"
    # Rule 9: a hosted provider view IS interactive.
    assert configured.interaction_available is True
    # No frames are captured by the hosted provider.
    assert configured.screenshot_available is False


def test_browser_use_key_does_not_enable_disabled_compatibility_adapter() -> None:
    disabled = _BROWSER_USE.model_copy(update={"browser_use_compatibility_enabled": False})

    state = project_browser_ui(
        settings=disabled,
        run_status="browser_running",
        event_types={"browser_session_started"},
        browser_session_id="bu_1",
    )

    assert state.lifecycle == "unavailable"
    assert state.live_view_available is False


# --- rule 3/4: a running session is not a credential page ---------------------
def test_browser_session_start_does_not_enable_credential_submission() -> None:
    state = project_browser_ui(
        settings=_BROWSER_USE,
        run_status="browser_running",
        event_types={"browser_session_started", "browser_navigation_completed"},
        browser_session_id="bu_1",
    )

    assert state.credential_page_verified is False
    assert state.can_submit_credential is False


def test_credential_page_ready_enables_credential_submission() -> None:
    state = project_browser_ui(
        settings=_BROWSER_USE,
        run_status="browser_running",
        event_types={"browser_session_started", "credential_page_ready"},
        browser_session_id="bu_1",
    )

    assert state.credential_page_verified is True
    assert state.lifecycle == "credential_page_ready"
    assert state.can_submit_credential is True


def test_reviewed_entry_only_route_enables_owner_submission_without_false_page_claim() -> None:
    state = project_browser_ui(
        settings=_PLAYWRIGHT,
        browser_provider="playwright",
        run_status="browser_running",
        event_types={"browser_session_started", "browser_entry_reached"},
        browser_session_id="pw_1",
        owner_submission_ready=True,
    )

    assert state.credential_page_verified is False
    assert state.can_submit_credential is True


def test_credential_submission_still_requires_the_owner_policy_opt_in() -> None:
    without_opt_in = _BROWSER_USE.model_copy(update={"allow_local_credential_submission": False})

    state = project_browser_ui(
        settings=without_opt_in,
        run_status="browser_running",
        event_types={"credential_page_ready"},
        browser_session_id="bu_1",
    )

    assert state.credential_page_verified is True
    # The submission endpoint is closed, so the control must not be offered.
    assert state.can_submit_credential is False


# --- rules 5/6/7: HITL capabilities -------------------------------------------
def _hitl(action_type: str, *, resumable: bool = True) -> HitlRequestView:
    return HitlRequestView(
        action_type=action_type,
        message="A human action is required in the live browser.",
        expected_completion_signal="The action has been completed.",
        resumable=resumable,
    )


def test_waiting_for_hitl_exposes_the_correct_capability() -> None:
    state = project_browser_ui(
        settings=_BROWSER_USE,
        run_status="waiting_for_hitl",
        event_types={"browser_session_started", "browser_hitl_required"},
        browser_session_id="bu_1",
        hitl=_hitl("login_required"),
    )

    assert state.lifecycle == "waiting_for_hitl"
    assert state.can_resume is True
    # A reviewed login gate plus the owner policy opt-in.
    assert state.can_submit_login is True
    # No OTP submission surface exists in the API yet, so it stays closed.
    assert state.can_submit_otp is False
    assert state.can_submit_credential is False


def test_provider_verification_is_cleared_in_the_browser_not_by_a_login_form() -> None:
    """Only a missing-login gate may offer another email/password submission.

    ``LOGIN_HITL_ACTIONS`` is deliberately just ``login_required``: a provider
    verification or new-device prompt is completed in the live browser, so
    advertising the login form there would offer a control that cannot clear it.
    """

    state = project_browser_ui(
        settings=_BROWSER_USE,
        run_status="waiting_for_hitl",
        event_types={"browser_session_started", "browser_hitl_required"},
        browser_session_id="bu_1",
        hitl=_hitl("provider_verification"),
    )

    assert state.can_resume is True
    assert state.can_submit_login is False


def test_a_captcha_gate_does_not_offer_the_login_form() -> None:
    state = project_browser_ui(
        settings=_BROWSER_USE,
        run_status="waiting_for_hitl",
        event_types={"browser_hitl_required"},
        browser_session_id="bu_1",
        hitl=_hitl("captcha"),
    )

    assert state.can_resume is True
    assert state.can_submit_login is False
    assert state.can_submit_otp is False


def test_an_email_otp_gate_exposes_the_owner_only_fallback() -> None:
    state = project_browser_ui(
        settings=_BROWSER_USE,
        run_status="waiting_for_hitl",
        event_types={"browser_hitl_required"},
        browser_session_id="bu_1",
        hitl=_hitl("email_otp"),
    )

    assert state.can_submit_otp is True
    assert state.can_resume is True


def test_resume_requires_a_resumable_request() -> None:
    state = project_browser_ui(
        settings=_BROWSER_USE,
        run_status="waiting_for_hitl",
        event_types={"browser_hitl_required"},
        browser_session_id="bu_1",
        hitl=_hitl("provider_verification", resumable=False),
    )

    assert state.can_resume is False
    assert state.can_submit_login is False


# --- rules 10/11: lost and terminal runs disable mutations -------------------
def test_session_lost_disables_all_mutations() -> None:
    state = project_browser_ui(
        settings=_PLAYWRIGHT,
        run_status="configuration_required",
        event_types={"browser_session_started", "credential_page_ready", "browser_hitl_required"},
        browser_session_id="pw_1",
        hitl=_hitl("provider_verification"),
        screenshot_present=True,
        session_lost=True,
    )

    assert state.lifecycle == "session_lost"
    assert state.reason_code == "browser_session_lost"
    assert state.live_view_mode == "unavailable"
    assert state.live_view_available is False
    assert state.interaction_available is False
    assert (
        state.can_resume,
        state.can_submit_login,
        state.can_submit_otp,
        state.can_submit_credential,
    ) == (False, False, False, False)
    # The verified fact itself is not rewritten; only the permissions close.
    assert state.credential_page_verified is True


@pytest.mark.parametrize("run_status", ["completed", "blocked", "failed"])
def test_terminal_runs_disable_unsafe_controls(run_status: str) -> None:
    state = project_browser_ui(
        settings=_BROWSER_USE,
        run_status=run_status,
        event_types={"browser_session_started", "credential_page_ready"},
        browser_session_id="bu_1",
        hitl=_hitl("provider_verification"),
    )

    assert state.can_resume is False
    assert state.can_submit_credential is False
    assert state.can_submit_login is False
    assert state.interaction_available is False


def test_plan_only_runs_report_no_browser_attempt() -> None:
    state = project_browser_ui(
        settings=_BROWSER_USE, run_status="route_selected", event_types=set(), plan_only=True
    )

    assert state.lifecycle == "not_started"
    assert state.reason_code == "plan_only_run"
    assert state.live_view_available is False
    assert state.can_submit_credential is False


def test_screenshot_availability_requires_an_actual_frame() -> None:
    without_frame = project_browser_ui(
        settings=_PLAYWRIGHT,
        run_status="browser_running",
        event_types={"browser_session_started"},
        browser_session_id="pw_1",
        screenshot_present=False,
    )

    assert without_frame.screenshot_available is False
    # No frame means there is genuinely nothing to show yet.
    assert without_frame.live_view_mode == "unavailable"
    assert without_frame.live_view_available is False


def test_interactive_playwright_streams_continuously_but_controls_only_during_hitl() -> None:
    waiting = project_browser_ui(
        settings=_PLAYWRIGHT_INTERACTIVE,
        run_status="waiting_for_hitl",
        event_types={"browser_hitl_required"},
        browser_session_id="pw_1",
        screenshot_present=False,
        hitl=_hitl("captcha"),
    )
    running = project_browser_ui(
        settings=_PLAYWRIGHT_INTERACTIVE,
        run_status="browser_running",
        event_types={"browser_session_started"},
        browser_session_id="pw_1",
        screenshot_present=True,
    )
    disabled = project_browser_ui(
        settings=_PLAYWRIGHT,
        run_status="waiting_for_hitl",
        event_types={"browser_hitl_required"},
        browser_session_id="pw_1",
        screenshot_present=True,
        hitl=_hitl("captcha"),
    )

    assert waiting.live_view_mode == "interactive_remote"
    assert waiting.interaction_available is True
    assert running.live_view_mode == "interactive_remote"
    assert running.interaction_available is False
    assert disabled.live_view_mode == "screenshot"
    assert disabled.interaction_available is False


# --- production path: api.main installs the projection layers ----------------
def _production_detail(tmp_path: Path) -> dict[str, Any]:
    """Run the production entry point in a SEPARATE process and return run detail.

    Importing ``api.main`` installs the assignment runtime, live bootstrap and
    projection patches onto shared classes permanently, so it must never be
    imported into this test session — it would change which code path every later
    test exercises.
    """

    root = Path(__file__).resolve().parents[1]
    environment = {
        **os.environ,
        "BROWSER_PROVIDER": "playwright",
        "ALLOW_LIVE_BROWSER": "true",
        "BROWSER_SERVICE_URL": "http://browser-worker:8081",
        "BROWSER_SERVICE_TOKEN": "service-token-" + ("s" * 32),
        "BROWSER_SESSION_CAPABILITY_KEY": "c" * 32,
        "OPS_INTERNAL_API_TOKEN": "probe-internal-token-" + ("i" * 32),
        "OPS_DB_PATH": str(tmp_path / "ops.db"),
        "CHECKPOINT_DB_PATH": str(tmp_path / "checkpoints.db"),
        "SECRET_VAULT_DB_PATH": str(tmp_path / "vault.db"),
        "PROVIDER_EFFECTS_DB_PATH": str(tmp_path / "effects.db"),
        "RESEARCH_CACHE_DB_PATH": str(tmp_path / "research.db"),
        "PYTHONPATH": str(root),
    }
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, str(root / "tests" / "support" / "api_main_probe.py")],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=root,
        env=environment,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    payload = json.loads(completed.stdout.strip().splitlines()[-1])
    assert "error" not in payload, payload
    return cast("dict[str, Any]", payload)


def test_production_api_main_projection_is_provider_aware(tmp_path: Path) -> None:
    detail_payload = _production_detail(tmp_path)
    browser = detail_payload["browser"]

    # api.main uses the same unpatched application factory as tests, and the
    # production projection must report the selected provider.
    assert browser["provider"] == "playwright"
    assert browser["lifecycle"] == "not_started"
    assert browser["reason_code"] == "plan_only_run"
    assert browser["interaction_available"] is False
    assert browser["can_submit_credential"] is False
    assert browser["credential_page_verified"] is False

    # Readiness is reported independently for both providers. Playwright is
    # configured without requiring a Browser Use key.
    states = {state["provider"]: state for state in detail_payload["provider_states"]}
    assert states["browser_use"]["status"] == "disabled"
    assert states["playwright"]["status"] == "configured_not_verified"

    # The production phase projection describes the selected provider too.
    browser_phase = next(phase for phase in detail_payload["phases"] if phase["key"] == "browser")
    assert "Browser Use" not in browser_phase["detail"]
