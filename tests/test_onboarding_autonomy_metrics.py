"""Autonomy metrics computed from the durable outcome records (Requirement 20.6).

One happy path: two runs are recorded in the real SQLite run ledger — one fully
autonomous, one blocked after a CAPTCHA — and the metric set is built from the
rows the ledger reads back rather than from any log line. The same rows are then
projected onto the run detail view the API consumes (Requirement 20.8), and the
correlation carries the nine identifiers Requirement 20.1 asks for.
"""

from __future__ import annotations

from ops.browser.metrics import (
    CORRELATION_FIELDS,
    AutonomyOutcomeRecord,
    OnboardingAutonomyMetrics,
    OnboardingCorrelation,
    autonomy_outcome_view,
)
from ops.core.storage import OperationsStorage
from ops.onboarding.driver import LedgerAutonomyOutcomes, SQLitePhaseHistoryStore

DIGEST = "b" * 64


def _outcome(
    run_id: str,
    *,
    verdict: str,
    terminal_phase: str,
    reason_code: str,
    captcha_prompts: int = 0,
    verification_attempts: int = 0,
    validation_attempts: int = 0,
    navigation_denials: int = 0,
) -> dict[str, object]:
    """One 19-field outcome record, the shape the driver hands the ledger."""

    return {
        "run_id": run_id,
        "profile_digest": DIGEST,
        "verdict": verdict,
        "terminal_phase": terminal_phase,
        "reason_code": reason_code,
        "started_at": "2025-01-01T00:00:00Z",
        "ended_at": "2025-01-01T00:05:00Z",
        "admission_prompts": 1,
        "captcha_prompts": captcha_prompts,
        "other_operator_prompts": 0,
        "model_calls": 4,
        "actions_executed": 11,
        "navigation_denials": navigation_denials,
        "phases_replayed": 0,
        "effects_skipped_as_duplicate": 1,
        "outcome_unknown_effects": 0,
        "verification_attempts": verification_attempts,
        "validation_attempts": validation_attempts,
        "duration_seconds": 300,
    }


def test_metrics_and_view_are_computed_from_the_durable_outcome_rows(tmp_path) -> None:
    db_path = tmp_path / "private" / "ops.db"
    ledger = OperationsStorage(db_path)
    phases = SQLitePhaseHistoryStore(db_path)
    for run_id in ("run-metrics-a", "run-metrics-b"):
        ledger.create_run(
            run_id=run_id,
            thread_id=f"thread-{run_id}",
            app_name="Example Provider",
            app_slug="example-provider",
        )

    assert ledger.record_autonomy_outcome(
        outcome=_outcome(
            "run-metrics-a",
            verdict="fully_autonomous",
            terminal_phase="completed",
            reason_code="credential_valid",
            verification_attempts=1,
            validation_attempts=1,
        )
    )
    assert ledger.record_autonomy_outcome(
        outcome=_outcome(
            "run-metrics-b",
            verdict="blocked",
            terminal_phase="blocked",
            reason_code="captcha_attempt_budget_exhausted",
            captcha_prompts=2,
            verification_attempts=1,
            navigation_denials=3,
        )
    )

    # The two per-phase metrics come from committed boundaries, which are durable
    # for the same reason the outcomes are.
    walk = (
        (None, "research", "profile_corroborated"),
        ("research", "vault_check", "profile_corroborated"),
        ("vault_check", "route_selected_login", "credentials_present"),
        ("route_selected_login", "authenticated", "session_reattached"),
    )
    for from_phase, to_phase, reason_code in walk:
        assert phases.commit_phase(
            run_id="run-metrics-a",
            from_phase=from_phase,
            to_phase=to_phase,
            reason_code=reason_code,
            profile_digest=DIGEST,
            attempt=0,
            correlation_id=f"seed-{to_phase}",
        )

    # The denial facts behind the blocked run, which supply only the per-phase
    # breakdown; the headline denial count comes from the outcome rows.
    for _ in range(3):
        ledger.record_navigation_denial(
            run_id="run-metrics-b",
            phase="signup",
            profile_digest=DIGEST,
            reason_code="browser_host_not_in_app_policy",
        )

    metrics = OnboardingAutonomyMetrics.from_records(
        outcomes=ledger.list_autonomy_outcomes(),
        boundaries=ledger.list_phase_boundaries(),
        denials=ledger.list_navigation_denials(),
    )

    assert metrics.runs_measured == 2
    assert metrics.runs_completed == 1
    assert metrics.fully_autonomous_completion_rate == 0.5
    # One admission prompt on the one completed run, and no CAPTCHA on it.
    assert metrics.operator_prompts_per_completed_run == 1.0
    assert metrics.phase_failure_counts_by_reason() == {
        "blocked:captcha_attempt_budget_exhausted": 1
    }
    # Both runs read a mailbox; neither carries `verification_unresolved`.
    assert metrics.verification_resolution_rate == 1.0
    assert metrics.first_attempt_validation_pass_rate == 1.0
    assert metrics.off_domain_denial_count == 3
    assert metrics.denials_by_phase == {"signup": 3}
    assert metrics.reattach_success_rate == 1.0
    assert metrics.duplicate_prevention_hits == 2
    assert metrics.outcome_unknown_count == 0

    snapshot = metrics.snapshot()
    assert set(snapshot["phase_duration_seconds"]) == {
        "research",
        "vault_check",
        "route_selected_login",
    }
    assert snapshot["time_to_verification_seconds"] == {
        "count": 0.0,
        "median_seconds": 0.0,
        "p95_seconds": 0.0,
        "max_seconds": 0.0,
    }

    # Requirement 20.8: the terminal run's outcome projects onto the run detail
    # view, and only the six declared view fields come with it.
    row = ledger.read_autonomy_outcome("run-metrics-a")
    assert row is not None
    assert autonomy_outcome_view(row) == {
        "verdict": "fully_autonomous",
        "terminal_phase": "completed",
        "reason_code": "credential_valid",
        "admission_prompts": 1,
        "captcha_prompts": 0,
        "duration_seconds": 300,
    }
    # The same record read back through the driver's reader port.
    outcome = LedgerAutonomyOutcomes(ledger).read_autonomy_outcome(run_id="run-metrics-a")
    assert outcome is not None
    assert autonomy_outcome_view(outcome.as_record()) == autonomy_outcome_view(row)

    # Requirement 20.1: the nine identifiers, assembled once and carried on the
    # log record, the metric labels, and the timeline event alike.
    correlation = AutonomyOutcomeRecord.from_row(row).correlation(
        attempt=1,
        session_id="session-a",
        correlation_id="corr-a",
        vault_reference_id="vault://example-provider/api_key/cred-1",
        browser_session_id="bsession-a",
    )
    assert isinstance(correlation, OnboardingCorrelation)
    assert tuple(correlation.as_log_fields()) == CORRELATION_FIELDS
    assert len(CORRELATION_FIELDS) == 9
    assert correlation.as_timeline_fields() == correlation.as_log_fields()
    assert correlation.as_metric_labels()["attempt"] == "1"
