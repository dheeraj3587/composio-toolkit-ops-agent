"""The audit trail holds every onboarding fact, redacted at write (17.12, 19.4).

One walk through the four kinds of fact Requirement 17.12 names — a phase
transition, a decision with its reason code, an escalation, and an effect
reservation followed by its completion — written in a single unit of work, then read
back through a *fresh* storage handle because "durable" means the rows outlive the
object that wrote them.

The secret non-leakage claim over these payloads is quantified in
``tests/test_onboarding_secret_nonleakage.py``; this module pins that the writers
exist, are atomic with the facts they describe, and keep the correlation set intact
through key-aware redaction.
"""

from __future__ import annotations

from pathlib import Path

from ops.core.storage import (
    ONBOARDING_AUDIT_DECISION_RECORDED,
    ONBOARDING_AUDIT_EFFECT_COMPLETED,
    ONBOARDING_AUDIT_EFFECT_RESERVED,
    ONBOARDING_AUDIT_ESCALATION_RAISED,
    ONBOARDING_AUDIT_EVENT_TYPES,
    ONBOARDING_AUDIT_PHASE_COMMITTED,
    OnboardingAuditContext,
    OperationsStorage,
)

RUN_ID = "run-audit-trail"
DIGEST = "a" * 64
CORRELATION_ID = "b" * 32
SESSION_ID = "bs_" + ("c" * 16)
OPERATION_KEY = f"{RUN_ID}:create-dev-app:0123456789abcdef:v1"


def test_one_onboarding_walk_leaves_a_complete_audit_trail(tmp_path: Path) -> None:
    db_path = tmp_path / "private" / "ops.db"
    storage = OperationsStorage(db_path)
    storage.create_run(
        run_id=RUN_ID,
        thread_id=f"thread-{RUN_ID}",
        app_name="Acme Labs",
        app_slug="acme-labs",
    )
    context = OnboardingAuditContext(
        run_id=RUN_ID,
        phase="developer_app",
        profile_digest=DIGEST,
        attempt=0,
        correlation_id=CORRELATION_ID,
        browser_session_id=SESSION_ID,
        vault_reference_id="ref0123456789",
    )

    with storage.unit_of_work() as transaction:
        transaction.record_phase_transition_audit(
            context=context,
            from_phase="authenticated",
            to_phase="developer_app",
            reason_code="developer_app_created",
        )
        transaction.record_decision_audit(
            context=context,
            decision="route_selected_login",
            reason_code="credentials_present",
            decided_by="system",
        )
        transaction.record_escalation_audit(
            context=context,
            gate_type="captcha",
            reason_code="captcha_detected",
        )
        transaction.record_effect_reservation_audit(
            context=context,
            operation_key=OPERATION_KEY,
            effect="create_dev_app",
            generation=0,
            disposition="execute",
            reason_code="developer_app_created",
        )
        transaction.record_effect_completion_audit(
            context=context,
            operation_key=OPERATION_KEY,
            effect="create_dev_app",
            generation=0,
            reason_code="developer_app_created",
            receipt={"developer_app_id": "app-91745"},
        )

    events = OperationsStorage(db_path).list_audit_events(RUN_ID)
    assert [event["event_type"] for event in events] == [
        ONBOARDING_AUDIT_PHASE_COMMITTED,
        ONBOARDING_AUDIT_DECISION_RECORDED,
        ONBOARDING_AUDIT_ESCALATION_RAISED,
        ONBOARDING_AUDIT_EFFECT_RESERVED,
        ONBOARDING_AUDIT_EFFECT_COMPLETED,
    ]
    assert set(ONBOARDING_AUDIT_EVENT_TYPES) == {event["event_type"] for event in events}

    # The correlation set survives redaction on every row, whatever the row is about.
    for event in events:
        payload = event["payload"]
        assert payload["run_id"] == RUN_ID
        assert payload["onboarding_phase"] == "developer_app"
        assert payload["profile_digest"] == DIGEST
        assert payload["attempt"] == 0
        assert payload["correlation_id"] == CORRELATION_ID
        assert payload["browser_session_id"] == SESSION_ID
        assert payload["vault_reference_id"] == "ref0123456789"
        assert payload["reason_code"] in {
            "developer_app_created",
            "credentials_present",
            "captcha_detected",
        }

    boundary, decision, escalation, reserved, completed = events
    assert boundary["payload"]["from_phase"] == "authenticated"
    assert boundary["payload"]["to_phase"] == "developer_app"
    assert decision["payload"]["decision"] == "route_selected_login"
    assert decision["payload"]["decided_by"] == "system"
    assert escalation["payload"]["gate_type"] == "captcha"
    assert reserved["payload"]["operation_id"] == OPERATION_KEY
    assert reserved["payload"]["disposition"] == "execute"
    assert completed["payload"]["effect"] == "create_dev_app"
    assert completed["payload"]["receipt"] == {"developer_app_id": "app-91745"}
