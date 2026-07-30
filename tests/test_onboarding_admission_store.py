"""One walk over the admission decision table: record, read back, and the DDL's refusal.

A login decision and an operator-approved signup decision for two runs cover the
write path both routes take, and a raw insert of a system-decided signup covers the
claim that the constraint lives in the schema and not only in the dataclass.
"""

from __future__ import annotations

import sqlite3

import pytest

from ops.core.storage import OperationsStorage
from ops.onboarding.admission import AdmissionDecision

DIGEST = "b" * 64
LOGIN_REFS = (
    ("login_email", "vault://acme-provider/account_login_email/ref-1"),
    ("login_password", "vault://acme-provider/account_login_password/ref-2"),
)


@pytest.fixture
def storage(tmp_path) -> OperationsStorage:
    store = OperationsStorage(tmp_path / "private" / "ops.db")
    for run_id in ("run-login", "run-signup", "run-raw"):
        store.create_run(
            run_id=run_id,
            thread_id=f"thread-{run_id}",
            app_name="Acme Provider",
            app_slug="acme-provider",
        )
    return store


def test_both_routes_round_trip_and_a_system_signup_is_refused(storage) -> None:
    login = AdmissionDecision(
        run_id="run-login",
        profile_digest=DIGEST,
        route="login",
        reason_code="credentials_present",
        decided_by="system",
        actor_owner_id="owner-1",
        decided_at="2025-01-01T00:00:00Z",
        credential_refs=LOGIN_REFS,
    )
    signup = AdmissionDecision(
        run_id="run-signup",
        profile_digest=DIGEST,
        route="signup",
        reason_code="operator_approved_signup",
        decided_by="operator",
        actor_owner_id="owner-2",
        decided_at="2025-01-01T00:05:00Z",
    )

    stored_login, replayed_login = storage.record_admission_decision(login)
    stored_signup, replayed_signup = storage.record_admission_decision(signup)
    assert (stored_login, replayed_login) == (login, False)
    assert (stored_signup, replayed_signup) == (signup, False)

    assert storage.read_admission_decision("run-login") == login
    assert storage.read_admission_decision("run-signup") == signup

    # Requirement 3.8: a second submission returns the original, unchanged.
    second = AdmissionDecision(
        run_id="run-signup",
        profile_digest=DIGEST,
        route="cancelled",
        reason_code="operator_cancelled",
        decided_by="operator",
        actor_owner_id="owner-3",
        decided_at="2025-01-01T00:09:00Z",
    )
    original, replayed = storage.record_admission_decision(second)
    assert (original, replayed) == (signup, True)

    # The dataclass cannot represent a system-decided signup, so the schema's own
    # refusal is checked the only way it can be: by writing around this module.
    with sqlite3.connect(storage.db_path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="CHECK"):
            connection.execute(
                """
                INSERT INTO onboarding_admission_decisions (
                    run_id, profile_digest, route, reason_code, decided_by,
                    actor_owner_id, decided_at, credential_refs_json
                ) VALUES ('run-raw', ?, 'signup', 'operator_approved_signup',
                          'system', 'owner-4', '2025-01-01T00:10:00Z', '[]')
                """,
                (DIGEST,),
            )
