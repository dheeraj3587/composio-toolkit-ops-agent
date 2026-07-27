"""Durable signup state-machine skeleton.

This milestone models policy branching and restart-safe transitions only. It does
not inspect, fill, or submit a browser form.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ops.policies import AccountPolicy
from ops.private_files import finalize_private_database, prepare_private_database


class SignupState(StrEnum):
    SIGNUP_NOT_STARTED = "signup_not_started"
    SIGNUP_PAGE_LOADING = "signup_page_loading"
    SIGNUP_FORM_DETECTED = "signup_form_detected"
    ACCOUNT_EXISTS_DETECTED = "account_exists_detected"
    SIGNUP_VALUES_READY = "signup_values_ready"
    SIGNUP_FORM_FILLED = "signup_form_filled"
    SIGNUP_SUBMISSION_READY = "signup_submission_ready"
    SIGNUP_SUBMITTED = "signup_submitted"
    EMAIL_VERIFICATION_REQUIRED = "email_verification_required"
    EMAIL_VERIFICATION_PENDING = "email_verification_pending"
    EMAIL_VERIFICATION_APPLYING = "email_verification_applying"
    ACCOUNT_CREATED = "account_created"
    SIGNUP_FAILED = "signup_failed"


_LEGAL_TRANSITIONS: dict[SignupState, frozenset[SignupState]] = {
    SignupState.SIGNUP_NOT_STARTED: frozenset(
        {
            SignupState.SIGNUP_PAGE_LOADING,
            SignupState.ACCOUNT_EXISTS_DETECTED,
            SignupState.SIGNUP_FAILED,
        }
    ),
    SignupState.SIGNUP_PAGE_LOADING: frozenset(
        {
            SignupState.SIGNUP_FORM_DETECTED,
            SignupState.ACCOUNT_EXISTS_DETECTED,
            SignupState.SIGNUP_FAILED,
        }
    ),
    SignupState.SIGNUP_FORM_DETECTED: frozenset(
        {
            SignupState.SIGNUP_VALUES_READY,
            SignupState.ACCOUNT_EXISTS_DETECTED,
            SignupState.SIGNUP_FAILED,
        }
    ),
    SignupState.ACCOUNT_EXISTS_DETECTED: frozenset(),
    SignupState.SIGNUP_VALUES_READY: frozenset(
        {SignupState.SIGNUP_FORM_FILLED, SignupState.SIGNUP_FAILED}
    ),
    SignupState.SIGNUP_FORM_FILLED: frozenset(
        {SignupState.SIGNUP_SUBMISSION_READY, SignupState.SIGNUP_FAILED}
    ),
    SignupState.SIGNUP_SUBMISSION_READY: frozenset(
        {SignupState.SIGNUP_SUBMITTED, SignupState.SIGNUP_FAILED}
    ),
    SignupState.SIGNUP_SUBMITTED: frozenset(
        {
            SignupState.EMAIL_VERIFICATION_REQUIRED,
            SignupState.ACCOUNT_CREATED,
            SignupState.SIGNUP_FAILED,
        }
    ),
    SignupState.EMAIL_VERIFICATION_REQUIRED: frozenset(
        {SignupState.EMAIL_VERIFICATION_PENDING, SignupState.SIGNUP_FAILED}
    ),
    SignupState.EMAIL_VERIFICATION_PENDING: frozenset(
        {SignupState.EMAIL_VERIFICATION_APPLYING, SignupState.SIGNUP_FAILED}
    ),
    SignupState.EMAIL_VERIFICATION_APPLYING: frozenset(
        {SignupState.ACCOUNT_CREATED, SignupState.SIGNUP_FAILED}
    ),
    SignupState.ACCOUNT_CREATED: frozenset(),
    SignupState.SIGNUP_FAILED: frozenset({SignupState.SIGNUP_PAGE_LOADING}),
}


class SignupStateConflict(RuntimeError):
    """Raised on an illegal or stale signup transition."""


class SignupStateSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    run_id: str = Field(min_length=1, max_length=180, pattern=r"^[A-Za-z0-9_-]+$")
    state: SignupState
    revision: int = Field(ge=0)
    updated_at: str


@dataclass(frozen=True, slots=True)
class SignupPolicyDecision:
    state: SignupState
    next_phase: Literal["signup", "login_account_detection"]
    account_creation_authorized: bool
    reason_code: str


class SQLiteSignupStateStore:
    """One monotonic signup state per run, persisted across process restarts."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

    def initialize(self) -> None:
        existed = prepare_private_database(self.db_path)
        connection = sqlite3.connect(self.db_path, timeout=10)
        try:
            finalize_private_database(self.db_path, existed=existed)
            connection.execute("PRAGMA secure_delete = ON")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS signup_states (
                    run_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.commit()
        finally:
            connection.close()

    def get_or_create(self, run_id: str) -> SignupStateSnapshot:
        self.initialize()
        now = _utc_now()
        with sqlite3.connect(self.db_path, timeout=10) as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO signup_states(run_id, state, revision, updated_at)
                VALUES (?, ?, 0, ?)
                """,
                (run_id, SignupState.SIGNUP_NOT_STARTED.value, now),
            )
            row = connection.execute(
                "SELECT run_id, state, revision, updated_at FROM signup_states WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            connection.commit()
        if row is None:
            raise RuntimeError("signup state initialization failed")
        return _snapshot(row)

    def transition(
        self,
        run_id: str,
        next_state: SignupState,
        *,
        expected_revision: int | None = None,
    ) -> SignupStateSnapshot:
        self.initialize()
        with sqlite3.connect(self.db_path, timeout=10) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT run_id, state, revision, updated_at FROM signup_states WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise KeyError("signup state was not initialized")
            current = _snapshot(row)
            if expected_revision is not None and current.revision != expected_revision:
                connection.rollback()
                raise SignupStateConflict("signup state revision changed")
            if current.state == next_state:
                connection.commit()
                return current
            if next_state not in _LEGAL_TRANSITIONS[current.state]:
                connection.rollback()
                raise SignupStateConflict(
                    f"illegal signup transition {current.state.value} -> {next_state.value}"
                )
            now = _utc_now()
            cursor = connection.execute(
                """
                UPDATE signup_states
                SET state = ?, revision = ?, updated_at = ?
                WHERE run_id = ? AND revision = ?
                """,
                (next_state.value, current.revision + 1, now, run_id, current.revision),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise SignupStateConflict("signup state update lost its revision race")
            connection.commit()
        return SignupStateSnapshot(
            run_id=run_id,
            state=next_state,
            revision=current.revision + 1,
            updated_at=now,
        )


class SignupStateMachine:
    """Policy-aware facade over the durable state store."""

    def __init__(self, store: SQLiteSignupStateStore) -> None:
        self._store = store

    def snapshot(self, run_id: str) -> SignupStateSnapshot:
        return self._store.get_or_create(run_id)

    def plan(
        self,
        run_id: str,
        *,
        account_policy: AccountPolicy,
        account_exists: bool,
    ) -> SignupPolicyDecision:
        current = self._store.get_or_create(run_id)
        if account_policy == "reuse_existing" or account_exists:
            target = SignupState.ACCOUNT_EXISTS_DETECTED
            updated = self._store.transition(
                run_id,
                target,
                expected_revision=current.revision,
            )
            return SignupPolicyDecision(
                state=updated.state,
                next_phase="login_account_detection",
                account_creation_authorized=False,
                reason_code=(
                    "account_policy_reuses_existing"
                    if account_policy == "reuse_existing"
                    else "existing_account_detected"
                ),
            )

        updated = self._store.transition(
            run_id,
            SignupState.SIGNUP_PAGE_LOADING,
            expected_revision=current.revision,
        )
        return SignupPolicyDecision(
            state=updated.state,
            next_phase="signup",
            account_creation_authorized=True,
            reason_code="account_missing_and_creation_authorized",
        )

    def advance(
        self,
        run_id: str,
        next_state: SignupState,
        *,
        expected_revision: int | None = None,
    ) -> SignupStateSnapshot:
        return self._store.transition(
            run_id,
            next_state,
            expected_revision=expected_revision,
        )


def _snapshot(row: tuple[object, ...]) -> SignupStateSnapshot:
    return SignupStateSnapshot(
        run_id=str(row[0]),
        state=SignupState(str(row[1])),
        revision=int(row[2]),
        updated_at=str(row[3]),
    )


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


__all__ = [
    "SQLiteSignupStateStore",
    "SignupPolicyDecision",
    "SignupState",
    "SignupStateConflict",
    "SignupStateMachine",
    "SignupStateSnapshot",
]
