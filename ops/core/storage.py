"""Narrow, sanitized persistence API for runs and structured audit events."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, get_args

from ops.browser.worker import HumanActionType
from ops.core.private_files import finalize_private_database, prepare_private_database
from ops.core.redaction import redact_data, redact_text
from ops.core.secret_store import parse_vault_reference
from ops.core.state import AccessRoute, RunStatus
from ops.onboarding.admission import AdmissionDecider, AdmissionDecision, AdmissionRoute
from ops.onboarding.effects import ONBOARDING_EFFECT_DISPOSITIONS, ONBOARDING_EFFECTS
from ops.onboarding.phase import ONBOARDING_PHASES, ONBOARDING_REASON_CODES

_RUN_COLUMNS = (
    "run_id",
    "thread_id",
    "app_name",
    "app_slug",
    "status",
    "access_route",
    "browser_session_id",
    "browser_live_url",
    "gmail_session_id",
    "gmail_thread_id",
    "integrator_bundle_json",
    "p1_summary_json",
    "operational_research_json",
    "request_json",
    "route_reason_code",
    "route_explanation",
    "missing_fields_json",
    "provider_status_json",
    "hitl_request_json",
    "validation_json",
    "scope_policy",
    "execution_mode",
    "browser_provider",
    "credential_creation_policy",
    "recipe_version",
    "recipe_snapshot_json",
    "route_kind",
    "readiness_tier",
    "browser_account_ref",
    "provider_session_id",
    "connection_request_id",
    "attempt",
    "phase",
    "reason_code",
    "effect_identity",
    "state_engine",
    "external_actions",
    "state_revision",
    "last_projected_revision",
    "created_at",
    "updated_at",
)

_JSON_RUN_FIELDS = {
    "integrator_bundle": "integrator_bundle_json",
    "p1_summary": "p1_summary_json",
    "operational_research": "operational_research_json",
    "request": "request_json",
    "recipe_snapshot": "recipe_snapshot_json",
    "missing_fields": "missing_fields_json",
    "provider_status": "provider_status_json",
    "hitl_request": "hitl_request_json",
    "validation": "validation_json",
}

_DEFAULT_JSON_VALUES: dict[str, object] = {
    "missing_fields": [],
    "provider_status": {},
}


# The onboarding effect reservation row carries identifiers a completed effect
# recorded — a developer application id, a vault reference id — and never
# material. The bound is enforced twice: here before the write, and by the
# table's own CHECK, so a writer that bypasses this module cannot store a blob.
MAX_EFFECT_RECEIPT_LENGTH = 2_000

_SIDE_EFFECT_STATUSES = frozenset({"pending", "completed", "outcome_unknown", "failed"})


# The audit trail's onboarding event types (Requirement 17.12, design "Event
# Model"). Closed and exported, so the timeline projector keys its static
# summaries off the same five strings the writers below emit rather than
# re-typing them.
ONBOARDING_AUDIT_PHASE_COMMITTED: Final = "onboarding_phase_committed"
ONBOARDING_AUDIT_DECISION_RECORDED: Final = "onboarding_decision_recorded"
ONBOARDING_AUDIT_ESCALATION_RAISED: Final = "onboarding_escalation_raised"
ONBOARDING_AUDIT_EFFECT_RESERVED: Final = "onboarding_effect_reserved"
ONBOARDING_AUDIT_EFFECT_COMPLETED: Final = "onboarding_effect_completed"

ONBOARDING_AUDIT_EVENT_TYPES: Final[tuple[str, ...]] = (
    ONBOARDING_AUDIT_PHASE_COMMITTED,
    ONBOARDING_AUDIT_DECISION_RECORDED,
    ONBOARDING_AUDIT_ESCALATION_RAISED,
    ONBOARDING_AUDIT_EFFECT_RESERVED,
    ONBOARDING_AUDIT_EFFECT_COMPLETED,
)

# The gate vocabulary an escalation row may name, taken from the type the browser
# worker and the gate policy are written against rather than retyped.
_ESCALATION_GATES: Final[tuple[HumanActionType, ...]] = get_args(HumanActionType)

# Every identifier an onboarding audit payload carries is bounded, and the bound is
# well below the audit column's practical size so one row cannot become a blob.
MAX_AUDIT_IDENTIFIER_LENGTH: Final = 200

# The label shape a decision name and a disposition share: lower snake_case, which
# is also the character class ``api.models.ReasonCode`` admits, so a decision label
# projects onto a timeline event without translation and no provider or page text
# can ride along inside one.
_AUDIT_LABEL = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

_PROFILE_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def _vocabulary_clause(values: tuple[str, ...]) -> str:
    """Render a closed vocabulary as a SQL ``IN`` list.

    The vocabularies come from :mod:`ops.onboarding.effects` rather than being
    retyped here, so the table's CHECK and the code that computes the values
    cannot disagree. Every member is asserted to be a bare snake_case word before
    it is interpolated, so no value can carry SQL of its own.
    """

    if not values:
        raise ValueError("a vocabulary clause needs at least one member")
    for value in values:
        if not value or not value.replace("_", "").isalnum() or not value.isascii():
            raise ValueError(f"vocabulary member is not a bare identifier: {value!r}")
    return ", ".join(f"'{value}'" for value in values)


# One row per (run, operation key): the onboarding-shaped view of a reservation
# that ``side_effect_intents`` holds the uniqueness for. The two tables are
# written in the same transaction as the phase commit, so a concurrent claim
# cannot land between the boundary and the reservation (Requirement 13.13).
_EFFECT_RESERVATIONS_DDL = f"""
CREATE TABLE IF NOT EXISTS onboarding_effect_reservations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    operation_key TEXT NOT NULL,
    effect TEXT NOT NULL CHECK (
        effect IN ({_vocabulary_clause(ONBOARDING_EFFECTS)})
    ),
    generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
    phase TEXT NOT NULL,
    disposition TEXT NOT NULL CHECK (
        disposition IN ({_vocabulary_clause(ONBOARDING_EFFECT_DISPOSITIONS)})
    ),
    receipt_json TEXT CHECK (
        receipt_json IS NULL
        OR (receipt_json LIKE '{{%}}' AND length(receipt_json) <= {MAX_EFFECT_RECEIPT_LENGTH})
    ),
    reason_code TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (run_id, operation_key),
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);
"""


# The two admission vocabularies as data, taken from the Literals in
# ``ops.onboarding.admission`` rather than retyped, so the table's CHECK lists and
# the type the deciding code is written against cannot drift apart.
_ADMISSION_ROUTES: Final[tuple[AdmissionRoute, ...]] = get_args(AdmissionRoute)
_ADMISSION_DECIDERS: Final[tuple[AdmissionDecider, ...]] = get_args(AdmissionDecider)

# A run needs two login references. The bound exists so that a *value* smuggled
# past the reference grammar — a long blob under a plausible field name — cannot
# be stored either.
MAX_CREDENTIAL_REFS_JSON_LENGTH = 1_000


# One row per run: admission is decided once, and the PRIMARY KEY is what makes a
# second decision unrepresentable rather than merely discouraged (Requirement
# 3.8's replay reads the original row back instead of overwriting it).
#
# The two CHECKs restate constraints that ``AdmissionDecision.__post_init__``
# already enforces, and the redundancy is deliberate (design LL-1.4): the
# dataclass protects callers that go through it, the table protects the durable
# record from anything that does not.
#   * ``route <> 'signup' OR decided_by = 'operator'`` — no autonomous path can
#     leave behind a stored authorization for account creation (Requirements 3.5,
#     3.6).
#   * the ``credential_refs_json`` shape — the column holds ``vault://`` references
#     or the empty list, never credential material (Requirement 19.8).
_ADMISSION_DECISIONS_DDL = f"""
CREATE TABLE IF NOT EXISTS onboarding_admission_decisions (
    run_id TEXT PRIMARY KEY,
    profile_digest TEXT NOT NULL,
    route TEXT NOT NULL CHECK (
        route IN ({_vocabulary_clause(_ADMISSION_ROUTES)})
    ),
    reason_code TEXT NOT NULL,
    decided_by TEXT NOT NULL CHECK (
        decided_by IN ({_vocabulary_clause(_ADMISSION_DECIDERS)})
    ),
    actor_owner_id TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    credential_refs_json TEXT NOT NULL DEFAULT '[]' CHECK (
        (credential_refs_json = '[]' OR credential_refs_json LIKE '%vault://%')
        AND length(credential_refs_json) <= {MAX_CREDENTIAL_REFS_JSON_LENGTH}
    ),
    CHECK (route <> 'signup' OR decided_by = 'operator'),
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);
"""


# One row per navigation denial (Requirement 5.15). Append-only on purpose: a
# denial is a fact about a moment, so the tenth denial of a phase does not
# overwrite the first — the count of rows is what makes "the loop kept trying to
# leave the allow-list" visible after the run ended.
#
# Every column is closed or fixed-width: the phase and the reason code come from
# the onboarding vocabularies (the CHECK lists are generated from them rather than
# retyped), the digest is a content address, and there is no free-form column at
# all. That is what keeps the URL the loop refused to visit — which is attacker-
# influenced text — out of the durable record entirely.
_NAVIGATION_DENIALS_DDL = f"""
CREATE TABLE IF NOT EXISTS onboarding_navigation_denials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (
        phase IN ({_vocabulary_clause(ONBOARDING_PHASES)})
    ),
    profile_digest TEXT NOT NULL,
    reason_code TEXT NOT NULL CHECK (
        reason_code IN ({_vocabulary_clause(ONBOARDING_REASON_CODES)})
    ),
    recorded_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_navigation_denials_run
ON onboarding_navigation_denials(run_id, id);
"""


# The autonomy verdict vocabulary (design LL-1.7). Typed here rather than
# imported from :mod:`ops.onboarding.driver`, which owns the ``AutonomyVerdict``
# Literal: the driver imports *this* module for the run ledger, so importing it
# back would be a cycle. Drift is refused rather than tolerated — the driver
# asserts at import time that its Literal and this tuple are the same four words,
# so a verdict added on one side fails to import instead of failing a CHECK
# against a live run.
AUTONOMY_VERDICT_VALUES: Final[tuple[str, ...]] = (
    "fully_autonomous",
    "operator_assisted",
    "blocked",
    "cancelled",
)

# An autonomy outcome's two timestamps are ISO-8601 UTC text, so the bound only
# has to be wide enough for that and narrow enough that no story fits in it.
MAX_AUTONOMY_TIMESTAMP_LENGTH: Final = 64

# The 19 fields of the autonomy outcome, split by the shape each column holds.
# Written down once, in the table's own column order, so the writer below does not
# list them a second time and the driver can hand over its dataclass as a mapping
# without this module restating the dataclass's fields (Requirement 20.5).
_AUTONOMY_OUTCOME_TEXT_COLUMNS: Final[tuple[str, ...]] = (
    "run_id",
    "profile_digest",
    "verdict",
    "terminal_phase",
    "reason_code",
    "started_at",
    "ended_at",
)
_AUTONOMY_OUTCOME_COUNT_COLUMNS: Final[tuple[str, ...]] = (
    "admission_prompts",
    "captcha_prompts",
    "other_operator_prompts",
    "model_calls",
    "actions_executed",
    "navigation_denials",
    "phases_replayed",
    "effects_skipped_as_duplicate",
    "outcome_unknown_effects",
    "verification_attempts",
    "validation_attempts",
    "duration_seconds",
)
_AUTONOMY_OUTCOME_COLUMNS: Final[tuple[str, ...]] = (
    *_AUTONOMY_OUTCOME_TEXT_COLUMNS,
    *_AUTONOMY_OUTCOME_COUNT_COLUMNS,
)

assert len(_AUTONOMY_OUTCOME_COLUMNS) == 19, (
    "an autonomy outcome carries the 19 fields Requirement 20.5 enumerates"
)


# One row per run: the durable record the autonomy metrics are computed from
# (Requirement 20.6), never a projection of logs.
#
# The PRIMARY KEY on ``run_id`` is what makes "exactly one record per run"
# (Requirement 20.4) unrepresentable otherwise rather than merely intended — a
# second write conflicts on it and the writer below discards the conflict, so the
# first record survives instead of being overwritten by a later replay of the
# terminal phase.
#
# Four of the CHECKs restate what ``AutonomyOutcome.__post_init__`` already
# enforces, and the redundancy is the same trade the admission table makes: the
# dataclass protects callers that go through it, the table protects the durable
# record from anything that does not.
#   * ``other_operator_prompts = 0`` — Requirement 11.15 as a storage constraint.
#     CAPTCHA and the pre-execution admission decision are the only prompts that
#     may exist, so a third one cannot be recorded even as a number.
#   * ``admission_prompts BETWEEN 0 AND 1`` — 0 on the login route, else 1.
#   * ``verdict <> 'fully_autonomous' OR (captcha_prompts = 0 AND
#     other_operator_prompts = 0)`` — Requirement 20.7. A measured autonomy rate
#     is only worth reading if the verdict cannot disagree with the counters
#     stored beside it.
#   * ``duration_seconds >= 0`` plus a non-negative CHECK on every other counter.
_AUTONOMY_OUTCOMES_DDL = f"""
CREATE TABLE IF NOT EXISTS onboarding_autonomy_outcomes (
    run_id TEXT PRIMARY KEY,
    profile_digest TEXT NOT NULL,
    verdict TEXT NOT NULL CHECK (
        verdict IN ({_vocabulary_clause(AUTONOMY_VERDICT_VALUES)})
    ),
    terminal_phase TEXT NOT NULL CHECK (
        terminal_phase IN ({_vocabulary_clause(ONBOARDING_PHASES)})
    ),
    reason_code TEXT NOT NULL CHECK (
        reason_code IN ({_vocabulary_clause(ONBOARDING_REASON_CODES)})
    ),
    started_at TEXT NOT NULL,
    ended_at TEXT NOT NULL,
    admission_prompts INTEGER NOT NULL CHECK (admission_prompts BETWEEN 0 AND 1),
    captcha_prompts INTEGER NOT NULL CHECK (captcha_prompts >= 0),
    other_operator_prompts INTEGER NOT NULL CHECK (other_operator_prompts = 0),
    model_calls INTEGER NOT NULL CHECK (model_calls >= 0),
    actions_executed INTEGER NOT NULL CHECK (actions_executed >= 0),
    navigation_denials INTEGER NOT NULL CHECK (navigation_denials >= 0),
    phases_replayed INTEGER NOT NULL CHECK (phases_replayed >= 0),
    effects_skipped_as_duplicate INTEGER NOT NULL CHECK (effects_skipped_as_duplicate >= 0),
    outcome_unknown_effects INTEGER NOT NULL CHECK (outcome_unknown_effects >= 0),
    verification_attempts INTEGER NOT NULL CHECK (verification_attempts >= 0),
    validation_attempts INTEGER NOT NULL CHECK (validation_attempts >= 0),
    duration_seconds INTEGER NOT NULL CHECK (duration_seconds >= 0),
    CHECK (
        verdict <> 'fully_autonomous'
        OR (captcha_prompts = 0 AND other_operator_prompts = 0)
    ),
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);
"""


# The columns one committed phase boundary is read back under, in the table's own
# order. Named here because the metrics reader below hands them out as a mapping.
_PHASE_BOUNDARY_COLUMNS: Final[tuple[str, ...]] = (
    "run_id",
    "sequence",
    "from_phase",
    "to_phase",
    "reason_code",
    "profile_digest",
    "attempt",
    "correlation_id",
    "committed_at",
)

# How many durable rows one metrics read may pull back. A bound rather than an
# unbounded scan: computing autonomy from durable records must stay a cheap read,
# and a deployment that wants a wider window asks for one explicitly.
MAX_METRIC_ROWS: Final = 5_000


def _metric_row_limit(limit: int) -> int:
    """Clamp a metrics window to ``1 .. MAX_METRIC_ROWS``."""

    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("a metrics window must be a positive row count")
    return min(limit, MAX_METRIC_ROWS)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _json(value: object) -> str:
    return json.dumps(
        redact_data(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _sanitize_structured(value: object) -> object:
    """Redact leaf strings while preserving a validated model's field shapes.

    Audit payloads use key-aware redaction because their shape is open-ended.
    Persisted Pydantic projections have fixed schemas whose legitimate field
    names include words such as ``token_url`` and ``credential_fields``.  A
    key-aware pass would replace those fields wholesale and make the stored
    model impossible to validate on read.
    """

    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return {str(key): _sanitize_structured(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_sanitize_structured(item) for item in value]
    return redact_data(value)


def _structured_json(value: object) -> str:
    return json.dumps(
        _sanitize_structured(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _safe_text(value: str | None) -> str | None:
    return redact_text(value) if value is not None else None


def _effect_receipt_json(receipt: Mapping[str, str] | None) -> str | None:
    """Serialize an effect receipt, refusing anything unbounded or secret-shaped.

    Mirrors ``ops.core.effect_ledger.SQLiteEffectStore._serialize_receipt`` on purpose:
    the two ledgers store the same receipt, so they must refuse the same values.
    A receipt that redaction would rewrite is rejected outright rather than
    silently stored in a redacted form, because a receipt is read back and adopted
    as fact by the skip path.
    """

    if receipt is None:
        return None
    if not receipt:
        raise ValueError("an effect receipt must carry at least one identifier")
    if not all(isinstance(key, str) and isinstance(value, str) for key, value in receipt.items()):
        raise ValueError("effect receipts must contain bounded string identifiers")
    sanitized = redact_data(dict(receipt))
    if not isinstance(sanitized, dict) or sanitized != dict(receipt):
        raise ValueError("effect receipts cannot contain secret-like values")
    serialized = json.dumps(dict(receipt), sort_keys=True, separators=(",", ":"))
    if len(serialized) > MAX_EFFECT_RECEIPT_LENGTH:
        raise ValueError("effect receipt is too large")
    return serialized


def _credential_refs_json(refs: tuple[tuple[str, str], ...]) -> str:
    """Serialize ``(login field, vault reference)`` pairs, refusing anything else.

    Every reference is parsed through the vault grammar before it is written, so a
    credential value cannot reach the column even from a caller that built the
    tuple without going through :class:`~ops.onboarding.admission.AdmissionDecision`.
    The column's own CHECK is the third line of defence behind those two.
    """

    for field, reference in refs:
        if not field or len(field) > 64:
            raise ValueError("credential reference field is invalid")
        parse_vault_reference(reference)
    serialized = json.dumps([[field, ref] for field, ref in refs], separators=(",", ":"))
    if len(serialized) > MAX_CREDENTIAL_REFS_JSON_LENGTH:
        raise ValueError("credential reference list is too large")
    return serialized


def _credential_refs(value: object) -> tuple[tuple[str, str], ...]:
    """Read the stored pairs back, re-checking the grammar on the way out."""

    if not isinstance(value, str):  # pragma: no cover - column is NOT NULL TEXT
        raise RuntimeError("admission credential references are invalid")
    decoded = json.loads(value)
    if not isinstance(decoded, list):  # pragma: no cover - written by this module
        raise RuntimeError("admission credential references are invalid")
    refs: list[tuple[str, str]] = []
    for item in decoded:
        if not isinstance(item, list) or len(item) != 2:
            raise RuntimeError("admission credential references are invalid")
        field, reference = item
        if not isinstance(field, str) or not isinstance(reference, str):
            raise RuntimeError("admission credential references are invalid")
        parse_vault_reference(reference)
        refs.append((field, reference))
    return tuple(refs)


def _audit_identifier(
    value: str,
    *,
    field: str,
    limit: int = MAX_AUDIT_IDENTIFIER_LENGTH,
) -> str:
    """Bound one identifier an audit payload carries, refusing secret-shaped text.

    A value redaction would rewrite is refused outright rather than stored in its
    redacted form, mirroring :func:`_effect_receipt_json`: an audit row exists to
    attribute a decision, and ``[REDACTED]`` in the attribution field would be a
    row that survives while its meaning does not. The refusal names the field and
    never the value.
    """

    stripped = value.strip()
    if not stripped or len(stripped) > limit:
        raise ValueError(f"an onboarding audit {field} must be a bounded, non-empty identifier")
    if redact_text(stripped) != stripped:
        raise ValueError(f"an onboarding audit {field} cannot carry secret-shaped material")
    return stripped


def _autonomy_timestamp(value: object, *, field: str) -> str:
    """One autonomy-outcome timestamp: bounded ISO-8601 UTC text, nothing else."""

    if not isinstance(value, str) or not value or len(value) > MAX_AUTONOMY_TIMESTAMP_LENGTH:
        raise ValueError(f"an autonomy outcome {field} must be a bounded timestamp")
    return value


def _autonomy_count(value: object, *, field: str) -> int:
    """One autonomy-outcome counter: a non-negative integer, and never a bool."""

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"an autonomy outcome {field} must be a non-negative count")
    return value


def _autonomy_outcome_row(outcome: Mapping[str, object]) -> tuple[object, ...]:
    """Read one autonomy outcome into the column order the table declares.

    The keys are required to be exactly the 19 declared columns, which is what
    lets the driver hand over its ``AutonomyOutcome`` as a mapping without this
    module listing that dataclass's fields a second time: a field renamed on one
    side stops matching here rather than being silently dropped on the way to the
    durable record (Requirement 20.5).

    Every value is checked against the shape its column holds, so the CHECKs in
    :data:`_AUTONOMY_OUTCOMES_DDL` are the second line of defence rather than the
    only one, and a refusal names the field instead of the value.
    """

    declared = frozenset(_AUTONOMY_OUTCOME_COLUMNS)
    if frozenset(outcome) != declared:
        raise ValueError("an autonomy outcome carries exactly the 19 declared outcome fields")

    verdict = outcome["verdict"]
    if verdict not in AUTONOMY_VERDICT_VALUES:
        raise ValueError("an autonomy outcome verdict must be a declared autonomy verdict")
    digest = outcome["profile_digest"]
    # Empty for a run that stopped before it built a profile; anything else must be
    # a real content address rather than a label.
    if not isinstance(digest, str) or (digest and _PROFILE_DIGEST.fullmatch(digest) is None):
        raise ValueError("an autonomy outcome profile digest must be a sha256 hex digest or empty")
    if not isinstance(outcome["terminal_phase"], str) or not isinstance(
        outcome["reason_code"], str
    ):
        raise ValueError("an autonomy outcome phase and reason code must be text")

    counts = {
        name: _autonomy_count(outcome[name], field=name) for name in _AUTONOMY_OUTCOME_COUNT_COLUMNS
    }
    if counts["admission_prompts"] > 1:
        raise ValueError("the admission prompt is emitted at most once per run")
    if counts["other_operator_prompts"] != 0:
        raise ValueError("an onboarding run emits no operator prompt beyond admission and captcha")
    # Requirement 20.7, ahead of the column CHECK that also states it: the verdict
    # and the counters recorded beside it cannot disagree.
    if verdict == "fully_autonomous" and counts["captcha_prompts"] != 0:
        raise ValueError("a fully autonomous run emitted no captcha prompt")

    return (
        _audit_identifier(str(outcome["run_id"]), field="run id"),
        digest,
        verdict,
        _audit_phase(str(outcome["terminal_phase"]), field="terminal phase"),
        _audit_reason_code(str(outcome["reason_code"])),
        _autonomy_timestamp(outcome["started_at"], field="start time"),
        _autonomy_timestamp(outcome["ended_at"], field="end time"),
        *(counts[name] for name in _AUTONOMY_OUTCOME_COUNT_COLUMNS),
    )


def _audit_label(value: str, *, field: str) -> str:
    if _AUDIT_LABEL.fullmatch(value) is None:
        raise ValueError(f"an onboarding audit {field} must be a lower snake_case label")
    return value


def _audit_phase(value: str, *, field: str = "phase") -> str:
    if value not in ONBOARDING_PHASES:
        raise ValueError(f"an onboarding audit {field} must be an onboarding phase")
    return value


def _audit_reason_code(value: str) -> str:
    if value not in ONBOARDING_REASON_CODES:
        raise ValueError("an onboarding audit reason code must be an onboarding reason code")
    return value


@dataclass(frozen=True, slots=True)
class OnboardingAuditContext:
    """The correlation set every onboarding audit row carries (design "Event Model").

    One object rather than nine repeated keyword arguments, because the design
    requires the *same* correlation values on every event of every kind: the run,
    the phase the event happened in, the profile digest that authorized it, the
    attempt, and the correlation identifier that ties the row to the phase-history
    row committed in the same transaction, plus the browser session and vault
    reference identifiers where they apply.

    Nothing here is free-form. The phase is a closed vocabulary, the digest is a
    content address, and every identifier is bounded and refused if redaction would
    rewrite it — so a payload built from a context cannot carry page text, a
    credential value, or a verification link into ``sanitized_payload_json``.

    ``vault_reference_id`` is the *id segment* of a ``vault://`` reference, which is
    generated independently of the secret's content (Requirement 17.13); the
    reference value itself never appears.
    """

    run_id: str
    phase: str
    profile_digest: str
    attempt: int
    correlation_id: str
    browser_session_id: str | None = None
    vault_reference_id: str | None = None

    def __post_init__(self) -> None:
        _audit_identifier(self.run_id, field="run id")
        _audit_phase(self.phase)
        if _PROFILE_DIGEST.fullmatch(self.profile_digest) is None:
            raise ValueError("an onboarding audit profile digest must be a sha-256 hex digest")
        if self.attempt < 0:
            raise ValueError("an onboarding audit attempt cannot be negative")
        _audit_identifier(self.correlation_id, field="correlation id", limit=64)
        if self.browser_session_id is not None:
            _audit_identifier(self.browser_session_id, field="browser session id")
        if self.vault_reference_id is not None:
            _audit_identifier(self.vault_reference_id, field="vault reference id", limit=64)

    def as_payload(self) -> dict[str, object]:
        """The correlation set as audit payload fields.

        The optional identifiers are omitted rather than written as ``null`` so an
        event that has no session and no credential yet says so by their absence.
        """

        payload: dict[str, object] = {
            "run_id": self.run_id,
            "onboarding_phase": self.phase,
            "profile_digest": self.profile_digest,
            "attempt": int(self.attempt),
            "correlation_id": self.correlation_id,
        }
        if self.browser_session_id is not None:
            payload["browser_session_id"] = self.browser_session_id
        if self.vault_reference_id is not None:
            payload["vault_reference_id"] = self.vault_reference_id
        return payload


def _effect_receipt(value: object) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise RuntimeError("effect reservation receipt is invalid")
    decoded = json.loads(value)
    if not isinstance(decoded, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in decoded.items()
    ):
        raise RuntimeError("effect reservation receipt is invalid")
    return decoded


class OperationsUnitOfWork:
    """Transaction-bound run/audit methods; the SQLite handle never escapes."""

    def __init__(self, storage: OperationsStorage, connection: sqlite3.Connection) -> None:
        self._storage = storage
        self._connection = connection

    def create_run(
        self,
        *,
        run_id: str,
        thread_id: str,
        app_name: str,
        app_slug: str,
        status: RunStatus = "created",
        access_route: AccessRoute | None = None,
        browser_session_id: str | None = None,
        browser_live_url: str | None = None,
        gmail_session_id: str | None = None,
        gmail_thread_id: str | None = None,
        integrator_bundle: Mapping[str, object] | None = None,
        p1_summary: Mapping[str, object] | None = None,
        operational_research: Mapping[str, object] | None = None,
        request: Mapping[str, object] | None = None,
        route_reason_code: str | None = None,
        route_explanation: str | None = None,
        missing_fields: list[str] | None = None,
        provider_status: Mapping[str, object] | None = None,
        hitl_request: Mapping[str, object] | None = None,
        validation: Mapping[str, object] | None = None,
        scope_policy: str = "maximum",
        execution_mode: str = "local_dry_run",
        browser_provider: str = "browser_use",
        credential_creation_policy: str = "reuse_only",
        recipe_version: str | None = None,
        recipe_snapshot: Mapping[str, object] | None = None,
        route_kind: str | None = None,
        readiness_tier: str | None = None,
        browser_account_ref: str | None = None,
        provider_session_id: str | None = None,
        connection_request_id: str | None = None,
        attempt: int = 0,
        phase: str = "created",
        reason_code: str | None = None,
        effect_identity: str | None = None,
        state_engine: str = "legacy",
        external_actions: bool = False,
        idempotency_key: str | None = None,
        request_fingerprint: str | None = None,
    ) -> dict[str, Any]:
        return self._storage._create_run(
            self._connection,
            run_id=run_id,
            thread_id=thread_id,
            app_name=app_name,
            app_slug=app_slug,
            status=status,
            access_route=access_route,
            browser_session_id=browser_session_id,
            browser_live_url=browser_live_url,
            gmail_session_id=gmail_session_id,
            gmail_thread_id=gmail_thread_id,
            integrator_bundle=integrator_bundle,
            p1_summary=p1_summary,
            operational_research=operational_research,
            request=request,
            route_reason_code=route_reason_code,
            route_explanation=route_explanation,
            missing_fields=missing_fields,
            provider_status=provider_status,
            hitl_request=hitl_request,
            validation=validation,
            scope_policy=scope_policy,
            execution_mode=execution_mode,
            browser_provider=browser_provider,
            credential_creation_policy=credential_creation_policy,
            recipe_version=recipe_version,
            recipe_snapshot=recipe_snapshot,
            route_kind=route_kind,
            readiness_tier=readiness_tier,
            browser_account_ref=browser_account_ref,
            provider_session_id=provider_session_id,
            connection_request_id=connection_request_id,
            attempt=attempt,
            phase=phase,
            reason_code=reason_code,
            effect_identity=effect_identity,
            state_engine=state_engine,
            external_actions=external_actions,
            idempotency_key=idempotency_key,
            request_fingerprint=request_fingerprint,
        )

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        return self._storage._get_run(self._connection, run_id)

    def get_idempotent_run(self, idempotency_key: str) -> tuple[dict[str, Any], str] | None:
        """Return the stored run and opaque request digest for one exact key."""

        return self._storage._get_idempotent_run(self._connection, idempotency_key)

    def update_run(self, run_id: str, **changes: object) -> dict[str, Any]:
        return self._storage._update_run(self._connection, run_id, **changes)

    def append_audit_event(
        self,
        *,
        run_id: str,
        event_type: str,
        payload: Mapping[str, object] | None = None,
    ) -> int:
        return self._storage._append_audit_event(
            self._connection,
            run_id=run_id,
            event_type=event_type,
            payload=payload,
        )

    def record_phase_transition_audit(
        self,
        *,
        context: OnboardingAuditContext,
        from_phase: str | None,
        to_phase: str,
        reason_code: str,
    ) -> int:
        """Audit one phase boundary in the transaction that commits it."""

        return self._storage.record_phase_transition_audit_in_transaction(
            self._connection,
            context=context,
            from_phase=from_phase,
            to_phase=to_phase,
            reason_code=reason_code,
        )

    def record_decision_audit(
        self,
        *,
        context: OnboardingAuditContext,
        decision: str,
        reason_code: str,
        decided_by: str,
        actor_owner_id: str | None = None,
    ) -> int:
        """Audit one decision in the transaction that records it."""

        return self._storage.record_decision_audit_in_transaction(
            self._connection,
            context=context,
            decision=decision,
            reason_code=reason_code,
            decided_by=decided_by,
            actor_owner_id=actor_owner_id,
        )

    def record_escalation_audit(
        self,
        *,
        context: OnboardingAuditContext,
        gate_type: str,
        reason_code: str,
    ) -> int:
        """Audit one escalation in the transaction that raises it."""

        return self._storage.record_escalation_audit_in_transaction(
            self._connection,
            context=context,
            gate_type=gate_type,
            reason_code=reason_code,
        )

    def record_effect_reservation_audit(
        self,
        *,
        context: OnboardingAuditContext,
        operation_key: str,
        effect: str,
        generation: int,
        disposition: str,
        reason_code: str,
    ) -> int:
        """Audit one effect reservation in the transaction that reserves it."""

        return self._storage.record_effect_reservation_audit_in_transaction(
            self._connection,
            context=context,
            operation_key=operation_key,
            effect=effect,
            generation=generation,
            disposition=disposition,
            reason_code=reason_code,
        )

    def record_effect_completion_audit(
        self,
        *,
        context: OnboardingAuditContext,
        operation_key: str,
        effect: str,
        generation: int,
        reason_code: str,
        receipt: Mapping[str, str],
    ) -> int:
        """Audit one effect completion in the transaction that records it."""

        return self._storage.record_effect_completion_audit_in_transaction(
            self._connection,
            context=context,
            operation_key=operation_key,
            effect=effect,
            generation=generation,
            reason_code=reason_code,
            receipt=receipt,
        )

    def reserve_side_effect(
        self,
        *,
        run_id: str,
        operation_key: str,
        provider: str,
    ) -> tuple[dict[str, Any], bool]:
        """Atomically reserve one external mutation inside this transaction."""

        return self._storage._reserve_side_effect(
            self._connection,
            run_id=run_id,
            operation_key=operation_key,
            provider=provider,
        )

    def update_side_effect(
        self,
        *,
        run_id: str,
        operation_key: str,
        status: str,
        external_id: str | None = None,
    ) -> dict[str, Any]:
        return self._storage._update_side_effect(
            self._connection,
            run_id=run_id,
            operation_key=operation_key,
            status=status,
            external_id=external_id,
        )


class OperationsStorage:
    """SQLite persistence that sanitizes every free-form value before writing."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    thread_id TEXT UNIQUE NOT NULL,
                    app_name TEXT NOT NULL,
                    app_slug TEXT NOT NULL,
                    status TEXT NOT NULL,
                    access_route TEXT,
                    browser_session_id TEXT,
                    browser_live_url TEXT,
                    gmail_session_id TEXT,
                    gmail_thread_id TEXT,
                    integrator_bundle_json TEXT,
                    p1_summary_json TEXT,
                    operational_research_json TEXT,
                    request_json TEXT,
                    route_reason_code TEXT,
                    route_explanation TEXT,
                    missing_fields_json TEXT NOT NULL DEFAULT '[]',
                    provider_status_json TEXT NOT NULL DEFAULT '{}',
                    hitl_request_json TEXT,
                    validation_json TEXT,
                    scope_policy TEXT NOT NULL DEFAULT 'maximum',
                    execution_mode TEXT NOT NULL DEFAULT 'local_dry_run',
                    browser_provider TEXT NOT NULL DEFAULT 'browser_use',
                    credential_creation_policy TEXT NOT NULL DEFAULT 'reuse_only',
                    recipe_version TEXT,
                    recipe_snapshot_json TEXT,
                    route_kind TEXT,
                    readiness_tier TEXT,
                    browser_account_ref TEXT,
                    provider_session_id TEXT,
                    connection_request_id TEXT,
                    attempt INTEGER NOT NULL DEFAULT 0,
                    phase TEXT NOT NULL DEFAULT 'legacy',
                    reason_code TEXT,
                    effect_identity TEXT,
                    state_engine TEXT NOT NULL DEFAULT 'legacy',
                    external_actions INTEGER NOT NULL DEFAULT 0,
                    state_revision INTEGER NOT NULL DEFAULT 0,
                    last_projected_revision INTEGER NOT NULL DEFAULT 0,
                    idempotency_key TEXT,
                    request_fingerprint TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    sanitized_payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_audit_events_run_id
                ON audit_events(run_id, id);

                CREATE TABLE IF NOT EXISTS side_effect_intents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    operation_key TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    status TEXT NOT NULL,
                    external_id TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE (run_id, operation_key),
                    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
                );

                -- At most one lease row per run, which is where "at most one
                -- live lease per run" comes from (Requirement 16.2): the
                -- PRIMARY KEY makes a second holder unrepresentable rather than
                -- merely unlikely. holder and deadline are NULL together — a
                -- free run has neither — and fencing_token survives a release
                -- because it is monotonic per run, not per lease
                -- (Requirement 16.3). A never-claimed run has no row at all, so
                -- the default 0 is what the first claim increments to 1.
                CREATE TABLE IF NOT EXISTS onboarding_leases (
                    run_id TEXT PRIMARY KEY,
                    holder TEXT,
                    fencing_token INTEGER NOT NULL DEFAULT 0,
                    deadline TEXT,
                    claimed_at TEXT,
                    released_at TEXT,
                    CHECK ((holder IS NULL) = (deadline IS NULL)),
                    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
                );

                -- Claim and crash detection both scan by deadline: "which runs
                -- are claimable now" is a range read over this column, and the
                -- deadline's canonical fixed-width text form is what makes that
                -- range read chronologically correct.
                CREATE INDEX IF NOT EXISTS idx_onboarding_leases_deadline
                ON onboarding_leases(deadline);

                -- The durable work queue. Keyed by run id so a run is queued
                -- exactly once no matter how many times it is enqueued
                -- (Requirement 16.1); not_before carries the deferral.
                CREATE TABLE IF NOT EXISTS onboarding_queue (
                    run_id TEXT PRIMARY KEY,
                    not_before TEXT NOT NULL,
                    enqueued_at TEXT NOT NULL,
                    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_onboarding_queue_ready
                ON onboarding_queue(not_before);

                -- One row per committed onboarding phase boundary. The two
                -- UNIQUE constraints are the mechanism, not a precaution: the
                -- phase-history store writes with a computed sequence and lets
                -- the boundary constraint reject a replayed transition, which is
                -- what makes a replay a no-op rather than a second row.
                CREATE TABLE IF NOT EXISTS onboarding_phase_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    from_phase TEXT,
                    to_phase TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    profile_digest TEXT NOT NULL,
                    attempt INTEGER NOT NULL DEFAULT 0,
                    correlation_id TEXT NOT NULL,
                    committed_at TEXT NOT NULL,
                    UNIQUE (run_id, sequence),
                    UNIQUE (run_id, from_phase, to_phase, attempt, correlation_id),
                    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_phase_history_run
                ON onboarding_phase_history(run_id, sequence);

                -- The NULL-safe restatement of the boundary constraint above.
                -- SQLite treats NULLs as distinct inside a UNIQUE constraint, so
                -- the declared constraint alone cannot reject a replay of a run's
                -- FIRST boundary, whose from_phase is NULL. Folding NULL to ''
                -- inside a unique index closes that hole, so idempotent replay
                -- holds for every boundary including the first.
                CREATE UNIQUE INDEX IF NOT EXISTS idx_phase_history_boundary
                ON onboarding_phase_history(
                    run_id, COALESCE(from_phase, ''), to_phase, attempt, correlation_id
                );

                -- A stored projection of onboarding_phase_history. It exists
                -- because the operation keys read credential_generation, and
                -- reading a counter must not require replaying history under a
                -- write lock.
                CREATE TABLE IF NOT EXISTS onboarding_run_state (
                    run_id TEXT PRIMARY KEY,
                    phase TEXT NOT NULL,
                    phase_at_pause TEXT,
                    profile_digest TEXT NOT NULL,
                    account_ref TEXT NOT NULL,
                    developer_app_id TEXT,
                    credential_kind TEXT,
                    credential_generation INTEGER NOT NULL DEFAULT 0,
                    verification_attempt INTEGER NOT NULL DEFAULT 0,
                    validation_attempt INTEGER NOT NULL DEFAULT 0,
                    captcha_prompts INTEGER NOT NULL DEFAULT 0,
                    admission_prompts INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
                );
                """
            )
            existing_columns = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(runs)").fetchall()
            }
            migration_columns = {
                "idempotency_key": "TEXT",
                "request_fingerprint": "TEXT",
                "p1_summary_json": "TEXT",
                "operational_research_json": "TEXT",
                "request_json": "TEXT",
                "route_reason_code": "TEXT",
                "route_explanation": "TEXT",
                "missing_fields_json": "TEXT NOT NULL DEFAULT '[]'",
                "provider_status_json": "TEXT NOT NULL DEFAULT '{}'",
                "hitl_request_json": "TEXT",
                "validation_json": "TEXT",
                "scope_policy": "TEXT NOT NULL DEFAULT 'maximum'",
                "execution_mode": "TEXT NOT NULL DEFAULT 'local_dry_run'",
                "browser_provider": "TEXT NOT NULL DEFAULT 'browser_use'",
                "credential_creation_policy": "TEXT NOT NULL DEFAULT 'reuse_only'",
                "recipe_version": "TEXT",
                "recipe_snapshot_json": "TEXT",
                "route_kind": "TEXT",
                "readiness_tier": "TEXT",
                "browser_account_ref": "TEXT",
                "provider_session_id": "TEXT",
                "connection_request_id": "TEXT",
                "attempt": "INTEGER NOT NULL DEFAULT 0",
                "phase": "TEXT NOT NULL DEFAULT 'legacy'",
                "reason_code": "TEXT",
                "effect_identity": "TEXT",
                "state_engine": "TEXT NOT NULL DEFAULT 'legacy'",
                "external_actions": "INTEGER NOT NULL DEFAULT 0",
                "state_revision": "INTEGER NOT NULL DEFAULT 0",
                "last_projected_revision": "INTEGER NOT NULL DEFAULT 0",
            }
            # Kept as their own scripts because their CHECK lists are generated
            # from the onboarding vocabularies rather than typed out.
            connection.executescript(_EFFECT_RESERVATIONS_DDL)
            connection.executescript(_ADMISSION_DECISIONS_DDL)
            connection.executescript(_NAVIGATION_DENIALS_DDL)
            connection.executescript(_AUTONOMY_OUTCOMES_DDL)
            for column_name, declaration in migration_columns.items():
                if column_name not in existing_columns:
                    connection.execute(f"ALTER TABLE runs ADD COLUMN {column_name} {declaration}")
            connection.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_runs_idempotency_key
                ON runs(idempotency_key)
                WHERE idempotency_key IS NOT NULL
                """
            )

    @contextmanager
    def unit_of_work(self) -> Iterator[OperationsUnitOfWork]:
        """Commit all run/audit mutations together or roll them all back."""

        self.initialize()
        with self._connect() as connection:
            # Serialize the idempotency lookup/insert pair across writers. The
            # transaction is still short because Phase 2 performs all snapshot
            # and routing computation before entering this boundary.
            connection.execute("BEGIN IMMEDIATE")
            yield OperationsUnitOfWork(self, connection)

    def create_run(
        self,
        *,
        run_id: str,
        thread_id: str,
        app_name: str,
        app_slug: str,
        status: RunStatus = "created",
        access_route: AccessRoute | None = None,
        browser_session_id: str | None = None,
        browser_live_url: str | None = None,
        gmail_session_id: str | None = None,
        gmail_thread_id: str | None = None,
        integrator_bundle: Mapping[str, object] | None = None,
        p1_summary: Mapping[str, object] | None = None,
        operational_research: Mapping[str, object] | None = None,
        request: Mapping[str, object] | None = None,
        route_reason_code: str | None = None,
        route_explanation: str | None = None,
        missing_fields: list[str] | None = None,
        provider_status: Mapping[str, object] | None = None,
        hitl_request: Mapping[str, object] | None = None,
        validation: Mapping[str, object] | None = None,
        scope_policy: str = "maximum",
        execution_mode: str = "local_dry_run",
        browser_provider: str = "browser_use",
        credential_creation_policy: str = "reuse_only",
        recipe_version: str | None = None,
        recipe_snapshot: Mapping[str, object] | None = None,
        route_kind: str | None = None,
        readiness_tier: str | None = None,
        browser_account_ref: str | None = None,
        provider_session_id: str | None = None,
        connection_request_id: str | None = None,
        attempt: int = 0,
        phase: str = "created",
        reason_code: str | None = None,
        effect_identity: str | None = None,
        state_engine: str = "legacy",
        external_actions: bool = False,
        idempotency_key: str | None = None,
        request_fingerprint: str | None = None,
    ) -> dict[str, Any]:
        self.initialize()
        with self._connect() as connection:
            return self._create_run(
                connection,
                run_id=run_id,
                thread_id=thread_id,
                app_name=app_name,
                app_slug=app_slug,
                status=status,
                access_route=access_route,
                browser_session_id=browser_session_id,
                browser_live_url=browser_live_url,
                gmail_session_id=gmail_session_id,
                gmail_thread_id=gmail_thread_id,
                integrator_bundle=integrator_bundle,
                p1_summary=p1_summary,
                operational_research=operational_research,
                request=request,
                route_reason_code=route_reason_code,
                route_explanation=route_explanation,
                missing_fields=missing_fields,
                provider_status=provider_status,
                hitl_request=hitl_request,
                validation=validation,
                scope_policy=scope_policy,
                execution_mode=execution_mode,
                browser_provider=browser_provider,
                credential_creation_policy=credential_creation_policy,
                recipe_version=recipe_version,
                recipe_snapshot=recipe_snapshot,
                route_kind=route_kind,
                readiness_tier=readiness_tier,
                browser_account_ref=browser_account_ref,
                provider_session_id=provider_session_id,
                connection_request_id=connection_request_id,
                attempt=attempt,
                phase=phase,
                reason_code=reason_code,
                effect_identity=effect_identity,
                state_engine=state_engine,
                external_actions=external_actions,
                idempotency_key=idempotency_key,
                request_fingerprint=request_fingerprint,
            )

    def _create_run(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        thread_id: str,
        app_name: str,
        app_slug: str,
        status: RunStatus = "created",
        access_route: AccessRoute | None = None,
        browser_session_id: str | None = None,
        browser_live_url: str | None = None,
        gmail_session_id: str | None = None,
        gmail_thread_id: str | None = None,
        integrator_bundle: Mapping[str, object] | None = None,
        p1_summary: Mapping[str, object] | None = None,
        operational_research: Mapping[str, object] | None = None,
        request: Mapping[str, object] | None = None,
        route_reason_code: str | None = None,
        route_explanation: str | None = None,
        missing_fields: list[str] | None = None,
        provider_status: Mapping[str, object] | None = None,
        hitl_request: Mapping[str, object] | None = None,
        validation: Mapping[str, object] | None = None,
        scope_policy: str = "maximum",
        execution_mode: str = "local_dry_run",
        browser_provider: str = "browser_use",
        credential_creation_policy: str = "reuse_only",
        recipe_version: str | None = None,
        recipe_snapshot: Mapping[str, object] | None = None,
        route_kind: str | None = None,
        readiness_tier: str | None = None,
        browser_account_ref: str | None = None,
        provider_session_id: str | None = None,
        connection_request_id: str | None = None,
        attempt: int = 0,
        phase: str = "created",
        reason_code: str | None = None,
        effect_identity: str | None = None,
        state_engine: str = "legacy",
        external_actions: bool = False,
        idempotency_key: str | None = None,
        request_fingerprint: str | None = None,
    ) -> dict[str, Any]:
        if (idempotency_key is None) != (request_fingerprint is None):
            raise ValueError("idempotency key and request fingerprint must be provided together")
        if browser_live_url is not None:
            raise ValueError("browser live capability URLs cannot be persisted")
        now = _utc_now()
        values = (
            _safe_text(run_id),
            _safe_text(thread_id),
            _safe_text(app_name),
            _safe_text(app_slug),
            status,
            access_route,
            _safe_text(browser_session_id),
            _safe_text(browser_live_url),
            _safe_text(gmail_session_id),
            _safe_text(gmail_thread_id),
            _structured_json(integrator_bundle) if integrator_bundle is not None else None,
            _structured_json(p1_summary) if p1_summary is not None else None,
            _structured_json(operational_research) if operational_research is not None else None,
            _structured_json(request) if request is not None else None,
            _safe_text(route_reason_code),
            _safe_text(route_explanation),
            _structured_json(missing_fields or []),
            _structured_json(provider_status or {}),
            _structured_json(hitl_request) if hitl_request is not None else None,
            _structured_json(validation) if validation is not None else None,
            _safe_text(scope_policy),
            _safe_text(execution_mode),
            _safe_text(browser_provider),
            _safe_text(credential_creation_policy),
            _safe_text(recipe_version),
            _structured_json(recipe_snapshot) if recipe_snapshot is not None else None,
            _safe_text(route_kind),
            _safe_text(readiness_tier),
            _safe_text(browser_account_ref),
            _safe_text(provider_session_id),
            _safe_text(connection_request_id),
            int(attempt),
            _safe_text(phase),
            _safe_text(reason_code),
            _safe_text(effect_identity),
            _safe_text(state_engine),
            int(external_actions),
            _safe_text(idempotency_key),
            _safe_text(request_fingerprint),
            now,
            now,
        )
        connection.execute(
            """
            INSERT INTO runs (
                run_id, thread_id, app_name, app_slug, status, access_route,
                browser_session_id, browser_live_url, gmail_session_id,
                gmail_thread_id, integrator_bundle_json,
                p1_summary_json, operational_research_json, request_json, route_reason_code,
                route_explanation, missing_fields_json, provider_status_json,
                hitl_request_json, validation_json, scope_policy, execution_mode,
                browser_provider, credential_creation_policy, recipe_version,
                recipe_snapshot_json, route_kind, readiness_tier, browser_account_ref,
                provider_session_id,
                connection_request_id, attempt, phase, reason_code,
                effect_identity, state_engine, external_actions,
                idempotency_key, request_fingerprint,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        created = self._get_run(connection, str(values[0]))
        if created is None:  # pragma: no cover - defensive invariant
            raise RuntimeError("created run could not be read back")
        return created

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        self.initialize()
        with self._connect() as connection:
            return self._get_run(connection, run_id)

    def get_idempotent_run(self, idempotency_key: str) -> tuple[dict[str, Any], str] | None:
        """Read an idempotent replay without opening a write transaction."""

        self.initialize()
        with self._connect() as connection:
            return self._get_idempotent_run(connection, idempotency_key)

    def _get_run(
        self,
        connection: sqlite3.Connection,
        run_id: str,
    ) -> dict[str, Any] | None:
        row = connection.execute(
            f"SELECT {', '.join(_RUN_COLUMNS)} FROM runs WHERE run_id = ?",
            (_safe_text(run_id),),
        ).fetchone()
        return self._run_from_row(row) if row is not None else None

    def _get_idempotent_run(
        self,
        connection: sqlite3.Connection,
        idempotency_key: str,
    ) -> tuple[dict[str, Any], str] | None:
        row = connection.execute(
            f"SELECT {', '.join(_RUN_COLUMNS)}, request_fingerprint "
            "FROM runs WHERE idempotency_key = ?",
            (_safe_text(idempotency_key),),
        ).fetchone()
        if row is None:
            return None
        fingerprint = row[len(_RUN_COLUMNS)]
        if not isinstance(fingerprint, str):  # pragma: no cover - paired write invariant
            raise RuntimeError("idempotent run is missing its request fingerprint")
        return (self._run_from_row(row[: len(_RUN_COLUMNS)]), fingerprint)

    def update_run(self, run_id: str, **changes: object) -> dict[str, Any]:
        """Update only declared mutable run columns and return the fresh record."""

        self.initialize()
        with self._connect() as connection:
            return self._update_run(connection, run_id, **changes)

    def _update_run(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        **changes: object,
    ) -> dict[str, Any]:
        """Update one run on a caller-owned transaction."""

        allowed = {
            "status",
            "access_route",
            "browser_session_id",
            "browser_live_url",
            "gmail_session_id",
            "gmail_thread_id",
            "integrator_bundle",
            "p1_summary",
            "operational_research",
            "route_reason_code",
            "route_explanation",
            "missing_fields",
            "provider_status",
            "hitl_request",
            "validation",
            "scope_policy",
            "execution_mode",
            "provider_session_id",
            "connection_request_id",
            "attempt",
            "phase",
            "reason_code",
            "effect_identity",
            "external_actions",
            "state_revision",
            "last_projected_revision",
        }
        unknown = set(changes) - allowed
        if unknown:
            raise ValueError("unsupported run update field")
        if not changes:
            existing = self._get_run(connection, run_id)
            if existing is None:
                raise KeyError("run was not found")
            return existing

        assignments: list[str] = []
        values: list[object] = []
        for name, value in changes.items():
            if name == "browser_live_url" and value is not None:
                raise ValueError("browser live capability URLs cannot be persisted")
            column = _JSON_RUN_FIELDS.get(name, name)
            assignments.append(f"{column} = ?")
            if name in _JSON_RUN_FIELDS:
                default = _DEFAULT_JSON_VALUES.get(name)
                values.append(
                    _structured_json(default)
                    if value is None and default is not None
                    else _structured_json(value)
                    if value is not None
                    else None
                )
            elif name == "external_actions":
                values.append(int(bool(value)))
            elif isinstance(value, str):
                values.append(_safe_text(value))
            else:
                values.append(value)
        assignments.append("updated_at = ?")
        values.extend((_utc_now(), _safe_text(run_id)))

        cursor = connection.execute(
            f"UPDATE runs SET {', '.join(assignments)} WHERE run_id = ?",
            values,
        )
        if cursor.rowcount != 1:
            raise KeyError("run was not found")
        updated = self._get_run(connection, run_id)
        if updated is None:  # pragma: no cover - defensive invariant
            raise RuntimeError("updated run could not be read back")
        return updated

    def list_runs(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        self.initialize()
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        if offset < 0:
            raise ValueError("offset must be zero or greater")
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT {', '.join(_RUN_COLUMNS)} "
                "FROM runs ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [self._run_from_row(row) for row in rows]

    def count_runs(self) -> int:
        """Return the number of run records without exposing database details."""

        self.initialize()
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) FROM runs").fetchone()
        if row is None:  # pragma: no cover - SQLite aggregate invariant
            raise RuntimeError("run count could not be read")
        return int(row[0])

    def append_audit_event(
        self,
        *,
        run_id: str,
        event_type: str,
        payload: Mapping[str, object] | None = None,
    ) -> int:
        self.initialize()
        with self._connect() as connection:
            return self._append_audit_event(
                connection,
                run_id=run_id,
                event_type=event_type,
                payload=payload,
            )

    def _append_audit_event(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        event_type: str,
        payload: Mapping[str, object] | None = None,
    ) -> int:
        cursor = connection.execute(
            """
            INSERT INTO audit_events (
                run_id, event_type, sanitized_payload_json, created_at
            ) VALUES (?, ?, ?, ?)
            """,
            (
                _safe_text(run_id),
                _safe_text(event_type),
                _json(payload or {}),
                _utc_now(),
            ),
        )
        event_id = cursor.lastrowid
        if event_id is None:  # pragma: no cover - sqlite invariant
            raise RuntimeError("audit event id was not generated")
        return int(event_id)

    def list_audit_events(self, run_id: str) -> list[dict[str, Any]]:
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, run_id, event_type, sanitized_payload_json, created_at
                FROM audit_events
                WHERE run_id = ?
                ORDER BY id ASC
                """,
                (_safe_text(run_id),),
            ).fetchall()
        return [
            {
                "id": row[0],
                "run_id": row[1],
                "event_type": row[2],
                "payload": json.loads(row[3]),
                "created_at": row[4],
            }
            for row in rows
        ]

    # --- The onboarding audit trail (Requirement 17.12, design "Event Model") ---
    #
    # Five writers, one per kind of fact the audit trail must hold: a phase
    # transition, a decision with its reason code, an escalation, an effect
    # reservation, and an effect completion. Each one composes a closed payload and
    # hands it to ``_append_audit_event``, which is the existing redacting write
    # path — there is no second insert into ``audit_events`` anywhere in this
    # module, so key-aware redaction cannot be bypassed by choosing a writer.
    #
    # Every writer takes the caller's connection and there is no self-transacting
    # variant on purpose. An audit row is the redacted account of a durable fact,
    # so it belongs in the same transaction as the fact: a phase-history row whose
    # audit row is missing (or an audit row whose phase never committed) is exactly
    # the disagreement the trail exists to rule out. Callers inside a unit of work
    # use the delegates on :class:`OperationsUnitOfWork`.

    def record_phase_transition_audit_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        context: OnboardingAuditContext,
        from_phase: str | None,
        to_phase: str,
        reason_code: str,
    ) -> int:
        """Record one committed phase boundary in the audit trail.

        PRE:  ``from_phase`` is an onboarding phase or ``None`` for a run's first
              boundary; ``to_phase`` is an onboarding phase and ``reason_code`` an
              onboarding reason code. Anything else is refused and nothing is
              written.
        POST: exactly one ``onboarding_phase_committed`` row exists for the call,
              carrying the correlation set, both phases, and the reason code.
        """

        payload = {
            **context.as_payload(),
            "from_phase": _audit_phase(from_phase, field="source phase")
            if from_phase is not None
            else None,
            "to_phase": _audit_phase(to_phase, field="target phase"),
            "reason_code": _audit_reason_code(reason_code),
        }
        return self._append_audit_event(
            connection,
            run_id=context.run_id,
            event_type=ONBOARDING_AUDIT_PHASE_COMMITTED,
            payload=payload,
        )

    def record_decision_audit_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        context: OnboardingAuditContext,
        decision: str,
        reason_code: str,
        decided_by: str,
        actor_owner_id: str | None = None,
    ) -> int:
        """Record one decision together with the reason code that explains it.

        ``decision`` is a lower snake_case label naming what was decided — the
        admission route, the selected route, the disposition of a gate — and
        ``decided_by`` is the admission decider vocabulary (``system`` or
        ``operator``), so "who decided this" is answerable from the row itself
        rather than inferred from which component happened to write it.
        """

        if decided_by not in _ADMISSION_DECIDERS:
            raise ValueError("an onboarding audit decider must be a known decider")
        payload = {
            **context.as_payload(),
            "decision": _audit_label(decision, field="decision"),
            "reason_code": _audit_reason_code(reason_code),
            "decided_by": decided_by,
        }
        if actor_owner_id is not None:
            payload["actor_owner_id"] = _audit_identifier(actor_owner_id, field="actor owner id")
        return self._append_audit_event(
            connection,
            run_id=context.run_id,
            event_type=ONBOARDING_AUDIT_DECISION_RECORDED,
            payload=payload,
        )

    def record_escalation_audit_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        context: OnboardingAuditContext,
        gate_type: str,
        reason_code: str,
    ) -> int:
        """Record one escalation to a human, typed by the gate that caused it.

        PRE:  ``gate_type`` is a declared human action type, so a gate invented
              from page content cannot be recorded as an escalation.
        POST: exactly one ``onboarding_escalation_raised`` row exists for the call.
        """

        if gate_type not in _ESCALATION_GATES:
            raise ValueError("an onboarding escalation gate type is not a human action type")
        payload = {
            **context.as_payload(),
            "gate_type": gate_type,
            "reason_code": _audit_reason_code(reason_code),
        }
        return self._append_audit_event(
            connection,
            run_id=context.run_id,
            event_type=ONBOARDING_AUDIT_ESCALATION_RAISED,
            payload=payload,
        )

    def record_effect_reservation_audit_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        context: OnboardingAuditContext,
        operation_key: str,
        effect: str,
        generation: int,
        disposition: str,
        reason_code: str,
    ) -> int:
        """Record one reserved operation key and the disposition it authorized.

        The operation key is written under the field name ``operation_id`` rather
        than ``operation_key``: key-aware redaction (correctly) replaces the value
        of any field whose name contains ``key``, and the operation key is a
        content-addressed identifier that the trail needs to keep in order to tie a
        reservation to the completion that closes it.
        """

        if effect not in ONBOARDING_EFFECTS:
            raise ValueError("an onboarding audit effect is not an onboarding effect")
        if disposition not in ONBOARDING_EFFECT_DISPOSITIONS:
            raise ValueError("an onboarding audit effect disposition is invalid")
        if generation < 0:
            raise ValueError("an onboarding audit effect generation cannot be negative")
        payload = {
            **context.as_payload(),
            "operation_id": _audit_identifier(operation_key, field="operation key"),
            "effect": effect,
            "generation": int(generation),
            "disposition": disposition,
            "reason_code": _audit_reason_code(reason_code),
        }
        return self._append_audit_event(
            connection,
            run_id=context.run_id,
            event_type=ONBOARDING_AUDIT_EFFECT_RESERVED,
            payload=payload,
        )

    def record_effect_completion_audit_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        context: OnboardingAuditContext,
        operation_key: str,
        effect: str,
        generation: int,
        reason_code: str,
        receipt: Mapping[str, str],
    ) -> int:
        """Record that one reserved effect completed, with its non-secret receipt.

        The receipt passes :func:`_effect_receipt_json`, the same guard the
        reservation table uses, so a receipt carrying secret-shaped material is
        refused here rather than stored in a redacted form the skip path would
        later adopt as fact.
        """

        if effect not in ONBOARDING_EFFECTS:
            raise ValueError("an onboarding audit effect is not an onboarding effect")
        if generation < 0:
            raise ValueError("an onboarding audit effect generation cannot be negative")
        _effect_receipt_json(receipt)
        payload = {
            **context.as_payload(),
            "operation_id": _audit_identifier(operation_key, field="operation key"),
            "effect": effect,
            "generation": int(generation),
            "reason_code": _audit_reason_code(reason_code),
            "receipt": dict(receipt),
        }
        return self._append_audit_event(
            connection,
            run_id=context.run_id,
            event_type=ONBOARDING_AUDIT_EFFECT_COMPLETED,
            payload=payload,
        )

    def record_navigation_denial(
        self,
        *,
        run_id: str,
        phase: str,
        profile_digest: str,
        reason_code: str,
    ) -> int:
        """Record one navigation denial as a durable fact (Requirement 5.15).

        PRE:  ``phase`` is an onboarding phase and ``reason_code`` an onboarding
              reason code; anything else is refused here and, for a writer that
              bypasses this method, by the column CHECKs.
        POST: one row exists per call. Denials are never deduplicated — a phase
              that reached its denial bound must show ten rows, not one.
        """

        self.initialize()
        with self._connect() as connection:
            return self.record_navigation_denial_in_transaction(
                connection,
                run_id=run_id,
                phase=phase,
                profile_digest=profile_digest,
                reason_code=reason_code,
            )

    def record_navigation_denial_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        phase: str,
        profile_digest: str,
        reason_code: str,
    ) -> int:
        """Record a denial inside the caller's unit of work.

        Offered as its own method so a driver that pauses a run on a denied-fatal
        outcome can write the last denial and the phase boundary that reports it in
        one transaction, instead of leaving a paused run whose reason code has no
        supporting fact.
        """

        if phase not in ONBOARDING_PHASES:
            raise ValueError("navigation denial phase is not an onboarding phase")
        if reason_code not in ONBOARDING_REASON_CODES:
            raise ValueError("navigation denial reason code is not an onboarding reason code")
        if not profile_digest:
            raise ValueError("navigation denial requires a profile digest")
        cursor = connection.execute(
            """
            INSERT INTO onboarding_navigation_denials (
                run_id, phase, profile_digest, reason_code, recorded_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                _safe_text(run_id),
                phase,
                profile_digest,
                reason_code,
                _utc_now(),
            ),
        )
        denial_id = cursor.lastrowid
        if denial_id is None:  # pragma: no cover - sqlite invariant
            raise RuntimeError("navigation denial id was not generated")
        return int(denial_id)

    def list_navigation_denials(
        self,
        run_id: str | None = None,
        *,
        limit: int = MAX_METRIC_ROWS,
    ) -> list[dict[str, Any]]:
        """Recorded denial facts, in the order they were recorded.

        One run's denials when ``run_id`` is given, and every run's denials when it
        is omitted — the second form is what the autonomy metrics read for the
        per-phase breakdown of off-domain denials (Requirement 20.3), since a
        fleet-wide breakdown cannot be assembled from per-run reads without first
        enumerating the runs. Bounded like the other metric reads so a breakdown
        cannot pull the whole table into memory.
        """

        self.initialize()
        clause = "" if run_id is None else "WHERE run_id = ? "
        parameters: tuple[object, ...] = (
            (_metric_row_limit(limit),)
            if run_id is None
            else (_safe_text(run_id), _metric_row_limit(limit))
        )
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT id, run_id, phase, profile_digest, reason_code, recorded_at "
                f"FROM onboarding_navigation_denials {clause}"
                "ORDER BY id ASC LIMIT ?",
                parameters,
            ).fetchall()
        return [
            {
                "id": row[0],
                "run_id": row[1],
                "phase": row[2],
                "profile_digest": row[3],
                "reason_code": row[4],
                "recorded_at": row[5],
            }
            for row in rows
        ]

    def reserve_side_effect(
        self,
        *,
        run_id: str,
        operation_key: str,
        provider: str,
    ) -> tuple[dict[str, Any], bool]:
        """Reserve an idempotent external mutation and report whether it is new."""

        self.initialize()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            return self._reserve_side_effect(
                connection,
                run_id=run_id,
                operation_key=operation_key,
                provider=provider,
            )

    def _reserve_side_effect(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        operation_key: str,
        provider: str,
    ) -> tuple[dict[str, Any], bool]:
        if not operation_key or len(operation_key) > 200:
            raise ValueError("operation key is invalid")
        if not provider or len(provider) > 64:
            raise ValueError("provider name is invalid")
        now = _utc_now()
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO side_effect_intents (
                run_id, operation_key, provider, status, created_at, updated_at
            ) VALUES (?, ?, ?, 'pending', ?, ?)
            """,
            (
                _safe_text(run_id),
                _safe_text(operation_key),
                _safe_text(provider),
                now,
                now,
            ),
        )
        record = self._get_side_effect(connection, run_id, operation_key)
        if record is None:  # pragma: no cover - foreign key/insertion invariant
            raise KeyError("run was not found")
        return (record, cursor.rowcount == 1)

    def reserve_side_effect_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        operation_key: str,
        provider: str,
    ) -> tuple[dict[str, Any], bool]:
        """Reserve one operation key on a caller-owned transaction.

        The onboarding phase driver commits a phase boundary and reserves that
        phase's operation key in a single ``BEGIN IMMEDIATE`` unit of work
        (Requirement 13.13), so it owns the connection and cannot use the
        self-transacting :meth:`reserve_side_effect`.
        """

        return self._reserve_side_effect(
            connection,
            run_id=run_id,
            operation_key=operation_key,
            provider=provider,
        )

    def read_side_effect_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        operation_key: str,
    ) -> dict[str, Any] | None:
        """Read one reservation row on a caller-owned transaction."""

        return self._get_side_effect(connection, run_id, operation_key)

    def update_side_effect_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        operation_key: str,
        status: str,
        external_id: str | None = None,
    ) -> dict[str, Any]:
        """Move one reservation to a new status on a caller-owned transaction."""

        return self._update_side_effect(
            connection,
            run_id=run_id,
            operation_key=operation_key,
            status=status,
            external_id=external_id,
        )

    def record_effect_reservation_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        operation_key: str,
        effect: str,
        generation: int,
        phase: str,
        disposition: str,
        reason_code: str,
        receipt: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        """Upsert the onboarding view of one reservation, inside the caller's work.

        ``effect`` and ``generation`` belong to the key and are written once; a
        later call updates the standing ``disposition``, the phase that last acted
        on the key, the reason code, and the receipt. A ``None`` receipt leaves a
        previously recorded receipt in place, because a completed effect's receipt
        outlives the disposition that recorded it.
        """

        if effect not in ONBOARDING_EFFECTS:
            raise ValueError("effect is not an onboarding effect")
        if disposition not in ONBOARDING_EFFECT_DISPOSITIONS:
            raise ValueError("effect disposition is invalid")
        if generation < 0:
            raise ValueError("effect generation must be zero or greater")
        if not operation_key or len(operation_key) > 200:
            raise ValueError("operation key is invalid")
        now = _utc_now()
        connection.execute(
            """
            INSERT INTO onboarding_effect_reservations (
                run_id, operation_key, effect, generation, phase, disposition,
                receipt_json, reason_code, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(run_id, operation_key) DO UPDATE SET
                phase = excluded.phase,
                disposition = excluded.disposition,
                receipt_json = COALESCE(excluded.receipt_json, receipt_json),
                reason_code = excluded.reason_code,
                updated_at = excluded.updated_at
            """,
            (
                _safe_text(run_id),
                _safe_text(operation_key),
                effect,
                generation,
                _safe_text(phase),
                disposition,
                _effect_receipt_json(receipt),
                _safe_text(reason_code),
                now,
                now,
            ),
        )
        record = self.read_effect_reservation_in_transaction(
            connection, run_id=run_id, operation_key=operation_key
        )
        if record is None:  # pragma: no cover - insertion invariant
            raise RuntimeError("effect reservation could not be read back")
        return record

    def read_effect_reservation_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        operation_key: str,
    ) -> dict[str, Any] | None:
        """Read the onboarding view of one reservation, inside the caller's work."""

        row = connection.execute(
            """
            SELECT run_id, operation_key, effect, generation, phase, disposition,
                   receipt_json, reason_code, created_at, updated_at
            FROM onboarding_effect_reservations
            WHERE run_id = ? AND operation_key = ?
            """,
            (_safe_text(run_id), _safe_text(operation_key)),
        ).fetchone()
        if row is None:
            return None
        return {
            "run_id": row[0],
            "operation_key": row[1],
            "effect": row[2],
            "generation": int(row[3]),
            "phase": row[4],
            "disposition": row[5],
            "receipt": _effect_receipt(row[6]),
            "reason_code": row[7],
            "created_at": row[8],
            "updated_at": row[9],
        }

    def list_effect_reservations(self, *, run_id: str) -> list[dict[str, Any]]:
        """Every standing reservation for one run, oldest key first.

        The durable enumeration the recovery and autonomy readers want: the
        reservation table already holds one row per ``(run_id, operation_key)``
        with its STANDING disposition, so counting duplicate skips and ambiguous
        outcomes is a read here rather than a walk of the audit trail used as an
        index.
        """

        self.initialize()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT operation_key
                FROM onboarding_effect_reservations
                WHERE run_id = ?
                ORDER BY created_at, operation_key
                """,
                (_safe_text(run_id),),
            ).fetchall()
            records: list[dict[str, Any]] = []
            for row in rows:
                record = self.read_effect_reservation_in_transaction(
                    connection, run_id=run_id, operation_key=str(row[0])
                )
                if record is not None:  # pragma: no branch - the key was just read
                    records.append(record)
        return records

    def record_admission_decision(
        self,
        decision: AdmissionDecision,
    ) -> tuple[AdmissionDecision, bool]:
        """Record one run's admission decision, or report the replay of an earlier one.

        PRE:  ``decision`` is a constructed
              :class:`~ops.onboarding.admission.AdmissionDecision`, so its own
              refusals (no system-decided signup, no login without references)
              already held.
        POST: returns ``(stored decision, replayed)``. On the first call the row is
              written and ``replayed`` is false. On any later call for the same run
              nothing is written and the ORIGINAL row comes back with ``replayed``
              true — which is what lets the API answer a second ``create_account``
              with the first decision and a replay indicator (Requirement 3.8/3.11)
              without needing to compare the two itself.

        Raises ``sqlite3.IntegrityError`` if the run does not exist, and — for a
        writer that bypasses the dataclass — if the stored shape would violate the
        route/decider or reference-only CHECKs.
        """

        self.initialize()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            return self.record_admission_decision_in_transaction(connection, decision=decision)

    def record_admission_decision_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        decision: AdmissionDecision,
    ) -> tuple[AdmissionDecision, bool]:
        """Record an admission decision inside the caller's unit of work.

        The phase driver commits ``route_selected_login`` or ``route_selected_signup``
        in the same transaction that records the decision authorizing it, so the two
        cannot disagree after a crash between them.

        ``ON CONFLICT(run_id) DO NOTHING`` rather than ``INSERT OR IGNORE``: the
        conflict target is the primary key alone, so a replayed run is a silent
        no-op while a CHECK violation still raises instead of vanishing.
        """

        cursor = connection.execute(
            """
            INSERT INTO onboarding_admission_decisions (
                run_id, profile_digest, route, reason_code, decided_by,
                actor_owner_id, decided_at, credential_refs_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(run_id) DO NOTHING
            """,
            (
                _safe_text(decision.run_id),
                decision.profile_digest,
                decision.route,
                decision.reason_code,
                decision.decided_by,
                _safe_text(decision.actor_owner_id),
                decision.decided_at,
                _credential_refs_json(decision.credential_refs),
            ),
        )
        stored = self.read_admission_decision_in_transaction(connection, run_id=decision.run_id)
        if stored is None:  # pragma: no cover - insertion invariant
            raise RuntimeError("admission decision could not be read back")
        # A row inserted now is the first decision; a conflict means this run already
        # held one, so the caller is looking at a replay of that earlier answer even
        # when the two happen to be identical.
        return (stored, cursor.rowcount == 0)

    def read_admission_decision(self, run_id: str) -> AdmissionDecision | None:
        """The run's recorded admission decision, or ``None`` if it has none yet."""

        self.initialize()
        with self._connect() as connection:
            return self.read_admission_decision_in_transaction(connection, run_id=run_id)

    def read_admission_decision_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
    ) -> AdmissionDecision | None:
        """Read the recorded decision inside the caller's unit of work.

        Rebuilt as an ``AdmissionDecision`` rather than handed back as a row, so a
        stored record passes the same construction checks a fresh one does before
        any caller acts on it.
        """

        row = connection.execute(
            """
            SELECT run_id, profile_digest, route, reason_code, decided_by,
                   actor_owner_id, decided_at, credential_refs_json
            FROM onboarding_admission_decisions
            WHERE run_id = ?
            """,
            (_safe_text(run_id),),
        ).fetchone()
        if row is None:
            return None
        route = str(row[2])
        decided_by = str(row[4])
        reason_code = str(row[3])
        if route not in _ADMISSION_ROUTES:
            raise RuntimeError("stored admission route is not a known route")
        if decided_by not in _ADMISSION_DECIDERS:
            raise RuntimeError("stored admission decider is not a known decider")
        if reason_code not in ONBOARDING_REASON_CODES:
            raise RuntimeError("stored admission reason code is not a known code")
        return AdmissionDecision(
            run_id=str(row[0]),
            profile_digest=str(row[1]),
            route=route,
            reason_code=reason_code,
            decided_by=decided_by,
            actor_owner_id=str(row[5]),
            decided_at=str(row[6]),
            credential_refs=_credential_refs(row[7]),
        )

    def record_autonomy_outcome(self, *, outcome: Mapping[str, object]) -> bool:
        """Write the run's one autonomy outcome, and only the first one.

        PRE:  ``outcome`` carries exactly the 19 declared fields — the shape
              ``dataclasses.asdict`` produces for
              :class:`ops.onboarding.driver.AutonomyOutcome`, whose own
              construction checks have already held.
        POST: returns ``True`` when this call wrote the record and ``False`` when
              the run already had one, in which case nothing was written and the
              ORIGINAL record stands. Requirement 20.4 is therefore a property of
              the primary key rather than of the caller's bookkeeping: a terminal
              phase re-driven after a crash, or driven twice by two workers,
              leaves exactly one record.

        Raises ``sqlite3.IntegrityError`` if the run does not exist, and
        ``ValueError`` for an outcome whose shape the durable record refuses.
        """

        self.initialize()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            return self.record_autonomy_outcome_in_transaction(connection, outcome=outcome)

    def record_autonomy_outcome_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        outcome: Mapping[str, object],
    ) -> bool:
        """Write the autonomy outcome inside the caller's unit of work.

        ``ON CONFLICT(run_id) DO NOTHING`` rather than ``INSERT OR IGNORE``, the
        same choice the admission decision makes: the conflict target is the
        primary key alone, so a second write for the run is a silent no-op while a
        CHECK violation still raises instead of vanishing.
        """

        row = _autonomy_outcome_row(outcome)
        columns = ", ".join(_AUTONOMY_OUTCOME_COLUMNS)
        placeholders = ", ".join("?" for _ in _AUTONOMY_OUTCOME_COLUMNS)
        cursor = connection.execute(
            f"INSERT INTO onboarding_autonomy_outcomes ({columns}) VALUES ({placeholders}) "
            "ON CONFLICT(run_id) DO NOTHING",
            row,
        )
        return cursor.rowcount == 1

    def read_autonomy_outcome(self, run_id: str) -> dict[str, Any] | None:
        """The run's recorded autonomy outcome, or ``None`` if it has none yet."""

        self.initialize()
        with self._connect() as connection:
            return self.read_autonomy_outcome_in_transaction(connection, run_id=run_id)

    def read_autonomy_outcome_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
    ) -> dict[str, Any] | None:
        """Read the recorded outcome inside the caller's unit of work."""

        columns = ", ".join(_AUTONOMY_OUTCOME_COLUMNS)
        row = connection.execute(
            f"SELECT {columns} FROM onboarding_autonomy_outcomes WHERE run_id = ?",
            (_safe_text(run_id),),
        ).fetchone()
        if row is None:
            return None
        return dict(zip(_AUTONOMY_OUTCOME_COLUMNS, row, strict=True))

    def list_autonomy_outcomes(self, *, limit: int = MAX_METRIC_ROWS) -> list[dict[str, Any]]:
        """Every recorded autonomy outcome, oldest first, bounded by ``limit``.

        The bulk read the autonomy metrics are computed from (Requirement 20.6).
        It exists so a metric is a projection of the durable records rather than a
        counter somebody incremented beside them: the same rows
        :meth:`read_autonomy_outcome` returns one at a time, in the same column
        order, so a metric and a run detail response cannot disagree.

        Bounded rather than unbounded because a metrics read must not be able to
        pull the whole table into memory; the caller that wants a wider window
        asks for one, up to :data:`MAX_METRIC_ROWS`.
        """

        self.initialize()
        columns = ", ".join(_AUTONOMY_OUTCOME_COLUMNS)
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT {columns} FROM onboarding_autonomy_outcomes "
                "ORDER BY ended_at ASC, run_id ASC LIMIT ?",
                (_metric_row_limit(limit),),
            ).fetchall()
        return [dict(zip(_AUTONOMY_OUTCOME_COLUMNS, row, strict=True)) for row in rows]

    def list_phase_boundaries(
        self,
        *,
        run_id: str | None = None,
        limit: int = MAX_METRIC_ROWS,
    ) -> list[dict[str, Any]]:
        """Committed phase boundaries, ordered per run, bounded by ``limit``.

        The autonomy outcome records one duration for the whole run, so the two
        metrics that are *per phase* — the phase duration distribution and
        time-to-verification — cannot be computed from it. They are computed from
        these boundaries instead, which are equally durable: the interval a run
        stood in a phase is the gap between the boundary that entered it and the
        boundary that left it. Still no log scraping (Requirement 20.6).
        """

        self.initialize()
        clause = "" if run_id is None else "WHERE run_id = ? "
        parameters: tuple[object, ...] = (
            (_metric_row_limit(limit),)
            if run_id is None
            else (_safe_text(run_id), _metric_row_limit(limit))
        )
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT run_id, sequence, from_phase, to_phase, reason_code, "
                "profile_digest, attempt, correlation_id, committed_at "
                f"FROM onboarding_phase_history {clause}"
                "ORDER BY run_id ASC, sequence ASC LIMIT ?",
                parameters,
            ).fetchall()
        return [dict(zip(_PHASE_BOUNDARY_COLUMNS, row, strict=True)) for row in rows]

    def get_side_effect(self, run_id: str, operation_key: str) -> dict[str, Any] | None:
        self.initialize()
        with self._connect() as connection:
            return self._get_side_effect(connection, run_id, operation_key)

    @staticmethod
    def _get_side_effect(
        connection: sqlite3.Connection,
        run_id: str,
        operation_key: str,
    ) -> dict[str, Any] | None:
        row = connection.execute(
            """
            SELECT run_id, operation_key, provider, status, external_id,
                   created_at, updated_at
            FROM side_effect_intents
            WHERE run_id = ? AND operation_key = ?
            """,
            (_safe_text(run_id), _safe_text(operation_key)),
        ).fetchone()
        if row is None:
            return None
        return dict(
            zip(
                (
                    "run_id",
                    "operation_key",
                    "provider",
                    "status",
                    "external_id",
                    "created_at",
                    "updated_at",
                ),
                row,
                strict=True,
            )
        )

    def update_side_effect(
        self,
        *,
        run_id: str,
        operation_key: str,
        status: str,
        external_id: str | None = None,
    ) -> dict[str, Any]:
        self.initialize()
        with self._connect() as connection:
            return self._update_side_effect(
                connection,
                run_id=run_id,
                operation_key=operation_key,
                status=status,
                external_id=external_id,
            )

    def _update_side_effect(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        operation_key: str,
        status: str,
        external_id: str | None = None,
    ) -> dict[str, Any]:
        if status not in _SIDE_EFFECT_STATUSES:
            raise ValueError("side-effect status is invalid")
        cursor = connection.execute(
            """
            UPDATE side_effect_intents
            SET status = ?, external_id = ?, updated_at = ?
            WHERE run_id = ? AND operation_key = ?
            """,
            (
                status,
                _safe_text(external_id),
                _utc_now(),
                _safe_text(run_id),
                _safe_text(operation_key),
            ),
        )
        if cursor.rowcount != 1:
            raise KeyError("side-effect intent was not found")
        record = self._get_side_effect(connection, run_id, operation_key)
        if record is None:  # pragma: no cover - update invariant
            raise RuntimeError("side-effect intent could not be read back")
        return record

    @staticmethod
    def _run_from_row(row: sqlite3.Row | tuple[object, ...]) -> dict[str, Any]:
        record = dict(zip(_RUN_COLUMNS, row, strict=True))
        for public_name, column_name in _JSON_RUN_FIELDS.items():
            serialized = record.pop(column_name)
            if serialized is None:
                record[public_name] = _DEFAULT_JSON_VALUES.get(public_name)
            else:
                record[public_name] = json.loads(str(serialized))
        record["external_actions"] = bool(record["external_actions"])
        return record

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        existed = prepare_private_database(self.db_path)
        connection = sqlite3.connect(self.db_path, timeout=5)
        try:
            finalize_private_database(self.db_path, existed=existed)
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA secure_delete = ON")
            with connection:
                yield connection
        finally:
            connection.close()
