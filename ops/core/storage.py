"""Narrow, sanitized persistence API for runs and structured audit events."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, get_args
from urllib.parse import urlsplit

from ops.browser.candidates import CandidateAction
from ops.browser.worker import HumanActionType
from ops.core.inference import DecisionReasonCode
from ops.core.model_input_dlp import (
    contains_secret_material,
    sanitize_element_name,
    sanitize_reason,
)
from ops.core.private_files import finalize_private_database, prepare_private_database
from ops.core.redaction import redact_data, redact_text
from ops.core.secret_store import parse_vault_reference
from ops.core.state import RUN_STATUSES, AccessRoute, RunStatus
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
    "decision_model",
    "decision_effort",
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


# The two closed words a plan revision's lifecycle uses, and the two ways a plan
# is authored. Exported so ``ops/planner/plan.py`` can assert its ``PlanSource``
# Literal against this tuple the way ``ops.onboarding.driver`` asserts its
# ``AutonomyVerdict`` against :data:`AUTONOMY_VERDICT_VALUES` — the planner
# imports this module for the run ledger, so importing it back would be a cycle.
RUN_PLAN_STATUS_VALUES: Final[tuple[str, ...]] = ("active", "superseded")
RUN_PLAN_SOURCE_VALUES: Final[tuple[str, ...]] = ("planner", "recipe")

# The stages one action-loop iteration reports from (reliability R4.1). Declared
# here for the same reason as the verdicts above: ``ops/onboarding/action_loop.py``
# owns the ``LoopStage`` Literal and asserts equality with this tuple, so a stage
# added on one side fails to import instead of failing a CHECK against a live run.
LOOP_STAGE_VALUES: Final[tuple[str, ...]] = (
    "observe",
    "candidates",
    "decide",
    "act",
    "verify",
    "gate",
    "exhausted",
)

# What one inference attempt is recorded as: usable, or the typed reason it was
# not. Derived from :data:`ops.core.inference.DecisionReasonCode` rather than
# retyped, so the column's vocabulary follows the producer's own Literal and the
# two cannot drift. ``ops.core.inference`` imports nothing from ``ops``, so the
# edge is safe.
DECISION_OUTCOME_VALUES: Final[tuple[str, ...]] = ("usable", *get_args(DecisionReasonCode))

# The two things a decision is made for: one loop action, or one pre-flight plan.
DECISION_ATTEMPT_PURPOSE_VALUES: Final[tuple[str, ...]] = ("action", "plan")

# A plan carries at most the recipe's own step count, and the recipe bounds that
# at 12. Enforced here as well as by ``ops.planner.plan.RunPlan`` for the reason
# the admission and autonomy tables give: the dataclass protects callers that go
# through it, the writer protects the durable record from anything that does not.
MAX_PLAN_SURFACES: Final = 12

# A surface is a host and a path, never a URL: the query string and the fragment
# are dropped before a plan is built, so no bound here has to be wide enough for
# one. The host bound is the DNS name limit; the path bound is the design's.
MAX_SURFACE_HOST_LENGTH: Final = 253
MAX_SURFACE_PATH_LENGTH: Final = 300

# Twelve surfaces of a bounded host and a bounded path fit inside this with room
# to spare, so the column bound is a blob guard rather than a working limit.
MAX_PLAN_SURFACES_JSON_LENGTH: Final = 4_000

# ``app_slug``, ``catalog_id`` and ``recipe_version`` are catalog identifiers —
# ``salesforce``, ``approved-50-routes-2026-07-28``, ``…-2026-07-28@1.0``. The
# shape admits what the catalog actually carries and refuses ``/``, ``?``, ``#``,
# ``:`` and whitespace, so a URL cannot be stored under any of the three.
MAX_PLAN_IDENTIFIER_LENGTH: Final = 200
_PLAN_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,199}$")

# A provider name is a lower snake_case word (``mercury``, ``openai_compatible``),
# bounded well below anything a payload would need.
MAX_DECISION_PROVIDER_LENGTH: Final = 40

# The bounds ``api.models.RunProgressEventView`` projects these two integers
# under. Enforced at the write so a durable row cannot exist that the API view
# would refuse to render.
MAX_PROGRESS_STEP_INDEX: Final = 100_000
MAX_TELEMETRY_ELAPSED_MS: Final = 3_600_000

# How one loop iteration's decision ended. The first three are the decisions
# ``ops.browser.decider.validate_choice`` admits; ``rejected`` is the loop's own
# verdict on a reply it threw away, which the model never authors.
STEP_DECISION_VALUES: Final[tuple[str, ...]] = (
    "select_candidate",
    "report_hitl",
    "report_blocked",
    "rejected",
)

# The action kinds a candidate can carry, derived from the policy generator's own
# Literal rather than retyped, for the reason :data:`DECISION_OUTCOME_VALUES`
# gives: the column's vocabulary follows the producer and the two cannot drift.
CANDIDATE_ACTION_VALUES: Final[tuple[str, ...]] = get_args(CandidateAction)

# A candidate label is one accessible name, already truncated to 120 characters by
# ``generate_candidates`` before it is stored. The bound is stated here as well so
# the column refuses anything longer regardless of who writes it.
MAX_CANDIDATE_LABEL_LENGTH: Final = 120

# The only column in this schema that holds model-authored prose. Bounded far
# below anything a payload would need, and screened before it is written: see
# :meth:`OperationsStorage.record_step_decision` for the quarantine rules.
MAX_DECISION_REASON_LENGTH: Final = 400


# One row per plan revision (Requirements 5.7, 6.6). History, not current state:
# a re-plan supersedes the active row and inserts its replacement in the same
# transaction, so the superseded plan and the plan that replaced it both stay
# readable and the route change is reconstructable.
#
# The partial unique index is what makes "at most one active plan per run"
# unrepresentable otherwise rather than merely intended, and it is also the reason
# two workers racing to re-plan produce one plan instead of two: the loser blocks
# on the write lock, then supersedes the winner's row rather than adding a second
# active one. ``UNIQUE (run_id, revision)`` gives the same guarantee for the
# revision sequence.
#
# No column here is free-form. The surfaces are a JSON array whose CHECK refuses a
# query string and a fragment outright; the credential surface is a bounded host
# and an absolute bounded path, both refusing the same two characters, so the
# design's claim that no column can hold a URL with a query string holds for the
# credential columns too and not only for the array; the reason code comes from
# the onboarding vocabulary; and the success signal is a digest of the recipe's own
# predicate rather than re-copied clause text.
_RUN_PLANS_DDL = f"""
CREATE TABLE IF NOT EXISTS onboarding_run_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    status TEXT NOT NULL CHECK (
        status IN ({_vocabulary_clause(RUN_PLAN_STATUS_VALUES)})
    ),
    source TEXT NOT NULL CHECK (
        source IN ({_vocabulary_clause(RUN_PLAN_SOURCE_VALUES)})
    ),
    app_slug TEXT NOT NULL,
    catalog_id TEXT NOT NULL,
    recipe_version TEXT NOT NULL,
    surfaces_json TEXT NOT NULL CHECK (
        surfaces_json LIKE '[%]' AND length(surfaces_json) <= {MAX_PLAN_SURFACES_JSON_LENGTH}
        AND surfaces_json NOT LIKE '%?%' AND surfaces_json NOT LIKE '%#%'
    ),
    -- NULL for an entry_only recipe, which declares no credential-management URL.
    -- The two columns are null together: a half-named surface is not a surface.
    credential_host TEXT CHECK (
        credential_host IS NULL OR (
            length(credential_host) <= {MAX_SURFACE_HOST_LENGTH}
            AND credential_host NOT LIKE '%/%'
            AND credential_host NOT LIKE '%?%' AND credential_host NOT LIKE '%#%'
        )
    ),
    credential_path TEXT CHECK (
        credential_path IS NULL OR (
            credential_path LIKE '/%' AND length(credential_path) <= {MAX_SURFACE_PATH_LENGTH}
            AND credential_path NOT LIKE '%?%' AND credential_path NOT LIKE '%#%'
        )
    ),
    success_digest TEXT NOT NULL,
    reason_code TEXT NOT NULL CHECK (
        reason_code IN ({_vocabulary_clause(ONBOARDING_REASON_CODES)})
    ),
    created_at TEXT NOT NULL,
    superseded_at TEXT,
    superseded_by INTEGER,
    CHECK ((credential_host IS NULL) = (credential_path IS NULL)),
    UNIQUE (run_id, revision),
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_run_plans_active
ON onboarding_run_plans(run_id) WHERE status = 'active';
"""


def _relax_run_plan_credential_columns(connection: sqlite3.Connection) -> None:
    """Drop NOT NULL from the credential columns of a pre-existing plan table.

    An entry_only recipe declares no credential-management URL, so its plan stores
    NULL there. SQLite cannot relax NOT NULL in place, so a database created before
    that change is rebuilt through the documented rename-copy-drop procedure. Rows
    are preserved exactly: every existing plan has both values and keeps them.
    """

    columns = connection.execute("PRAGMA table_info(onboarding_run_plans)").fetchall()
    if not columns:  # A fresh database; _RUN_PLANS_DDL creates it correctly.
        return
    not_null = {str(row[1]) for row in columns if int(row[3]) == 1}
    if not not_null & {"credential_host", "credential_path"}:
        return

    # The declared column order, so an added column fails loudly at the INSERT
    # rather than being silently dropped on the next open.
    names = ", ".join(_RUN_PLAN_COLUMNS)
    # The index travels with the table across a rename, so it is dropped first and
    # recreated by _RUN_PLANS_DDL against the rebuilt table.
    connection.execute("DROP INDEX IF EXISTS idx_run_plans_active")
    connection.execute("ALTER TABLE onboarding_run_plans RENAME TO onboarding_run_plans_legacy")
    connection.executescript(_RUN_PLANS_DDL)
    connection.execute(
        f"INSERT INTO onboarding_run_plans ({names}) "  # noqa: S608 - fixed column list
        f"SELECT {names} FROM onboarding_run_plans_legacy"
    )
    connection.execute("DROP TABLE onboarding_run_plans_legacy")


# The CHECK ``runs.status`` gains, generated from the Literal so the column and the
# type cannot drift. It is applied by rebuild rather than written into the CREATE
# TABLE above because that statement is a plain script shared with a long list of
# ALTER-migrated columns; one rebuild path serves a fresh and a deployed database
# alike, and a rebuilt table carries whichever columns the database actually has.
_RUN_STATUS_CHECK: Final = f"CHECK (status IN ({_vocabulary_clause(RUN_STATUSES)}))"
_RUNS_TABLE_REBUILD = "runs_status_check_rebuild"
# ``status TEXT NOT NULL`` exactly once, and only where a CHECK does not already
# follow it. Anchored on the column name so the transform cannot land on a
# same-named column of another table's SQL.
_RUN_STATUS_COLUMN = re.compile(r"\bstatus\s+TEXT\s+NOT\s+NULL\b(?!\s*CHECK)", re.IGNORECASE)
# sqlite_master stores the statement without ``IF NOT EXISTS`` and may quote the
# name, so the rebuild renames the target by pattern rather than by literal text.
_RUNS_CREATE_PREFIX = re.compile(
    r"^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[\"'`\[]?runs[\"'`\]]?", re.IGNORECASE
)


def _add_run_status_check(connection: sqlite3.Connection) -> None:
    """Constrain ``runs.status`` to the closed vocabulary, preserving every row.

    SQLite cannot add a CHECK in place, so the table is rebuilt by the documented
    create-copy-drop-rename procedure. The replacement is derived from the *stored*
    schema rather than from a literal here: thirteen tables carry a foreign key into
    ``runs`` and a deployed database has columns this module only adds by ALTER, so
    re-deriving is what keeps the rebuilt table identical but for the constraint.

    A row whose status is outside the vocabulary fails the copy. That is the
    intended outcome — it is the same value the API cannot name — and it surfaces as
    a refusal to open the ledger rather than a corrupted one, because the rebuild is
    a single transaction that takes the old table with it when it rolls back.
    """

    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'runs'"
    ).fetchone()
    if row is None or not row[0]:  # pragma: no cover - initialize() just created it
        return
    original = str(row[0])
    if "CHECK (status IN (" in original:
        return
    replacement, substitutions = _RUN_STATUS_COLUMN.subn(
        lambda match: f"{match.group(0)} {_RUN_STATUS_CHECK}", original, count=1
    )
    if substitutions != 1:  # pragma: no cover - the column is in the DDL above
        raise RuntimeError("runs.status column could not be located for its CHECK migration")
    names = ", ".join(
        str(column[1]) for column in connection.execute("PRAGMA table_info(runs)").fetchall()
    )

    # Foreign keys MUST be off for the whole rebuild. `DROP TABLE runs` with them on
    # runs an implicit DELETE first, and thirteen child tables cascade on delete: the
    # drop would take the entire ledger with it. The pragma is also a no-op inside a
    # transaction, so the pending one is committed before it is set.
    connection.commit()
    connection.execute("PRAGMA foreign_keys = OFF")
    try:
        connection.execute("BEGIN IMMEDIATE")
        # Renaming `runs` would rewrite the referencing tables' FOREIGN KEY clauses to
        # follow it. Building the replacement under a temporary name and renaming *it*
        # into place leaves those clauses naming `runs` throughout, which is why the
        # order is create-copy-drop-rename rather than rename-copy-drop.
        rebuild_ddl, renamed = _RUNS_CREATE_PREFIX.subn(
            f"CREATE TABLE {_RUNS_TABLE_REBUILD}", replacement, count=1
        )
        if renamed != 1:  # pragma: no cover - the statement came from sqlite_master
            raise RuntimeError("runs table statement could not be renamed for its CHECK migration")
        connection.execute(rebuild_ddl)
        connection.execute(
            f"INSERT INTO {_RUNS_TABLE_REBUILD} ({names}) "  # noqa: S608 - names come from PRAGMA
            f"SELECT {names} FROM runs"
        )
        connection.execute("DROP TABLE runs")
        # Legacy rename semantics for this one statement: the modern form re-parses
        # every referencing table, and they name a `runs` that does not exist between
        # the drop and this rename.
        connection.execute("PRAGMA legacy_alter_table = ON")
        try:
            connection.execute(f"ALTER TABLE {_RUNS_TABLE_REBUILD} RENAME TO runs")
        finally:
            connection.execute("PRAGMA legacy_alter_table = OFF")
        orphans = connection.execute("PRAGMA foreign_key_check").fetchall()
        if orphans:
            raise RuntimeError("runs.status CHECK migration would orphan referencing rows")
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.execute("PRAGMA foreign_keys = ON")


# One row per completed loop iteration (Requirement 4.1). Append-only and never
# deduplicated, like the denial facts above: "the loop stepped again" is a fact
# about a moment, and the absence of new rows is exactly what makes a stalled run
# visible (Requirement 4.9).
#
# Every column is closed, fixed-width, or a bounded count — a phase and a stage
# from the code vocabularies, a content-addressed digest, the correlation id that
# ties the row to the phase boundary it happened under, and two integers. There is
# no column a prompt, a page projection, or a URL could be written into
# (Requirement 4.10).
_PROGRESS_EVENTS_DDL = f"""
CREATE TABLE IF NOT EXISTS onboarding_progress_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (
        phase IN ({_vocabulary_clause(ONBOARDING_PHASES)})
    ),
    profile_digest TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    step_index INTEGER NOT NULL CHECK (step_index >= 1),
    stage TEXT NOT NULL CHECK (
        stage IN ({_vocabulary_clause(LOOP_STAGE_VALUES)})
    ),
    elapsed_ms INTEGER NOT NULL CHECK (elapsed_ms >= 0),
    recorded_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_progress_events_run
ON onboarding_progress_events(run_id, id);
"""


# One row per inference attempt (Requirement 4.3): the provider that was called,
# how the attempt ended, and how long it took. Nothing else — no prompt, no
# payload, no answer (Requirement 4.10).
#
# One row *per attempt* rather than per decision is the point of the table: a
# provider skipped by its circuit breaker never appears in a decision's reason
# codes, so "Mercury was attempted first" is only answerable from attempts
# (Requirement 4.11).
_DECISION_ATTEMPTS_DDL = f"""
CREATE TABLE IF NOT EXISTS onboarding_decision_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (
        phase IN ({_vocabulary_clause(ONBOARDING_PHASES)})
    ),
    purpose TEXT NOT NULL CHECK (
        purpose IN ({_vocabulary_clause(DECISION_ATTEMPT_PURPOSE_VALUES)})
    ),
    provider TEXT NOT NULL CHECK (length(provider) <= {MAX_DECISION_PROVIDER_LENGTH}),
    outcome TEXT NOT NULL CHECK (
        outcome IN ({_vocabulary_clause(DECISION_OUTCOME_VALUES)})
    ),
    latency_ms INTEGER NOT NULL CHECK (latency_ms >= 0),
    recorded_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_decision_attempts_run
ON onboarding_decision_attempts(run_id, id);
"""


# One row per decision the loop reached, so the operator console can say *what*
# the agent chose and *why* rather than only that an iteration happened. Joins to
# ``onboarding_progress_events`` on ``(run_id, correlation_id, step_index)``; the
# loop writes exactly one progress row per iteration (invariant I5), so the join
# is one-to-one.
#
# ``reason_text`` is the one column in this schema that holds model-authored
# prose, and it is the reason the rest of the row is shaped the way it is. Every
# other column is a closed vocabulary, a bounded accessible name, or a bare host —
# nothing that could carry a URL with a query string, a selector, or page markup.
# The prose itself is capped, screened, and stored inert: see
# :meth:`OperationsStorage.record_step_decision`. When the screen refuses it the
# row still exists with ``reason_withheld = 1``, because "the model explained
# itself and we would not repeat it" and "the model said nothing" are different
# facts and the console renders them differently.
_STEP_DECISIONS_DDL = f"""
CREATE TABLE IF NOT EXISTS onboarding_step_decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (
        phase IN ({_vocabulary_clause(ONBOARDING_PHASES)})
    ),
    correlation_id TEXT NOT NULL,
    step_index INTEGER NOT NULL CHECK (step_index >= 1),
    decision TEXT NOT NULL CHECK (
        decision IN ({_vocabulary_clause(STEP_DECISION_VALUES)})
    ),
    reason_code TEXT,
    candidate_label TEXT CHECK (
        candidate_label IS NULL OR length(candidate_label) <= {MAX_CANDIDATE_LABEL_LENGTH}
    ),
    action TEXT CHECK (
        action IS NULL OR action IN ({_vocabulary_clause(CANDIDATE_ACTION_VALUES)})
    ),
    target_host TEXT CHECK (
        target_host IS NULL OR length(target_host) <= {MAX_SURFACE_HOST_LENGTH}
    ),
    reason_text TEXT CHECK (
        reason_text IS NULL OR length(reason_text) <= {MAX_DECISION_REASON_LENGTH}
    ),
    reason_withheld INTEGER NOT NULL DEFAULT 0 CHECK (reason_withheld IN (0, 1)),
    recorded_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_step_decisions_run
ON onboarding_step_decisions(run_id, id);
"""


# The three new tables' columns, in each table's own declared order, so the
# readers below hand out mappings without listing the columns a second time.
_RUN_PLAN_COLUMNS: Final[tuple[str, ...]] = (
    "id",
    "run_id",
    "revision",
    "status",
    "source",
    "app_slug",
    "catalog_id",
    "recipe_version",
    "surfaces_json",
    "credential_host",
    "credential_path",
    "success_digest",
    "reason_code",
    "created_at",
    "superseded_at",
    "superseded_by",
)
_PROGRESS_EVENT_COLUMNS: Final[tuple[str, ...]] = (
    "id",
    "run_id",
    "phase",
    "profile_digest",
    "correlation_id",
    "step_index",
    "stage",
    "elapsed_ms",
    "recorded_at",
)
_DECISION_ATTEMPT_COLUMNS: Final[tuple[str, ...]] = (
    "id",
    "run_id",
    "phase",
    "purpose",
    "provider",
    "outcome",
    "latency_ms",
    "recorded_at",
)
_STEP_DECISION_COLUMNS: Final[tuple[str, ...]] = (
    "id",
    "run_id",
    "phase",
    "correlation_id",
    "step_index",
    "decision",
    "reason_code",
    "candidate_label",
    "action",
    "target_host",
    "reason_text",
    "reason_withheld",
    "recorded_at",
)


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


def _vocabulary_member(value: object, *, vocabulary: tuple[str, ...], field: str) -> str:
    """One value from a closed vocabulary, refused here before the column CHECK."""

    if not isinstance(value, str) or value not in vocabulary:
        raise ValueError(f"an onboarding {field} must be one of: {', '.join(vocabulary)}")
    return value


def _telemetry_count(value: object, *, field: str, minimum: int, maximum: int) -> int:
    """One bounded telemetry integer, and never a bool.

    Bounded at the top as well as the bottom because
    :class:`api.models.RunProgressEventView` projects these integers under the same
    bounds: a durable row the API view would refuse to render must not be writable.
    """

    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(
            f"an onboarding telemetry {field} must be an integer between {minimum} and {maximum}"
        )
    return value


def _plan_identifier(value: object, *, field: str) -> str:
    """One catalog identifier a plan row carries.

    The shape refuses ``/``, ``?``, ``#``, ``:`` and whitespace, so none of the
    three identifier columns can hold a URL even though only the surface columns
    carry a CHECK that says so.
    """

    if not isinstance(value, str) or _PLAN_IDENTIFIER.fullmatch(value) is None:
        raise ValueError(
            f"a run plan {field} must be a catalog identifier of at most "
            f"{MAX_PLAN_IDENTIFIER_LENGTH} characters"
        )
    return value


def _plan_digest(value: object, *, field: str) -> str:
    """The sha-256 digest a plan row carries in place of re-copied clause text."""

    if not isinstance(value, str) or _PROFILE_DIGEST.fullmatch(value) is None:
        raise ValueError(f"a run plan {field} must be a sha256 hex digest")
    return value


def _surface_host(value: object, *, field: str) -> str:
    """One planned surface's host: lower case, no port, no userinfo, no path.

    A host that would need normalizing is refused rather than normalized here.
    ``ops.planner.plan.canonical_surface`` owns canonicalization; a durable row that
    differed from what the planner canonicalized would make an adherence comparison
    lie about where the run was expected to be.
    """

    if not isinstance(value, str) or not value or len(value) > MAX_SURFACE_HOST_LENGTH:
        raise ValueError(f"a plan {field} must be a bounded host name")
    if not value.isascii() or value != value.lower():
        raise ValueError(f"a plan {field} must be a lower-case ascii host name")
    if any(character in value for character in "/?#:@ "):
        raise ValueError(f"a plan {field} carries no port, userinfo, path, query, or fragment")
    return value


def _decision_label(value: object) -> str | None:
    """One candidate's accessible name, bounded and stripped of secret material.

    The name is page-derived, so it goes through the same sanitizer the model's own
    projection uses (:func:`ops.core.model_input_dlp.sanitize_element_name`) before
    it is bounded here. A name that sanitizes away to nothing is stored as ``NULL``
    rather than as an empty string: the console distinguishes "no label" from a
    label it would not repeat.
    """

    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("a step decision candidate label must be text")
    cleaned = _collapse_whitespace(sanitize_element_name(value))
    if not cleaned:
        return None
    return cleaned[:MAX_CANDIDATE_LABEL_LENGTH]


def _decision_reason(value: object) -> str | None:
    """The model's own explanation, quarantined before it becomes a durable row.

    This is the only model-authored prose the ledger holds, and it was written by a
    backend that had just read a live third-party page — so it is treated as
    hostile input on the way in, not as an explanation to be trusted.

    Three things happen here, and a failure at any of them yields ``None`` (the
    caller records ``reason_withheld``) rather than an exception: a decision must
    stay recordable even when its stated reason is not repeatable.

    1. Control characters go, whitespace collapses, and the text is capped at
       :data:`MAX_DECISION_REASON_LENGTH`.
    2. :func:`ops.core.model_input_dlp.sanitize_reason` redacts secret-shaped
       tokens the way it does for every other page-derived string.
    3. :func:`ops.core.model_input_dlp.contains_secret_material` gets the last
       word: text that still looks credential-bearing after redaction is dropped
       whole rather than stored partly redacted. So is text that redaction hollowed
       out — a reason that is nothing but ``[REDACTED]`` is withheld rather than
       stored, because rendering it would attribute the placeholder to the model.

    What is *not* done here is any attempt to make the text safe to interpret. It
    is stored inert and rendered inert — never parsed as markup, never linkified,
    never allowed to drive a control. See ``web/src/components/agent-trace.tsx``.
    """

    if value is None:
        return None
    if not isinstance(value, str):
        return None
    collapsed = _collapse_whitespace(value)[:MAX_DECISION_REASON_LENGTH]
    if not collapsed:
        return None
    sanitized = _collapse_whitespace(
        sanitize_reason(collapsed, max_length=MAX_DECISION_REASON_LENGTH)
    )
    if not sanitized or contains_secret_material(sanitized):
        return None
    if not _REASON_SUBSTANCE.sub("", sanitized).strip():
        return None
    return sanitized[:MAX_DECISION_REASON_LENGTH]


# Everything redaction leaves behind that is not the model's own words: the
# placeholder itself, and the punctuation a hollowed-out sentence keeps.
_REASON_SUBSTANCE = re.compile(r"\[[A-Z_]+\]|[\W_]+")


def _decision_host(value: object) -> str | None:
    """The bare host a decision's action pointed at, or ``NULL``.

    Deliberately lenient where :func:`_surface_host` is strict. A plan surface is
    compared against later, so a host that would need normalizing is a bug worth
    raising on; a decision row is a description of something that already happened,
    and losing the whole row because a host had a port in it would be the wrong
    trade. Anything unusable becomes ``NULL``.

    Only the host is kept — never the path, query, or fragment — so a URL that
    carried a token in its query cannot reach the row through this column.
    """

    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()
    host = urlsplit(candidate).hostname if "//" in candidate else candidate.split("/")[0]
    if not host:
        return None
    host = host.split("@")[-1].split(":")[0].strip().lower()
    if not host or not host.isascii() or len(host) > MAX_SURFACE_HOST_LENGTH:
        return None
    if any(character in host for character in "/?#@ "):
        return None
    return host


def _collapse_whitespace(value: str) -> str:
    """Drop control characters and squeeze runs of whitespace to single spaces."""

    printable = "".join(character if character.isprintable() else " " for character in value)
    return " ".join(printable.split())


def _surface_path(value: object, *, field: str) -> str:
    """One planned surface's path: absolute, bounded, and never a URL."""

    if not isinstance(value, str) or len(value) > MAX_SURFACE_PATH_LENGTH:
        raise ValueError(f"a plan {field} must be a bounded absolute path")
    if not value.isascii() or not value.startswith("/"):
        raise ValueError(f"a plan {field} must be an absolute ascii path")
    if any(character in value for character in "?# "):
        raise ValueError(f"a plan {field} carries no query string and no fragment")
    return value


def _both_or_neither(host: object, path: object) -> bool:
    """Whether the credential pair is absent, refusing a half-named surface."""

    if host is None and path is None:
        return True
    if host is None or path is None:
        raise ValueError("a plan credential surface names both a host and a path, or neither")
    return False


def _optional_surface_host(host: object, path: object) -> str | None:
    if _both_or_neither(host, path):
        return None
    return _surface_host(host, field="credential surface host")


def _optional_surface_path(host: object, path: object) -> str | None:
    if _both_or_neither(host, path):
        return None
    return _surface_path(path, field="credential surface path")


def _decision_provider(value: object) -> str:
    """One backend's own name (``mercury``, ``openai_compatible``), bounded.

    Refused rather than truncated: a truncated provider name would still be stored,
    and a telemetry row that names the wrong provider is worse than none.
    """

    if not isinstance(value, str) or len(value) > MAX_DECISION_PROVIDER_LENGTH:
        raise ValueError(
            f"a decision provider name must be at most {MAX_DECISION_PROVIDER_LENGTH} characters"
        )
    return _audit_label(value, field="decision provider")


def _surfaces_json(surfaces: Sequence[Mapping[str, str]]) -> str:
    """Serialize the ordered surfaces a plan names, refusing anything else.

    Each surface is exactly a host, a path, and a purpose. The purpose vocabulary is
    ``ops.planner.plan.SurfacePurpose``'s to declare, so it is bounded here as a
    label rather than restated as a second closed list that could disagree with it.
    """

    if not 1 <= len(surfaces) <= MAX_PLAN_SURFACES:
        raise ValueError(f"a run plan names 1..{MAX_PLAN_SURFACES} surfaces")
    encoded: list[dict[str, str]] = []
    for ordinal, surface in enumerate(surfaces, start=1):
        if frozenset(surface) != frozenset({"host", "path", "purpose"}):
            raise ValueError(f"plan surface {ordinal} carries a host, a path, and a purpose")
        purpose = surface["purpose"]
        if not isinstance(purpose, str):
            raise ValueError(f"plan surface {ordinal} purpose must be a label")
        encoded.append(
            {
                "host": _surface_host(surface["host"], field=f"surface {ordinal} host"),
                "path": _surface_path(surface["path"], field=f"surface {ordinal} path"),
                "purpose": _audit_label(purpose, field=f"surface {ordinal} purpose"),
            }
        )
    serialized = json.dumps(encoded, separators=(",", ":"), sort_keys=True)
    if len(serialized) > MAX_PLAN_SURFACES_JSON_LENGTH:
        raise ValueError("a run plan's surface list is too large")
    return serialized


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
        browser_provider: str = "playwright",
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
        # The decision model this run is pinned to, already resolved against
        # ``ops.core.model_catalog``. ``None`` means the deployment's own chain.
        decision_model: str | None = None,
        decision_effort: str | None = None,
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
            decision_model=decision_model,
            decision_effort=decision_effort,
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

    def count_run_plans(self, run_id: str) -> int:
        """Count every plan revision inside this run transaction."""

        return self._storage.count_run_plans_in_transaction(
            self._connection,
            run_id=run_id,
        )

    def read_active_run_plan(self, run_id: str) -> dict[str, Any] | None:
        """Read the active plan inside this run transaction."""

        return self._storage.read_active_run_plan_in_transaction(
            self._connection,
            run_id=run_id,
        )

    def record_run_plan(
        self,
        *,
        run_id: str,
        source: str,
        app_slug: str,
        catalog_id: str,
        recipe_version: str,
        surfaces: Sequence[Mapping[str, str]],
        credential_host: str | None,
        credential_path: str | None,
        success_digest: str,
        reason_code: str,
    ) -> dict[str, Any]:
        """Supersede and insert a plan inside this run transaction."""

        return self._storage.record_run_plan_in_transaction(
            self._connection,
            run_id=run_id,
            source=source,
            app_slug=app_slug,
            catalog_id=catalog_id,
            recipe_version=recipe_version,
            surfaces=surfaces,
            credential_host=credential_host,
            credential_path=credential_path,
            success_digest=success_digest,
            reason_code=reason_code,
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
                    browser_provider TEXT NOT NULL DEFAULT 'playwright',
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
                # Deliberately still 'browser_use': this ALTER backfills rows in a
                # database old enough to predate the column, and those runs really
                # did execute on the cloud adapter. Fresh tables default to
                # 'playwright' (the CREATE above), which is what every write supplies.
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
                # The decision model this run was pinned to, if the operator chose
                # one. Both nullable: a run that chose nothing uses the
                # deployment's chain, and that is the overwhelming majority.
                "decision_model": "TEXT",
                "decision_effort": "TEXT",
            }
            # Kept as their own scripts because their CHECK lists are generated
            # from the onboarding vocabularies rather than typed out.
            connection.executescript(_EFFECT_RESERVATIONS_DDL)
            connection.executescript(_ADMISSION_DECISIONS_DDL)
            connection.executescript(_NAVIGATION_DENIALS_DDL)
            connection.executescript(_AUTONOMY_OUTCOMES_DDL)
            # Additive: three new tables and their indexes, no data migration.
            # An existing database gains them on the next open (design "Release 2").
            _relax_run_plan_credential_columns(connection)
            connection.executescript(_RUN_PLANS_DDL)
            connection.executescript(_PROGRESS_EVENTS_DDL)
            connection.executescript(_DECISION_ATTEMPTS_DDL)
            connection.executescript(_STEP_DECISIONS_DDL)
            for column_name, declaration in migration_columns.items():
                if column_name in existing_columns:
                    continue
                try:
                    connection.execute(f"ALTER TABLE runs ADD COLUMN {column_name} {declaration}")
                except sqlite3.OperationalError:
                    # ``existing_columns`` was read before this statement, so another
                    # process opening the same database can add the column in between
                    # and leave our snapshot stale. That is the migration succeeding,
                    # not failing -- but only if the column is genuinely there now, so
                    # re-read rather than swallow every OperationalError.
                    current = {
                        str(row[1])
                        for row in connection.execute("PRAGMA table_info(runs)").fetchall()
                    }
                    if column_name not in current:
                        raise
            # After the ALTER migrations, so the rebuilt table carries the columns the
            # database ended up with, and before the index below, which the rebuild
            # drops along with the table it belongs to.
            _add_run_status_check(connection)
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
        browser_provider: str = "playwright",
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
        # The decision model this run is pinned to, already resolved against
        # ``ops.core.model_catalog``. ``None`` means the deployment's own chain.
        decision_model: str | None = None,
        decision_effort: str | None = None,
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
                decision_model=decision_model,
                decision_effort=decision_effort,
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
        browser_provider: str = "playwright",
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
        # The decision model this run is pinned to, already resolved against
        # ``ops.core.model_catalog``. ``None`` means the deployment's own chain.
        decision_model: str | None = None,
        decision_effort: str | None = None,
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
            _safe_text(decision_model),
            _safe_text(decision_effort),
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
                decision_model, decision_effort,
                idempotency_key, request_fingerprint,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

    def record_run_plan(
        self,
        *,
        run_id: str,
        source: str,
        app_slug: str,
        catalog_id: str,
        recipe_version: str,
        surfaces: Sequence[Mapping[str, str]],
        credential_host: str | None,
        credential_path: str | None,
        success_digest: str,
        reason_code: str,
    ) -> dict[str, Any]:
        """Record a plan revision, superseding the run's active plan in one transaction.

        PRE:  ``surfaces`` names 1..12 surfaces, each exactly a host, a path and a
              purpose, with the query string and the fragment already dropped;
              ``source`` and ``reason_code`` are members of their vocabularies.
              Everything else is refused here and, for a writer that bypasses this
              method, by the column CHECKs.
        POST: exactly one row for the run has ``status = 'active'`` — this one, at
              ``revision = max + 1``. If the run had an active plan, that row now
              reads ``superseded`` with ``superseded_at`` set and ``superseded_by``
              naming this row, so the superseded plan and its replacement are both
              still readable (Requirement 6.6). Returns the stored row.

        The supersession and the insert are one ``BEGIN IMMEDIATE`` transaction, so
        two workers racing to re-plan produce one plan rather than two: the second
        writer waits for the first to commit, then supersedes *its* row and inserts
        the next revision. The partial unique index is the backstop — a second
        active row is unrepresentable rather than merely unlikely.

        ``superseded_by`` is set by a second UPDATE after the insert because the
        replacement's id does not exist until then; the intermediate state never
        leaves the transaction.

        Raises ``sqlite3.IntegrityError`` if the run does not exist.
        """

        self.initialize()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            return self.record_run_plan_in_transaction(
                connection,
                run_id=run_id,
                source=source,
                app_slug=app_slug,
                catalog_id=catalog_id,
                recipe_version=recipe_version,
                surfaces=surfaces,
                credential_host=credential_host,
                credential_path=credential_path,
                success_digest=success_digest,
                reason_code=reason_code,
            )

    def record_run_plan_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        source: str,
        app_slug: str,
        catalog_id: str,
        recipe_version: str,
        surfaces: Sequence[Mapping[str, str]],
        credential_host: str | None,
        credential_path: str | None,
        success_digest: str,
        reason_code: str,
    ) -> dict[str, Any]:
        """Supersede and insert a plan inside the caller's transaction."""

        stored_run_id = _safe_text(run_id)
        values = (
            stored_run_id,
            _vocabulary_member(source, vocabulary=RUN_PLAN_SOURCE_VALUES, field="run plan source"),
            _plan_identifier(app_slug, field="app slug"),
            _plan_identifier(catalog_id, field="catalog id"),
            _plan_identifier(recipe_version, field="recipe version"),
            _surfaces_json(surfaces),
            # Null together or not at all: an entry_only recipe names no credential
            # surface, and a half-named one is not a surface.
            _optional_surface_host(credential_host, credential_path),
            _optional_surface_path(credential_host, credential_path),
            _plan_digest(success_digest, field="success digest"),
            _audit_reason_code(reason_code),
        )
        columns = ", ".join(_RUN_PLAN_COLUMNS)
        active = connection.execute(
            "SELECT id FROM onboarding_run_plans WHERE run_id = ? AND status = 'active'",
            (stored_run_id,),
        ).fetchone()
        highest = connection.execute(
            "SELECT COALESCE(MAX(revision), 0) FROM onboarding_run_plans WHERE run_id = ?",
            (stored_run_id,),
        ).fetchone()
        recorded_at = _utc_now()
        if active is not None:
            connection.execute(
                "UPDATE onboarding_run_plans "
                "SET status = 'superseded', superseded_at = ? WHERE id = ?",
                (recorded_at, active[0]),
            )
        cursor = connection.execute(
            """
            INSERT INTO onboarding_run_plans (
                run_id, revision, status, source, app_slug, catalog_id, recipe_version,
                surfaces_json, credential_host, credential_path, success_digest,
                reason_code, created_at
            ) VALUES (?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                values[0],
                int(highest[0]) + 1,
                *values[1:],
                recorded_at,
            ),
        )
        plan_id = cursor.lastrowid
        if plan_id is None:  # pragma: no cover - sqlite invariant
            raise RuntimeError("run plan id was not generated")
        if active is not None:
            connection.execute(
                "UPDATE onboarding_run_plans SET superseded_by = ? WHERE id = ?",
                (int(plan_id), active[0]),
            )
        row = connection.execute(
            f"SELECT {columns} FROM onboarding_run_plans WHERE id = ?",
            (int(plan_id),),
        ).fetchone()
        if row is None:  # pragma: no cover - insertion invariant
            raise RuntimeError("run plan could not be read back")
        return dict(zip(_RUN_PLAN_COLUMNS, row, strict=True))

    def read_active_run_plan(self, run_id: str) -> dict[str, Any] | None:
        """The run's one active plan, or ``None`` if it has never been planned.

        The read a re-entering worker performs before planning again (Requirement
        5.9): a run that already recorded a validated plan reuses it, so re-queuing
        a run performs no second planning call. The partial unique index is what
        makes "one active plan" a fact about the table rather than about this query.
        """

        self.initialize()
        with self._connect() as connection:
            return self.read_active_run_plan_in_transaction(connection, run_id=run_id)

    def read_active_run_plan_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
    ) -> dict[str, Any] | None:
        """Read the active plan inside the caller's transaction."""

        columns = ", ".join(_RUN_PLAN_COLUMNS)
        row = connection.execute(
            f"SELECT {columns} FROM onboarding_run_plans WHERE run_id = ? AND status = 'active'",
            (_safe_text(run_id),),
        ).fetchone()
        if row is None:
            return None
        return dict(zip(_RUN_PLAN_COLUMNS, row, strict=True))

    def count_run_plans(self, run_id: str) -> int:
        """How many plan revisions the run has recorded, superseded ones included.

        This is how "has this run already re-planned?" is answered (Requirement
        6.2): a run with one revision may still re-plan once, and a run with two has
        spent that authorization. A count of durable rows rather than an in-memory
        flag, so it survives the worker that planned.
        """

        self.initialize()
        with self._connect() as connection:
            return self.count_run_plans_in_transaction(connection, run_id=run_id)

    def count_run_plans_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
    ) -> int:
        """Count every plan revision inside the caller's transaction."""

        row = connection.execute(
            "SELECT COUNT(*) FROM onboarding_run_plans WHERE run_id = ?",
            (_safe_text(run_id),),
        ).fetchone()
        return int(row[0])

    def record_progress_event(
        self,
        *,
        run_id: str,
        phase: str,
        profile_digest: str,
        correlation_id: str,
        step_index: int,
        stage: str,
        elapsed_ms: int,
    ) -> int:
        """Record one completed loop iteration as a durable fact (Requirement 4.1).

        PRE:  ``phase`` is an onboarding phase and ``stage`` a loop stage; the digest
              is a content address and the correlation id ties the row to the phase
              boundary it happened under. Nothing free-form is accepted, so no prompt
              text or page content can reach the row (Requirement 4.10).
        POST: one row exists per call. Progress events are never deduplicated — an
              iteration that acted on nothing must still leave a row, because the
              absence of new rows is exactly what makes a stalled run visible
              (Requirement 4.9).
        """

        self.initialize()
        values = (
            _safe_text(run_id),
            _audit_phase(phase),
            _plan_digest(profile_digest, field="profile digest"),
            _audit_identifier(correlation_id, field="correlation id", limit=64),
            _telemetry_count(
                step_index,
                field="step index",
                minimum=1,
                maximum=MAX_PROGRESS_STEP_INDEX,
            ),
            _vocabulary_member(stage, vocabulary=LOOP_STAGE_VALUES, field="loop stage"),
            _telemetry_count(
                elapsed_ms,
                field="elapsed time",
                minimum=0,
                maximum=MAX_TELEMETRY_ELAPSED_MS,
            ),
            _utc_now(),
        )
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO onboarding_progress_events (
                    run_id, phase, profile_digest, correlation_id, step_index,
                    stage, elapsed_ms, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )
            event_id = cursor.lastrowid
            if event_id is None:  # pragma: no cover - sqlite invariant
                raise RuntimeError("progress event id was not generated")
        return int(event_id)

    def list_progress_events(
        self,
        run_id: str,
        *,
        limit: int = MAX_METRIC_ROWS,
    ) -> list[dict[str, Any]]:
        """The run's progress events, newest first, bounded by ``limit``.

        Newest first because the question this read answers is "is the run still
        stepping?" — a bounded window taken from the oldest end would answer it about
        a moment that has passed. The API projects the same rows in the same order
        over ``onboarding_progress_window`` (Requirement 4.2).
        """

        self.initialize()
        columns = ", ".join(_PROGRESS_EVENT_COLUMNS)
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT {columns} FROM onboarding_progress_events "
                "WHERE run_id = ? ORDER BY id DESC LIMIT ?",
                (_safe_text(run_id), _metric_row_limit(limit)),
            ).fetchall()
        return [dict(zip(_PROGRESS_EVENT_COLUMNS, row, strict=True)) for row in rows]

    def record_step_decision(
        self,
        *,
        run_id: str,
        phase: str,
        correlation_id: str,
        step_index: int,
        decision: str,
        reason_code: str | None = None,
        candidate_label: str | None = None,
        action: str | None = None,
        target_host: str | None = None,
        reason: str | None = None,
    ) -> int:
        """Record what the loop decided on one iteration, and the model's stated why.

        PRE:  ``decision`` is one of :data:`STEP_DECISION_VALUES` and ``action``, when
              given, is a candidate action the policy generator can produce. The
              ``(run_id, correlation_id, step_index)`` triple is the same one
              :meth:`record_progress_event` writes, so the two rows join.
        POST: exactly one row exists per call, and it holds no URL, no selector, and
              no page markup. ``reason`` is quarantined by :func:`_decision_reason`
              before it is stored; when that returns ``None`` for a non-empty input
              the row is written with ``reason_text = NULL`` and
              ``reason_withheld = 1``, which the console renders as *withheld*
              rather than as *nothing was said*.

        The write never fails on account of the reason text. A decision that cannot
        be explained is still a decision that must be recorded — dropping the row
        would hide the step itself in order to hide the prose, which is backwards.
        """

        self.initialize()
        offered = isinstance(reason, str) and bool(reason.strip())
        stored_reason = _decision_reason(reason)
        values = (
            _safe_text(run_id),
            _audit_phase(phase),
            _audit_identifier(correlation_id, field="correlation id", limit=64),
            _telemetry_count(
                step_index,
                field="step index",
                minimum=1,
                maximum=MAX_PROGRESS_STEP_INDEX,
            ),
            _vocabulary_member(decision, vocabulary=STEP_DECISION_VALUES, field="step decision"),
            None if reason_code is None else _audit_reason_code(reason_code),
            _decision_label(candidate_label),
            (
                None
                if action is None
                else _vocabulary_member(
                    action,
                    vocabulary=CANDIDATE_ACTION_VALUES,
                    field="candidate action",
                )
            ),
            _decision_host(target_host),
            stored_reason,
            1 if offered and stored_reason is None else 0,
            _utc_now(),
        )
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO onboarding_step_decisions (
                    run_id, phase, correlation_id, step_index, decision, reason_code,
                    candidate_label, action, target_host, reason_text, reason_withheld,
                    recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )
            decision_id = cursor.lastrowid
            if decision_id is None:  # pragma: no cover - sqlite invariant
                raise RuntimeError("step decision id was not generated")
        return int(decision_id)

    def list_step_decisions(
        self,
        run_id: str,
        *,
        limit: int = MAX_METRIC_ROWS,
    ) -> list[dict[str, Any]]:
        """The run's decisions, newest first, bounded by ``limit``.

        Same order as :meth:`list_progress_events` so the two windows line up when
        the API zips them on ``(correlation_id, step_index)``.
        """

        self.initialize()
        columns = ", ".join(_STEP_DECISION_COLUMNS)
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT {columns} FROM onboarding_step_decisions "
                "WHERE run_id = ? ORDER BY id DESC LIMIT ?",
                (_safe_text(run_id), _metric_row_limit(limit)),
            ).fetchall()
        return [dict(zip(_STEP_DECISION_COLUMNS, row, strict=True)) for row in rows]

    def record_decision_attempt(
        self,
        *,
        run_id: str,
        phase: str,
        purpose: str,
        provider: str,
        outcome: str,
        latency_ms: int,
    ) -> int:
        """Record one inference attempt: provider, outcome, latency (Requirement 4.3).

        PRE:  ``purpose`` says what the decision was for, ``provider`` is the
              backend's own name, and ``outcome`` is ``usable`` or the typed reason
              it was not. No prompt, no payload and no answer is accepted, which is
              the whole of Requirement 4.10 for this table.
        POST: one row exists per *attempt*, not per decision. A provider skipped by
              its circuit breaker never appears in a decision's reason codes, so
              attribution (Requirement 4.11) is only possible from these rows.
        """

        self.initialize()
        values = (
            _safe_text(run_id),
            _audit_phase(phase),
            _vocabulary_member(
                purpose,
                vocabulary=DECISION_ATTEMPT_PURPOSE_VALUES,
                field="decision purpose",
            ),
            _decision_provider(provider),
            _vocabulary_member(
                outcome,
                vocabulary=DECISION_OUTCOME_VALUES,
                field="decision outcome",
            ),
            _telemetry_count(
                latency_ms,
                field="attempt latency",
                minimum=0,
                maximum=MAX_TELEMETRY_ELAPSED_MS,
            ),
            _utc_now(),
        )
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO onboarding_decision_attempts (
                    run_id, phase, purpose, provider, outcome, latency_ms, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )
            attempt_id = cursor.lastrowid
            if attempt_id is None:  # pragma: no cover - sqlite invariant
                raise RuntimeError("decision attempt id was not generated")
        return int(attempt_id)

    def list_decision_attempts(
        self,
        run_id: str,
        *,
        limit: int = MAX_METRIC_ROWS,
    ) -> list[dict[str, Any]]:
        """The run's inference attempts, newest first, bounded by ``limit``.

        Newest first for the same reason as the progress window: the diagnosis an
        operator is making is about the decision the run is failing on now, and the
        provider order inside one decision is still readable because the rows of one
        decision share a recorded second and descend by id.
        """

        self.initialize()
        columns = ", ".join(_DECISION_ATTEMPT_COLUMNS)
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT {columns} FROM onboarding_decision_attempts "
                "WHERE run_id = ? ORDER BY id DESC LIMIT ?",
                (_safe_text(run_id), _metric_row_limit(limit)),
            ).fetchall()
        return [dict(zip(_DECISION_ATTEMPT_COLUMNS, row, strict=True)) for row in rows]

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
