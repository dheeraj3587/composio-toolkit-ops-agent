"""The Run_Plan port and its SQLite adapter over ``onboarding_run_plans``.

A re-plan is one transaction in the storage writer: the active row is superseded
and the replacement is inserted at ``revision = max + 1``. Two racing workers
therefore produce one plan, and the loser reads the winner's.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol, cast

from ops.core.storage import OperationsStorage
from ops.onboarding.phase import OnboardingReasonCode
from ops.planner.plan import SURFACE_PURPOSES, PlannedSurface, PlanSource, RunPlan


class RunPlanStore(Protocol):
    """Durable plan revisions, with at most one active plan per run."""

    def record_initial_plan(
        self, *, run_id: str, plan: RunPlan, reason_code: OnboardingReasonCode
    ) -> RunPlan:
        """Atomically insert revision 1 or return the existing active plan.

        Concurrent admission callers must converge on one initial row rather than
        turning the second caller's plan into an unowned replan.
        """

    def record_plan(
        self, *, run_id: str, plan: RunPlan, reason_code: OnboardingReasonCode
    ) -> RunPlan:
        """Record ``plan`` as the run's active plan, superseding the previous one.

        POST: the run has exactly one active plan — the returned one, carrying the
              revision the store assigned rather than the one the caller guessed.
        """

    def read_active_plan(self, *, run_id: str) -> RunPlan | None:
        """The run's active plan, or ``None`` if it has never been planned."""

    def count_plans(self, *, run_id: str) -> int:
        """How many revisions the run has recorded — "has it already re-planned?"."""


def _surface(row: Mapping[str, object]) -> PlannedSurface:
    purpose = row.get("purpose")
    if purpose not in SURFACE_PURPOSES:
        raise ValueError("a stored plan surface purpose is outside the closed vocabulary")
    return PlannedSurface(
        host=str(row.get("host", "")),
        path=str(row.get("path", "")),
        purpose=purpose,
    )


def _credential_surface(row: Mapping[str, Any]) -> PlannedSurface | None:
    """The stored credential surface, or ``None`` for an entry_only recipe's plan.

    The two columns are null together by table CHECK, so a row carrying only one of
    them is corrupt rather than entry_only and is refused instead of half-read.
    """

    host = row["credential_host"]
    path = row["credential_path"]
    if host is None and path is None:
        return None
    if host is None or path is None:
        raise ValueError("a stored plan names both a credential host and path, or neither")
    return PlannedSurface(host=str(host), path=str(path), purpose="credential")


def plan_from_row(row: Mapping[str, Any]) -> RunPlan:
    """Rebuild a plan from one ``onboarding_run_plans`` row."""

    decoded = json.loads(str(row["surfaces_json"]))
    if not isinstance(decoded, list):
        raise ValueError("a stored plan's surfaces must be a JSON array")
    return RunPlan(
        app_slug=str(row["app_slug"]),
        catalog_id=str(row["catalog_id"]),
        recipe_version=str(row["recipe_version"]),
        revision=int(row["revision"]),
        source=cast("PlanSource", str(row["source"])),
        surfaces=tuple(_surface(item) for item in decoded),
        credential_surface=_credential_surface(row),
        success_digest=str(row["success_digest"]),
    )


class SQLiteRunPlanStore:
    """The plan store in the run ledger, in the shape ``SQLitePhaseHistoryStore`` uses."""

    def __init__(self, db_path: str | Path) -> None:
        # ops/core/storage.py owns every ops.db table, this one included.
        self._ledger = OperationsStorage(Path(db_path))
        self._ledger.initialize()

    def record_initial_plan(
        self, *, run_id: str, plan: RunPlan, reason_code: OnboardingReasonCode
    ) -> RunPlan:
        """Atomically insert revision 1 or return the active plan already present."""

        if plan.revision != 1:
            raise ValueError("an initial run plan must be revision 1")
        with self._ledger.unit_of_work() as transaction:
            existing = transaction.read_active_run_plan(run_id)
            if transaction.count_run_plans(run_id) != 0:
                if existing is None:
                    raise RuntimeError("a run with plan history must have an active plan")
                return plan_from_row(existing)
            row = transaction.record_run_plan(
                run_id=run_id,
                source=plan.source,
                app_slug=plan.app_slug,
                catalog_id=plan.catalog_id,
                recipe_version=plan.recipe_version,
                surfaces=plan.as_surface_rows(),
                credential_host=plan.credential_host,
                credential_path=plan.credential_path,
                success_digest=plan.success_digest,
                reason_code=reason_code,
            )
        return plan_from_row(row)

    def record_plan(
        self, *, run_id: str, plan: RunPlan, reason_code: OnboardingReasonCode
    ) -> RunPlan:
        row = self._ledger.record_run_plan(
            run_id=run_id,
            source=plan.source,
            app_slug=plan.app_slug,
            catalog_id=plan.catalog_id,
            recipe_version=plan.recipe_version,
            surfaces=plan.as_surface_rows(),
            credential_host=plan.credential_host,
            credential_path=plan.credential_path,
            success_digest=plan.success_digest,
            reason_code=reason_code,
        )
        return plan_from_row(row)

    def read_active_plan(self, *, run_id: str) -> RunPlan | None:
        row = self._ledger.read_active_run_plan(run_id)
        return None if row is None else plan_from_row(row)

    def count_plans(self, *, run_id: str) -> int:
        return self._ledger.count_run_plans(run_id)


__all__ = ["RunPlanStore", "SQLiteRunPlanStore", "plan_from_row"]
