"""The planner's inference attempts are durable, and attributed to a real phase.

``purpose="plan"`` has been in the durable vocabulary since the decision-attempts
table existed, but nothing wrote it: the action loop attached a sink to its chain
(``ops/onboarding/composition.py``) and the planner did not, so every recorded
attempt read as ``action`` regardless of which model call produced it.

The trap these tests guard is the attribution. The initial plan is made *during*
``research``, and the driver commits the ``research -> vault_check`` boundary only
after that handler returns — so at planning time the phase history is normally
EMPTY, and no run ever holds a boundary whose ``to_phase`` is ``research``. A sink
that resolved its phase from the history alone would drop every first plan
silently: writing nothing, and failing nothing.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from ops.core.config import Settings
from ops.core.inference import JsonInference
from ops.core.storage import OperationsStorage
from ops.onboarding.composition import SettingsRunPlanner
from ops.onboarding.driver import SQLitePhaseHistoryStore
from ops.planner.decide import PlanOutcome
from ops.planner.validator import PlanRefusal, declared_surface_paths
from ops.recipes.app_recipes import recipes_for_route

RUN_ID = "run_planner_telemetry"


class _Backend:
    """One provider that answers, or raises, on demand."""

    def __init__(self, name: str, answers: list[dict[str, object] | Exception]) -> None:
        self.name = name
        self._answers = answers
        self.calls = 0

    def generate_json(self, prompt: str, schema: Mapping[str, object] | None) -> dict[str, object]:
        del prompt, schema
        answer = self._answers[min(self.calls, len(self._answers) - 1)]
        self.calls += 1
        if isinstance(answer, Exception):
            raise answer
        return answer


@pytest.fixture
def storage(tmp_path: Path) -> OperationsStorage:
    """A run ledger holding one run and no committed phase boundary."""

    ledger = OperationsStorage(tmp_path / "private" / "ops.db")
    ledger.create_run(
        run_id=RUN_ID,
        thread_id=f"thread-{RUN_ID}",
        app_name="Example Provider",
        app_slug="example-provider",
    )
    return ledger


@pytest.fixture
def settings() -> Settings:
    return Settings.from_env(env={})


@pytest.fixture
def recipe() -> Any:
    """The first reviewed browser-route recipe, which declares plannable surfaces."""

    reviewed = recipes_for_route("playwright")
    if not reviewed:
        pytest.skip("no browser-route recipe in the catalog")
    return reviewed[0]


def _accepted_payload(recipe: Any) -> dict[str, object]:
    """A decision the plan schema accepts: the recipe's own host and paths.

    The planner inlines the recipe's hosts and paths as JSON-schema *enums*, so a
    model can only reorder what the catalog already declared. Building the payload
    the same way keeps this test asserting telemetry rather than accidentally
    asserting schema rejection.
    """

    host = recipe.browser.exact_hosts[0]
    paths = declared_surface_paths(recipe)
    return {
        "surfaces": [{"host": host, "path": paths[0], "purpose": "login"}],
        "credential_surface": {"host": host, "path": paths[-1], "purpose": "credential"},
    }


def _planner(
    settings: Settings,
    storage: OperationsStorage,
    backends: list[_Backend],
) -> SettingsRunPlanner:
    return SettingsRunPlanner(
        settings,
        inference=JsonInference(backends),
        store=storage,
        phases=SQLitePhaseHistoryStore(storage.db_path),
    )


def test_planner_attempts_are_recorded_as_plan_not_action(
    settings: Settings, storage: OperationsStorage, recipe: Any
) -> None:
    planner = _planner(settings, storage, [_Backend("stub_provider", [_accepted_payload(recipe)])])

    result = planner.plan_for(recipe=recipe, revision=1, run_id=RUN_ID)

    assert isinstance(result, PlanOutcome | PlanRefusal)
    rows = storage.list_decision_attempts(RUN_ID)
    assert rows, "the planner recorded no inference attempt"
    assert {row["purpose"] for row in rows} == {"plan"}
    assert {row["provider"] for row in rows} == {"stub_provider"}
    assert all(row["latency_ms"] >= 0 for row in rows)


def test_a_first_plan_is_attributed_to_research_despite_an_empty_history(
    settings: Settings, storage: OperationsStorage, recipe: Any
) -> None:
    """The regression guard: an empty phase history must not swallow the row."""

    phases = SQLitePhaseHistoryStore(storage.db_path)
    assert not phases.history(run_id=RUN_ID), "fixture committed a boundary it should not"

    _planner(settings, storage, [_Backend("stub_provider", [_accepted_payload(recipe)])]).plan_for(
        recipe=recipe, revision=1, run_id=RUN_ID
    )

    rows = storage.list_decision_attempts(RUN_ID)
    assert rows, "an empty phase history dropped the attempt"
    assert {row["phase"] for row in rows} == {"research"}


def test_every_provider_attempt_is_its_own_row(
    settings: Settings, storage: OperationsStorage, recipe: Any
) -> None:
    """A provider that failed stays visible next to the one that answered.

    This is the whole point of per-attempt rows: the reason code on the plan says
    only whether a route was accepted. Without these rows there is no way to learn
    that the first provider was down and the second one carried the run.
    """

    planner = _planner(
        settings,
        storage,
        [
            _Backend("failing_provider", [RuntimeError("boom")]),
            _Backend("working_provider", [_accepted_payload(recipe)]),
        ],
    )

    planner.plan_for(recipe=recipe, revision=1, run_id=RUN_ID)

    rows = storage.list_decision_attempts(RUN_ID)
    outcomes = {row["provider"]: row["outcome"] for row in rows}
    assert set(outcomes) == {"failing_provider", "working_provider"}
    assert outcomes["working_provider"] == "usable"
    assert outcomes["failing_provider"] != "usable"
    assert all(row["purpose"] == "plan" for row in rows)


def test_planning_without_telemetry_ports_still_plans(
    settings: Settings, storage: OperationsStorage, recipe: Any
) -> None:
    """Telemetry is optional: the route must not depend on being observable."""

    planner = SettingsRunPlanner(
        settings, inference=JsonInference([_Backend("stub_provider", [_accepted_payload(recipe)])])
    )

    result = planner.plan_for(recipe=recipe, revision=1, run_id=RUN_ID)

    assert isinstance(result, PlanOutcome | PlanRefusal)
    assert not storage.list_decision_attempts(RUN_ID)


def test_a_run_id_is_required_to_attribute_an_attempt(
    settings: Settings, storage: OperationsStorage, recipe: Any
) -> None:
    """Without a run to attribute to, the plan is unchanged and nothing is written."""

    planner = _planner(settings, storage, [_Backend("stub_provider", [_accepted_payload(recipe)])])

    result = planner.plan_for(recipe=recipe, revision=1)

    assert isinstance(result, PlanOutcome | PlanRefusal)
    assert not storage.list_decision_attempts(RUN_ID)
