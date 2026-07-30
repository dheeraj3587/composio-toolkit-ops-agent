"""Happy-path check for the action loop's vocabulary and its budget wiring."""

from __future__ import annotations

import inspect

from ops.browser.candidates import generate_candidates
from ops.browser.worker import BrowserObservation
from ops.core.config import Settings
from ops.onboarding.action_loop import (
    MAX_ACTIONS,
    MAX_CANDIDATES,
    MAX_MODEL_CALLS,
    MAX_NAVIGATION_DENIALS,
    MAX_NO_PROGRESS,
    MAX_WALLCLOCK_SECONDS,
    LoopBudget,
    LoopResult,
    PhaseGoal,
)


def test_budget_defaults_match_settings_and_name_their_bounds() -> None:
    budget = LoopBudget()
    assert (
        (
            budget.max_actions,
            budget.max_model_calls,
            budget.max_no_progress,
            budget.max_wallclock_seconds,
            budget.max_navigation_denials,
        )
        == (
            MAX_ACTIONS,
            MAX_MODEL_CALLS,
            MAX_NO_PROGRESS,
            MAX_WALLCLOCK_SECONDS,
            MAX_NAVIGATION_DENIALS,
        )
        == (60, 80, 6, 900, 10)
    )
    # The code-level defaults and the deployment's configured budget are the same
    # numbers, so tightening one place cannot leave the other behind.
    assert LoopBudget.from_settings(Settings()) == budget
    # Requirement 4.3's bound is the same one the candidate generator applies.
    generator_bound = inspect.signature(generate_candidates).parameters["max_candidates"].default
    assert MAX_CANDIDATES == generator_bound

    assert (
        budget.exhausted_bound(actions=1, model_calls=1, no_progress=0, elapsed_seconds=1.0) is None
    )
    bound = budget.exhausted_bound(actions=60, model_calls=1, no_progress=0, elapsed_seconds=1.0)
    assert bound == "actions"
    assert LoopBudget.exhaustion_reason(bound) == "loop_action_budget_exhausted"


def test_phase_goal_for_phase_and_done_result() -> None:
    goal = PhaseGoal.for_phase(
        "signup",
        provider_name="Example Provider",
        description="Create an account so an API key can be generated.",
        instruction="Fill the signup form and submit it.",
        success_reason_code="signup_submitted",
        signals=("Create account",),
    )
    assert goal.phase == "signup"
    assert goal.postconditions == ("signup_submitted",)
    assert goal.max_candidates == MAX_CANDIDATES

    result = LoopResult(
        outcome="done",
        observation=BrowserObservation(
            status="developer_app_ready",
            current_url="https://example.com/signup/done",
            page_title="Welcome",
        ),
        reason_code=goal.success_reason_code,
        actions_executed=4,
        model_calls=5,
    )
    assert result.terminal_for_phase is False
    assert result.navigation_denials == 0
