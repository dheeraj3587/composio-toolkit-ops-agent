"""A navigation denial survives the process that produced it (Requirement 5.15).

One walk: the loop observes a page outside the run's allow-list, ends the phase as
``denied_fatal``, and the durable telemetry leaves behind a fact carrying the run,
the phase, the profile digest, and the denial reason code. The fact is then read
back through a *fresh* storage handle, because "durable" means the row outlives the
object that wrote it.
"""

from __future__ import annotations

import asyncio

import pytest

from ops.browser.candidates import ActionCandidate
from ops.browser.host_policy import BrowserAllowedHosts
from ops.browser.worker import BrowserObservation
from ops.core.storage import OperationsStorage
from ops.onboarding.action_loop import (
    LoopBudget,
    LoopObservation,
    PhaseGoal,
    run_action_loop,
)
from ops.onboarding.loop_telemetry import DurableLoopTelemetry

DIGEST = "c" * 64

_ALLOWED = BrowserAllowedHosts(
    app_slug="example", exact_hosts=("console.example.com",), vendor_wildcard_domains=()
)


class _OffDomainSession:
    """A page the provider redirected somewhere the allow-list does not admit."""

    async def observe(self) -> LoopObservation:
        return LoopObservation(
            observation=BrowserObservation(
                status="developer_console_ready",
                current_url="https://phish.invalid/apps",
                page_title="Elsewhere",
            ),
        )

    async def act(self, candidate: ActionCandidate) -> None:  # pragma: no cover - never reached
        raise AssertionError("a denied phase must not act")


class _UnusedDecider:
    async def choose(self, prompt, *, schema):  # pragma: no cover - never reached
        raise AssertionError("a denied phase must not call the model")


@pytest.fixture
def storage(tmp_path) -> OperationsStorage:
    store = OperationsStorage(tmp_path / "private" / "ops.db")
    store.create_run(
        run_id="run-denied",
        thread_id="thread-run-denied",
        app_name="Example Provider",
        app_slug="example",
    )
    return store


def test_a_denied_navigation_leaves_a_durable_fact(storage, tmp_path) -> None:
    telemetry = DurableLoopTelemetry(
        store=storage,
        run_id="run-denied",
        phase="developer_app",
        profile_digest=DIGEST,
        correlation_id="a" * 32,
    )
    goal = PhaseGoal.for_phase(
        "developer_app",
        provider_name="Example Provider",
        description="Create a developer app so an API key can be generated.",
        instruction="Create a new developer application.",
        success_reason_code="developer_app_created",
    )

    result = asyncio.run(
        run_action_loop(
            phase="developer_app",
            goal=goal,
            session=_OffDomainSession(),
            allowed=_ALLOWED,
            budget=LoopBudget(),
            decider=_UnusedDecider(),
            telemetry=telemetry,
        )
    )

    assert result.outcome == "denied_fatal"
    assert result.reason_code == "browser_host_not_in_app_policy"
    assert result.navigation_denials == 1
    assert telemetry.denials == 1

    # Requirement 5.15: read the fact back through a handle that never saw the loop.
    reopened = OperationsStorage(tmp_path / "private" / "ops.db")
    facts = reopened.list_navigation_denials("run-denied")
    assert len(facts) == 1
    fact = facts[0]
    assert fact["run_id"] == "run-denied"
    assert fact["phase"] == "developer_app"
    assert fact["profile_digest"] == DIGEST
    assert fact["reason_code"] == "browser_host_not_in_app_policy"
    assert fact["recorded_at"].endswith("Z")
    # The URL the loop refused is attacker-influenced text; no column can hold it.
    assert "phish.invalid" not in str(fact)


def test_denial_facts_accumulate_and_refuse_a_code_outside_the_vocabulary(storage) -> None:
    telemetry = DurableLoopTelemetry(
        store=storage,
        run_id="run-denied",
        phase="signup",
        profile_digest=DIGEST,
        correlation_id="a" * 32,
    )

    telemetry.denial("browser_host_not_in_app_policy")
    telemetry.denial("browser_url_not_https_or_malformed")

    codes = [fact["reason_code"] for fact in storage.list_navigation_denials("run-denied")]
    assert codes == ["browser_host_not_in_app_policy", "browser_url_not_https_or_malformed"]

    with pytest.raises(ValueError):
        telemetry.denial("page_said_so")  # type: ignore[arg-type]
    assert telemetry.denials == 2
