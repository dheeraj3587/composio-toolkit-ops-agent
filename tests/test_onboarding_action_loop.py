"""Happy path for ``run_action_loop``: one candidate, one action, ``done``."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence

from ops.browser.candidates import ActionCandidate
from ops.browser.host_policy import BrowserAllowedHosts
from ops.browser.worker import BrowserObservation
from ops.onboarding.action_loop import (
    LoopBudget,
    LoopObservation,
    PhaseGoal,
    run_action_loop,
)

_ALLOWED = BrowserAllowedHosts(
    app_slug="example", exact_hosts=("console.example.com",), vendor_wildcard_domains=()
)

_RAW_ELEMENTS: tuple[Mapping[str, object], ...] = (
    {"role": "button", "name": "Create app", "visible": True, "enabled": True},
)


class _Session:
    """A two-step page: the create-app control, then a created app."""

    def __init__(self) -> None:
        self.acted: list[ActionCandidate] = []

    async def observe(self) -> LoopObservation:
        if self.acted:
            return LoopObservation(
                observation=BrowserObservation(
                    status="developer_console_ready",
                    current_url="https://console.example.com/apps/created",
                    page_title="App created",
                    developer_app_id="app_1",
                ),
            )
        return LoopObservation(
            observation=BrowserObservation(
                status="developer_console_ready",
                current_url="https://console.example.com/apps",
                page_title="Apps",
            ),
            raw_elements=_RAW_ELEMENTS,
        )

    async def act(self, candidate: ActionCandidate) -> None:
        self.acted.append(candidate)


class _Decider:
    """Picks the first id the schema offers, as a constrained backend would."""

    def __init__(self) -> None:
        self.prompts: list[str] = []

    async def choose(self, prompt: str, *, schema: Mapping[str, object]) -> Mapping[str, object]:
        self.prompts.append(prompt)
        properties = schema["properties"]
        assert isinstance(properties, Mapping)
        candidate_id = properties["candidate_id"]
        assert isinstance(candidate_id, Mapping)
        ids = candidate_id["enum"]
        assert isinstance(ids, Sequence)
        return {"decision": "select_candidate", "candidate_id": ids[0], "reason": "next step"}


class _Telemetry:
    def __init__(self) -> None:
        self.rejects: list[str] = []
        self.denials: list[str] = []
        self.dlp_refusals = 0
        self.actions = 0

    def denial(self, reason_code: str) -> None:
        self.denials.append(reason_code)

    def reject(self, reason_code: str) -> None:
        self.rejects.append(reason_code)

    def dlp_refusal(self) -> None:
        self.dlp_refusals += 1

    def action(self, *, candidate_id: str, actions_executed: int) -> None:
        self.actions = actions_executed

    def model_call(self, *, model_calls: int) -> None:
        return None


def test_short_cycle_returns_done_with_the_phase_success_code() -> None:
    goal = PhaseGoal.for_phase(
        "developer_app",
        provider_name="Example Provider",
        description="Create a developer app so an API key can be generated.",
        instruction="Create a new developer application.",
        success_reason_code="developer_app_created",
        signals=("Create app",),
    )
    session = _Session()
    decider = _Decider()
    telemetry = _Telemetry()

    result = asyncio.run(
        run_action_loop(
            phase="developer_app",
            goal=goal,
            session=session,
            allowed=_ALLOWED,
            budget=LoopBudget(),
            decider=decider,
            telemetry=telemetry,
        )
    )

    assert result.outcome == "done"
    assert result.reason_code == "developer_app_created"
    assert (result.actions_executed, result.model_calls, result.navigation_denials) == (1, 1, 0)
    assert result.observation.developer_app_id == "app_1"
    # Exactly one candidate was executed, and it was policy-generated.
    assert [candidate.action for candidate in session.acted] == ["click"]
    assert telemetry.actions == 1
    assert (telemetry.rejects, telemetry.denials, telemetry.dlp_refusals) == ([], [], 0)
    # The model saw the candidate list and never a selector.
    assert "CANDIDATES:" in decider.prompts[0]
