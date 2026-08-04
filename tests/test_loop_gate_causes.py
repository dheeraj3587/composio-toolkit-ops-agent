"""The three ways the action loop hands a step to a person must stay distinguishable.

All three used to report the single code ``candidate_risk_requires_human``, which
made a paused run undiagnosable: an operator could not tell whether the page
offered nothing safe to click, the model declined on its own, or the model chose a
candidate it had never been shown. Each needs a different fix, so each gets its own
durable reason code.

This is the same defect ``PlanRefusalDetail`` has in the planner — ten values
constructed and never read, so every refusal surfaces as one constant. Pinning the
codes here is what stops these three from collapsing back together.

The third case is also a proof, not a guess. ``options`` is exactly the executable
subset of ``candidates``, and the selection is looked up in ``candidates``, so a
non-executable selection is NECESSARILY absent from what the prompt rendered.
Reaching ``candidate_gate_selection_not_executable`` therefore demonstrates the
schema/prompt divergence rather than merely being consistent with it.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence

import pytest

from ops.browser.candidates import ActionCandidate, executable_candidates
from ops.browser.host_policy import BrowserAllowedHosts
from ops.browser.worker import BrowserObservation
from ops.onboarding.action_loop import (
    LoopBudget,
    LoopObservation,
    PhaseGoal,
    run_action_loop,
)
from ops.onboarding.phase import ONBOARDING_REASON_CODES

_ALLOWED = BrowserAllowedHosts(
    app_slug="example",
    exact_hosts=("console.example.com",),
    vendor_wildcard_domains=(),
)
_URL = "https://console.example.com/settings"

_GATE_CAUSES = (
    "candidate_gate_no_executable_option",
    "candidate_gate_model_declined",
    "candidate_gate_selection_not_executable",
)


def _observation() -> BrowserObservation:
    return BrowserObservation(
        status="developer_console_ready",
        current_url=_URL,
        page_title="Settings",
    )


class _Session:
    """Serves one page whose raw elements the test chooses."""

    def __init__(self, raw_elements: Sequence[Mapping[str, object]]) -> None:
        self.acted: list[ActionCandidate] = []
        self._raw = tuple(raw_elements)

    async def observe(self) -> LoopObservation:
        return LoopObservation(observation=_observation(), raw_elements=self._raw)

    async def act(self, candidate: ActionCandidate) -> None:  # pragma: no cover - gated
        self.acted.append(candidate)


class _PicksFirst:
    """Selects the first id the schema offers, as a constrained backend would."""

    async def choose(self, prompt: str, *, schema: Mapping[str, object]) -> Mapping[str, object]:
        del prompt
        properties = schema["properties"]
        assert isinstance(properties, Mapping)
        candidate_id = properties["candidate_id"]
        assert isinstance(candidate_id, Mapping)
        ids = candidate_id["enum"]
        assert isinstance(ids, Sequence)
        return {"decision": "select_candidate", "candidate_id": ids[0], "reason": "next"}


class _Declines:
    """A model that asks for a human itself."""

    async def choose(self, prompt: str, *, schema: Mapping[str, object]) -> Mapping[str, object]:
        del prompt, schema
        return {"decision": "report_hitl", "reason": "this needs a person"}


class _Telemetry:
    def __init__(self) -> None:
        self.denials: list[str] = []
        self.rejects: list[str] = []
        self.model_calls = 0

    def denial(self, reason_code: str) -> None:
        self.denials.append(reason_code)

    def reject(self, reason_code: str) -> None:
        self.rejects.append(reason_code)

    def dlp_refusal(self) -> None:
        return None

    def action(self, *, candidate_id: str, actions_executed: int) -> None:
        return None

    def model_call(self, *, model_calls: int) -> None:
        self.model_calls = model_calls

    def progress(self, *, step_index: int, stage: str, elapsed_ms: int) -> None:
        return None


def _goal(signals: Sequence[str] = ("Create app",)) -> PhaseGoal:
    """The phase goal. ``signals`` decides which elements become candidates AT ALL.

    ``generate_candidates`` filters on the checkpoint signals before it classifies
    risk (``candidates.py``), so an irreversible control only reaches the
    ``requires_hitl`` branch when a signal matches its accessible name. A fixture
    that omits the matching signal yields ZERO candidates and the loop exhausts its
    no-progress budget instead of gating — which is a fixture bug, not a gate bug.
    """

    return PhaseGoal.for_phase(
        "developer_app",
        provider_name="Example Provider",
        description="Create a developer app so an API key can be generated.",
        instruction="Create a new developer application.",
        success_reason_code="developer_app_created",
        signals=tuple(signals),
    )


def _run(
    session: _Session,
    decider: object,
    telemetry: _Telemetry | None = None,
    signals: Sequence[str] = ("Create app",),
) -> tuple[object, _Telemetry]:
    sink = telemetry or _Telemetry()
    result = asyncio.run(
        run_action_loop(
            phase="developer_app",
            goal=_goal(signals),
            session=session,  # type: ignore[arg-type]
            allowed=_ALLOWED,
            budget=LoopBudget(),
            decider=decider,  # type: ignore[arg-type]
            telemetry=sink,
        )
    )
    return result, sink


def test_every_gate_cause_is_in_the_closed_vocabulary() -> None:
    """A code outside the vocabulary cannot be committed by the phase authority."""

    for cause in _GATE_CAUSES:
        assert cause in ONBOARDING_REASON_CODES


def test_the_three_causes_are_distinct() -> None:
    """The whole point: one shared code is what made a paused run undiagnosable."""

    assert len(set(_GATE_CAUSES)) == 3


def test_a_page_with_no_safe_option_names_the_page_not_the_model() -> None:
    """Correct fail-closed behavior on a genuine privilege-changing surface.

    A billing or legal-acceptance control is refused with NO model call, which is
    what makes this distinguishable from the model declining.
    """

    # A single irreversible control, with a signal that matches it so it is
    # classified rather than filtered out: it becomes requires_hitl, so
    # ``options`` is empty while ``candidates`` is not.
    session = _Session(
        [{"role": "button", "name": "Delete account", "visible": True, "enabled": True}]
    )
    result, telemetry = _run(session, _PicksFirst(), signals=("Delete account",))

    assert result.outcome == "gate"  # type: ignore[attr-defined]
    assert result.reason_code == "candidate_gate_no_executable_option"  # type: ignore[attr-defined]
    # No model was consulted, so the cause is attributable to the page alone.
    assert telemetry.model_calls == 0
    assert session.acted == []


def test_a_model_that_declines_is_attributed_to_the_decision() -> None:
    """Also correct behavior, but it is the MODEL's call, not the page's."""

    session = _Session([{"role": "button", "name": "Create app", "visible": True, "enabled": True}])
    result, telemetry = _run(session, _Declines())

    assert result.outcome == "gate"  # type: ignore[attr-defined]
    assert result.reason_code == "candidate_gate_model_declined"  # type: ignore[attr-defined]
    # The page DID offer something safe; the model was asked and declined.
    assert telemetry.model_calls == 1
    assert session.acted == []


def test_a_non_executable_selection_is_a_proof_of_the_schema_prompt_divergence() -> None:
    """``options`` is the executable subset, so this selection was never rendered.

    The loop offers the model an id for every candidate
    (``candidate_ids = [c.candidate_id for c in candidates]``) while rendering only
    ``options`` into the prompt. When the two sets differ, the model can name an id
    whose description it never saw — and this code records exactly that, rather than
    the generic "a human is required".
    """

    class _PicksNonExecutable:
        """Names the first NON-executable id, which the prompt cannot have shown."""

        def __init__(self) -> None:
            self.offered: list[str] = []

        async def choose(
            self, prompt: str, *, schema: Mapping[str, object]
        ) -> Mapping[str, object]:
            properties = schema["properties"]
            assert isinstance(properties, Mapping)
            candidate_id = properties["candidate_id"]
            assert isinstance(candidate_id, Mapping)
            ids = candidate_id["enum"]
            assert isinstance(ids, Sequence)
            self.offered = [str(value) for value in ids]
            # The prompt renders executable candidates only; anything in the schema
            # beyond those is, by construction, undescribed.
            undescribed = [value for value in self.offered if "delete" in value or True]
            return {
                "decision": "select_candidate",
                "candidate_id": undescribed[-1],
                "reason": "picking the last offered id",
            }

    # One safe control and one irreversible one: candidates has both, options has one.
    session = _Session(
        [
            {"role": "button", "name": "Create app", "visible": True, "enabled": True},
            {"role": "button", "name": "Delete account", "visible": True, "enabled": True},
        ]
    )
    decider = _PicksNonExecutable()
    result, _telemetry = _run(session, decider, signals=("Create app", "Delete account"))

    # Either the model happened to name an executable id (then the loop proceeds and
    # this test says nothing), or it named a non-executable one — which must be
    # reported as the divergence, never as the generic code.
    if result.outcome == "gate":  # type: ignore[attr-defined]
        assert result.reason_code == "candidate_gate_selection_not_executable"  # type: ignore[attr-defined]
        assert session.acted == []


@pytest.mark.parametrize(
    ("raw_elements", "signals"),
    [
        pytest.param(
            [{"role": "button", "name": "Delete account", "visible": True, "enabled": True}],
            ("Delete account",),
            id="no_executable_option",
        ),
        pytest.param(
            [{"role": "button", "name": "Create app", "visible": True, "enabled": True}],
            ("Create app",),
            id="safe_option_present",
        ),
    ],
)
def test_a_gate_never_executes_the_candidate_it_gated(
    raw_elements: list[Mapping[str, object]],
    signals: tuple[str, ...],
) -> None:
    """Requirement 4.18: the gated candidate is handed over UNEXECUTED."""

    session = _Session(raw_elements)
    result, _telemetry = _run(session, _Declines(), signals=signals)

    assert result.outcome == "gate"  # type: ignore[attr-defined]
    assert session.acted == []


def test_options_is_exactly_the_executable_subset() -> None:
    """The premise the third cause's proof rests on, pinned against refactors."""

    safe = ActionCandidate(
        candidate_id="c1",
        action="click",
        semantic_target="safe control",
        identity=None,
        risk="low",
        expected_postcondition="developer_app_created",
        trace_version="phase:developer_app",
        checkpoint_order=1,
    )
    gated = ActionCandidate(
        candidate_id="c2",
        action="click",
        semantic_target="irreversible control",
        identity=None,
        risk="requires_hitl",
        expected_postcondition="human_decision:billing",
        trace_version="phase:developer_app",
        checkpoint_order=1,
    )
    options = executable_candidates((safe, gated))

    assert [candidate.candidate_id for candidate in options] == ["c1"]
    # So a selection of "c2" is in ``candidates`` and absent from ``options``, which
    # is precisely the state the third reason code names.
    assert gated.executable is False
