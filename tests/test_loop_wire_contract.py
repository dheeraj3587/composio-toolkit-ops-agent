"""The loop RPC contract: what crosses to an executor, and what must not.

``ops.browser.candidates`` asserts its own executor/decision partition at import,
so a field added to ``ActionCandidate`` fails to import until it is classified.
What that assertion cannot see is the OTHER side of the wire: the Pydantic models
in ``browser_service`` live in a different package and could drift from the
partition without anything noticing.

That is the drift that actually bit this codebase before — ``setup_fields`` was
capped at 20 on the server while the client's own normalizer admitted 22. Both
sides were individually strict and ``extra="forbid"`` did not help, because
``extra="forbid"`` catches an EXTRA field and says nothing about a missing one.
These tests compare the two field sets directly.
"""

from __future__ import annotations

from browser_service.models import ActRequest, ExecutableAction, WireElementIdentity
from ops.browser.candidates import (
    EXECUTOR_CANDIDATE_FIELDS,
    WIRE_IDENTITY_FIELDS,
    ActionCandidate,
    ElementIdentity,
    candidate_from_executable_payload,
    executable_action_payload,
)


def test_wire_action_carries_exactly_the_executor_side_fields() -> None:
    """Adding an executable candidate field must fail here, not in production."""

    assert set(ExecutableAction.model_fields) == EXECUTOR_CANDIDATE_FIELDS


def test_wire_identity_carries_every_part_of_element_identity() -> None:
    """``ElementIdentity`` evolves; a part left behind resolves the wrong element."""

    assert set(WireElementIdentity.model_fields) == WIRE_IDENTITY_FIELDS


def test_risk_never_reaches_the_executor() -> None:
    """The HITL gate stays in the control plane.

    ``ActionCandidate.executable`` is exactly ``risk != "requires_hitl"``, so this
    one field decides whether a CAPTCHA, an MFA prompt or a billing confirmation
    needs a person. Shipping it to the browser container would put the gate's input
    next to the code that clicks.
    """

    assert "risk" not in ExecutableAction.model_fields
    assert "risk" not in set(EXECUTOR_CANDIDATE_FIELDS)


def test_verification_fields_stay_with_the_caller() -> None:
    """The caller holds the goal, so nothing verify-shaped needs to cross."""

    for field in (
        "postcondition",
        "expected_postcondition",
        "semantic_target",
        "trace_version",
        "checkpoint_order",
        "hint_index",
        "option_value",
    ):
        assert field not in ExecutableAction.model_fields


def _candidate(**overrides: object) -> ActionCandidate:
    base: dict[str, object] = {
        "candidate_id": "c1",
        "action": "click",
        "semantic_target": "signup_submit",
        "identity": ElementIdentity(
            role="button",
            name="Create account",
            element_type="submit",
            frame_path=("main",),
            test_id="signup",
            href_path="/signup",
            nearby_heading="Get started",
        ),
        "risk": "low",
        "expected_postcondition": "url_changed",
        "trace_version": "v1",
        "checkpoint_order": 2,
    }
    base.update(overrides)
    return ActionCandidate(**base)  # type: ignore[arg-type]


def test_projection_round_trips_through_the_strict_wire_model() -> None:
    """The payload validates as ``ExecutableAction`` and rebuilds what the executor reads."""

    candidate = _candidate()
    payload = executable_action_payload(candidate)

    # The strict model is the contract; validating here proves the projection cannot
    # produce a body the server would 422.
    wire = ExecutableAction.model_validate(payload)
    request = ActRequest(action=wire, expected_generation=7)
    assert request.expected_generation == 7

    rebuilt = candidate_from_executable_payload(request.action.model_dump())
    assert rebuilt.candidate_id == candidate.candidate_id
    assert rebuilt.action == candidate.action
    assert rebuilt.identity == candidate.identity
    assert rebuilt.value_ref == candidate.value_ref
    assert rebuilt.press_key == candidate.press_key
    assert rebuilt.url == candidate.url
    # Cleared the gate in the control plane, so the local reconstruction is executable.
    assert rebuilt.executable


def test_projection_refuses_to_dispatch_a_human_only_candidate() -> None:
    """A ``requires_hitl`` candidate has no wire form at all."""

    try:
        executable_action_payload(_candidate(risk="requires_hitl"))
    except ValueError as error:
        assert "requires_hitl" in str(error)
    else:  # pragma: no cover - the raise is the behaviour under test
        raise AssertionError("a requires_hitl candidate must never be dispatched")


def test_unknown_verb_is_refused_when_rebuilding() -> None:
    """A verb outside the closed vocabulary cannot be reconstructed."""

    payload = executable_action_payload(_candidate())
    try:
        candidate_from_executable_payload({**payload, "action": "exfiltrate"})
    except ValueError as error:
        assert "unknown verb" in str(error)
    else:  # pragma: no cover - the raise is the behaviour under test
        raise AssertionError("an unknown action verb must be refused")
