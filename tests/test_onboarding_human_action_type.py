"""The `signup_authorization` gate type: present in the vocabulary, never page-inferred.

Requirement 3.4 makes the admission prompt a typed gate, and Requirement 3.7 keeps it
human-only. Both depend on the literal existing in ``ops.browser.worker.HumanActionType``
at runtime, and on no page classifier ever producing it: an admission decision is a
business decision the vault probe triggers, not something a rendered page can assert.
"""

from __future__ import annotations

from typing import get_args

from ops.browser.signup import SignupActionType
from ops.browser.worker import BrowserObservation, HumanActionType, _classify_human_action
from ops.core.models import HitlRequest
from ops.playwright.gates import _HUMAN_GATE_PATTERNS, _classify_gate
from ops.workflow.canonical_runtime import _HUMAN_ACTION_TYPES

# Page and reason text an admission-shaped surface would plausibly carry.
_ADMISSION_SHAPED_TEXT = (
    "create an account",
    "sign up for a free account",
    "signup authorization",
    "authorize account creation",
    "Create your developer account to continue",
)


def test_signup_authorization_is_in_the_human_action_vocabulary() -> None:
    assert "signup_authorization" in get_args(HumanActionType)


def test_an_observation_may_carry_the_signup_authorization_gate() -> None:
    observation = BrowserObservation(
        status="human_action_required",
        current_url="https://provider.example/",
        page_title="Admission required",
        human_action_type="signup_authorization",
        human_instruction="Authorize creating an account with this provider.",
    )

    assert observation.human_action_type == "signup_authorization"


def test_the_runtime_mirror_stays_total_over_the_type() -> None:
    """A gate absent from the mirror is silently downgraded on the resume path."""

    assert _HUMAN_ACTION_TYPES == frozenset(get_args(HumanActionType))
    assert "signup_authorization" in _HUMAN_ACTION_TYPES


def test_the_hitl_request_type_stays_total_over_the_gate_vocabulary() -> None:
    """ops.workflow.graph passes a gate type straight into HitlRequest, so it must accept all."""

    field = HitlRequest.model_fields["type"]
    assert frozenset(get_args(field.annotation)) == frozenset(get_args(HumanActionType))

    request = HitlRequest(
        type="signup_authorization",
        app_name="Example Provider",
        message="Authorize creating an account with this provider.",
        expected_completion_signal="An admission decision is recorded.",
    )
    assert request.type == "signup_authorization"


def test_no_page_classifier_can_emit_signup_authorization() -> None:
    declared = {action_type for _, action_type in _HUMAN_GATE_PATTERNS}
    assert "signup_authorization" not in declared
    assert "signup_authorization" not in get_args(SignupActionType)

    for text in _ADMISSION_SHAPED_TEXT:
        assert _classify_gate(text) != "signup_authorization"
        assert _classify_human_action(text) != "signup_authorization"
