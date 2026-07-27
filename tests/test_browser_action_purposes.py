from __future__ import annotations

import pytest

from ops.browser_api_trace_catalog import BrowserApiTraceStep
from ops.browser_candidates import ActionCandidate, ElementIdentity
from ops.browser_decider import SnapshotElement
from ops.browser_risk import (
    ActionAuthorizationContext,
    BrowserActionRiskPolicy,
)


def ready_signup_context(**overrides: object) -> ActionAuthorizationContext:
    values: dict[str, object] = {
        "purpose": "signup_submit",
        "account_policy": "create_if_missing",
        "contract_active": True,
        "signup_supported": True,
        "signup_state": "signup_submission_ready",
        "required_fields_verified": True,
        "submit_control_unique": True,
        "code_owned": True,
    }
    values.update(overrides)
    return ActionAuthorizationContext(**values)  # type: ignore[arg-type]


def click_candidate(name: str, *, risk: str = "requires_hitl") -> ActionCandidate:
    return ActionCandidate(
        candidate_id="c_signup",
        action="click",
        semantic_target=name,
        identity=ElementIdentity(role="button", name=name),
        risk=risk,  # type: ignore[arg-type]
        expected_postcondition="signup_dispatched",
        trace_version="2.0",
        checkpoint_order=1,
    )


def checkpoint() -> BrowserApiTraceStep:
    return BrowserApiTraceStep(
        order=1,
        instruction="Submit the prepared signup form",
        expected_signals=("Create account",),
    )


def element(name: str) -> SnapshotElement:
    return SnapshotElement(index=0, role="button", name=name, element_type="submit")


def test_ready_signup_submit_is_the_only_autonomous_creation_exception() -> None:
    policy = BrowserActionRiskPolicy()
    decision = policy.classify(
        candidate=click_candidate("Create account"),
        checkpoint=checkpoint(),
        element=element("Create account"),
        purpose_context=ready_signup_context(),
    )

    assert decision.autonomous_allowed is True
    assert decision.disposition == "allow"
    assert decision.reason_code == "authorized_checkpoint_progression"


@pytest.mark.parametrize(
    ("overrides", "reason_code"),
    [
        ({"account_policy": "reuse_existing"}, "signup_submit_account_policy_blocked"),
        ({"contract_active": False}, "signup_submit_contract_inactive"),
        ({"signup_supported": False}, "signup_submit_not_supported_by_contract"),
        ({"signup_state": "signup_form_filled"}, "signup_submit_state_not_ready"),
        ({"required_fields_verified": False}, "signup_submit_fields_not_verified"),
        ({"submit_control_unique": False}, "signup_submit_control_not_unique"),
        ({"code_owned": False}, "signup_submit_requires_code_owned_flow"),
    ],
)
def test_signup_submit_is_default_deny(
    overrides: dict[str, object],
    reason_code: str,
) -> None:
    decision = BrowserActionRiskPolicy().authorize_purpose(
        ready_signup_context(**overrides)
    )

    assert decision.autonomous_allowed is False
    assert decision.disposition == "block"
    assert decision.reason_code == reason_code


@pytest.mark.parametrize(
    ("gate", "reason_code"),
    [
        ("captcha_present", "captcha_requires_human"),
        ("phone_verification_present", "phone_verification_requires_human"),
        ("legal_acceptance_present", "legal_acceptance_requires_human"),
        ("billing_present", "billing_requires_human"),
    ],
)
def test_signup_human_gates_are_never_downgraded(
    gate: str,
    reason_code: str,
) -> None:
    decision = BrowserActionRiskPolicy().authorize_purpose(
        ready_signup_context(**{gate: True})
    )

    assert decision.autonomous_allowed is False
    assert decision.disposition == "require_hitl"
    assert decision.reason_code == reason_code


@pytest.mark.parametrize(
    "purpose",
    ["rotate_credential", "revoke_credential", "delete_resource"],
)
def test_destructive_purposes_are_blocked(purpose: str) -> None:
    decision = BrowserActionRiskPolicy().authorize_purpose(
        ActionAuthorizationContext(purpose=purpose)  # type: ignore[arg-type]
    )

    assert decision.autonomous_allowed is False
    assert decision.disposition == "block"


@pytest.mark.parametrize(
    "label",
    [
        "Create API key",
        "Create developer application",
        "Create workspace",
        "Create account and accept terms",
    ],
)
def test_signup_exception_does_not_disable_global_create_guards(label: str) -> None:
    decision = BrowserActionRiskPolicy().classify(
        candidate=click_candidate(label),
        checkpoint=checkpoint(),
        element=element(label),
        purpose_context=ready_signup_context(),
    )

    assert decision.autonomous_allowed is False
    assert decision.disposition == "require_hitl"
