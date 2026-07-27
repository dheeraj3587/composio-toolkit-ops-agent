from __future__ import annotations

import asyncio
import json

from ops.automation_contracts import (
    BrowserAutomationContract,
    ContractEvidence,
    ContractHosts,
    ContractLogin,
    ContractRouting,
    ContractSignup,
    evidence_hash_for,
)
from ops.playwright_signup_result import SignupResultCapture, wait_for_signup_result
from ops.signup_result import SignupResultObservation
from ops.signup_submission_gates import SignupSubmissionGateInspection


class FakePage:
    pass


def contract() -> BrowserAutomationContract:
    sources = ("https://docs.example.test/signup",)
    return BrowserAutomationContract(
        app_slug="example",
        app_name="Example",
        contract_version="2026.07.27",
        status="active",
        generated_at="2026-07-27T00:00:00Z",
        expires_at="2027-07-27T00:00:00Z",
        confidence=0.99,
        evidence_hash=evidence_hash_for(sources),
        routing=ContractRouting(
            route_classification="self_serve",
            signup_supported=True,
            login_supported=True,
        ),
        hosts=ContractHosts(vendor_hosts=("app.example.test",)),
        signup=ContractSignup(
            entrypoints=("https://app.example.test/signup",),
            success_predicates=("url_path:/welcome",),
        ),
        login=ContractLogin(
            entrypoints=("https://app.example.test/login",),
            authentication_success_predicates=("accessible_name:dashboard",),
        ),
        evidence=ContractEvidence(source_urls=sources),
    )


def success_observation() -> SignupResultObservation:
    return SignupResultObservation(
        page_url="https://app.example.test/welcome",
        title="Welcome",
        visible_text="Welcome",
        status_text="Welcome",
        accessible_names=("Dashboard",),
        inspected_controls=4,
    )


async def clear_gates(_page, _contract) -> SignupSubmissionGateInspection:
    return SignupSubmissionGateInspection(
        status="clear",
        reason_code="signup_submission_gates_clear",
        inspected_controls=4,
    )


async def test_waiter_requires_stable_positive_observations() -> None:
    calls = 0

    async def reader(_page, _contract) -> SignupResultCapture:
        nonlocal calls
        calls += 1
        return SignupResultCapture(
            status="captured",
            reason_code="signup_result_observation_captured",
            observation=success_observation(),
        )

    result = await wait_for_signup_result(
        FakePage(),
        contract(),
        timeout_seconds=1.0,
        poll_seconds=0.05,
        stable_observations=2,
        observation_reader=reader,
        gate_reader=clear_gates,
    )

    assert result.status == "classified"
    assert result.outcome == "account_created_authenticated"
    assert result.stable_observations == 2
    assert calls == 2


async def test_transient_observation_failure_does_not_become_signup_failure() -> None:
    responses = [
        SignupResultCapture(
            status="retryable",
            reason_code="signup_result_surface_unavailable",
        ),
        SignupResultCapture(
            status="captured",
            reason_code="signup_result_observation_captured",
            observation=success_observation(),
        ),
        SignupResultCapture(
            status="captured",
            reason_code="signup_result_observation_captured",
            observation=success_observation(),
        ),
    ]

    async def reader(_page, _contract) -> SignupResultCapture:
        return responses.pop(0)

    result = await wait_for_signup_result(
        FakePage(),
        contract(),
        timeout_seconds=1.0,
        poll_seconds=0.05,
        stable_observations=2,
        observation_reader=reader,
        gate_reader=clear_gates,
    )

    assert result.outcome == "account_created_authenticated"
    assert responses == []


async def test_blind_spot_resets_the_stability_streak() -> None:
    responses = [
        SignupResultCapture(
            status="captured",
            reason_code="signup_result_observation_captured",
            observation=success_observation(),
        ),
        SignupResultCapture(
            status="retryable",
            reason_code="signup_result_surface_unavailable",
        ),
        SignupResultCapture(
            status="captured",
            reason_code="signup_result_observation_captured",
            observation=success_observation(),
        ),
        SignupResultCapture(
            status="captured",
            reason_code="signup_result_observation_captured",
            observation=success_observation(),
        ),
    ]
    calls = 0

    async def reader(_page, _contract) -> SignupResultCapture:
        nonlocal calls
        calls += 1
        return responses.pop(0)

    result = await wait_for_signup_result(
        FakePage(),
        contract(),
        timeout_seconds=1.0,
        poll_seconds=0.05,
        stable_observations=2,
        observation_reader=reader,
        gate_reader=clear_gates,
    )

    assert result.outcome == "account_created_authenticated"
    assert calls == 4
    assert responses == []


async def test_hung_observation_is_bounded_by_total_deadline() -> None:
    async def reader(_page, _contract) -> SignupResultCapture:
        await asyncio.sleep(10)
        raise AssertionError("deadline cancellation should stop this reader")

    loop = asyncio.get_running_loop()
    started = loop.time()
    result = await wait_for_signup_result(
        FakePage(),
        contract(),
        timeout_seconds=0.5,
        poll_seconds=0.05,
        stable_observations=2,
        observation_reader=reader,
        gate_reader=clear_gates,
    )
    elapsed = loop.time() - started

    assert result.status == "outcome_unknown"
    assert result.reason_code == "signup_result_observation_timeout"
    assert elapsed < 1.0


async def test_hung_gate_inspection_is_bounded_by_total_deadline() -> None:
    async def reader(_page, _contract) -> SignupResultCapture:
        return SignupResultCapture(
            status="captured",
            reason_code="signup_result_observation_captured",
            observation=success_observation(),
        )

    async def hanging_gates(_page, _contract) -> SignupSubmissionGateInspection:
        await asyncio.sleep(10)
        raise AssertionError("deadline cancellation should stop this gate reader")

    loop = asyncio.get_running_loop()
    started = loop.time()
    result = await wait_for_signup_result(
        FakePage(),
        contract(),
        timeout_seconds=0.5,
        poll_seconds=0.05,
        stable_observations=2,
        observation_reader=reader,
        gate_reader=hanging_gates,
    )
    elapsed = loop.time() - started

    assert result.status == "outcome_unknown"
    assert result.reason_code == "signup_result_observation_timeout"
    assert elapsed < 1.0


async def test_unproven_timeout_remains_outcome_unknown() -> None:
    unknown = SignupResultObservation(
        page_url="https://app.example.test/loading",
        title="Loading",
        visible_text="Please wait",
        status_text="Please wait",
        accessible_names=("Loading",),
        inspected_controls=1,
    )

    async def reader(_page, _contract) -> SignupResultCapture:
        return SignupResultCapture(
            status="captured",
            reason_code="signup_result_observation_captured",
            observation=unknown,
        )

    result = await wait_for_signup_result(
        FakePage(),
        contract(),
        timeout_seconds=0.5,
        poll_seconds=0.05,
        stable_observations=2,
        observation_reader=reader,
        gate_reader=clear_gates,
    )

    assert result.status == "outcome_unknown"
    assert result.outcome == "outcome_unknown"
    assert result.next_phase == "reconcile"
    assert result.reason_code == "signup_result_unproven_timeout"


async def test_result_model_contains_no_page_material() -> None:
    sensitive_marker = "owner@example.com"

    async def reader(_page, _contract) -> SignupResultCapture:
        observed = SignupResultObservation(
            page_url="https://app.example.test/welcome?email=owner@example.com",
            title="Welcome owner@example.com",
            visible_text="Welcome owner@example.com",
            status_text="Welcome owner@example.com",
            accessible_names=("Dashboard", sensitive_marker),
            inspected_controls=5,
        )
        return SignupResultCapture(
            status="captured",
            reason_code="signup_result_observation_captured",
            observation=observed,
        )

    result = await wait_for_signup_result(
        FakePage(),
        contract(),
        timeout_seconds=1.0,
        poll_seconds=0.05,
        stable_observations=1,
        observation_reader=reader,
        gate_reader=clear_gates,
    )
    serialized = json.dumps(result.model_dump(mode="json"), sort_keys=True)

    assert result.outcome == "account_created_authenticated"
    assert sensitive_marker not in serialized
    assert "welcome?email" not in serialized
