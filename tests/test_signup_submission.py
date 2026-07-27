from __future__ import annotations

import re
from pathlib import Path

import pytest

from ops.approved_run_values import ApprovedRunValues
from ops.automation_contracts import (
    BrowserAutomationContract,
    ContractEvidence,
    ContractHosts,
    ContractRouting,
    ContractSignup,
    evidence_hash_for,
)
from ops.effect_ledger import SQLiteEffectStore
from ops.signup_credentials import SignupAccountBinding
from ops.signup_forms import (
    SignupControlCandidate,
    SignupFillResult,
    SignupFormInspection,
    detect_signup_form,
)
from ops.signup_state_machine import SignupState
from ops.signup_submission import (
    SignupSubmissionResult,
    _signup_effect_key,
    submit_signup_form,
)

# Obviously synthetic and assembled rather than stored as a password-shaped
# fixture literal. The value exists only in the fake in-memory secret store.
SYNTHETIC_CREDENTIAL_VALUE = "".join(("Example", "Account", "42"))


class FakeSecretStore:
    def __init__(self, values: dict[str, str]) -> None:
        self.values = values
        self.reads = 0

    def get(self, reference: str) -> str:
        self.reads += 1
        return self.values[reference]


class FakeCredentialManager:
    def __init__(self, password_ref: str) -> None:
        self.password_ref = password_ref

    def get_account_password_reference(
        self,
        binding: SignupAccountBinding,
    ) -> str | None:
        del binding
        return self.password_ref


class FakeLocator:
    def __init__(
        self,
        *,
        value: str = "",
        accessible_name: str = "",
        gate_metadata: dict[str, object] | None = None,
        submit_metadata: dict[str, object] | None = None,
        page: FakePage | None = None,
        fail_click: bool = False,
        count_value: int = 1,
    ) -> None:
        self.value = value
        self.accessible_name = accessible_name
        self.gate_metadata = gate_metadata or {
            "tag": "input",
            "type": "text",
            "role": "",
            "autocomplete": "",
            "name": "",
            "id": "",
            "ariaLabel": accessible_name,
            "placeholder": "",
            "title": "",
            "src": "",
            "text": "",
            "required": False,
        }
        self.submit_metadata = submit_metadata
        self.page = page
        self.fail_click = fail_click
        self.count_value = count_value
        self.trial_clicks = 0
        self.actual_clicks = 0

    async def count(self) -> int:
        return self.count_value

    async def is_visible(self) -> bool:
        return True

    async def is_disabled(self) -> bool:
        return False

    async def aria_snapshot(self, *, timeout: int) -> str:
        del timeout
        return f'- button "{self.accessible_name}"' if self.accessible_name else "- textbox"

    async def evaluate(
        self,
        expression: str,
        argument: object = None,
    ) -> object:
        if "insideForm" in expression:
            if self.submit_metadata is None:
                raise AssertionError("submit metadata requested from a non-submit control")
            return dict(self.submit_metadata)
        if "autocomplete" in expression and "required" in expression:
            return dict(self.gate_metadata)
        if isinstance(argument, dict):
            expected = str(argument["expected"])
            return self.value == expected
        return self.value == argument

    async def click(
        self,
        *,
        trial: bool = False,
        timeout: int,
    ) -> None:
        del timeout
        if trial:
            self.trial_clicks += 1
            return
        self.actual_clicks += 1
        if self.fail_click:
            raise TimeoutError("ambiguous provider response")
        if self.page is not None:
            self.page.url = "https://app.example.test/signup-dispatched"


class FakeCollection:
    def __init__(self, locators: list[FakeLocator]) -> None:
        self.locators = locators

    async def all(self) -> list[FakeLocator]:
        return list(self.locators)


class FakePage:
    def __init__(
        self,
        *,
        token_locators: dict[str, FakeLocator],
        gate_locators: list[FakeLocator] | None = None,
    ) -> None:
        self.url = "https://app.example.test/signup"
        self.token_locators = token_locators
        self.gate_locators = gate_locators or list(token_locators.values())
        for locator in token_locators.values():
            locator.page = self

    def locator(self, selector: str) -> FakeLocator | FakeCollection:
        if selector.startswith("input:not([type='hidden'])"):
            return FakeCollection(self.gate_locators)
        match = re.fullmatch(
            r'\[data-ops-signup-ref="(?P<token>sf_[0-9a-f]{32})"\]',
            selector,
        )
        if match is None:
            raise AssertionError(f"unexpected selector: {selector}")
        return self.token_locators[match.group("token")]


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
        ),
        hosts=ContractHosts(vendor_hosts=("app.example.test",)),
        signup=ContractSignup(
            entrypoints=("https://app.example.test/signup",),
            required_semantic_fields=(
                "email",
                "password",
                "password_confirmation",
                "company_name",
            ),
        ),
        evidence=ContractEvidence(source_urls=sources),
    )


def candidate(index: int, *, kind: str, name: str) -> SignupControlCandidate:
    return SignupControlCandidate(
        token=f"sf_{index:032x}",
        control_kind=kind,  # type: ignore[arg-type] - fixture validates runtime vocabulary
        accessible_name=name,
    )


def prepared_form() -> tuple[SignupFormInspection, SignupFillResult]:
    current_contract = contract()
    inspection = detect_signup_form(
        (
            candidate(1, kind="email", name="Email"),
            candidate(2, kind="password", name="Password"),
            candidate(3, kind="password", name="Confirm password"),
            candidate(4, kind="text", name="Company name"),
            candidate(5, kind="button", name="Create account"),
        ),
        current_contract.signup,
        current_contract.contract_version,
    )
    fill_result = SignupFillResult(
        status="filled",
        reason_code="signup_form_filled_and_verified",
        contract_version=current_contract.contract_version,
        filled_fields=(
            "email",
            "password",
            "password_confirmation",
            "company_name",
        ),
        verified_fields=(
            "email",
            "password",
            "password_confirmation",
            "company_name",
        ),
        screenshots_disabled=True,
    )
    return inspection, fill_result


def approved_values(
    *,
    email_ref: str,
    password_ref: str,
) -> ApprovedRunValues:
    return ApprovedRunValues(
        run_id="run_1",
        session_id="bs_1",
        legal_name="Example Labs",
        company_website="https://example.com",
        use_case="Authorized integration provisioning",
        signup_email_ref=email_ref,
        account_password_ref=password_ref,
        generated_application_name="Example Labs Integration",
        account_display_name="Example Labs",
        workspace_name="Example Labs",
    )


def page_for(
    inspection: SignupFormInspection,
    *,
    gate_locator: FakeLocator | None = None,
    fail_click: bool = False,
    form_method: str = "post",
) -> tuple[FakePage, FakeLocator]:
    values = {
        "email": "owner@example.com",
        "password": SYNTHETIC_CREDENTIAL_VALUE,  # pragma: allowlist secret
        "password_confirmation": SYNTHETIC_CREDENTIAL_VALUE,  # pragma: allowlist secret
        "company_name": "Example Labs",
    }
    locators: dict[str, FakeLocator] = {}
    submit_locator: FakeLocator | None = None
    for field in inspection.fields:
        if field.semantic_field == "signup_submit":
            locator = FakeLocator(
                accessible_name="Create account",
                fail_click=fail_click,
                submit_metadata={
                    "tag": "button",
                    "type": "submit",
                    "role": "button",
                    "formAction": "https://app.example.test/signup",
                    "formMethod": form_method,
                    "formTarget": "",
                    "insideForm": True,
                },
                gate_metadata={
                    "tag": "button",
                    "type": "submit",
                    "role": "button",
                    "autocomplete": "",
                    "name": "",
                    "id": "",
                    "ariaLabel": "Create account",
                    "placeholder": "",
                    "title": "",
                    "src": "",
                    "text": "Create account",
                    "required": False,
                },
            )
            submit_locator = locator
        else:
            locator = FakeLocator(
                value=values[field.semantic_field],
                accessible_name=field.semantic_field,
            )
        locators[field.token] = locator
    assert submit_locator is not None
    gates = list(locators.values())
    if gate_locator is not None:
        gates.append(gate_locator)
    page = FakePage(token_locators=locators, gate_locators=gates)
    return page, submit_locator


def submission_dependencies() -> tuple[
    ApprovedRunValues,
    FakeSecretStore,
    FakeCredentialManager,
    SignupAccountBinding,
]:
    email_ref = "vault://example/signup_email/email_1"
    password_ref = "vault://example/account_password/password_1"  # pragma: allowlist secret
    values = approved_values(email_ref=email_ref, password_ref=password_ref)
    secret_store = FakeSecretStore(
        {
            email_ref: "owner@example.com",
            password_ref: SYNTHETIC_CREDENTIAL_VALUE,
        }
    )
    binding = SignupAccountBinding(
        owner_ref="owner_1",
        app_slug="example",
        gmail_account_fingerprint="a" * 64,
    )
    manager = FakeCredentialManager(password_ref)
    return values, secret_store, manager, binding


async def dispatch(
    tmp_path: Path,
    page: FakePage,
    inspection: SignupFormInspection,
    fill_result: SignupFillResult,
    *,
    effect_store: SQLiteEffectStore | None = None,
    capture_guard: bool = True,
) -> SignupSubmissionResult:
    values, store, manager, binding = submission_dependencies()
    return await submit_signup_form(
        page,
        inspection=inspection,
        fill_result=fill_result,
        contract=contract(),
        approved_values=values,
        account_policy="create_if_missing",
        current_state=SignupState.SIGNUP_SUBMISSION_READY,
        run_id="run_1",
        session_id="bs_1",
        secret_store=store,  # type: ignore[arg-type] - focused fake store
        credential_manager=manager,  # type: ignore[arg-type] - focused fake manager
        account_binding=binding,
        effect_store=effect_store or SQLiteEffectStore(tmp_path / "effects.db"),
        assert_secret_capture_disabled=(lambda: None) if capture_guard else None,
    )


async def test_approved_signup_submission_is_dispatched_at_most_once(
    tmp_path: Path,
) -> None:
    inspection, fill_result = prepared_form()
    page, submit = page_for(inspection)

    first = await dispatch(tmp_path, page, inspection, fill_result)
    page.token_locators = {}
    page.gate_locators = []
    second = await dispatch(tmp_path, page, inspection, fill_result)

    assert first.status == "submitted"
    assert first.submit_clicked is True
    assert first.reason_code == "signup_submit_dispatched"
    assert second.status == "submitted"
    assert second.effect_replayed is True
    assert submit.actual_clicks == 1
    assert submit.trial_clicks == 2


@pytest.mark.parametrize(
    ("metadata", "gate"),
    [
        (
            {
                "tag": "label",
                "type": "",
                "role": "",
                "autocomplete": "",
                "name": "",
                "id": "",
                "ariaLabel": "",
                "placeholder": "",
                "title": "",
                "src": "",
                "text": "I agree to the Terms of Service",
                "required": False,
            },
            "legal_acceptance",
        ),
        (
            {
                "tag": "input",
                "type": "text",
                "role": "",
                "autocomplete": "cc-number",
                "name": "card-number",
                "id": "",
                "ariaLabel": "Card number",
                "placeholder": "",
                "title": "",
                "src": "",
                "text": "",
                "required": True,
            },
            "billing",
        ),
    ],
)
async def test_legal_and_payment_gates_never_submit(
    tmp_path: Path,
    metadata: dict[str, object],
    gate: str,
) -> None:
    inspection, fill_result = prepared_form()
    page, submit = page_for(inspection, gate_locator=FakeLocator(gate_metadata=metadata))

    result = await dispatch(tmp_path, page, inspection, fill_result)

    assert result.status == "authorization_denied"
    assert gate in result.present_gates
    assert submit.actual_clicks == 0
    assert submit.trial_clicks == 0


async def test_ambiguous_click_outcome_is_never_blindly_retried(
    tmp_path: Path,
) -> None:
    inspection, fill_result = prepared_form()
    page, submit = page_for(inspection, fail_click=True)

    first = await dispatch(tmp_path, page, inspection, fill_result)
    second = await dispatch(tmp_path, page, inspection, fill_result)

    assert first.status == "outcome_unknown"
    assert first.reason_code == "signup_submit_outcome_unknown"
    assert second.status == "outcome_unknown"
    assert second.reason_code == "signup_submit_reconciliation_required"
    assert submit.actual_clicks == 1


async def test_get_form_is_blocked_before_click(tmp_path: Path) -> None:
    inspection, fill_result = prepared_form()
    page, submit = page_for(inspection, form_method="get")

    result = await dispatch(tmp_path, page, inspection, fill_result)

    assert result.status == "configuration_required"
    assert result.reason_code == "signup_submit_get_form_blocked"
    assert submit.actual_clicks == 0


async def test_duplicate_page_token_safe_stops_before_click(tmp_path: Path) -> None:
    inspection, fill_result = prepared_form()
    page, submit = page_for(inspection)
    submit.count_value = 2

    result = await dispatch(tmp_path, page, inspection, fill_result)

    assert result.status == "failed"
    assert result.reason_code == "signup_submit_control_stale_or_ambiguous"
    assert submit.actual_clicks == 0
    assert submit.trial_clicks == 0


async def test_secret_capture_guard_is_required_before_dom_comparison(
    tmp_path: Path,
) -> None:
    inspection, fill_result = prepared_form()
    page, submit = page_for(inspection)

    result = await dispatch(
        tmp_path,
        page,
        inspection,
        fill_result,
        capture_guard=False,
    )

    assert result.status == "configuration_required"
    assert result.reason_code == "signup_secret_capture_guard_missing"
    assert submit.actual_clicks == 0


def test_effect_key_changes_with_every_stable_identity_component() -> None:
    baseline = _signup_effect_key(
        run_id="run_1",
        contract_version="2026.07.27",
        account_binding_id="binding_1",
    )

    assert baseline != _signup_effect_key(
        run_id="run_2",
        contract_version="2026.07.27",
        account_binding_id="binding_1",
    )
    assert baseline != _signup_effect_key(
        run_id="run_1",
        contract_version="2026.07.28",
        account_binding_id="binding_1",
    )
    assert baseline != _signup_effect_key(
        run_id="run_1",
        contract_version="2026.07.27",
        account_binding_id="binding_2",
    )


async def test_completed_receipt_must_match_exact_account_binding(
    tmp_path: Path,
) -> None:
    inspection, fill_result = prepared_form()
    page, submit = page_for(inspection)
    values, _store, _manager, binding = submission_dependencies()
    effects = SQLiteEffectStore(tmp_path / "effects.db")
    key = _signup_effect_key(
        run_id=values.run_id,
        contract_version=contract().contract_version,
        account_binding_id=binding.binding_id,
    )
    effects.reserve(
        provider="example",
        action="signup_submit",
        idempotency_key=key,
    )
    effects.complete(
        provider="example",
        action="signup_submit",
        idempotency_key=key,
        receipt={
            "result": "dispatched",
            "purpose": "signup_submit",
            "contract_version": contract().contract_version,
            "account_binding_id": "different_binding",
        },
    )

    result = await dispatch(
        tmp_path,
        page,
        inspection,
        fill_result,
        effect_store=effects,
    )

    assert result.status == "outcome_unknown"
    assert result.reason_code == "signup_submit_receipt_invalid"
    assert submit.actual_clicks == 0
