from __future__ import annotations

import json
import re
from pathlib import Path

from cryptography.fernet import Fernet

from ops.approved_run_values import ApprovedRunValues
from ops.automation_contracts import (
    BrowserAutomationContract,
    ContractEvidence,
    ContractHosts,
    ContractRouting,
    ContractSelectOption,
    ContractSignup,
    ContractSignupFieldHints,
    evidence_hash_for,
)
from ops.playwright_signup import fill_signup_form
from ops.secret_store import SQLiteSecretStore
from ops.signup_credentials import (
    SQLiteSignupCredentialRegistry,
    SignupAccountBinding,
    SignupCredentialManager,
)
from ops.signup_forms import SignupControlCandidate, detect_signup_form


class FakeLocator:
    def __init__(self, *, kind: str) -> None:
        self.kind = kind
        self.value = ""
        self.selected_label = ""
        self.selected_value = ""
        self.fill_calls: list[str] = []
        self.click_calls = 0

    async def count(self) -> int:
        return 1

    async def is_visible(self) -> bool:
        return True

    async def is_disabled(self) -> bool:
        return False

    async def fill(self, value: str, *, timeout: int) -> None:
        del timeout
        self.fill_calls.append(value)
        self.value = value

    async def select_option(
        self,
        *,
        label: str | None = None,
        value: str | None = None,
        timeout: int,
    ) -> None:
        del timeout
        if label is not None:
            self.selected_label = label
        if value is not None:
            self.selected_value = value

    async def evaluate(self, expression: str, argument: object) -> bool:
        del expression
        if isinstance(argument, dict):
            expected = str(argument["expected"])
            return (
                self.selected_label == expected
                if argument["byLabel"]
                else self.selected_value == expected
            )
        return self.value == argument


class FakePage:
    def __init__(self, locators: dict[str, FakeLocator]) -> None:
        self.locators = locators

    def locator(self, selector: str) -> FakeLocator:
        match = re.fullmatch(
            r'\[data-ops-signup-ref="(?P<token>sf_[0-9a-f]{32})"\]',
            selector,
        )
        if match is None:
            raise AssertionError(f"unexpected selector: {selector}")
        return self.locators[match.group("token")]


def contract(*, require_first_name: bool = False) -> BrowserAutomationContract:
    required = [
        "email",
        "password",
        "password_confirmation",
        "company_name",
        "country",
    ]
    if require_first_name:
        required.append("first_name")
    sources = ("https://docs.example.test/signup",)
    return BrowserAutomationContract(
        app_slug="pipedrive",
        app_name="Pipedrive",
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
        hosts=ContractHosts(vendor_hosts=("example.test",)),
        signup=ContractSignup(
            entrypoints=("https://example.test/signup",),
            required_semantic_fields=tuple(required),
            field_hints={
                "country": ContractSignupFieldHints(
                    select_option=ContractSelectOption(mode="approved_label"),
                )
            },
        ),
        evidence=ContractEvidence(source_urls=sources),
    )


def candidate(index: int, *, kind: str, name: str) -> SignupControlCandidate:
    return SignupControlCandidate(
        token=f"sf_{index:032x}",
        control_kind=kind,
        accessible_name=name,
    )


def inspection_for(current_contract: BrowserAutomationContract):
    candidates = [
        candidate(1, kind="email", name="Email"),
        candidate(2, kind="password", name="Password"),
        candidate(3, kind="password", name="Confirm password"),
        candidate(4, kind="text", name="Company name"),
        candidate(7, kind="select", name="Country"),
        candidate(5, kind="button", name="Create account"),
    ]
    if "first_name" in current_contract.signup.required_semantic_fields:
        candidates.insert(3, candidate(6, kind="text", name="First name"))
    return detect_signup_form(
        candidates,
        current_contract.signup,
        current_contract.contract_version,
    )


def approved_values(
    *,
    email_ref: str,
    password_ref: str,
    first_name: str | None = "Akhilesh",
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
        first_name=first_name,
        last_name="Joshi",
        job_title="Engineer",
        country="India",
    )


async def test_required_fields_are_filled_and_verified_without_submit(
    tmp_path: Path,
) -> None:
    vault = SQLiteSecretStore(tmp_path / "vault.db", Fernet.generate_key().decode())
    email_ref = vault.put(
        app_slug="pipedrive",
        kind="signup_email",
        value="owner@example.com",
    )
    registry = SQLiteSignupCredentialRegistry(tmp_path / "signup.db")
    manager = SignupCredentialManager(vault, registry)
    binding = SignupAccountBinding(
        owner_ref="owner_1",
        app_slug="pipedrive",
        gmail_account_fingerprint="a" * 64,
    )
    generated = manager.generate_account_password(binding)
    values = approved_values(
        email_ref=email_ref,
        password_ref=generated.password_ref,
    )
    current_contract = contract()
    inspection = inspection_for(current_contract)
    locators = {
        field.token: FakeLocator(kind=field.control_kind)
        for field in inspection.fields
    }
    page = FakePage(locators)
    screenshot_state = {"disabled": False}

    result = await fill_signup_form(
        page,
        inspection=inspection,
        contract=current_contract,
        approved_values=values,
        run_id="run_1",
        session_id="bs_1",
        secret_store=vault,
        credential_manager=manager,
        account_binding=binding,
        disable_screenshots=lambda: screenshot_state.update(disabled=True),
    )

    assert result.status == "filled"
    assert result.reason_code == "signup_form_filled_and_verified"
    assert set(result.filled_fields) == {
        "email",
        "password",
        "password_confirmation",
        "company_name",
        "country",
    }
    assert result.filled_fields == result.verified_fields
    assert result.submit_clicked is False
    assert screenshot_state["disabled"] is True
    submit = inspection.match_for("signup_submit")
    assert submit is not None
    assert locators[submit.token].fill_calls == []
    assert locators[submit.token].click_calls == 0


async def test_password_never_enters_prompt_safe_or_result_models(
    tmp_path: Path,
) -> None:
    vault = SQLiteSecretStore(tmp_path / "vault.db", Fernet.generate_key().decode())
    email_ref = vault.put(
        app_slug="pipedrive",
        kind="signup_email",
        value="owner@example.com",
    )
    manager = SignupCredentialManager(
        vault,
        SQLiteSignupCredentialRegistry(tmp_path / "signup.db"),
    )
    binding = SignupAccountBinding(
        owner_ref="owner_1",
        app_slug="pipedrive",
        gmail_account_fingerprint="b" * 64,
    )
    generated = manager.generate_account_password(binding)
    raw_password = vault.get(generated.password_ref)
    values = approved_values(
        email_ref=email_ref,
        password_ref=generated.password_ref,
    )
    current_contract = contract()
    inspection = inspection_for(current_contract)
    page = FakePage(
        {
            field.token: FakeLocator(kind=field.control_kind)
            for field in inspection.fields
        }
    )

    result = await fill_signup_form(
        page,
        inspection=inspection,
        contract=current_contract,
        approved_values=values,
        run_id="run_1",
        session_id="bs_1",
        secret_store=vault,
        credential_manager=manager,
        account_binding=binding,
        disable_screenshots=lambda: None,
    )

    model_material = json.dumps(
        {
            "inspection": inspection.prompt_safe_projection(),
            "result": result.model_dump(mode="json"),
            "approved_projection": values.prompt_safe_projection(),
        },
        sort_keys=True,
    )
    assert raw_password not in model_material
    assert generated.password_ref not in model_material
    assert email_ref not in model_material


async def test_missing_required_value_returns_configuration_required_before_fill(
    tmp_path: Path,
) -> None:
    vault = SQLiteSecretStore(tmp_path / "vault.db", Fernet.generate_key().decode())
    email_ref = vault.put(
        app_slug="pipedrive",
        kind="signup_email",
        value="owner@example.com",
    )
    manager = SignupCredentialManager(
        vault,
        SQLiteSignupCredentialRegistry(tmp_path / "signup.db"),
    )
    binding = SignupAccountBinding(
        owner_ref="owner_1",
        app_slug="pipedrive",
        gmail_account_fingerprint="c" * 64,
    )
    generated = manager.generate_account_password(binding)
    values = approved_values(
        email_ref=email_ref,
        password_ref=generated.password_ref,
        first_name=None,
    )
    current_contract = contract(require_first_name=True)
    inspection = inspection_for(current_contract)
    locators = {
        field.token: FakeLocator(kind=field.control_kind)
        for field in inspection.fields
    }

    result = await fill_signup_form(
        FakePage(locators),
        inspection=inspection,
        contract=current_contract,
        approved_values=values,
        run_id="run_1",
        session_id="bs_1",
        secret_store=vault,
        credential_manager=manager,
        account_binding=binding,
        disable_screenshots=lambda: (_ for _ in ()).throw(
            AssertionError("screenshots should not be disabled before planning succeeds")
        ),
    )

    assert result.status == "configuration_required"
    assert result.reason_code == "signup_required_value_missing"
    assert result.missing_values == ("first_name",)
    assert all(not locator.fill_calls for locator in locators.values())
