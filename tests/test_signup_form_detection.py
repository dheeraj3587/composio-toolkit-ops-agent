from __future__ import annotations

from ops.automation_contracts import ContractSignup, ContractSignupFieldHints
from ops.signup_forms import SignupControlCandidate, detect_signup_form


def candidate(
    index: int,
    *,
    kind: str,
    name: str = "",
    aria_label: str = "",
    associated_labels: tuple[str, ...] = (),
    placeholder: str = "",
    test_id: str = "",
) -> SignupControlCandidate:
    return SignupControlCandidate(
        token=f"sf_{index:032x}",
        control_kind=kind,  # type: ignore[arg-type] - focused fixture vocabulary
        accessible_name=name,
        aria_label=aria_label,
        associated_labels=associated_labels,
        placeholder=placeholder,
        test_id=test_id,
    )


def signup_contract() -> ContractSignup:
    return ContractSignup(
        required_semantic_fields=(
            "email",
            "password",
            "password_confirmation",
            "company_name",
        )
    )


def test_simple_one_page_signup_form_is_detected() -> None:
    inspection = detect_signup_form(
        (
            candidate(1, kind="email", name="Email"),
            candidate(2, kind="password", aria_label="Password"),
            candidate(
                3,
                kind="password",
                associated_labels=("Confirm password",),
            ),
            candidate(4, kind="text", placeholder="Company name"),
            candidate(5, kind="button", name="Create account"),
        ),
        signup_contract(),
        "2026.07.27",
    )

    assert inspection.status == "detected"
    assert inspection.reason_code == "signup_form_detected"
    assert {
        field.semantic_field: field.strategy for field in inspection.fields
    } == {
        "email": "accessible_role_name",
        "password": "accessible_label",  # pragma: allowlist secret
        "password_confirmation": "associated_label",  # pragma: allowlist secret
        "company_name": "placeholder",
        "signup_submit": "accessible_role_name",
    }
    assert inspection.password_fields_present is True


def test_ambiguous_duplicate_email_fields_safe_stop() -> None:
    inspection = detect_signup_form(
        (
            candidate(1, kind="email", name="Email"),
            candidate(2, kind="email", name="Email"),
            candidate(3, kind="password", name="Password"),
            candidate(4, kind="password", name="Confirm password"),
            candidate(5, kind="text", name="Company name"),
            candidate(6, kind="button", name="Create account"),
        ),
        signup_contract(),
        "2026.07.27",
    )

    assert inspection.status == "safe_stop"
    assert inspection.reason_code == "signup_field_ambiguous"
    assert inspection.ambiguous_fields == ("email",)
    assert inspection.match_for("email") is None


def test_reviewed_test_id_has_priority_over_accessible_name() -> None:
    signup = signup_contract().model_copy(
        update={
            "field_hints": {
                "email": ContractSignupFieldHints(
                    reviewed_test_ids=("signup-email",),
                )
            }
        }
    )
    inspection = detect_signup_form(
        (
            candidate(
                1,
                kind="email",
                name="Unhelpful generated label",
                test_id="signup-email",
            ),
            candidate(2, kind="password", name="Password"),
            candidate(3, kind="password", name="Confirm password"),
            candidate(4, kind="text", name="Company name"),
            candidate(5, kind="button", name="Create account"),
        ),
        signup,
        "2026.07.27",
    )

    assert inspection.status == "detected"
    email = inspection.match_for("email")
    assert email is not None
    assert email.strategy == "reviewed_test_id"


def test_nearby_heading_is_not_used_without_contract_review() -> None:
    unreviewed = candidate(1, kind="email")
    unreviewed = unreviewed.model_copy(update={"nearby_headings": ("Your email",)})
    candidates = (
        unreviewed,
        candidate(2, kind="password", name="Password"),
        candidate(3, kind="password", name="Confirm password"),
        candidate(4, kind="text", name="Company name"),
        candidate(5, kind="button", name="Create account"),
    )

    inspection = detect_signup_form(candidates, signup_contract(), "2026.07.27")
    assert inspection.status == "safe_stop"
    assert inspection.missing_required_fields == ("email",)

    reviewed = signup_contract().model_copy(
        update={
            "field_hints": {
                "email": ContractSignupFieldHints(
                    nearby_headings=("Your email",),
                )
            }
        }
    )
    inspection = detect_signup_form(candidates, reviewed, "2026.07.27")
    assert inspection.status == "detected"
    email = inspection.match_for("email")
    assert email is not None
    assert email.strategy == "reviewed_nearby_heading"


def test_unmapped_required_control_safe_stops() -> None:
    unknown = candidate(6, kind="text", name="Invitation code")
    unknown = unknown.model_copy(update={"required": True})
    inspection = detect_signup_form(
        (
            candidate(1, kind="email", name="Email"),
            candidate(2, kind="password", name="Password"),
            candidate(3, kind="password", name="Confirm password"),
            candidate(4, kind="text", name="Company name"),
            candidate(5, kind="button", name="Create account"),
            unknown,
        ),
        signup_contract(),
        "2026.07.27",
    )

    assert inspection.status == "safe_stop"
    assert inspection.reason_code == "unmapped_required_signup_control"
    assert inspection.unmapped_required_controls == 1
