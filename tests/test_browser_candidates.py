"""Item 2 + 3: policy-generated candidates and identity-based re-resolution.

The security property under test: a model can select but never author. There is no
path by which a model-supplied selector, URL, or typed value becomes executable,
and irreversible controls are never executable candidates at all.
"""

from __future__ import annotations

import pytest

from ops.browser_candidates import (
    APPROVED_VALUE_REFS,
    ActionCandidate,
    ElementIdentity,
    classify_irreversible,
    executable_candidates,
    generate_candidates,
    render_candidates,
    select_candidate,
    validate_press_key,
)
from ops.browser_decider import (
    CandidateChoice,
    build_snapshot,
    candidate_choice_schema,
    validate_choice,
)

_TRACE_VERSION = "2.0"


def _elements(*specs: dict[str, object]) -> tuple:
    return build_snapshot(list(specs))


def _generate(elements: tuple, signals: tuple[str, ...] = ("API",), **kwargs: object) -> tuple:
    return generate_candidates(
        elements=elements,
        checkpoint_signals=signals,
        checkpoint_order=1,
        trace_version=_TRACE_VERSION,
        expected_postcondition="api_settings_visible",
        **kwargs,  # type: ignore[arg-type]
    )


# --- Candidates are bounded, opaque, and carry policy metadata -----------------
def test_candidates_are_opaque_and_carry_required_metadata() -> None:
    elements = _elements({"tag": "link", "name": "API settings"})
    candidates = _generate(elements)
    assert candidates, "a matching element must yield a candidate"
    candidate = candidates[0]
    assert candidate.candidate_id.startswith("c_")  # opaque, not a selector
    assert candidate.action == "click"
    assert candidate.semantic_target == "API settings"
    assert candidate.identity == ElementIdentity("link", "API settings", "")
    assert candidate.risk == "low"
    assert candidate.expected_postcondition == "api_settings_visible"
    assert candidate.trace_version == _TRACE_VERSION
    assert candidate.checkpoint_order == 1


def test_candidate_set_is_bounded() -> None:
    elements = _elements(*[{"tag": "link", "name": f"API item {i}"} for i in range(30)])
    assert len(_generate(elements, max_candidates=5)) <= 5


def test_only_signal_relevant_elements_become_candidates() -> None:
    elements = _elements(
        {"tag": "link", "name": "API settings"},
        {"tag": "link", "name": "Completely unrelated marketing link"},
    )
    candidates = _generate(elements, ("API",))
    targets = [candidate.semantic_target for candidate in candidates]
    assert "API settings" in targets
    assert "Completely unrelated marketing link" not in targets


# --- Irreversible intents are never executable --------------------------------
@pytest.mark.parametrize(
    ("label", "category"),
    [
        ("Delete account", "account_deletion"),
        ("Revoke API key", "key_revocation"),
        ("Regenerate token", "key_revocation"),
        ("Change plan", "billing"),
        ("Add payment method", "billing"),
        ("I agree", "legal_acceptance"),
        ("Transfer ownership", "permission_escalation"),
        ("Delete workspace", "destructive_change"),
    ],
)
def test_irreversible_controls_require_hitl(label: str, category: str) -> None:
    flagged, detected = classify_irreversible(label)
    assert flagged is True and detected == category

    elements = _elements({"tag": "button", "name": label})
    candidates = _generate(elements, (label,))
    assert candidates and candidates[0].risk == "requires_hitl"
    assert candidates[0].executable is False
    # And it is filtered out of the executable set entirely.
    assert executable_candidates(candidates) == ()


def test_selecting_a_hitl_candidate_is_refused() -> None:
    elements = _elements({"tag": "button", "name": "Delete account"})
    candidates = _generate(elements, ("Delete account",))
    with pytest.raises(ValueError, match="human authorization"):
        select_candidate(candidates, candidates[0].candidate_id)


def test_ordinary_controls_are_not_flagged() -> None:
    assert classify_irreversible("Personal preferences") == (False, "")


# --- The model cannot author selectors, URLs, or typed values ------------------
def test_choice_model_has_no_field_for_authoring_an_action() -> None:
    fields = set(CandidateChoice.model_fields)
    # No selector/url/text/index field exists at all.
    assert fields == {"decision", "candidate_id", "reason"}


def test_unknown_candidate_id_is_rejected() -> None:
    with pytest.raises(ValueError, match="not in the generated policy set"):
        validate_choice(
            {"decision": "select_candidate", "candidate_id": "c_forged", "reason": ""},
            candidate_ids=["c_real"],
        )


def test_select_without_an_id_is_rejected() -> None:
    with pytest.raises(ValueError, match="requires a candidate_id"):
        validate_choice(
            {"decision": "select_candidate", "candidate_id": None, "reason": ""},
            candidate_ids=["c_real"],
        )


def test_extra_fields_are_rejected() -> None:
    with pytest.raises(ValueError):
        validate_choice(
            {
                "decision": "select_candidate",
                "candidate_id": "c_real",
                "reason": "",
                "url": "https://evil.example",  # attempted smuggling
            },
            candidate_ids=["c_real"],
        )


@pytest.mark.parametrize("decision", ["report_hitl", "report_blocked"])
def test_report_decisions_need_no_candidate(decision: str) -> None:
    choice = validate_choice(
        {"decision": decision, "candidate_id": None, "reason": "x"}, candidate_ids=[]
    )
    assert choice.decision == decision


def test_choice_schema_enumerates_only_generated_ids() -> None:
    schema = candidate_choice_schema(["c_a", "c_b"])
    enum = schema["properties"]["candidate_id"]["enum"]  # type: ignore[index]
    assert "c_a" in enum and "c_b" in enum and "c_forged" not in enum
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"])  # type: ignore[arg-type]


# --- fill/press/goto candidates are policy-sourced ----------------------------
# Phase 2 renamed the value action "type" -> "fill" (Playwright's own verb);
# "type" stays a valid literal for backward compatibility, so these tests accept
# either name and assert the SECURITY property: the value comes from an approved
# reference, never from the model.
_VALUE_ACTIONS = {"fill", "type"}


def test_value_candidates_use_an_approved_value_reference_only() -> None:
    elements = _elements({"tag": "input", "type": "text", "name": "Company"})
    candidates = _generate(elements, ("Company",), allow_value_refs=("company_name",))
    typed = [candidate for candidate in candidates if candidate.action in _VALUE_ACTIONS]
    assert typed and typed[0].value_ref == "company_name"
    assert typed[0].value_ref in APPROVED_VALUE_REFS


def test_unapproved_value_reference_yields_no_value_candidate() -> None:
    elements = _elements({"tag": "input", "type": "text", "name": "Company"})
    candidates = _generate(elements, ("Company",), allow_value_refs=("arbitrary_text",))
    assert [c for c in candidates if c.action in _VALUE_ACTIONS] == []


def test_secret_fields_never_become_value_candidates() -> None:
    elements = _elements({"tag": "input", "type": "password", "name": "Password"})
    candidates = _generate(elements, ("Password",), allow_value_refs=("company_name",))
    assert [c for c in candidates if c.action in _VALUE_ACTIONS] == []


def test_goto_candidates_come_from_the_reviewed_trace() -> None:
    reviewed = "https://app.pipedrive.com/settings/api"
    candidates = _generate(_elements(), (), reviewed_goto_urls=(reviewed,))
    gotos = [candidate for candidate in candidates if candidate.action == "goto"]
    assert gotos and gotos[0].url == reviewed


def test_press_candidates_target_a_reviewed_element_not_page_global() -> None:
    elements = _elements({"tag": "input", "type": "text", "name": "Search"})
    candidates = _generate(elements, ("Search",))
    presses = [candidate for candidate in candidates if candidate.action == "press"]
    assert presses and presses[0].identity is not None  # bound to an element
    assert presses[0].press_key == "Enter"


def test_press_key_allowlist_is_enforced() -> None:
    assert validate_press_key("Enter") == "Enter"
    for key in ("F12", "Control+P", "a"):
        with pytest.raises(ValueError):
            validate_press_key(key)


# --- Identity-based re-resolution (TOCTOU protection) -------------------------
def test_identity_matches_by_role_name_type_not_position() -> None:
    identity = ElementIdentity("link", "API settings", "")
    moved = build_snapshot(
        [{"tag": "button", "name": "Other"}, {"tag": "link", "name": "API settings"}]
    )
    # The element is now at index 1, but identity still matches it and NOT index 0.
    assert identity.matches(moved[1]) is True
    assert identity.matches(moved[0]) is False


def test_identity_rejects_a_renamed_element() -> None:
    identity = ElementIdentity("button", "Generate token", "")
    changed = build_snapshot([{"tag": "button", "name": "Delete everything"}])
    assert identity.matches(changed[0]) is False


def test_rendered_candidates_expose_ids_and_semantics_only() -> None:
    elements = _elements({"tag": "link", "name": "API settings"})
    rendered = render_candidates(_generate(elements))
    assert "c_" in rendered and "API settings" in rendered
    # No raw selector syntax is offered to the model.
    assert "input[" not in rendered and "nth" not in rendered


def test_render_omits_hitl_candidates() -> None:
    elements = _elements({"tag": "button", "name": "Delete account"})
    assert "no executable candidates" in render_candidates(_generate(elements, ("Delete",)))


def test_candidate_ids_are_stable_and_distinct() -> None:
    elements = _elements(
        {"tag": "link", "name": "API settings"}, {"tag": "link", "name": "API keys"}
    )
    first = _generate(elements, ("API",))
    second = _generate(elements, ("API",))
    assert [c.candidate_id for c in first] == [c.candidate_id for c in second]  # deterministic
    assert len({c.candidate_id for c in first}) == len(first)  # distinct


def test_candidate_dataclass_is_immutable() -> None:
    candidate = ActionCandidate(
        candidate_id="c_x",
        action="click",
        semantic_target="t",
        identity=None,
        risk="low",
        expected_postcondition="p",
        trace_version=_TRACE_VERSION,
        checkpoint_order=1,
    )
    # frozen dataclass: mutation raises FrozenInstanceError, so a validated
    # candidate cannot be rewritten after policy generation.
    from dataclasses import FrozenInstanceError

    with pytest.raises(FrozenInstanceError):
        candidate.action = "goto"  # type: ignore[misc]
