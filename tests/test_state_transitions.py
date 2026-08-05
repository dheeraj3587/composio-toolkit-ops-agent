"""The single domain status-transition authority."""

from __future__ import annotations

import pytest

from ops.core.state import (
    _LEGAL_STATUS_TRANSITIONS,
    IllegalStatusTransition,
    RunStatus,
    validate_status_transition,
)

# The full table, pinned. Duplication is deliberate: the point of this snapshot is
# that widening the machine for one flow cannot silently widen it for another, so
# an edge added or removed anywhere fails here and has to be argued for.
_EXPECTED_TRANSITIONS: dict[RunStatus, frozenset[RunStatus]] = {
    "created": frozenset(
        {
            "researching",
            "route_selected",
            "connection_required",
            "configuration_required",
            "blocked",
            "failed",
        }
    ),
    "researching": frozenset(
        {"researching", "route_selected", "configuration_required", "blocked", "failed"}
    ),
    "route_selected": frozenset(
        {
            "connection_required",
            "browser_running",
            "outreach_sent",
            "waiting_for_hitl",
            "configuration_required",
            "blocked",
            "failed",
        }
    ),
    "connection_required": frozenset(
        {"connection_required", "completed", "configuration_required", "blocked", "failed"}
    ),
    "browser_running": frozenset(
        {
            "waiting_for_hitl",
            "outreach_sent",
            "waiting_for_reply",
            "credentials_ready",
            "configuration_required",
            "blocked",
            "failed",
        }
    ),
    "waiting_for_hitl": frozenset(
        {"browser_running", "configuration_required", "blocked", "failed"}
    ),
    "outreach_sent": frozenset({"waiting_for_reply", "configuration_required", "failed"}),
    "waiting_for_reply": frozenset(
        {
            "waiting_for_reply",
            "browser_running",
            "credentials_ready",
            "configuration_required",
            "blocked",
            "failed",
        }
    ),
    "credentials_ready": frozenset({"completed", "failed"}),
    "configuration_required": frozenset(
        {
            "researching",
            "route_selected",
            "browser_running",
            "outreach_sent",
            "waiting_for_reply",
            "blocked",
            "failed",
        }
    ),
    "blocked": frozenset(),
    "failed": frozenset({"researching", "browser_running", "outreach_sent"}),
    "completed": frozenset(),
    # Terminal and unreachable, on purpose. ``cancelled`` entered the vocabulary so
    # rows written by a since-removed path stay readable, not so the machine could
    # reach it: a cancellation is the ``cancelled`` *phase*, which projects onto
    # ``blocked``. An empty edge set on both sides is what keeps that true, so a
    # later edge into it has to be argued for here first.
    "cancelled": frozenset(),
}


def test_representative_legal_transitions_are_accepted() -> None:
    assert validate_status_transition("created", "researching", "create") == "researching"
    assert validate_status_transition("created", "route_selected", "create") == "route_selected"
    assert (
        validate_status_transition("researching", "route_selected", "workflow") == "route_selected"
    )
    assert (
        validate_status_transition("route_selected", "browser_running", "resume")
        == "browser_running"
    )
    assert validate_status_transition("credentials_ready", "completed", "workflow") == "completed"


def test_identity_transition_is_always_permitted() -> None:
    for status in ("created", "route_selected", "configuration_required", "completed", "blocked"):
        assert validate_status_transition(status, status, "project") == status


def test_no_route_selected_to_completed_edge() -> None:
    with pytest.raises(IllegalStatusTransition):
        validate_status_transition("route_selected", "completed", "workflow")


def test_terminal_states_have_no_outgoing_transition() -> None:
    with pytest.raises(IllegalStatusTransition):
        validate_status_transition("completed", "researching", "retry")
    with pytest.raises(IllegalStatusTransition):
        validate_status_transition("blocked", "route_selected", "retry")
    with pytest.raises(IllegalStatusTransition):
        validate_status_transition("cancelled", "browser_running", "retry")


def test_no_status_transitions_into_cancelled() -> None:
    """A cancellation is a phase; the status it projects onto is ``blocked``.

    ``cancelled`` is in the vocabulary only so a row already carrying it reads back.
    Making it a legal target would give the machine a second way to say "terminal"
    that no projection produces and no console renders differently.
    """

    for source, targets in _LEGAL_STATUS_TRANSITIONS.items():
        assert "cancelled" not in targets, f"{source} gained an edge into cancelled"


def test_illegal_transition_is_rejected() -> None:
    with pytest.raises(IllegalStatusTransition):
        validate_status_transition("created", "completed", "create")
    with pytest.raises(IllegalStatusTransition):
        validate_status_transition("researching", "completed", "workflow")


def test_admission_pause_is_representable_from_route_selected() -> None:
    """An onboarding run holding a profile and no session pauses for admission."""

    assert (
        validate_status_transition("route_selected", "waiting_for_hitl", "onboarding_admission")
        == "waiting_for_hitl"
    )


def test_the_admission_pause_still_resumes_and_cancels() -> None:
    """The pause is only usable because its two outgoing edges already exist."""

    assert (
        validate_status_transition("waiting_for_hitl", "browser_running", "resume")
        == "browser_running"
    )
    assert validate_status_transition("waiting_for_hitl", "blocked", "cancel") == "blocked"


def test_the_table_holds_exactly_the_declared_edges() -> None:
    """No source status gained or lost an edge beyond the admission pause."""

    assert _LEGAL_STATUS_TRANSITIONS == _EXPECTED_TRANSITIONS
