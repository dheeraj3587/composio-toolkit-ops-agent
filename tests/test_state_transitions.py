"""The single domain status-transition authority."""

from __future__ import annotations

import pytest

from ops.state import IllegalStatusTransition, validate_status_transition


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


def test_illegal_transition_is_rejected() -> None:
    with pytest.raises(IllegalStatusTransition):
        validate_status_transition("created", "completed", "create")
    with pytest.raises(IllegalStatusTransition):
        validate_status_transition("researching", "completed", "workflow")
