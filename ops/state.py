"""Typed workflow state shared by deterministic Phase 2+ orchestration.

The state deliberately has no field for raw credential material. Credential
values cross the workflow boundary only as ``vault://`` references.
"""

from __future__ import annotations

from typing import Literal, TypedDict

AccessRoute = Literal[
    "self_serve",
    "approval_required",
    "partner_gated",
    "hybrid",
    "blocked",
    "unknown",
]

RunStatus = Literal[
    "created",
    "researching",
    "route_selected",
    "browser_running",
    "waiting_for_hitl",
    "outreach_sent",
    "waiting_for_reply",
    "credentials_ready",
    "configuration_required",
    "blocked",
    "failed",
    "completed",
]


class IllegalStatusTransition(ValueError):
    """Raised when a run status change is not permitted by the legal table."""


# Terminal statuses have no legal outgoing transition. There is deliberately no
# ``route_selected -> completed`` edge: a plan_only run terminates at
# ``route_selected`` and only an executed run that reaches ``credentials_ready``
# may become ``completed``.
_LEGAL_STATUS_TRANSITIONS: dict[RunStatus, frozenset[RunStatus]] = {
    "created": frozenset(
        {"researching", "route_selected", "configuration_required", "blocked", "failed"}
    ),
    "researching": frozenset(
        {"researching", "route_selected", "configuration_required", "blocked", "failed"}
    ),
    "route_selected": frozenset(
        {"browser_running", "outreach_sent", "configuration_required", "blocked", "failed"}
    ),
    "browser_running": frozenset(
        {"waiting_for_hitl", "credentials_ready", "configuration_required", "blocked", "failed"}
    ),
    "waiting_for_hitl": frozenset({"browser_running", "blocked", "failed"}),
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
}


def validate_status_transition(
    previous_status: RunStatus,
    next_status: RunStatus,
    command: str,
) -> RunStatus:
    """Return ``next_status`` when the transition is legal, else raise.

    This is the single transition authority consumed by the domain projection
    layer; the API, graph, and storage do not keep separate transition logic.
    An identity transition (no status change) is always permitted so an
    idempotent re-projection never fails. ``completed`` and ``blocked`` are
    terminal.
    """

    if previous_status == next_status:
        return next_status
    if next_status not in _LEGAL_STATUS_TRANSITIONS.get(previous_status, frozenset()):
        raise IllegalStatusTransition(
            f"illegal status transition {previous_status!r} -> {next_status!r} "
            f"for command {command!r}"
        )
    return next_status


class OperationsState(TypedDict, total=False):
    """Serializable orchestration state containing references, never secrets."""

    run_id: str
    thread_id: str
    app_name: str
    app_slug: str

    p1_record: dict[str, object]
    request: dict[str, object]
    operational_research: dict[str, object]
    evidence_urls: list[str]
    missing_fields: list[str]

    access_route: AccessRoute
    route_reason: str
    route_reason_code: str
    status: RunStatus
    state_revision: int
    last_projected_revision: int

    browser_profile_id: str
    browser_session_id: str
    browser_live_view_available: bool
    current_url: str
    browser_attempts: int
    browser_observation: dict[str, object]
    browser_session_started_at: str
    browser_session_last_active_at: str
    browser_session_inactivity_expires_at: str
    browser_session_max_expires_at: str

    hitl_request: dict[str, object] | None
    hitl_count: int
    resume_signal: str

    gmail_session_id: str
    gmail_thread_id: str
    intended_recipient: str
    actual_recipient: str
    outreach_round: int
    latest_reply_class: str

    credential_refs: dict[str, str]
    validation_status: str
    validation_endpoint: str
    validation_http_status: int
    validation_checked_at: str

    capability_statuses: list[dict[str, object]]
    side_effect_keys: dict[str, str]

    integrator_bundle: dict[str, object] | None
    errors: list[dict[str, object]]
    audit_events: list[dict[str, object]]
