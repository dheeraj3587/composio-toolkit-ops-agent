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
