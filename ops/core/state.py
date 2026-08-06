"""Typed workflow state shared by deterministic Phase 2+ orchestration.

The state deliberately has no field for raw credential material. Credential
values cross the workflow boundary only as ``vault://`` references.
"""

from __future__ import annotations

from typing import Final, Literal, TypedDict, get_args

AccessRoute = Literal[
    "self_serve",
    "approval_required",
    "partner_gated",
    "hybrid",
    "blocked",
    "unknown",
]
# "playwright" is the only backend that exists. "browser_use" is retained as a
# READ-ONLY legacy value: runs created before the cloud adapter was removed carry
# it in their persisted rows and checkpoints, and narrowing this Literal would make
# those rows fail validation in the console rather than render as history.
BrowserProvider = Literal["browser_use", "playwright"]
CredentialCreationPolicy = Literal["reuse_only", "create_if_missing"]

RunStatus = Literal[
    "created",
    "researching",
    "route_selected",
    "connection_required",
    "browser_running",
    "waiting_for_hitl",
    "outreach_sent",
    "waiting_for_reply",
    "credentials_ready",
    "configuration_required",
    "blocked",
    "failed",
    "completed",
    # Terminal, and legacy: ``project_status`` maps the ``cancelled`` phase onto
    # ``blocked``, so no current code path writes this. It stays in the vocabulary
    # because rows carrying it exist in deployed ledgers, and a status the type
    # cannot name is a status the API cannot read back. See the note on the
    # transition table for why it has no incoming edge.
    "cancelled",
]

# The vocabulary as data, so the ledger's ``runs.status`` CHECK and the API's
# read-back coercion are both generated from the Literal rather than restating it.
RUN_STATUSES: Final[tuple[RunStatus, ...]] = get_args(RunStatus)


class IllegalStatusTransition(ValueError):
    """Raised when a run status change is not permitted by the legal table."""


# Terminal statuses have no legal outgoing transition. There is deliberately no
# ``route_selected -> completed`` edge: a plan_only run terminates at
# ``route_selected`` and only an executed run that reaches ``credentials_ready``
# may become ``completed``.
_LEGAL_STATUS_TRANSITIONS: dict[RunStatus, frozenset[RunStatus]] = {
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
            # An onboarding admission pause holds a corroborated provider profile
            # and no browser session yet. Projecting it as ``browser_running``
            # would claim a session that does not exist, and the browser UI
            # projection would then advertise a live view for nothing.
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
    # ``configuration_required`` is reachable from ``waiting_for_hitl`` because a
    # self-hosted (in-process) browser session does not survive an api restart: such
    # a run is recoverable by operator action, not failed. Cloud-backed providers
    # whose session can be reattached are simply never reconciled out of this state.
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
    # No status transitions *into* ``cancelled``: the phase machine expresses a
    # cancellation as the ``cancelled`` phase projected onto ``blocked`` status.
    # A row already carrying it is terminal, so it needs an entry here for the
    # lookup to resolve, and an empty one is the truthful answer.
    "cancelled": frozenset(),
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
    browser_provider: BrowserProvider
    credential_creation_policy: CredentialCreationPolicy
    state_revision: int
    last_projected_revision: int

    browser_profile_id: str
    browser_session_id: str
    # The Browser Use *provider* session id, distinct from the local session
    # handle. It MUST be declared here so LangGraph persists it in the encrypted
    # checkpoint; otherwise an api restart loses it and a paused HITL run can no
    # longer be resumed (provider_session_missing) and its live view is lost.
    browser_provider_session_id: str
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

    # Autonomous provider onboarding. Every field here is a reference or a
    # non-secret identifier: the phase machine's durable position, the content
    # address of the run's immutable provider profile, the vault binding, and the
    # provider-issued developer application id. There is deliberately no field
    # for credential material — a minted credential reaches the workflow only as
    # a ``vault://`` reference in ``credential_refs``.
    #
    # ``onboarding_phase`` and ``onboarding_phase_at_pause`` carry a member of
    # ``ops.onboarding.phase.OnboardingPhase``, and ``onboarding_reason_code`` a
    # member of ``ops.onboarding.phase.OnboardingReasonCode``. They are annotated
    # ``str`` rather than those literals because this module is a leaf that those
    # vocabularies import ``RunStatus`` from, so the annotation cannot name them
    # without a cycle, and because ``OperationsState``'s annotations are resolved
    # at runtime (``typing.get_type_hints``), which rules out a
    # ``TYPE_CHECKING``-only import. The phase machine validates both against its
    # closed tables before either is written.
    onboarding_phase: str
    onboarding_phase_at_pause: str
    profile_digest: str
    provider_registrable_domain: str
    # ``vault://app/kind/id`` reference, never a login value.
    onboarding_account_ref: str
    developer_app_id: str
    onboarding_credential_generation: int
    onboarding_reason_code: str

    integrator_bundle: dict[str, object] | None
    errors: list[dict[str, object]]
    audit_events: list[dict[str, object]]
