"""Durable onboarding phases, their status projection, and the reason vocabulary.

An onboarding run carries two pieces of state that are easy to confuse. The
coarse, externally visible ``ops.core.state.RunStatus`` is what the API and the
operator console show. The *phase* defined here is the fine-grained, durable
position inside the onboarding walk: it is the value a worker resumes from after
a crash, and it is the value each phase boundary commits before the next phase's
first side effect is reserved.

Three deliberate properties of this module:

Phase → status is one total mapping.
    ``_PHASE_STATUS`` covers every phase, so the coarse status can never be
    computed two different ways in two different callers. The single conditional
    in the projection (``vault_storage`` / ``credential_validation`` becoming
    ``credentials_ready`` once a credential is stored and validated) is written
    out explicitly rather than scattered through the driver.

Legal transitions are a table, not control flow.
    ``_LEGAL_PHASE_TRANSITIONS`` mirrors ``ops.core.state._LEGAL_STATUS_TRANSITIONS``,
    including its identity-transition rule: re-applying a transition that has
    already been applied is admitted so an idempotent replay never raises. A
    target phase absent from the source phase's set is refused, and the refusal
    carries both phases so the caller can record it.

Reason codes are a closed list that already satisfies the API's constraint.
    Every member of ``OnboardingReasonCode`` matches ``REASON_CODE_PATTERN``,
    which is the same character class ``api.models.ReasonCode`` enforces, so a
    reason code projects onto an API response without translation and no
    provider or page text can ride along inside one. Closed also has to mean
    *sufficient*: where one code would have covered two pauses that ask
    different things of the operator, the list carries both — see
    ``flow_unsupported`` against ``capture_spec_unavailable``.

This module owns vocabulary and projection only. Committing a phase is the phase
driver's job, and persisting one is the phase-history store's; neither lives
here.
"""

from __future__ import annotations

import re
from typing import Final, Literal, get_args

from ops.core.state import RunStatus

OnboardingPhase = Literal[
    "research",
    "vault_check",
    "awaiting_admission",
    "route_selected_login",
    "route_selected_signup",
    "signup",
    "email_verification",
    "authenticated",
    "developer_app",
    "credential_generation",
    "vault_storage",
    "credential_validation",
    "captcha_paused",
    "completed",
    "paused",
    "blocked",
    "cancelled",
]

# Derived from the literal itself so the tuple cannot drift from the type. Used
# by callers that need to enumerate phases (totality checks, phase-walk
# generators) without re-typing the list.
ONBOARDING_PHASES: Final[tuple[OnboardingPhase, ...]] = get_args(OnboardingPhase)

# A run's phase history necessarily begins here: research runs before a vault
# probe, before any browser session, and before any effect reservation, so it is
# the only phase reachable without a source phase.
INITIAL_PHASE: Final[OnboardingPhase] = "research"

TERMINAL_PHASES: frozenset[OnboardingPhase] = frozenset({"completed", "blocked", "cancelled"})

# Phases in which a browser session must exist and be reattachable.
SESSION_BEARING_PHASES: frozenset[OnboardingPhase] = frozenset(
    {
        "route_selected_login",
        "signup",
        "email_verification",
        "authenticated",
        "developer_app",
        "credential_generation",
        "captcha_paused",
    }
)

# Phases that may be resumed into after a crash. A phase absent here is a
# transient computation and is recomputed from the prior durable phase, which
# today means the three terminal phases: nothing resumes into them.
RESUMABLE_PHASES: frozenset[OnboardingPhase] = SESSION_BEARING_PHASES | frozenset(
    {
        "research",
        "vault_check",
        "awaiting_admission",
        "route_selected_signup",
        "vault_storage",
        "credential_validation",
        "paused",
    }
)

# Total phase → coarse status mapping. ``vault_storage`` and
# ``credential_validation`` sit at ``browser_running`` while the credential is
# still being stored and proven; the projection lifts them to
# ``credentials_ready`` only when the caller states the credential is both
# stored and validated.
_PHASE_STATUS: dict[OnboardingPhase, RunStatus] = {
    "research": "researching",
    "vault_check": "researching",
    "awaiting_admission": "waiting_for_hitl",
    "route_selected_login": "route_selected",
    "route_selected_signup": "route_selected",
    "signup": "browser_running",
    "email_verification": "browser_running",
    "authenticated": "browser_running",
    "developer_app": "browser_running",
    "credential_generation": "browser_running",
    "vault_storage": "browser_running",
    "credential_validation": "browser_running",
    "captcha_paused": "waiting_for_hitl",
    "completed": "completed",
    "paused": "waiting_for_hitl",
    "blocked": "blocked",
    # A cancelled run is externally indistinguishable from a blocked one: both
    # are terminal and neither will advance. The phase keeps the distinction.
    "cancelled": "blocked",
}

_CREDENTIAL_READY_PHASES: frozenset[OnboardingPhase] = frozenset(
    {"vault_storage", "credential_validation"}
)


def project_status(phase: OnboardingPhase, *, credential_ready: bool = False) -> RunStatus:
    """Project one phase onto the coarse run status.

    This is the single authority for a run's coarse status. The result depends on
    the phase and the ``credential_ready`` flag and on nothing else — no clock,
    no attempt counter, no provider state — so two callers projecting the same
    pair always agree.
    """

    if credential_ready and phase in _CREDENTIAL_READY_PHASES:
        return "credentials_ready"
    return _PHASE_STATUS[phase]


# Legal phase transitions, mirroring ``ops.core.state._LEGAL_STATUS_TRANSITIONS``.
#
# ``signup -> route_selected_login`` is the autonomous duplicate-account
# recovery: the provider reports the account already exists, the run already
# holds that account's credentials in Vault, so it re-routes to login with no
# operator prompt. ``captcha_paused -> route_selected_login`` exists for the
# same reason on the login route.
#
# ``captcha_paused`` fans back out to every phase a CAPTCHA can interrupt, so a
# resume re-enters the phase recorded at pause rather than restarting the walk.
#
# ``paused -> research`` is the reset path: reset clears workflow state and
# starts the walk again, preserving every vault reference.
_LEGAL_PHASE_TRANSITIONS: dict[OnboardingPhase, frozenset[OnboardingPhase]] = {
    "research": frozenset({"vault_check", "blocked", "cancelled"}),
    "vault_check": frozenset({"route_selected_login", "awaiting_admission", "blocked"}),
    "awaiting_admission": frozenset({"route_selected_signup", "cancelled", "paused"}),
    "route_selected_login": frozenset({"authenticated", "captcha_paused", "paused", "cancelled"}),
    "route_selected_signup": frozenset({"signup", "paused", "cancelled"}),
    "signup": frozenset(
        {"email_verification", "route_selected_login", "captcha_paused", "paused", "cancelled"}
    ),
    "email_verification": frozenset({"authenticated", "captcha_paused", "paused", "cancelled"}),
    "authenticated": frozenset({"developer_app", "captcha_paused", "paused", "cancelled"}),
    "developer_app": frozenset({"credential_generation", "captcha_paused", "paused", "cancelled"}),
    "credential_generation": frozenset({"vault_storage", "captcha_paused", "paused", "cancelled"}),
    "vault_storage": frozenset({"credential_validation", "paused", "cancelled"}),
    "credential_validation": frozenset(
        {"completed", "credential_generation", "paused", "cancelled"}
    ),
    "captcha_paused": frozenset(
        {
            "signup",
            "email_verification",
            "authenticated",
            "developer_app",
            "credential_generation",
            "route_selected_login",
            "paused",
            "cancelled",
        }
    ),
    # A paused run re-enters the phase it parked from — exactly what
    # ``captcha_paused`` above already does. The two waiting phases differ in WHY
    # they parked, not in what continuing means, and before this a run parked at any
    # gate could only be restarted or cancelled, so every gate cost a whole new run.
    #
    # Widening this table does NOT widen what a resume may do:
    # ``OnboardingRunControlService.resume_from_pause`` reads ``phase_at_pause`` from
    # the last committed boundary and refuses any target this table does not admit,
    # so a run can only ever re-enter a phase it actually stood in. ``research`` is
    # retained because reset routes through it.
    "paused": frozenset(
        {
            "research",
            "route_selected_login",
            "signup",
            "email_verification",
            "authenticated",
            "developer_app",
            "credential_generation",
            "cancelled",
        }
    ),
    "completed": frozenset(),
    "blocked": frozenset(),
    "cancelled": frozenset(),
}


def legal_phase_targets(phase: OnboardingPhase) -> frozenset[OnboardingPhase]:
    """Target phases declared for ``phase``, excluding the identity transition."""

    return _LEGAL_PHASE_TRANSITIONS[phase]


def is_legal_phase_transition(
    previous_phase: OnboardingPhase | None,
    next_phase: OnboardingPhase,
) -> bool:
    """Whether the transition is admitted, identity transitions included.

    ``previous_phase`` is ``None`` only for a run's first committed phase, which
    is :data:`INITIAL_PHASE`.
    """

    if previous_phase is None:
        return next_phase == INITIAL_PHASE
    if previous_phase == next_phase:
        return True
    return next_phase in _LEGAL_PHASE_TRANSITIONS[previous_phase]


OnboardingReasonCode = Literal[
    # --- research -----------------------------------------------------------
    "profile_corroborated",
    "research_inconclusive",
    "research_domain_disagreement",
    "research_no_evidence",
    "research_adapters_unavailable",
    "profile_url_unreachable",
    # --- admission ----------------------------------------------------------
    "credentials_present",
    "credentials_missing",
    "signup_authorization_required",
    "operator_approved_signup",
    "operator_cancelled",
    # --- pre-flight plan ----------------------------------------------------
    # Raised by the plan validator before any browser session exists: a surface
    # the plan would drive is absent from the recipe catalog, so the run is
    # refused here rather than failing mid-walk (reliability R5.6).
    "plan_surface_not_in_catalog",
    # The three ways a plan lands recipe-only — the plan carries the recipe's
    # declared surfaces and nothing inferred. Kept apart because each names a
    # different thing to fix: configuration, the provider chain, or the answer.
    "plan_provider_unconfigured",  # no provider key is configured (reliability R5.8)
    "plan_decision_failed",  # every configured provider was called and none was usable
    "plan_decision_unusable",  # the chain answered and the decision was unusable
    # --- route adherence ----------------------------------------------------
    "route_replanned",  # the one authorized re-plan (reliability R6.2, R6.4)
    "route_divergence_unresolved",  # divergence after that re-plan (reliability R6.5)
    # --- action loop / navigation ------------------------------------------
    "host_in_app_policy",  # from BrowserHostDecision
    "browser_host_not_in_app_policy",  # from BrowserHostDecision
    "browser_url_not_https_or_malformed",  # from BrowserHostDecision
    "action_not_in_candidate_set",
    "candidate_identity_not_found",
    "candidate_identity_ambiguous",
    # Retained: the coarse code every gate used to report, still written by rows
    # created before the three causes below were separated, and still the fallback
    # when a PAGE (not a candidate) names the human action.
    "candidate_risk_requires_human",
    # The three distinguishable ways the action loop hands a step to a person.
    # They were one code, which made a paused run undiagnosable: "a human is
    # required" did not say whether the page offered nothing safe, the model
    # declined, or the model chose something it was never shown. Each names a
    # different thing to fix, so each is its own durable code.
    #
    # Every option on the page is irreversible or privilege-changing. No model call
    # happened. This is the correct fail-closed outcome for a genuine billing,
    # legal-acceptance or captcha surface.
    "candidate_gate_no_executable_option",
    # The model itself asked for a human (``report_hitl``). Also correct behavior,
    # but attributable to the decision rather than to the page.
    "candidate_gate_model_declined",
    # The model named a candidate that is not executable. Reaching this PROVES the
    # id was offered in the schema enum while its description was withheld from the
    # rendered prompt, because a non-executable candidate is by construction absent
    # from the rendered set.
    "candidate_gate_selection_not_executable",
    "dlp_prompt_refused",
    "loop_action_budget_exhausted",
    "loop_no_progress_budget_exhausted",
    "loop_wallclock_budget_exhausted",
    "loop_model_call_budget_exhausted",
    "postcondition_failed",
    # Loop liveness and per-attempt decision telemetry: a run that is not
    # deciding says so, rather than looking identical to one that is working.
    "run_progress_stale",  # no progress event inside the staleness window (reliability R4.9)
    "decision_provider_unconfigured",  # the inference builder returned None in the loop
    "decision_provider_failed",  # every configured provider was called, none was usable
    "decision_unusable",  # schema-invalid, or a decision naming no candidate action
    # A profile-bound plan was admitted, but this deployment has no generic
    # observe/act/signup RPC. The run pauses before creating a session or effect.
    "browser_adapter_unavailable",
    # --- signup / verification ---------------------------------------------
    "signup_submitted",
    "signup_rejected_duplicate_account",
    # Signup reached for an app whose recipe declares no signup policy: nothing
    # was submitted, so an operator reads this as a recipe gap (reliability R7.2).
    "signup_policy_absent",
    # The recipe-declared observable postcondition for signup did not hold, so
    # the submission is not treated as successful (reliability R7.6).
    "signup_postcondition_unmet",
    "verification_email_found",
    "verification_unresolved",
    "verification_link_blocked",
    "verification_claim_contended",
    # --- developer app / credentials ---------------------------------------
    "developer_app_created",
    "developer_app_approval_required",
    "billing_required",
    "credential_generated",
    "credential_stored",
    "credential_valid",
    "credential_invalid_retryable",
    "credential_invalid_terminal",
    "credential_superseded",
    # The provider offers no drivable flow for the requested credential kind:
    # the matching ``FlowSpec.supported`` is ``False`` (Requirement 9.10). The
    # run pauses and reserves no developer-application operation key. Nothing
    # was attempted and nothing on this side failed, which is why this is not
    # ``capture_spec_unavailable``: an operator reading it needs to pick a
    # different credential kind or a different provider, not re-run the phase.
    # Consumed by the developer-application phase (task 17.1).
    "flow_unsupported",
    # A capture or validation *contract could not be constructed* for a flow
    # the profile does declare. This is the recoverable half of the split above
    # — the run's own inputs are insufficient, so re-research or a corrected
    # profile can make the same phase provable. Two paths carry it:
    #   * ``profile_capture_contract`` raising because the matching ``FlowSpec``
    #     carries no ``entry_url`` to capture from (LL-1.6, task 11.2)
    #   * ``profile_validation_policy`` returning ``None``, meaning the stored
    #     credential is unprovable — always a pause with the reference left
    #     unpublished, never an implicit pass (Requirement 10.11, LL-2.3,
    #     task 17.3)
    "capture_spec_unavailable",
    # --- gates --------------------------------------------------------------
    "captcha_detected",
    "captcha_resolved",
    "captcha_attempt_budget_exhausted",
    # A human cleared the gate and the clearance was observed, but the re-entry
    # into the phase recorded at pause is not committable, so the run stays
    # paused rather than continuing into a phase the transition table refuses
    # (reliability R1.11). Distinct from ``captcha_resolved``: the gate is gone,
    # the continuation is what is unavailable.
    "takeover_step_unavailable",
    # --- operator control surface -------------------------------------------
    # The total fallback for a capability projection that withholds a control:
    # the console renders the humanized code where the button would be, never an
    # empty panel with no explanation (reliability R3.2).
    "control_withheld",
    # --- lifecycle ----------------------------------------------------------
    "lease_claimed",
    "lease_expired_recovered",
    "session_reattached",
    "session_recreated",
    "session_unreattachable",
    # Max-age closure of a paused session a human is attached to: idle expiry is
    # skipped while the human works, the absolute lifetime is not (reliability R2.5).
    "session_lifetime_exceeded",
    "outcome_unknown",
    "phase_replay_noop",
    "run_paused_by_operator",
    "run_reset",
    "step_retried",
]

# Derived from the literal so the tuple cannot drift from the closed list.
ONBOARDING_REASON_CODES: Final[tuple[OnboardingReasonCode, ...]] = get_args(OnboardingReasonCode)

# The character class ``api.models.ReasonCode`` enforces. Kept here as the
# checkable form of "every onboarding reason code projects to the API without
# translation": a code that fails this pattern would need a translation layer,
# and there is none.
REASON_CODE_PATTERN: Final = re.compile(r"^[a-z0-9][a-z0-9_:-]{0,63}$")


class IllegalPhaseTransition(ValueError):
    """Raised when a phase transition is not permitted by the legal table.

    Carries both phases and the reason code of the attempt so the refusal can be
    recorded durably without parsing the message.
    """

    def __init__(
        self,
        previous_phase: OnboardingPhase | None,
        next_phase: OnboardingPhase,
        reason_code: OnboardingReasonCode,
    ) -> None:
        super().__init__(
            f"illegal phase transition {previous_phase!r} -> {next_phase!r} "
            f"for reason code {reason_code!r}"
        )
        self.previous_phase = previous_phase
        self.next_phase = next_phase
        self.reason_code = reason_code


def validate_phase_transition(
    previous_phase: OnboardingPhase | None,
    next_phase: OnboardingPhase,
    reason_code: OnboardingReasonCode,
) -> OnboardingPhase:
    """Return ``next_phase`` when the transition is legal, else raise.

    This is the single transition authority for the phase machine, consumed by
    the phase driver before it commits and by the phase-history store before it
    writes. An identity transition is always permitted so an idempotent replay
    of an already-applied transition never fails; ``completed``, ``blocked``, and
    ``cancelled`` are terminal and admit nothing but themselves.

    A refused transition leaves the caller's current phase untouched: this
    function has no state to change.
    """

    if not is_legal_phase_transition(previous_phase, next_phase):
        raise IllegalPhaseTransition(previous_phase, next_phase, reason_code)
    return next_phase


__all__ = [
    "INITIAL_PHASE",
    "ONBOARDING_PHASES",
    "ONBOARDING_REASON_CODES",
    "REASON_CODE_PATTERN",
    "RESUMABLE_PHASES",
    "SESSION_BEARING_PHASES",
    "TERMINAL_PHASES",
    "IllegalPhaseTransition",
    "OnboardingPhase",
    "OnboardingReasonCode",
    "is_legal_phase_transition",
    "legal_phase_targets",
    "project_status",
    "validate_phase_transition",
]
