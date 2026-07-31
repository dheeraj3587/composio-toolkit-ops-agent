"""Resume of a run parked at a human gate, on the SAME browser session.

Resume continues the durable workflow through the EXISTING thread id: no new
session is created, so the human's browser and the agent's browser are the same
one. That is the whole point of the method and it constrains everything else here.

Three outcomes are possible and each must be reported truthfully. A repeated
interrupt keeps the run waiting with a refreshed instruction. A cleared gate
advances toward the credential page, where a deterministic capture may complete the
run outright. A blocked or failed observation ends the run: projecting those as
browser_running used to park the run permanently, because nothing drives a
browser_running run (the advancer only sweeps waiting_for_hitl, retry records no
action, and the UI offers no resume), so it held the single browser slot until the
next API restart.

Injected sign-in values are resolved in memory for exactly one workflow.resume
call, passed through the provider's one-time secret boundary, and dropped as soon
as it returns. Only the non-secret field names and their source reach the ledger,
which is what makes an autonomous vault reuse distinguishable from an owner
submission in the timeline.

The second half of this module is the operator run-control surface for onboarding
runs — Pause, Resume, and Cancel over the durable phase machine
(:mod:`ops.onboarding.phase`) rather than over the coarse run status. Four
properties shape it:

A pause settles the effect ledger before it stops the run.
    Requirement 14.3 is the reason pause is not simply a status write: a
    submission the ledger has already reserved must be *completed or reconciled*
    before the run stops, otherwise the pause parks a run whose provider-visible
    effect is in flight and the next worker cannot tell whether the provider saw
    it. Every in-flight reservation is settled first — completed when a read-only
    probe observes the outcome, marked ``outcome_unknown`` when it cannot —
    and only then is the boundary committed. ``outcome_unknown`` authorizes
    nothing, which is why an unprobeable submission is safe to leave paused.

A pause keeps the session; a cancel releases it.
    Pause never calls the release port (Requirement 14.2) — the operator is
    expected to come back to the same authenticated browser. Cancel releases it,
    persists, and commits ``cancelled`` before the caller gets its answer
    (Requirements 14.5, 14.6), which is why the release happens inside this call
    rather than in a background sweep.

The phase at pause is read from the committed boundary, not from a worker.
    A resume names the phase the run was in when it paused, and that fact is the
    ``from_phase`` of the boundary into the waiting phase. Reading it from history
    means a worker that crashed between the pause and the resume loses nothing,
    and no in-memory hand-off has to survive a restart.

Illegal is refused, not improvised.
    Every boundary is checked against the phase table before it is committed, and
    a control whose boundary the table refuses changes nothing at all: no session
    released, no status written, ``committed=False`` reported. The one visible
    consequence is that a run parked at ``paused`` cannot be re-entered into its
    recorded phase, because the table declares ``paused -> {research, cancelled}``
    only; ``captcha_paused`` is the waiting phase that fans back out. That
    tension between Requirement 14.4 and the phase table is reported rather than
    papered over.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final, Protocol, cast

from pydantic import SecretStr

from ops.browser.link_log import log_event
from ops.browser.worker import BrowserWorker
from ops.core.models import OperationalResearch, OperationsRequest
from ops.core.secret_store import SQLiteSecretStore
from ops.core.state import (
    BrowserProvider,
    IllegalStatusTransition,
    RunStatus,
    validate_status_transition,
)
from ops.core.storage import OperationsStorage
from ops.onboarding.driver import (
    PHASE_REPLAY_NOOP,
    WAITING_PHASES,
    EffectReservationRecord,
    PhaseHistoryStore,
    PhaseTransition,
    phase_correlation_id,
)
from ops.onboarding.effects import EffectDisposition, OnboardingEffect
from ops.onboarding.phase import (
    RESUMABLE_PHASES,
    TERMINAL_PHASES,
    OnboardingPhase,
    OnboardingReasonCode,
    is_legal_phase_transition,
    project_status,
)
from ops.runs.errors import CredentialSubmissionError, RunConflictError
from ops.runs.projections import _TERMINAL_BROWSER_STATUSES, _browser_result_reason, _public_run

LOGGER = logging.getLogger("composio_ops.run_service")


class RunResumeContext(Protocol):
    """Run-service state and helpers the resume path drives."""

    storage: OperationsStorage
    _workflow: Any
    _secret_store: SQLiteSecretStore | None
    _credential_validator: Any

    def _run_lock(self, run_id: str) -> Any: ...

    def _browser_worker_for(self, record: Any) -> BrowserWorker | None: ...

    def _remember_reusable_login(
        self,
        *,
        app_slug: str,
        account_ref: str,
        values: Mapping[str, SecretStr],
    ) -> tuple[str, ...]: ...

    def _browser_login_payload(
        self,
        *,
        provider: BrowserProvider,
        app_slug: str,
        scope_id: str,
        values: Mapping[str, SecretStr],
    ) -> dict[str, str]: ...

    def _finalize_captured_credentials(
        self,
        research: OperationalResearch,
        request: OperationsRequest,
        credential_refs: Mapping[str, str],
    ) -> Any: ...

    def _session_context_for(self, run_id: str) -> Any: ...

    def _release_browser_session(
        self,
        context: Any,
        provider: BrowserProvider,
        *,
        reason: str,
    ) -> None: ...


class RunResumeService:
    """Continue a waiting_for_hitl run on its existing session and thread."""

    def __init__(self, context: RunResumeContext) -> None:
        self._context = context

    def resume_run(
        self,
        run_id: str,
        *,
        signal: str = "completed",
        browser_login: Mapping[str, SecretStr] | None = None,
    ) -> dict[str, Any]:
        """Resume a waiting_for_hitl run on the SAME browser session/thread.

        Continues the durable workflow through the existing thread id (no new
        session is created), then projects the resumed state. A repeated
        interrupt keeps the run at waiting_for_hitl with a refreshed instruction;
        a cleared path advances toward the credential page.

        When ``browser_login`` is supplied (owner-only, loopback), its raw values
        are resolved in-memory ONLY for the single ``workflow.resume`` call and
        injected through the selected provider's one-time secret boundary so the
        agent logs in autonomously. The raw values are never written to run state,
        checkpoints, audit events, or logs, and are dropped as soon as resume
        returns; only the non-secret field names are recorded.
        """

        context = self._context

        if context._workflow is None:
            raise CredentialSubmissionError("workflow_not_configured")
        lock = context._run_lock(run_id)
        if not lock.acquire(blocking=False):
            raise RunConflictError(run_id, "resume")
        try:
            current = context.storage.get_run(run_id)
            if current is None:
                raise KeyError("run was not found")
            if current["status"] != "waiting_for_hitl":
                raise CredentialSubmissionError("run_not_waiting_for_hitl")
            thread_id = str(current.get("thread_id") or run_id)
            app_slug = str(current.get("app_slug") or "unknown")
            remembered_fields: tuple[str, ...] = ()
            if browser_login:
                # Remember the owner's sign-in credentials so the NEXT resume (or
                # the next run) can authenticate without asking again.
                remembered_fields = context._remember_reusable_login(
                    app_slug=app_slug,
                    # Legacy runs predate durable account bindings. Keep any new
                    # write isolated to this run rather than reviving app-global
                    # credential replacement.
                    account_ref=run_id,
                    values=browser_login,
                )
            login_values: Mapping[str, SecretStr] | None = browser_login
            login_source = "owner_supplied"
            # Resume never recreates consumed credential references. Only values
            # explicitly included in THIS owner request may be injected. Reusable
            # credentials can seed a fresh run, but CAPTCHA/provider-verification
            # resume must inspect and continue the existing browser session.
            injected_login_fields: list[str] = sorted(login_values) if login_values else []
            sensitive_data: dict[str, str] | None = None
            if login_values:
                sensitive_data = context._browser_login_payload(
                    provider=cast(
                        BrowserProvider,
                        current.get("browser_provider", "browser_use"),
                    ),
                    app_slug=app_slug,
                    scope_id=run_id,
                    values=login_values,
                )
            try:
                state = context._workflow.resume(thread_id, signal, sensitive_data=sensitive_data)
            finally:
                # Drop the resolved raw values as soon as resume returns.
                if sensitive_data is not None:
                    sensitive_data.clear()
                    sensitive_data = None
            interrupts = context._workflow.get_interrupts(thread_id)

            observation = state.get("browser_observation")
            observation_status = (
                str(observation.get("status")) if isinstance(observation, Mapping) else None
            )
            current_url = state.get("current_url")
            still_blocked = bool(interrupts) or observation_status == "human_action_required"
            next_status: RunStatus
            capture_events: list[tuple[str, dict[str, object]]] = []
            capture_updates: dict[str, object] = {}
            provider_browser = "running"
            validation_status = "not_started"

            if signal == "cancelled":
                next_status = "blocked"
                provider_browser = "blocked"
            elif still_blocked:
                next_status = "waiting_for_hitl"
            elif observation_status in {"credential_page_ready", "developer_console_ready"}:
                next_status = "browser_running"
                provider_browser = "credential_page_ready"
                capture_events.append(
                    (
                        "credential_page_ready",
                        {
                            "current_url": current_url,
                            "status": "browser_running",
                            "external_actions": True,
                        },
                    )
                )
                research_payload = state.get("operational_research")
                if not isinstance(research_payload, Mapping):
                    research_payload = current.get("operational_research")
                request_payload = state.get("request")
                try:
                    research_obj = OperationalResearch.model_validate(research_payload)
                    request_obj = OperationsRequest.model_validate(request_payload)
                except Exception:
                    research_obj = None
                    request_obj = None

                selected_worker = context._browser_worker_for(
                    cast(BrowserProvider, current.get("browser_provider", "browser_use"))
                )
                auto_capture = getattr(selected_worker, "auto_capture_credentials", None)
                captured_refs: dict[str, str] | None = None
                if (
                    research_obj is not None
                    and request_obj is not None
                    and callable(auto_capture)
                    and context._credential_validator is not None
                    and context._secret_store is not None
                ):
                    capture_events.append(
                        (
                            "credential_capture_started",
                            {
                                "app_slug": research_obj.app_slug,
                                "external_actions": True,
                            },
                        )
                    )
                    handle = str(
                        state.get("browser_session_id") or current.get("browser_session_id") or ""
                    )
                    try:
                        capture_scope_kwargs = (
                            {"capability_scope": run_id}
                            if bool(
                                getattr(
                                    selected_worker,
                                    "requires_session_capability_scope",
                                    False,
                                )
                            )
                            else {}
                        )
                        captured_refs = asyncio.run(
                            auto_capture(
                                handle,
                                research_obj.app_slug,
                                context._secret_store,
                                **capture_scope_kwargs,
                            )
                        )
                    except Exception as exc:
                        log_event(
                            "browser.resume.autocapture_error",
                            level=40,
                            run_id=run_id,
                            error=type(exc).__name__,
                        )
                        next_status = "configuration_required"
                        validation_status = "configuration_required"
                        capture_updates["route_reason_code"] = "credential_capture_failed"
                        capture_events.append(
                            (
                                "credential_capture_failed",
                                {
                                    "reason_code": "credential_capture_failed",
                                    "external_actions": True,
                                },
                            )
                        )

                if captured_refs and research_obj is not None and request_obj is not None:
                    try:
                        outcome = context._finalize_captured_credentials(
                            research_obj, request_obj, captured_refs
                        )
                    except Exception as exc:
                        log_event(
                            "browser.resume.credential_finalization_error",
                            level=40,
                            run_id=run_id,
                            error=type(exc).__name__,
                        )
                        # Finalization never persisted these refs. Remove the
                        # just-captured entries best-effort so an unexpected
                        # validator/bundle error cannot leave unreachable vault
                        # rows behind.
                        store = context._secret_store
                        if store is not None:
                            for reference in captured_refs.values():
                                with contextlib.suppress(Exception):
                                    store.delete(reference)
                        next_status = "configuration_required"
                        validation_status = "configuration_required"
                        capture_updates["route_reason_code"] = "credential_finalization_failed"
                        capture_events.append(
                            (
                                "credential_finalization_failed",
                                {
                                    "reason_code": "credential_finalization_failed",
                                    "external_actions": True,
                                },
                            )
                        )
                    else:
                        next_status = cast(RunStatus, outcome.status)
                        validation_status = outcome.validation_status or "configuration_required"
                        capture_updates["route_reason_code"] = outcome.reason_code
                        if outcome.bundle is not None:
                            capture_updates["integrator_bundle"] = outcome.bundle
                        capture_events.extend(outcome.events)
            elif observation_status in {"blocked", "failed"}:
                # A resume that ends blocked/failed must say so. Projecting these as
                # ``browser_running`` parked the run permanently: nothing drives a
                # browser_running run (the advancer only sweeps waiting_for_hitl,
                # retry records no action, and the UI offers no resume), so the run
                # held the single browser slot until the next API restart.
                next_status = "blocked" if observation_status == "blocked" else "failed"
                provider_browser = next_status
                capture_updates["route_reason_code"] = _browser_result_reason(
                    state, f"browser_resume_{observation_status}"
                )
                capture_events.append(
                    (
                        "browser_resume_terminal",
                        {
                            "status": next_status,
                            "reason_code": capture_updates["route_reason_code"],
                            "external_actions": True,
                        },
                    )
                )
                # The shared terminal-release block at the end of this method hands
                # the browser session back for these statuses.
            else:
                # "navigating" (or an absent status) is genuinely still in progress.
                next_status = "browser_running"

            with context.storage.unit_of_work() as transaction:
                record = transaction.get_run(run_id)
                if record is None:  # pragma: no cover - re-checked under lock
                    raise KeyError("run was not found")
                revision = int(record.get("state_revision", 0) or 0) + 1
                if next_status == "completed":
                    # Capture completed all three domain phases during this one
                    # atomic resume projection; validate every legal edge even
                    # though only the terminal row is persisted.
                    validate_status_transition("waiting_for_hitl", "browser_running", "resume")
                    validate_status_transition("browser_running", "credentials_ready", "resume")
                    validate_status_transition("credentials_ready", "completed", "resume")
                else:
                    validate_status_transition("waiting_for_hitl", next_status, "resume")
                hitl_payload: dict[str, object] | None = None
                if next_status == "waiting_for_hitl":
                    source = interrupts[0] if interrupts else state.get("hitl_request")
                    if isinstance(source, Mapping):
                        hitl_payload = {str(k): v for k, v in source.items()}
                changes: dict[str, object] = {
                    "status": next_status,
                    "state_revision": revision,
                    "last_projected_revision": revision,
                    "external_actions": True,
                    "hitl_request": hitl_payload,
                    "provider_status": {
                        "research": "baseline_ready",
                        "browser": provider_browser,
                        "email": "not_started",
                        "validation": validation_status,
                    },
                    **capture_updates,
                }
                if isinstance(current_url, str) and current_url:
                    changes["browser_live_url"] = None  # never persist the signed URL
                updated = transaction.update_run(run_id, **changes)
                cancelled = signal == "cancelled"
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="hitl_cancelled" if cancelled else "hitl_resumed",
                    payload={
                        "status": "blocked" if cancelled else "browser_running",
                        "signal": signal,
                        "external_actions": True,
                    },
                )
                if injected_login_fields:
                    # Record ONLY the non-secret field names that were injected;
                    # the values never touch the ledger, state, or logs. The
                    # source distinguishes an owner submission from an autonomous
                    # vault reuse, which is what makes the timeline auditable.
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="login_credentials_injected",
                        payload={
                            "fields": injected_login_fields,
                            "source": login_source,
                            "external_actions": True,
                        },
                    )
                if remembered_fields:
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="login_credentials_remembered",
                        payload={
                            "fields": list(remembered_fields),
                            "external_actions": False,
                        },
                    )
                if next_status == "waiting_for_hitl":
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="browser_hitl_required",
                        payload={
                            "status": "waiting_for_hitl",
                            "current_url": current_url,
                            "required_human_action": (
                                hitl_payload.get("type") if hitl_payload else None
                            ),
                            "external_actions": True,
                        },
                    )
                else:
                    for event_type, payload in capture_events:
                        transaction.append_audit_event(
                            run_id=run_id,
                            event_type=event_type,
                            payload=payload,
                        )
                projected = _public_run(updated)
            if next_status in _TERMINAL_BROWSER_STATUSES:
                # A cancelled (or otherwise terminal) resume ends the run, so the
                # session is released here instead of lingering as a held slot.
                context._release_browser_session(
                    context._session_context_for(run_id),
                    cast(BrowserProvider, current.get("browser_provider", "browser_use")),
                    reason=f"resume_{next_status}",
                )
            return projected
        finally:
            lock.release()


# --- operator run controls over the onboarding phase machine ----------------

# The reason code each control writes onto the boundary it commits. Every one is
# a member of the closed onboarding vocabulary, so it projects onto an API
# response without translation. ``PAUSE_REASON_CODE`` is the operator's cause and
# stays the DEFAULT of :meth:`OnboardingRunControlService.request_pause`; a
# non-operator caller of that one path names its own cause instead.
PAUSE_REASON_CODE: Final[OnboardingReasonCode] = "run_paused_by_operator"
CANCEL_REASON_CODE: Final[OnboardingReasonCode] = "operator_cancelled"
# Re-entry after the one mid-flight prompt that exists says the CAPTCHA was
# resolved; re-entry after an operator pause is a fresh attempt at the step the
# run stopped in, and ``step_retried`` is the code the closed list carries for
# that. Neither invents a code, which is what keeps the vocabulary closed.
CAPTCHA_RESUME_REASON_CODE: Final[OnboardingReasonCode] = "captcha_resolved"
PAUSE_RESUME_REASON_CODE: Final[OnboardingReasonCode] = "step_retried"

# The phase a pause commits into. ``captcha_paused`` is the *other* waiting phase
# and is never reached by an operator pause: it is committed by the loop when a
# page shows a challenge (task 18.1), and the two must stay distinguishable
# because only one of them means "a human asked for this".
PAUSED_PHASE: Final[OnboardingPhase] = "paused"
CANCELLED_PHASE: Final[OnboardingPhase] = "cancelled"

# Dispositions under which a reserved submission is still in flight, so a pause
# has to settle it before the run stops (Requirement 14.3). ``skip`` is a
# completed effect and ``pause_outcome_unknown`` is already reconciled to a
# disposition that authorizes nothing, so neither needs settling again — which is
# also what makes the settlement idempotent across a repeated pause request.
IN_FLIGHT_DISPOSITIONS: Final[frozenset[EffectDisposition]] = frozenset({"execute", "reconcile"})

# Audit event types this surface writes. An event type the API's static
# ``_EVENT_SUMMARIES`` allow-list does not carry degrades to the generic
# run-updated summary rather than leaking a payload — the timeline projection's
# default is closed. The two continuation events are allow-listed, because a
# continuation the operator cannot read in the timeline is the whole of the
# reliability evidence Requirement 10.2 asks for.
PAUSE_REQUESTED_EVENT: Final = "onboarding_pause_requested"
PAUSED_EVENT: Final = "onboarding_paused"
RESUMED_EVENT: Final = "onboarding_resumed"
# The continuation of a CAPTCHA pause has its own event type: the timeline says
# "the challenge is cleared", not "the run was resumed", and the allow-list
# already carried this exception summary from the sibling spec with no writer.
# Selected beside :data:`CAPTCHA_RESUME_REASON_CODE`, by the same waiting phase,
# so the event type and the reason code can never disagree.
CAPTCHA_RESOLVED_EVENT: Final = "onboarding_captcha_resolved"
CANCELLED_EVENT: Final = "onboarding_cancelled"
EFFECT_SETTLED_EVENT: Final = "onboarding_effect_settled"

# The events that open or close an outstanding pause request. Read in commit
# order, the last of them answers "is a pause outstanding right now?", so the
# answer is a durable fact a restarted worker can still read. Both continuation
# events close a request, because which one a resume writes is a legibility
# choice about the waiting phase and must not change whether the run stops again.
_PAUSE_LIFECYCLE_EVENTS: Final[frozenset[str]] = frozenset(
    {PAUSE_REQUESTED_EVENT, RESUMED_EVENT, CAPTCHA_RESOLVED_EVENT, CANCELLED_EVENT}
)


@dataclass(frozen=True, slots=True)
class EffectSettlement:
    """How one already-reserved submission was settled before the run stopped.

    ``disposition`` is the standing answer the ledger now records for the key:
    ``skip`` when a read-only probe observed the outcome and the effect was
    completed, ``pause_outcome_unknown`` when it stayed ambiguous. Nothing here
    carries provider material — an operation key and a receipt identifier only.
    """

    operation_key: str
    effect: OnboardingEffect
    disposition: EffectDisposition
    reason_code: OnboardingReasonCode


@dataclass(frozen=True, slots=True)
class PauseOutcome:
    """What a pause request did, and the boundary at which it takes effect.

    ``pausing_after_phase`` is the phase the run stops *after* (Requirement 14.2):
    the phase it was in when the request arrived. ``committed`` is ``False`` for a
    replayed request and for a phase whose boundary into ``paused`` the phase
    table refuses, and in both cases nothing was written.
    """

    run_id: str
    accepted: bool
    pausing_after_phase: OnboardingPhase
    reason_code: OnboardingReasonCode
    committed: bool
    # Pause deliberately never releases the session (Requirement 14.2). The field
    # exists so a caller reads the guarantee off the response instead of assuming
    # it, and it is always False.
    browser_session_released: bool = False
    settlements: tuple[EffectSettlement, ...] = ()


@dataclass(frozen=True, slots=True)
class ResumeOutcome:
    """The phase a paused run re-enters, named from the committed boundary.

    ``phase_at_pause`` is the ``from_phase`` of the boundary that parked the run,
    so it survives a worker restart. ``resumed_phase`` is what was actually
    committed, and is ``None`` when nothing was.
    """

    run_id: str
    accepted: bool
    phase_at_pause: OnboardingPhase | None
    resumed_phase: OnboardingPhase | None
    reason_code: OnboardingReasonCode
    committed: bool


@dataclass(frozen=True, slots=True)
class CancelOutcome:
    """The result of a cancellation, which is durable before the caller sees it."""

    run_id: str
    accepted: bool
    phase: OnboardingPhase
    reason_code: OnboardingReasonCode
    committed: bool
    browser_session_released: bool


class OnboardingEffectLedger(Protocol):
    """The reservation reads and settlements the pause path needs.

    ``complete_effect_reservation`` and ``mark_effect_reservation_outcome_unknown``
    match :class:`ops.onboarding.driver.SQLitePhaseHistoryStore` verb for verb, so
    that store already satisfies two thirds of this port. ``reservations`` is the
    one addition: settling a run's outstanding submissions needs them enumerated
    by run rather than looked up by key, and no reader does that yet.
    """

    def reservations(self, *, run_id: str) -> tuple[EffectReservationRecord, ...]:
        """Every standing reservation for the run, in reservation order."""

    def complete_effect_reservation(
        self, *, run_id: str, operation_key: str, receipt: Mapping[str, str]
    ) -> EffectReservationRecord:
        """Record that the reserved effect happened, with its non-secret receipt."""

    def mark_effect_reservation_outcome_unknown(
        self, *, run_id: str, operation_key: str
    ) -> EffectReservationRecord:
        """Mark a reserved effect whose reconciliation stayed ambiguous."""


class EffectOutcomeProbe(Protocol):
    """A read-only look at the provider, used to settle one reservation.

    Read-only is the whole contract: this is called while a pause is outstanding,
    so a probe that submitted anything would be the duplicate submission the
    effect ledger exists to prevent. ``None`` means "could not tell", which the
    caller turns into ``outcome_unknown`` rather than into a retry.
    """

    def observed_receipt(
        self, *, run_id: str, reservation: EffectReservationRecord
    ) -> Mapping[str, str] | None:
        """The non-secret receipt of an observed effect, or ``None`` if unknown."""


class BrowserSessionRelease(Protocol):
    """How a cancellation hands the run's browser session back.

    A port rather than a direct call into the run service, so the control surface
    stays testable without a browser and the release stays synchronous — the
    session must be gone before the API answers (Requirement 14.5).
    """

    def __call__(self, *, run_id: str, reason: str) -> bool:
        """Release the run's bound session. ``True`` when one was released."""


class OnboardingRunControlService:
    """Pause, Resume, and Cancel for a run driven by the onboarding phase machine.

    Every control is one durable step: settle what the ledger has outstanding,
    commit one boundary, project the coarse status, and write the audit row. None
    of them drives a provider, and none of them touches a vault reference — reset
    (task 20.2) is the control that clears state, and it preserves every
    reference even then.
    """

    def __init__(
        self,
        *,
        storage: OperationsStorage,
        phases: PhaseHistoryStore,
        effects: OnboardingEffectLedger,
        release_session: BrowserSessionRelease | None = None,
        probe: EffectOutcomeProbe | None = None,
    ) -> None:
        self._storage = storage
        self._phases = phases
        self._effects = effects
        self._release_session = release_session
        self._probe = probe

    # --- pause --------------------------------------------------------------

    def request_pause(
        self,
        run_id: str,
        *,
        reason: str | None = None,
        reason_code: OnboardingReasonCode = PAUSE_REASON_CODE,
    ) -> PauseOutcome:
        """Stop the run at the next boundary with no reserved effect in flight.

        PRE:  ``run_id`` names a run with at least one committed phase boundary.
        POST: Q1. every reservation that was in flight is settled — completed
                  against an observed outcome, or marked ``outcome_unknown``
                  (Requirement 14.3).
              Q2. the bound browser session is untouched (Requirement 14.2).
              Q3. the run's phase is ``paused`` when the phase table admits that
                  boundary, and unchanged otherwise; either way the outstanding
                  request is durable, so a worker still driving the run reads it
                  at its next boundary through :meth:`pause_requested`.
              Q4. ``pausing_after_phase`` names the phase the run stops after.
              Q5. the durable reason code, the audit row and the returned outcome
                  all carry ``reason_code`` — one cause, named once.

        ``reason`` is the operator's free-text note. It is deliberately *not*
        written anywhere: the durable record carries the closed reason code, and
        an operator-supplied string on an audit row is the one field that could
        carry anything at all.

        ``reason_code`` is an EXTENSION of this one pause path, not a second path.
        Everything a pause does — settling reservations, the outstanding request,
        the boundary, the projection, the audit rows — is unchanged and happens in
        this method only; the argument names the *cause*, which used to be
        hard-coded to the operator's. So the autonomous caller that must pause a
        run for ``session_unreattachable`` or ``session_lifetime_exceeded``
        (reliability R1.11, R2.5, R2.6) gets the same settlement guarantees rather
        than a parallel implementation that would have to re-derive them. The
        operator path passes nothing and is byte-for-byte what it was: the default
        is :data:`PAUSE_REASON_CODE`.
        """

        boundary = self._last_boundary(run_id)
        if boundary is None or boundary.to_phase in TERMINAL_PHASES:
            # Nothing to pause: the run has no committed phase, or it has already
            # stopped for good. Reported as a replay rather than an error, because
            # a duplicate operator click is not a failure.
            return PauseOutcome(
                run_id=run_id,
                accepted=False,
                pausing_after_phase=boundary.to_phase if boundary else PAUSED_PHASE,
                reason_code=PHASE_REPLAY_NOOP,
                committed=False,
            )

        phase = boundary.to_phase
        if phase == PAUSED_PHASE:
            # Already stopped. Reported as accepted with nothing committed rather
            # than as a second pause: the identity boundary would otherwise be
            # admitted by the phase table and write a redundant row.
            return PauseOutcome(
                run_id=run_id,
                accepted=True,
                pausing_after_phase=phase,
                reason_code=reason_code,
                committed=False,
            )

        settlements = self._settle_reserved_effects(run_id)
        # Recorded before the boundary is attempted, so a request whose boundary
        # the phase table refuses is still durable and still honored by the worker
        # that is driving the run.
        self._storage.append_audit_event(
            run_id=run_id,
            event_type=PAUSE_REQUESTED_EVENT,
            payload={
                "pausing_after_phase": phase,
                "reason_code": reason_code,
                "settled_effects": len(settlements),
                "external_actions": False,
            },
        )
        committed = False
        if is_legal_phase_transition(phase, PAUSED_PHASE):
            committed = self._commit(
                run_id=run_id,
                boundary=boundary,
                to_phase=PAUSED_PHASE,
                reason_code=reason_code,
                # A second pause of the same phase after a resume is a genuinely
                # new boundary, so it must not collide with the first one; a
                # repeated request for the *same* pause must. Counting the
                # committed pauses gives both.
                attempt=boundary.attempt + self._pause_count(run_id),
                event_type=PAUSED_EVENT,
            )
        LOGGER.info(
            "onboarding run %s pausing after phase %s (%d effect(s) settled)",
            run_id,
            phase,
            len(settlements),
        )
        return PauseOutcome(
            run_id=run_id,
            accepted=True,
            pausing_after_phase=phase,
            reason_code=reason_code,
            committed=committed,
            settlements=settlements,
        )

    def pause_requested(self, run_id: str) -> bool:
        """Whether an operator pause is outstanding for the run.

        The seam a driver consults at its next boundary. Derived from the durable
        audit trail — the last pause-lifecycle event wins — so it answers the same
        way for a worker that has just restarted as for the one that recorded it.
        """

        outstanding = False
        for event in self._storage.list_audit_events(run_id):
            event_type = str(event.get("event_type") or "")
            if event_type in _PAUSE_LIFECYCLE_EVENTS:
                outstanding = event_type == PAUSE_REQUESTED_EVENT
        return outstanding

    # --- resume -------------------------------------------------------------

    def resume_from_pause(self, run_id: str) -> ResumeOutcome:
        """Re-enter the phase recorded at pause (Requirement 14.4).

        PRE:  the run's current phase is a waiting phase.
        POST: Q1. the outcome names the phase at pause, read from the ``from_phase``
                  of the boundary that parked the run.
              Q2. that phase is committed as the run's current phase when the phase
                  table admits the re-entry, and nothing is written otherwise.
              Q3. the outstanding pause request is closed, so a driver claiming the
                  run next drives it rather than stopping again.
              Q4. the committed boundary is recorded under the audit event type the
                  waiting phase names — ``onboarding_captcha_resolved`` out of
                  ``captcha_paused``, ``onboarding_resumed`` out of any other
                  waiting phase — both of which the API's static summary allow-list
                  carries, so a continuation reads as itself in the timeline rather
                  than as a generic run update (Requirements 1.13, 10.2).

        The refused case is real and worth naming: the phase table declares
        ``paused -> {research, cancelled}``, so a run parked by an operator pause
        cannot be re-entered into, say, ``developer_app``. Such a run leaves
        ``paused`` through reset or cancel. ``captcha_paused`` fans back out to
        every phase a challenge can interrupt, which is the re-entry this method
        performs in practice.
        """

        boundary = self._last_boundary(run_id)
        if boundary is None or boundary.to_phase not in WAITING_PHASES:
            return ResumeOutcome(
                run_id=run_id,
                accepted=False,
                phase_at_pause=None,
                resumed_phase=None,
                reason_code=PHASE_REPLAY_NOOP,
                committed=False,
            )

        waiting_phase = boundary.to_phase
        phase_at_pause = self._phase_at_pause(run_id)
        # One reading of the waiting phase decides both what the boundary says and
        # what the timeline shows, so the audit event type is selected here beside
        # the reason code rather than fixed at the commit call.
        resuming_from_captcha = waiting_phase == "captcha_paused"
        reason_code = (
            CAPTCHA_RESUME_REASON_CODE if resuming_from_captcha else PAUSE_RESUME_REASON_CODE
        )
        event_type = CAPTCHA_RESOLVED_EVENT if resuming_from_captcha else RESUMED_EVENT
        if phase_at_pause is None or not is_legal_phase_transition(waiting_phase, phase_at_pause):
            LOGGER.info(
                "onboarding run %s cannot re-enter %s from %s",
                run_id,
                phase_at_pause,
                waiting_phase,
            )
            return ResumeOutcome(
                run_id=run_id,
                accepted=False,
                phase_at_pause=phase_at_pause,
                resumed_phase=None,
                reason_code=PHASE_REPLAY_NOOP,
                committed=False,
            )

        committed = self._commit(
            run_id=run_id,
            boundary=boundary,
            to_phase=phase_at_pause,
            reason_code=reason_code,
            # A resume is a fresh attempt at the phase it re-enters, so the
            # attempt advances and a second pause/resume cycle cannot replay onto
            # this boundary.
            attempt=boundary.attempt + 1,
            event_type=event_type,
        )
        return ResumeOutcome(
            run_id=run_id,
            accepted=True,
            phase_at_pause=phase_at_pause,
            resumed_phase=phase_at_pause if committed else None,
            reason_code=reason_code,
            committed=committed,
        )

    # --- cancel -------------------------------------------------------------

    def cancel_run(self, run_id: str) -> CancelOutcome:
        """Release the session, persist, and commit ``cancelled`` before returning.

        PRE:  ``run_id`` names a run with at least one committed phase boundary.
        POST: Q1. the bound browser session is released (Requirement 14.5).
              Q2. phase ``cancelled`` is durably committed before this returns, so
                  the API cannot answer a cancellation that is not yet a fact
                  (Requirement 14.6).
              Q3. a run whose current phase the table gives no ``cancelled`` edge
                  is left entirely alone — no session released, no status written.
                  Fail-closed here matters more than convenience: a half-cancelled
                  run holding a released session would look resumable and not be.
        """

        boundary = self._last_boundary(run_id)
        if boundary is None or boundary.to_phase in TERMINAL_PHASES:
            return CancelOutcome(
                run_id=run_id,
                accepted=False,
                phase=boundary.to_phase if boundary else CANCELLED_PHASE,
                reason_code=PHASE_REPLAY_NOOP,
                committed=False,
                browser_session_released=False,
            )
        if not is_legal_phase_transition(boundary.to_phase, CANCELLED_PHASE):
            return CancelOutcome(
                run_id=run_id,
                accepted=False,
                phase=boundary.to_phase,
                reason_code=PHASE_REPLAY_NOOP,
                committed=False,
                browser_session_released=False,
            )

        released = False
        if self._release_session is not None:
            released = bool(
                self._release_session(run_id=run_id, reason=f"cancel_{CANCEL_REASON_CODE}")
            )
        committed = self._commit(
            run_id=run_id,
            boundary=boundary,
            to_phase=CANCELLED_PHASE,
            reason_code=CANCEL_REASON_CODE,
            attempt=boundary.attempt,
            event_type=CANCELLED_EVENT,
            browser_session_released=released,
        )
        LOGGER.info("onboarding run %s cancelled (session released: %s)", run_id, released)
        return CancelOutcome(
            run_id=run_id,
            accepted=True,
            phase=CANCELLED_PHASE if committed else boundary.to_phase,
            reason_code=CANCEL_REASON_CODE,
            committed=committed,
            browser_session_released=released,
        )

    # --- internals ----------------------------------------------------------

    def _last_boundary(self, run_id: str) -> PhaseTransition | None:
        """The run's most recent committed boundary, or ``None`` before the first."""

        history = self._phases.history(run_id=run_id)
        return history[-1] if history else None

    def _pause_count(self, run_id: str) -> int:
        """How many operator pauses the run has already committed."""

        return sum(
            1
            for boundary in self._phases.history(run_id=run_id)
            if boundary.to_phase == PAUSED_PHASE
        )

    def _phase_at_pause(self, run_id: str) -> OnboardingPhase | None:
        """The phase the run was in when it parked, from the durable boundary.

        The source of the *last* boundary into a waiting phase is the answer. A
        source that is not itself resumable is rejected rather than re-entered:
        those phases name transient computations, and standing in one is what
        Requirement 12.13 exists to prevent.
        """

        for boundary in reversed(self._phases.history(run_id=run_id)):
            if boundary.to_phase not in WAITING_PHASES:
                continue
            source = boundary.from_phase
            if source is None or source not in RESUMABLE_PHASES:
                return None
            return source
        return None

    def _settle_reserved_effects(self, run_id: str) -> tuple[EffectSettlement, ...]:
        """Complete or reconcile every in-flight reservation (Requirement 14.3).

        A probe that observes the outcome completes the reservation with its
        non-secret receipt. Anything else — no probe wired, or a probe that cannot
        tell — marks the key ``outcome_unknown``, which is a settlement precisely
        because it authorizes nothing: no later arrival can turn it back into a
        submission.
        """

        settlements: list[EffectSettlement] = []
        for reservation in self._effects.reservations(run_id=run_id):
            if reservation.disposition not in IN_FLIGHT_DISPOSITIONS:
                continue
            receipt = (
                None
                if self._probe is None
                else self._probe.observed_receipt(run_id=run_id, reservation=reservation)
            )
            if receipt:
                record = self._effects.complete_effect_reservation(
                    run_id=run_id,
                    operation_key=reservation.operation_key,
                    receipt=dict(receipt),
                )
            else:
                record = self._effects.mark_effect_reservation_outcome_unknown(
                    run_id=run_id, operation_key=reservation.operation_key
                )
            settlement = EffectSettlement(
                operation_key=record.operation_key,
                effect=record.effect,
                disposition=record.disposition,
                reason_code=record.reason_code,
            )
            settlements.append(settlement)
            self._storage.append_audit_event(
                run_id=run_id,
                event_type=EFFECT_SETTLED_EVENT,
                payload={
                    "effect": settlement.effect,
                    "disposition": settlement.disposition,
                    "reason_code": settlement.reason_code,
                    "external_actions": True,
                },
            )
        return tuple(settlements)

    def _commit(
        self,
        *,
        run_id: str,
        boundary: PhaseTransition,
        to_phase: OnboardingPhase,
        reason_code: OnboardingReasonCode,
        attempt: int,
        event_type: str,
        browser_session_released: bool = False,
    ) -> bool:
        """Commit one control boundary and project it onto the run row.

        The phase is committed first: it is the fact the next worker resumes from,
        and the coarse status is a projection of it. A replayed boundary returns
        ``False`` and leaves the run row untouched, so a duplicate operator click
        cannot bump a revision or write a second audit row.
        """

        committed = self._phases.commit_phase(
            run_id=run_id,
            from_phase=boundary.to_phase,
            to_phase=to_phase,
            reason_code=reason_code,
            profile_digest=boundary.profile_digest,
            attempt=attempt,
            correlation_id=phase_correlation_id(run_id=run_id, phase=to_phase, attempt=attempt),
        )
        if not committed:
            LOGGER.info("onboarding run %s %s was a %s", run_id, to_phase, PHASE_REPLAY_NOOP)
            return False
        self._project(
            run_id=run_id,
            phase=to_phase,
            reason_code=reason_code,
            event_type=event_type,
            browser_session_released=browser_session_released,
        )
        return True

    def _project(
        self,
        *,
        run_id: str,
        phase: OnboardingPhase,
        reason_code: OnboardingReasonCode,
        event_type: str,
        browser_session_released: bool,
    ) -> None:
        """Write the coarse status the committed phase projects onto, plus the row.

        The status is derived through :func:`project_status`, never chosen here, so
        the console and the phase machine cannot disagree. A status edge the run
        status table refuses leaves the status alone and still records the phase:
        the phase is the authority, and refusing the whole projection would hide a
        committed boundary from the operator.
        """

        with self._storage.unit_of_work() as transaction:
            record = transaction.get_run(run_id)
            if record is None:  # pragma: no cover - the boundary proved it exists
                raise KeyError("run was not found")
            revision = int(record.get("state_revision", 0) or 0) + 1
            changes: dict[str, object] = {
                "phase": phase,
                "reason_code": reason_code,
                "state_revision": revision,
                "last_projected_revision": revision,
            }
            previous = cast(RunStatus, record["status"])
            target = project_status(phase)
            if previous != target:
                try:
                    validate_status_transition(previous, target, "onboarding_control")
                except IllegalStatusTransition:
                    LOGGER.info(
                        "onboarding run %s kept status %s while committing phase %s",
                        run_id,
                        previous,
                        phase,
                    )
                else:
                    changes["status"] = target
            transaction.update_run(run_id, **changes)
            transaction.append_audit_event(
                run_id=run_id,
                event_type=event_type,
                payload={
                    "onboarding_phase": phase,
                    "reason_code": reason_code,
                    "status": changes.get("status", previous),
                    "browser_session_released": browser_session_released,
                    "external_actions": browser_session_released,
                },
            )


__all__ = [
    "CANCELLED_EVENT",
    "CANCELLED_PHASE",
    "CANCEL_REASON_CODE",
    "CAPTCHA_RESOLVED_EVENT",
    "CAPTCHA_RESUME_REASON_CODE",
    "EFFECT_SETTLED_EVENT",
    "IN_FLIGHT_DISPOSITIONS",
    "PAUSED_EVENT",
    "PAUSED_PHASE",
    "PAUSE_REASON_CODE",
    "PAUSE_REQUESTED_EVENT",
    "PAUSE_RESUME_REASON_CODE",
    "RESUMED_EVENT",
    "BrowserSessionRelease",
    "CancelOutcome",
    "EffectOutcomeProbe",
    "EffectSettlement",
    "OnboardingEffectLedger",
    "OnboardingRunControlService",
    "PauseOutcome",
    "ResumeOutcome",
    "RunResumeContext",
    "RunResumeService",
]
