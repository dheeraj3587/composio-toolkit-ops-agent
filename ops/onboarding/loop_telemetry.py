"""The action loop's telemetry sink, with navigation denials made durable.

:class:`~ops.onboarding.action_loop.LoopTelemetry` is a port: the loop reports what
it denied, rejected, and refused without knowing where those reports land. This
module is the implementation the orchestrator binds, and it exists because one of
those reports is not a metric. Requirement 5.15 asks for each navigation denial to
be a **durable fact** carrying the run identifier, the phase, the profile digest,
and the denial reason code — so that a run paused with
`browser_host_not_in_app_policy` can be explained after the process that produced
it is gone.

Three decisions are worth stating.

A denial is a row; everything else is a counter.
    Denials go through :meth:`~ops.core.storage.OperationsStorage.record_navigation_denial`
    inside :meth:`DurableLoopTelemetry.denial`, one row per call and never
    deduplicated: a phase that reached its ten-denial bound must be visible as ten
    facts. Rejections, DLP refusals, executed actions, and model calls stay
    in-memory counts, because the loop already hands those back to the driver on
    :class:`~ops.onboarding.action_loop.LoopResult` and the driver writes them onto
    the phase boundary it commits.

The write is allowed to fail loudly.
    If the fact cannot be written, the exception propagates and the phase stops.
    Swallowing it would leave the containment event that mattered most — the loop
    trying to leave the allow-list — recorded nowhere, which is the one outcome
    Requirement 5.15 exists to prevent.

The run's identity is fixed at construction, not passed per call.
    ``run_id``, ``phase``, and ``profile_digest`` are constructor arguments, so the
    loop cannot influence which run or phase a denial is attributed to: the port it
    sees takes a closed reason code and nothing else.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from ops.onboarding.phase import (
    ONBOARDING_PHASES,
    ONBOARDING_REASON_CODES,
    OnboardingPhase,
    OnboardingReasonCode,
)
from ops.providers.profile import SOURCE_DIGEST_LENGTH

if TYPE_CHECKING:  # pragma: no cover - imported for typing only
    from ops.onboarding.action_loop import LoopStage, LoopTelemetry, StepDecision

LOGGER = logging.getLogger("composio_ops.onboarding_loop_telemetry")


class DenialFactStore(Protocol):
    """The three durable writes this telemetry performs.

    Narrower than :class:`~ops.core.storage.OperationsStorage` on purpose: these
    appends are the only capabilities this module needs, so nothing else in the run
    ledger is reachable from here.
    """

    def record_navigation_denial(
        self,
        *,
        run_id: str,
        phase: str,
        profile_digest: str,
        reason_code: str,
    ) -> int:
        """Append one denial fact and return its identifier."""
        ...

    def record_progress_event(
        self,
        *,
        run_id: str,
        phase: str,
        profile_digest: str,
        correlation_id: str,
        step_index: int,
        stage: str,
        elapsed_ms: int,
    ) -> int:
        """Append one loop-iteration fact and return its identifier."""
        ...

    def record_decision_attempt(
        self,
        *,
        run_id: str,
        phase: str,
        purpose: str,
        provider: str,
        outcome: str,
        latency_ms: int,
    ) -> int:
        """Append one inference-attempt fact and return its identifier."""
        ...

    def record_step_decision(
        self,
        *,
        run_id: str,
        phase: str,
        correlation_id: str,
        step_index: int,
        decision: str,
        reason_code: str | None = None,
        candidate_label: str | None = None,
        action: str | None = None,
        target_host: str | None = None,
        reason: str | None = None,
    ) -> int:
        """Append one decision fact and return its identifier.

        The implementation quarantines ``reason`` — the only untrusted argument —
        before it is stored; see
        :meth:`ops.core.storage.OperationsStorage.record_step_decision`.
        """
        ...


@dataclass(slots=True)
class DurableLoopTelemetry:
    """Loop telemetry that persists every navigation denial (Requirement 5.15).

    The counters are readable after the phase ends so a caller can cross-check
    them against the counters :class:`~ops.onboarding.action_loop.LoopResult`
    carries; they are not the durable record.
    """

    store: DenialFactStore
    run_id: str
    phase: OnboardingPhase
    profile_digest: str
    # Ties every progress row to the phase attempt it happened under, so a retried
    # phase reads as one thread.
    correlation_id: str
    denials: int = field(default=0, init=False)
    rejects: int = field(default=0, init=False)
    dlp_refusals: int = field(default=0, init=False)
    actions_executed: int = field(default=0, init=False)
    model_calls: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        if not self.run_id or not self.run_id.strip():
            raise ValueError("loop telemetry requires a run id")
        if self.phase not in ONBOARDING_PHASES:
            raise ValueError("loop telemetry requires an onboarding phase")
        # The digest identifies the profile whose allow-list did the denying, so a
        # fact recorded against an unrecognizable digest would not be explainable.
        if len(self.profile_digest) != SOURCE_DIGEST_LENGTH:
            raise ValueError("loop telemetry requires a sha256 profile digest")

    def denial(self, reason_code: OnboardingReasonCode) -> None:
        """Record one navigation denial durably, then count it.

        POST: one durable fact exists carrying this run, phase, profile digest, and
              reason code. The in-memory count is advanced only after the write
              succeeded, so the count never claims a fact the ledger does not hold.
        """

        if reason_code not in ONBOARDING_REASON_CODES:
            raise ValueError("navigation denial reason code is not an onboarding reason code")
        self.store.record_navigation_denial(
            run_id=self.run_id,
            phase=self.phase,
            profile_digest=self.profile_digest,
            reason_code=reason_code,
        )
        self.denials += 1
        LOGGER.warning(
            "navigation denied",
            extra={
                "run_id": self.run_id,
                "phase": self.phase,
                "reason_code": reason_code,
                "navigation_denials": self.denials,
            },
        )

    def reject(self, reason_code: OnboardingReasonCode) -> None:
        """Count one discarded model selection (Requirements 4.5, 4.7, 4.8)."""

        self.rejects += 1
        LOGGER.info(
            "model selection discarded",
            extra={"run_id": self.run_id, "phase": self.phase, "reason_code": reason_code},
        )

    def dlp_refusal(self) -> None:
        """Count one refused page projection (`dlp_prompt_refused`, 4.19)."""

        self.dlp_refusals += 1
        LOGGER.warning(
            "page projection refused",
            extra={
                "run_id": self.run_id,
                "phase": self.phase,
                "reason_code": "dlp_prompt_refused",
            },
        )

    def action(self, *, candidate_id: str, actions_executed: int) -> None:
        """Count one executed action and adopt the loop's running total."""

        self.actions_executed = actions_executed
        LOGGER.debug(
            "candidate executed",
            extra={
                "run_id": self.run_id,
                "phase": self.phase,
                "candidate_id": candidate_id,
                "actions_executed": actions_executed,
            },
        )

    def model_call(self, *, model_calls: int) -> None:
        """Adopt the loop's running model-call total."""

        self.model_calls = model_calls

    def progress(self, *, step_index: int, stage: LoopStage, elapsed_ms: int) -> None:
        """Record one completed loop iteration durably (Requirement 4.1)."""

        self.store.record_progress_event(
            run_id=self.run_id,
            phase=self.phase,
            profile_digest=self.profile_digest,
            correlation_id=self.correlation_id,
            step_index=step_index,
            stage=stage,
            elapsed_ms=elapsed_ms,
        )

    def decision(
        self,
        *,
        step_index: int,
        decision: StepDecision,
        reason_code: OnboardingReasonCode | None = None,
        candidate_label: str | None = None,
        action: str | None = None,
        target_host: str | None = None,
        reason: str | None = None,
    ) -> None:
        """Record what one iteration decided, durably, beside its progress row.

        Unlike :meth:`denial`, this write is *not* allowed to fail the phase. A
        denial is the containment event the ledger exists to preserve, so losing it
        must stop the run; a decision row is an explanation of a step that has
        already happened, and stopping a run because its narration could not be
        stored would trade a working onboarding for a nicer timeline. The failure is
        logged with the step it belonged to and the loop continues.

        ``reason`` is the model's own prose, read off a live third-party page. It is
        passed straight to the store, which caps, redacts, and screens it, and marks
        the row withheld rather than storing anything it will not vouch for.
        """

        try:
            self.store.record_step_decision(
                run_id=self.run_id,
                phase=self.phase,
                correlation_id=self.correlation_id,
                step_index=step_index,
                decision=decision,
                reason_code=reason_code,
                candidate_label=candidate_label,
                action=action,
                target_host=target_host,
                reason=reason,
            )
        except Exception:  # pragma: no cover - narration must not stop the run
            LOGGER.warning(
                "step decision not recorded",
                exc_info=True,
                extra={
                    "run_id": self.run_id,
                    "phase": self.phase,
                    "step_index": step_index,
                    "decision": decision,
                },
            )

    def record_attempt(self, *, provider: str, outcome: str, latency_ms: int) -> None:
        """Record one inference attempt of this phase's loop (Requirement 4.3)."""

        self.store.record_decision_attempt(
            run_id=self.run_id,
            phase=self.phase,
            purpose="action",
            provider=provider,
            outcome=outcome,
            latency_ms=latency_ms,
        )


def _port_conformance(telemetry: DurableLoopTelemetry) -> LoopTelemetry:
    """Typecheck-only proof that this implementation satisfies the loop's port.

    The composition root that binds the two lands later; without this, a renamed
    or re-signatured method here would go unnoticed until then.
    """

    return telemetry


__all__ = ["DenialFactStore", "DurableLoopTelemetry"]
