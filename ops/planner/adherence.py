"""Route_Adherence_Monitor: host-and-path divergence, and the single re-plan.

The observed URL is canonicalized on arrival, so query, fragment and userinfo are
gone before anything is compared or recorded. The full URL is never stored.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal, Protocol

from ops.core.model_input_dlp import REDACTED, sanitize_url
from ops.onboarding.phase import OnboardingReasonCode
from ops.planner.plan import RunPlan, canonical_surface
from ops.planner.store import RunPlanStore

ROUTE_DIVERGENCE_EVENT: Final = "onboarding_route_divergence"
ELIDED: Final = REDACTED

AdherenceAction = Literal["proceed", "replan", "pause"]


@dataclass(frozen=True, slots=True)
class Divergence:
    """Where the run was expected and where it is, as host and path only.

    ``unresolved`` means the observation could not be recorded verbatim — it was
    unsanitizable or out of bounds — so the path is elided and the run escalates
    instead of re-planning against something unreadable.
    """

    expected_host: str
    expected_path: str
    observed_host: str
    observed_path: str
    step_index: int
    unresolved: bool = False


@dataclass(frozen=True, slots=True)
class AdherenceOutcome:
    """What the divergence authorizes: nothing, one re-plan, or an escalation."""

    action: AdherenceAction
    reason_code: OnboardingReasonCode | None
    divergence: Divergence | None


class AuditSink(Protocol):
    """The audit writer the divergence fact is recorded through."""

    def append_audit_event(
        self,
        *,
        run_id: str,
        event_type: str,
        payload: dict[str, object] | None = None,
    ) -> int: ...


def _observed(observed_url: str) -> tuple[str, str, bool]:
    """The canonical observed host and path, plus whether it had to be elided."""

    try:
        surface = canonical_surface(observed_url, purpose="entry")
    except ValueError:
        return ELIDED, ELIDED, True
    rebuilt = f"https://{surface.host}{surface.path}"
    if sanitize_url(rebuilt) != rebuilt:
        return surface.host, ELIDED, True
    return surface.host, surface.path, False


def observe_surface(*, plan: RunPlan, step_index: int, observed_url: str) -> Divergence | None:
    """``None`` when the observed host and path are the ones the plan expects.

    A step the plan names no surface for is inert rather than divergent: adherence
    never invents an expectation the plan did not record.
    """

    expected = plan.surface_for_step(step_index)
    if expected is None:
        return None
    host, path, unresolved = _observed(observed_url)
    if not unresolved and (host, path) == (expected.host, expected.path):
        return None
    return Divergence(
        expected_host=expected.host,
        expected_path=expected.path,
        observed_host=host,
        observed_path=path,
        step_index=step_index,
        unresolved=unresolved,
    )


def decide_adherence(*, divergence: Divergence | None, plans_recorded: int) -> AdherenceOutcome:
    """One re-plan while the run has recorded a single plan, then escalation.

    The re-plan is committed as a boundary into the phase the run already stands
    in, carrying ``route_replanned`` at the incremented attempt, so it consumes one
    attempt rather than opening a second budget.
    """

    if divergence is None:
        return AdherenceOutcome(action="proceed", reason_code=None, divergence=None)
    if divergence.unresolved or plans_recorded > 1:
        return AdherenceOutcome(
            action="pause",
            reason_code="route_divergence_unresolved",
            divergence=divergence,
        )
    return AdherenceOutcome(action="replan", reason_code="route_replanned", divergence=divergence)


def record_divergence(
    sink: AuditSink,
    *,
    run_id: str,
    divergence: Divergence,
    reason_code: OnboardingReasonCode,
) -> int:
    """Write the sanitized divergence fact; four bounded fields and a code."""

    return sink.append_audit_event(
        run_id=run_id,
        event_type=ROUTE_DIVERGENCE_EVENT,
        payload={
            "expected_host": divergence.expected_host,
            "expected_path": divergence.expected_path,
            "observed_host": divergence.observed_host,
            "observed_path": divergence.observed_path,
            "step_index": divergence.step_index,
            "reason_code": reason_code,
        },
    )


class RouteAdherenceMonitor:
    """Adherence over one run's recorded plan, through the store and the audit sink.

    A run with no plan row is inert: it proceeds, nothing is compared, and nothing
    is recorded. That is what a run admitted before planning existed — or one whose
    recipe declares no plannable route — looks like here.
    """

    def __init__(self, *, plans: RunPlanStore, audit: AuditSink) -> None:
        self._plans = plans
        self._audit = audit

    def observe(self, *, run_id: str, step_index: int, observed_url: str) -> AdherenceOutcome:
        """Decide what one observed surface authorizes, recording any divergence."""

        plan = self._plans.read_active_plan(run_id=run_id)
        if plan is None:
            return AdherenceOutcome(action="proceed", reason_code=None, divergence=None)
        divergence = observe_surface(plan=plan, step_index=step_index, observed_url=observed_url)
        outcome = decide_adherence(
            divergence=divergence, plans_recorded=self._plans.count_plans(run_id=run_id)
        )
        if outcome.divergence is not None and outcome.reason_code is not None:
            record_divergence(
                self._audit,
                run_id=run_id,
                divergence=outcome.divergence,
                reason_code=outcome.reason_code,
            )
        return outcome


__all__ = [
    "ELIDED",
    "ROUTE_DIVERGENCE_EVENT",
    "AdherenceAction",
    "AdherenceOutcome",
    "AuditSink",
    "Divergence",
    "RouteAdherenceMonitor",
    "decide_adherence",
    "observe_surface",
    "record_divergence",
]
