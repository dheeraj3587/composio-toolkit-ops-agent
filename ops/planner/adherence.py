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
    """What the divergence authorizes: nothing, one re-plan, or an escalation.

    ``evidence`` is the sanitized prose the re-plan is worth spending on: what the
    superseded plan ordered and where the browser actually landed. It is empty for
    every action but ``replan``, and it is model input, so it is built by
    :func:`replan_evidence` under the same DLP rules the action loop obeys.
    """

    action: AdherenceAction
    reason_code: OnboardingReasonCode | None
    divergence: Divergence | None
    evidence: str = ""


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


def _model_safe_url(host: str, path: str) -> str | None:
    """``https://host/path`` when it survives :func:`sanitize_url` unchanged, else ``None``.

    Everything this module hands the planner becomes model input, so a surface is
    quoted only if the sanitizer agrees it is already inert. A path the sanitizer
    rewrites is one it judged token-shaped, and a rewritten surface is not something
    the model could act on anyway: dropping the fact makes the evidence thinner,
    never a channel. The elision sentinel is dropped for the same reason -- it names
    nothing the planner can choose between.
    """

    if not host or not path or ELIDED in (host, path):
        return None
    rebuilt = f"https://{host}{path}"
    return rebuilt if sanitize_url(rebuilt) == rebuilt else None


def replan_evidence(*, divergence: Divergence, plan: RunPlan | None = None) -> str:
    """The divergence, and the superseded route, as sanitized prose for the planner.

    This is the whole reason the one authorized re-plan is worth spending.
    ``plan_prompt`` varies only on its ``evidence`` argument, so while nothing was
    passed, revision 2's prompt was byte-identical to revision 1's: the model
    re-derived the same route, the run diverged at the same step, and the second
    pass fell through to ``pause`` and a permanent ``blocked``. The re-plan was
    spent proving the plan was reproducible.

    Only facts go in -- where the run was expected, where it landed, and what the
    superseded revision ordered, which is the closest thing this run keeps to a
    record of what has been tried. No instruction and no candidate host: the
    planner still chooses out of the recipe's reviewed enums, and
    ``ops.planner.validator`` still refuses anything else.

    A surface that cannot be quoted safely is described rather than dropped: "a
    different host that cannot be shown" is still a fact the planner can act on, and
    losing it would silently restore the byte-identical prompt this exists to
    prevent. Only when neither side can be named at all is the result empty, and the
    caller then re-plans without evidence exactly as before.
    """

    expected = _model_safe_url(divergence.expected_host, divergence.expected_path)
    observed = _model_safe_url(divergence.observed_host, divergence.observed_path)
    if expected is None and observed is None:
        return ""
    where = expected if expected is not None else "the surface it named"
    landed = (
        f"landed on {observed}"
        if observed is not None
        else "landed somewhere that cannot be shown here"
    )
    lines = [
        "The previous plan for this run did not hold. At surface"
        f" {divergence.step_index + 1} it expected {where}, but the browser"
        f" {landed} -- a different host, so the run cannot simply continue where"
        " it is.",
        "Re-planning the same route would land in the same place.",
    ]
    if plan is not None:
        ordered = [
            f"{index + 1}. {url}"
            for index, surface in enumerate(plan.surfaces)
            if (url := _model_safe_url(surface.host, surface.path)) is not None
        ]
        if ordered:
            lines.append(
                f"The superseded revision {plan.revision} ordered: " + "; ".join(ordered) + "."
            )
        credential = plan.credential_surface
        if credential is not None:
            url = _model_safe_url(credential.host, credential.path)
            if url is not None:
                lines.append(f"It named {url} as the credential surface.")
    return " ".join(lines)


def decide_adherence(
    *, divergence: Divergence | None, plans_recorded: int, plan: RunPlan | None = None
) -> AdherenceOutcome:
    """Proceed on the same host, one re-plan off it, then escalation.

    The re-plan is committed as a boundary into the phase the run already stands
    in, carrying ``route_replanned`` at the incremented attempt, so it consumes one
    attempt rather than opening a second budget.

    A path-only divergence under the host the plan already named is normal site
    behaviour, not a route the run lost: vendors redirect ``/`` to ``/k/``, append
    a locale segment, or land a signed-in visitor on a dashboard path. Escalating
    those was terminal, and re-planning them was no better: the one authorized
    re-plan used to be byte-identical to the plan it replaced, because
    ``plan_prompt`` varies only on evidence and no evidence was ever passed. It
    re-derived the same path, diverged again, and the second pass fell through to
    ``pause`` and a permanent ``blocked``. Every ``entry_only`` recipe whose landing
    path is not literally the planned one died this way, on success.

    ``plan`` is the plan the divergence was measured against, and it is threaded
    here only to build that missing evidence: on a cross-host divergence the outcome
    now carries :func:`replan_evidence`, so revision 2 is planned against where the
    run actually landed. ``None`` -- a caller that has no plan row to hand -- is the
    old evidence-free re-plan, not an error.

    Proceeding here widens nothing: ``expected_host`` is read off the plan, which
    ``ops.planner.validator`` already checked against the recipe's allowed hosts,
    so an equal ``observed_host`` is allow-listed by construction, and navigation
    is fenced independently at the browser policy regardless of what this returns.
    The divergence is still recorded -- the reason code is non-``None`` precisely
    so ``RouteAdherenceMonitor.observe`` writes the audit event -- so a site that
    quietly moved its route is visible without failing the run.

    ``unresolved`` is checked first and on its own. It means the observation could
    not be recorded verbatim, which elides ``observed_path`` and sometimes the host
    as well; a host that compares equal because both sides are the redaction
    sentinel is not evidence of anything, and must not proceed.
    """

    if divergence is None:
        return AdherenceOutcome(action="proceed", reason_code=None, divergence=None)
    if divergence.unresolved:
        return AdherenceOutcome(
            action="pause",
            reason_code="route_divergence_unresolved",
            divergence=divergence,
        )
    if divergence.observed_host == divergence.expected_host:
        return AdherenceOutcome(
            action="proceed",
            reason_code="route_divergence_same_host",
            divergence=divergence,
        )
    if plans_recorded > 1:
        return AdherenceOutcome(
            action="pause",
            reason_code="route_divergence_unresolved",
            divergence=divergence,
        )
    return AdherenceOutcome(
        action="replan",
        reason_code="route_replanned",
        divergence=divergence,
        evidence=replan_evidence(divergence=divergence, plan=plan),
    )


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
            divergence=divergence,
            plans_recorded=self._plans.count_plans(run_id=run_id),
            plan=plan,
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
    "replan_evidence",
]
