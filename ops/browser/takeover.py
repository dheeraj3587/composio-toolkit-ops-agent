"""The takeover decision: one observation in, one action out, nothing else.

An onboarding run parked at ``captcha_paused`` is waiting on a person. When that
person solves the challenge in the live view, something has to notice and let the
run continue on its own — the reported bug is that nothing did, and the run sat
there until an operator clicked resume. Noticing is split across two containers
by necessity: the page is in the browser worker, and the phase store and the run
capability key are in the API. This module is the seam between them, and it is
deliberately the *only* part of the takeover that has no side of its own.

What lives here is the rule, as a pure function of one observation:

* No I/O. No clock, no database, no HTTP, no settings, no logging. Everything the
  decision needs arrives in :class:`ClearanceObservation`, which is why the rule
  is exhaustively testable from a table of values.
* No import from ``ops.runs`` — asserted here as a rule, not an accident. The
  sweep in ``ops/runs/takeover.py`` imports *this*; if the arrow ever pointed the
  other way, the decision would be able to reach a phase store, a queue and an
  audit log, and "the watcher decided" and "the watcher wrote" would stop being
  separable. The import direction is the guarantee.

The decision is TOTAL: every combination of observation fields yields exactly one
:class:`TakeoverDecision`, and every non-continuing outcome names a member of the
closed ``OnboardingReasonCode`` vocabulary, so what the watcher decided projects
onto an API response and a durable row without translation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ops.browser.worker import HumanActionType
from ops.onboarding.phase import OnboardingReasonCode

# Why the API side names five causes where the service names four. This is the
# API-side set and it is a strict SUPERSET of
# ``browser_service/models.py::ClearanceProbeReason``: it adds
# ``session_not_found``, because a 404 never produces a report at all, so the
# service can never name it — the service can only describe a session it still
# has. Every other member is shared, spelled identically, and the two must stay
# in step: adding a member to one and not the other is a contract break, not a
# widening.
ClearanceProbeReason = Literal[
    "observed",  # the page was read
    "operation_in_flight",  # the operation lock was held; nothing was read
    "probe_failed",  # the read raised, timed out, or the route is absent
    "session_max_age_exceeded",  # the session was closed by the absolute bound
    "session_not_found",  # API-side only: a 404 carries no report to name it
]

# What the watcher may do about a run, and nothing more. There is no "resume"
# member on purpose: the only thing that resumes a run is the existing
# ``OnboardingRunControlService.resume_from_pause``, and ``continue`` is a
# request to call it, not a second way of doing it.
TakeoverAction = Literal["continue", "keep_waiting", "pause", "stop_polling"]

# The three lifecycle values the service reports, plus the empty string a client
# uses when it never got a report. Kept as a plain ``str`` on the observation:
# this module compares it to ``"ACTIVE"`` and treats everything else — including
# a value from a newer service it has never heard of — as not active, which is
# the fail-closed direction.
_ACTIVE_LIFECYCLE = "ACTIVE"


@dataclass(frozen=True, slots=True)
class ClearanceObservation:
    """One read of a paused run's session, as reported across the boundary.

    Frozen because a decision must be a function of the facts as observed: a
    caller that could mutate an observation between rules could make two rules
    disagree, and the ordering guarantee below would mean nothing.

    ``session_present`` is its own field rather than something inferred from
    ``lifecycle``. The client sets it ``False`` only for a 404 whose detail is
    exactly ``session_not_found`` — an id this service has no session for. Any
    *other* 404 (an older worker that does not serve the clearance route at all)
    is a read that could not happen, so it arrives as a present session with
    ``probe_reason_code="probe_failed"`` and keeps the run waiting instead of
    pausing it for a cause that was never observed.

    ``gate`` is what the page shows NOW, which is not necessarily the gate that
    parked the run: a different typed gate is a new disposition for the
    re-entered phase to make, not this watcher's business.
    """

    session_present: bool
    lifecycle: str  # "ACTIVE" | "CLOSING" | "CLOSED" | "" (no report)
    hitl_pending: bool
    attached: bool
    final_probe_owed: bool
    gate: HumanActionType | None
    probe_reason_code: ClearanceProbeReason
    hitl_generation: int


@dataclass(frozen=True, slots=True)
class TakeoverDecision:
    """What to do about one paused run, and the closed code that says why.

    ``reason_code`` is always populated, including for the actions that write
    nothing: it is what the sweep logs and, for ``pause``, what it hands to
    ``request_pause`` as the durable cause. ``poll_again`` is the watcher's own
    bookkeeping — ``False`` means this run is finished with the watcher, either
    because it is continuing, because it is being paused for a cause a further
    read cannot change, or because nobody is attached and no final read is owed.
    """

    action: TakeoverAction
    reason_code: OnboardingReasonCode
    poll_again: bool


def decide_takeover(
    *, paused_gate: HumanActionType, observation: ClearanceObservation
) -> TakeoverDecision:
    """Decide what one clearance observation means for the run that produced it.

    PRE:  ``paused_gate`` is the gate type the run parked on, and ``observation``
          describes the session that run is bound to.
    POST: Q1. exactly one decision is returned for every possible observation —
              the function is total and raises nothing.
          Q2. ``reason_code`` is a member of ``OnboardingReasonCode``, so it
              projects onto a durable row and an API response untranslated.
          Q3. no state anywhere changes: this function reads its arguments and
              returns a value.

    The rules are checked in a FIXED order, and the order is the contract. Two
    facts that both apply — a closed session that also shows no gate, say — must
    always answer the same way, or the same clearance would continue a run on one
    interval and pause it on the next:

    1. ``session_max_age_exceeded``: the absolute lifetime bound closed the
       session under the human. That is not "the gate is gone", and it must not be
       read as clearance, so it is checked before anything about the page
       (reliability R2.5).
    2. ``not session_present``: no session for this id, and the closure ring did
       not name it, so the run cannot be continued where it left off (R2.6).
    3. ``lifecycle != "ACTIVE"``: closing or closed is equally unreattachable.
       Checked as "not active" rather than against a list of dead values, so a
       lifecycle value from a newer service fails closed.
    4. ``not hitl_pending``: something else already cleared this pause — the
       operator clicked resume, or an earlier interval continued the run. Stop
       polling and claim nothing; the resume path already recorded the boundary.
    5. ``operation_in_flight`` or ``probe_failed``: nothing was read. A watcher
       that continued a run on no evidence is the failure mode this whole feature
       exists to avoid, so an unread page keeps the run waiting.
    6. ``gate == paused_gate``: the challenge the run parked on is still there.
       Nothing is recorded and no operator prompt is counted (R1.8). A successful
       owed post-detach read ends polling immediately when it still sees the gate;
       otherwise this is the common waiting case while a human remains attached.
    7. otherwise the gate the run parked on is gone: ``continue`` only while a
       human is attached or this is the one owed post-detach probe (R1.3). A page
       observed without either authorization stops polling and cannot resume the
       run.

    Then one downgrade, applied last so it cannot reorder the rules above: a
    ``keep_waiting`` becomes ``stop_polling`` when ``not (attached or
    final_probe_owed)``. Nobody is in the session and no post-detach read is
    owed, so a further interval would read the same page forever (R1.2, R1.12).
    A failed owed probe remains retryable because it did not answer the final
    observation; a successful owed probe always returns ``poll_again=False``.
    A ``pause`` is never downgraded; ``continue`` has already passed the same
    attachment/final-probe authorization.
    """

    if observation.probe_reason_code == "session_max_age_exceeded":
        return TakeoverDecision(
            action="pause", reason_code="session_lifetime_exceeded", poll_again=False
        )
    if not observation.session_present:
        return TakeoverDecision(
            action="pause", reason_code="session_unreattachable", poll_again=False
        )
    if observation.lifecycle != _ACTIVE_LIFECYCLE:
        return TakeoverDecision(
            action="pause", reason_code="session_unreattachable", poll_again=False
        )
    if not observation.hitl_pending:
        return TakeoverDecision(
            action="stop_polling", reason_code="captcha_resolved", poll_again=False
        )
    if observation.probe_reason_code in {"operation_in_flight", "probe_failed"}:
        return _waiting(observation)
    if observation.gate == paused_gate:
        if not observation.attached and observation.final_probe_owed:
            # This successful read consumed the one observation owed after the
            # last detach. The gate is still present, so there is nothing to
            # continue and no second post-detach poll is authorized.
            return TakeoverDecision(
                action="stop_polling",
                reason_code="captcha_detected",
                poll_again=False,
            )
        return _waiting(observation)
    if not (observation.attached or observation.final_probe_owed):
        return TakeoverDecision(
            action="stop_polling",
            reason_code="captcha_detected",
            poll_again=False,
        )
    return TakeoverDecision(action="continue", reason_code="captcha_resolved", poll_again=False)


def _waiting(observation: ClearanceObservation) -> TakeoverDecision:
    """``keep_waiting``, downgraded to ``stop_polling`` when nobody is left.

    The downgrade lives in one place so the two rules that produce a wait — an
    unread page and a gate that is still up — can never disagree about when the
    watcher gives up on a run.
    """

    if observation.attached or observation.final_probe_owed:
        return TakeoverDecision(
            action="keep_waiting", reason_code="captcha_detected", poll_again=True
        )
    return TakeoverDecision(action="stop_polling", reason_code="captcha_detected", poll_again=False)


__all__ = [
    "ClearanceObservation",
    "ClearanceProbeReason",
    "TakeoverAction",
    "TakeoverDecision",
    "decide_takeover",
]
