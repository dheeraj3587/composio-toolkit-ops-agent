"""The sweep that acts on a takeover decision: probe, commit, audit, enqueue.

The decision itself is :func:`ops.browser.takeover.decide_takeover`, and the commit
is the existing ``OnboardingRunControlService``. This module only polls the runs
standing at ``captcha_paused`` and applies what the decision says, which is why the
happy path issues no browser call beyond the worker's own ``/resume`` RPC.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Coroutine, Mapping
from typing import Any, Final, Protocol, cast, get_args

from ops.browser.link_log import log_event
from ops.browser.takeover import ClearanceObservation, decide_takeover
from ops.browser.worker import HumanActionType
from ops.core.config import Settings
from ops.core.storage import OperationsStorage
from ops.deploy.acceptance import wait_for_deployment_acceptance
from ops.onboarding.driver import PhaseHistoryStore
from ops.onboarding.lease import RunQueue
from ops.onboarding.phase import OnboardingPhase, OnboardingReasonCode
from ops.runs.resume import OnboardingRunControlService

CAPTCHA_PAUSED_PHASE: Final[OnboardingPhase] = "captcha_paused"
CANONICAL_CHALLENGE_PHASE: Final = "challenge_pending"
TAKEOVER_CONTINUED_EVENT: Final = "onboarding_takeover_continued"
# The gate a CAPTCHA pause parked on when the run row no longer names one.
DEFAULT_PAUSED_GATE: Final[HumanActionType] = "captcha"
_HUMAN_ACTION_TYPES: Final[frozenset[str]] = frozenset(get_args(HumanActionType))


class ClearanceProbe(Protocol):
    """The one browser read the sweep needs.

    Declared here rather than imported from the client so this module depends on the
    verb and not on the transport. The verb is a coroutine because the client is one;
    the sweep runs it to completion per run.
    """

    def probe_gate_clearance(
        self, session_id: str, *, capability_scope: str
    ) -> Coroutine[Any, Any, ClearanceObservation]: ...


class CanonicalTakeoverControl(Protocol):
    """The existing canonical continuation and terminal-pause authorities."""

    def resume_after_takeover(
        self,
        run_id: str,
        *,
        expected_state_revision: int,
        expected_session_id: str,
        expected_gate: HumanActionType,
        expected_hitl_generation: int,
    ) -> Mapping[str, object]: ...

    def pause_after_takeover(
        self,
        run_id: str,
        *,
        reason_code: OnboardingReasonCode,
        expected_state_revision: int,
        expected_session_id: str,
        expected_gate: HumanActionType,
        expected_hitl_generation: int,
    ) -> bool: ...


class RunTakeoverService:
    """Poll paused runs for clearance and continue the ones a human has cleared."""

    def __init__(
        self,
        *,
        storage: OperationsStorage,
        phases: PhaseHistoryStore,
        control: OnboardingRunControlService,
        clearance: ClearanceProbe,
        queue: RunQueue | None,
        settings: Settings,
        canonical: CanonicalTakeoverControl | None = None,
    ) -> None:
        self._storage = storage
        self._phases = phases
        self._control = control
        self._clearance = clearance
        self._queue = queue
        self._settings = settings
        self._canonical = canonical
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        # ``stop_polling`` applies to one exact durable pause observation. A
        # revision/session/gate change re-arms the run; an unchanged detached
        # pause is not reprobed forever after the final owed read is consumed.
        self._stopped_observations: dict[
            str,
            tuple[int, str, HumanActionType, int],
        ] = {}

    def start(self) -> None:
        """Start the polling thread unless it is switched off or already running."""

        if not self._settings.onboarding_takeover_enabled:
            return
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="onboarding-takeover",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop polling and wait through the bounded in-flight clearance read."""

        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            timeout = max(
                5.0,
                float(self._settings.onboarding_takeover_probe_timeout_seconds) + 1.0,
            )
            thread.join(timeout=timeout)

    def _loop(self) -> None:
        settings = self._settings
        if self._stop.wait(max(1.0, float(settings.ops_automation_start_delay_seconds))):
            return
        if not wait_for_deployment_acceptance(settings, self._stop):
            return
        interval = max(1, int(settings.onboarding_takeover_interval_seconds))
        while not self._stop.wait(interval):
            try:
                self.sweep()
            except Exception:  # pragma: no cover - the loop must never die
                pass

    def sweep(self, *, limit: int = 100) -> int:
        """Apply one takeover decision per paused run; return how many continued."""

        if not self._settings.onboarding_takeover_enabled or self._stop.is_set():
            return 0
        continued = 0
        offset = 0
        candidate_ids: set[str] = set()
        completed_scan = False
        while not self._stop.is_set():
            records = self._storage.list_runs(limit=limit, offset=offset)
            if not records:
                completed_scan = True
                break
            for record in records:
                if self._stop.is_set():
                    break
                run_id = str(record.get("run_id") or "")
                if not run_id:
                    continue
                canonical = _is_canonical_captcha_wait(record)
                if not canonical:
                    if record.get("phase") != CAPTCHA_PAUSED_PHASE:
                        continue
                    if not self._standing_at_captcha_pause(run_id):
                        continue
                candidate_ids.add(run_id)
                watch_key = _takeover_watch_key(record)
                if self._stopped_observations.get(run_id) == watch_key:
                    continue
                self._stopped_observations.pop(run_id, None)
                try:
                    if self._apply(run_id, record, canonical=canonical):
                        continued += 1
                except Exception:
                    # One unhappy run must not end the sweep for the others.
                    log_event("browser.takeover.error", level=40, run_id=run_id)
            offset += len(records)
            if len(records) < limit:
                completed_scan = True
                break
        if completed_scan and not self._stop.is_set():
            for run_id in set(self._stopped_observations).difference(candidate_ids):
                self._stopped_observations.pop(run_id, None)
        return continued

    def _standing_at_captcha_pause(self, run_id: str) -> bool:
        """Whether the committed boundary agrees with the projected phase."""

        history = self._phases.history(run_id=run_id)
        return bool(history) and history[-1].to_phase == CAPTCHA_PAUSED_PHASE

    def _pause(
        self,
        run_id: str,
        *,
        reason_code: OnboardingReasonCode,
        canonical: bool,
        expected_state_revision: int,
        expected_session_id: str,
        expected_gate: HumanActionType,
        expected_hitl_generation: int,
    ) -> None:
        if canonical:
            if self._canonical is not None:
                self._canonical.pause_after_takeover(
                    run_id,
                    reason_code=reason_code,
                    expected_state_revision=expected_state_revision,
                    expected_session_id=expected_session_id,
                    expected_gate=expected_gate,
                    expected_hitl_generation=expected_hitl_generation,
                )
            return
        self._control.request_pause(run_id, reason_code=reason_code)

    def _apply(
        self,
        run_id: str,
        record: Mapping[str, object],
        *,
        canonical: bool,
    ) -> bool:
        state_revision, session_id, gate, hitl_generation = _takeover_watch_key(record)
        if not session_id:
            self._pause(
                run_id,
                reason_code="session_unreattachable",
                canonical=canonical,
                expected_state_revision=state_revision,
                expected_session_id=session_id,
                expected_gate=gate,
                expected_hitl_generation=hitl_generation,
            )
            return False
        observation = self._probe(run_id, session_id)
        if observation is None:
            return False
        decision = decide_takeover(paused_gate=gate, observation=observation)
        if (
            canonical
            and observation.probe_reason_code == "observed"
            and observation.hitl_generation != hitl_generation
        ):
            # A page read from a different browser HITL generation cannot
            # authorize or terminalize this durable pause. Suppress only this
            # exact observation; a new projected generation re-arms polling.
            self._stopped_observations[run_id] = _takeover_watch_key(record)
            log_event("browser.takeover.generation_mismatch", run_id=run_id, gate=gate)
            return False
        if decision.action == "stop_polling" and not decision.poll_again:
            self._stopped_observations[run_id] = _takeover_watch_key(record)
            return False
        if decision.action == "pause":
            self._pause(
                run_id,
                reason_code=decision.reason_code,
                canonical=canonical,
                expected_state_revision=state_revision,
                expected_session_id=session_id,
                expected_gate=gate,
                expected_hitl_generation=hitl_generation,
            )
            return False
        if decision.action != "continue":
            return False
        return self._continue_run(
            run_id,
            gate,
            canonical=canonical,
            expected_state_revision=state_revision,
            expected_session_id=session_id,
            expected_hitl_generation=hitl_generation,
        )

    def _probe(self, run_id: str, session_id: str) -> ClearanceObservation | None:
        """Read the session once. An unread page yields ``None`` and no write."""

        try:
            return asyncio.run(
                self._clearance.probe_gate_clearance(session_id, capability_scope=run_id)
            )
        except Exception:
            log_event("browser.takeover.probe_failed", run_id=run_id)
            return None

    def _continue_run(
        self,
        run_id: str,
        gate: HumanActionType,
        *,
        canonical: bool,
        expected_state_revision: int,
        expected_session_id: str,
        expected_hitl_generation: int,
    ) -> bool:
        if canonical:
            if self._canonical is None:
                return False
            try:
                result = self._canonical.resume_after_takeover(
                    run_id,
                    expected_state_revision=expected_state_revision,
                    expected_session_id=expected_session_id,
                    expected_gate=gate,
                    expected_hitl_generation=expected_hitl_generation,
                )
            except Exception:
                # An owner resume or another sweep may have moved the revision
                # after clearance was observed. That is a replay/conflict, not
                # evidence that the newly authoritative state is unavailable.
                log_event("browser.takeover.replayed", run_id=run_id, gate=gate)
                return False
            self._storage.append_audit_event(
                run_id=run_id,
                event_type=TAKEOVER_CONTINUED_EVENT,
                payload={
                    "gate": gate,
                    "hitl_generation": expected_hitl_generation,
                    "onboarding_phase": str(result.get("phase") or "browser_running"),
                    "reason_code": "captcha_resolved",
                },
            )
            return True

        outcome = self._control.resume_from_pause(run_id)
        if not outcome.accepted:
            self._control.request_pause(run_id, reason_code="takeover_step_unavailable")
            return False
        if not outcome.committed:
            log_event("browser.takeover.replayed", run_id=run_id, gate=gate)
            return False
        self._storage.append_audit_event(
            run_id=run_id,
            event_type=TAKEOVER_CONTINUED_EVENT,
            payload={
                "gate": gate,
                "onboarding_phase": outcome.resumed_phase,
                "reason_code": outcome.reason_code,
            },
        )
        if self._queue is not None:
            self._queue.enqueue(run_id=run_id)
        return True


def _takeover_watch_key(
    record: Mapping[str, object],
) -> tuple[int, str, HumanActionType, int]:
    """Identity of one durable pause observation used by poll suppression."""

    raw_state_revision = record.get("state_revision", 0)
    state_revision = (
        raw_state_revision
        if isinstance(raw_state_revision, int) and not isinstance(raw_state_revision, bool)
        else 0
    )
    return (
        state_revision,
        str(record.get("browser_session_id") or ""),
        _paused_gate(record),
        _paused_hitl_generation(record),
    )


def _is_canonical_captcha_wait(record: Mapping[str, object]) -> bool:
    """Whether this is the canonical runtime's explicitly typed CAPTCHA pause."""

    hitl = record.get("hitl_request")
    return bool(
        record.get("state_engine") == "canonical_v1"
        and record.get("status") == "waiting_for_hitl"
        and record.get("phase") == CANONICAL_CHALLENGE_PHASE
        and isinstance(hitl, Mapping)
        and hitl.get("type") == "captcha"
        and _paused_hitl_generation(record) > 0
    )


def _paused_gate(record: Mapping[str, object]) -> HumanActionType:
    """The gate type the run parked on, from its standing human-action request."""

    hitl = record.get("hitl_request")
    if isinstance(hitl, Mapping):
        gate = hitl.get("type")
        if isinstance(gate, str) and gate in _HUMAN_ACTION_TYPES:
            return cast(HumanActionType, gate)
    return DEFAULT_PAUSED_GATE


def _paused_hitl_generation(record: Mapping[str, object]) -> int:
    """The positive browser-service generation bound to this durable pause."""

    hitl = record.get("hitl_request")
    generation = hitl.get("hitl_generation") if isinstance(hitl, Mapping) else None
    return generation if type(generation) is int and generation > 0 else 0


__all__ = [
    "CANONICAL_CHALLENGE_PHASE",
    "CAPTCHA_PAUSED_PHASE",
    "DEFAULT_PAUSED_GATE",
    "TAKEOVER_CONTINUED_EVENT",
    "CanonicalTakeoverControl",
    "ClearanceProbe",
    "RunTakeoverService",
]
