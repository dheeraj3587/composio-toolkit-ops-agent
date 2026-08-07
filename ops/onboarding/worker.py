"""The pump: claim a queued onboarding run, drive it, settle its queue entry.

Everything under ``ops/onboarding`` was built and nothing turned the crank.
``SQLiteLeaseStore.claim_next``, ``SQLiteRunQueue.dequeue_candidates`` and
``drive_run`` all had zero non-test callers, which is the literal reason a run
created with ``onboarding: true`` did nothing: the queue row was written (once
the API stopped refusing) and no process ever read it. This module is the loop
that reads it.

**Three responsibilities and no fourth.** Claim through the store, compose the
run's deps through :meth:`OnboardingPorts.deps_for`, hand both to
:func:`~ops.onboarding.driver.drive_run`. It decides nothing about a phase, it
commits no boundary, and it writes no outcome — every one of those belongs to the
driver, and a worker that second-guessed any of them would be a second state
machine racing the first one.

**The lease's lifetime is the driver's, not this module's.** ``drive_run``
documents it (Q3): a lease passed in is released by its ``LeaseGuard`` on every
exit path, so this worker must not release one it handed over. It releases in
exactly one case — it claimed a lease and then could NOT hand it to the driver
(deps that will not compose) — because that is the one path where the guard never
existed and the run would otherwise stay leased until the TTL expired.

**Settling the queue is this module's, not the driver's.** The driver only ever
*defers* (a phase that asked to come back later, ``PhaseStep.yield``). Two other
endings need a queue write, and both are read off the outcome rather than
guessed:

* a terminal phase is removed, because ``dequeue_candidates`` promises a
  candidate stays queued until the run is terminal, and a terminal run left
  queued is re-claimed and re-walked forever;
* a waiting phase (``paused``/``captcha_paused``) is deferred by
  :data:`WAITING_BACKOFF_SECONDS`, because a human or the takeover sweep owns the
  run from there. Without the deferral the queue is immediately due again and the
  worker spins on a run it cannot advance. ``enqueue`` folds to ``MIN(existing,
  requested)``, so the resume path — ``RunTakeoverService`` and the operator
  resume both call it — pulls the ready time straight back to now. The deferral
  is a scheduling fact, never a pause: it adds no human gate and clears none.

**One host, restated where it is depended on.** Every store behind
:class:`~ops.onboarding.composition.OnboardingPorts` is SQLite-backed, so this
worker is correct only while onboarding workers run on exactly one host
(Requirement 21.7, ``ops/onboarding/composition.py`` lines 28-32). Nothing here
adds a second assumption: exclusivity within a host is the lease store's atomic
claim, and concurrency inside this process is bounded by
:attr:`OnboardingWorker.max_concurrent_runs` so a single host does not open more
browser containers than it was sized for. Multi-host scale-out is the shared-store
port swap (Requirement 21.8), not a change here.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final, Literal

from ops.core.config import Settings
from ops.core.model_catalog import ModelSelection, resolve_selection
from ops.deploy.acceptance import wait_for_deployment_acceptance
from ops.onboarding.composition import OnboardingPorts
from ops.onboarding.driver import (
    WAITING_PHASES,
    AutonomyOutcome,
    LoopSessionFactory,
    drive_run,
)
from ops.onboarding.lease import Lease, claim_jitter_seconds, format_deadline
from ops.onboarding.phase import TERMINAL_PHASES
from ops.providers.errors import ConfigurationRequiredError, PhaseUnavailableError

LOGGER = logging.getLogger("composio_ops.onboarding_worker")

# How long a run that stopped at a waiting phase stays out of the queue. Long
# enough that a paused run costs one claim per minute rather than one per poll,
# short enough that a resume path which somehow did NOT re-enqueue still recovers
# on its own. The resume paths do re-enqueue, so this is the belt to their braces.
WAITING_BACKOFF_SECONDS: Final = 60

# What one turn of the pump did. A closed vocabulary because it is logged and
# counted, never rendered: no page text, no provider name, no run content.
WorkerDisposition = Literal["idle", "driven", "fenced", "refused", "failed"]


@dataclass(frozen=True, slots=True)
class WorkerTurn:
    """The result of one claim attempt, as a value a caller can assert on.

    ``outcome`` is present only for ``driven`` and carries the driver's own
    :class:`~ops.onboarding.driver.AutonomyOutcome`; this worker never builds one.
    ``reason_code`` is set for ``refused`` and ``failed`` and is always an
    internal code, never an exception message — a provider's error text is not
    something a worker log line may quote.
    """

    disposition: WorkerDisposition
    run_id: str | None = None
    outcome: AutonomyOutcome | None = None
    reason_code: str | None = None


def default_worker_id() -> str:
    """A stable-per-process identifier that names the host and the process.

    The host half matters even though the deployment is single-host: an operator
    reading two workers in the lease table needs to see immediately whether that
    is two processes on one box (expected during a rolling restart) or the
    Requirement 21.7 violation. Bounded and space-free because
    :class:`~ops.onboarding.lease.Lease` refuses anything else.
    """

    try:
        host = socket.gethostname() or "unknown"
    except OSError:  # pragma: no cover - a host with no resolvable name
        host = "unknown"
    host = "".join(character for character in host if character.isalnum() or character in "-_.")
    return f"onboarding-{host[:60] or 'unknown'}-{os.getpid()}"


class OnboardingWorker:
    """Drive queued onboarding runs until the queue is empty, then wait.

    PRE:  ``ports`` is a fully composed root (``build_onboarding_ports``) and
          ``sessions`` is the process's browser-session factory — the component
          that owns a bound session owns its lifecycle, which is why it is passed
          in rather than reached for here.
    POST: every claim this worker wins is either driven under the driver's own
          lease guard or released before any effect; no run is left leased by a
          claim this worker made and did not use.
    """

    def __init__(
        self,
        *,
        ports: OnboardingPorts,
        sessions: LoopSessionFactory,
        settings: Settings | None = None,
        worker_id: str | None = None,
        max_concurrent_runs: int | None = None,
        interval_seconds: int | None = None,
        jitter: Callable[[], float] = claim_jitter_seconds,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._ports = ports
        self._sessions = sessions
        self._settings = settings if settings is not None else ports.settings
        self._worker_id = worker_id or default_worker_id()
        self._max_concurrent = max(
            1,
            max_concurrent_runs
            if max_concurrent_runs is not None
            else self._settings.onboarding_worker_max_concurrent_runs,
        )
        self._interval = max(
            1,
            interval_seconds
            if interval_seconds is not None
            else self._settings.onboarding_worker_interval_seconds,
        )
        self._jitter = jitter
        self._now = now
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    @property
    def worker_id(self) -> str:
        """The identifier this worker's leases are held under."""

        return self._worker_id

    @property
    def max_concurrent_runs(self) -> int:
        """How many runs this process drives at once (Requirement 21.7's bound)."""

        return self._max_concurrent

    def drivable(self) -> str | None:
        """``None`` when this worker can drive, else the reason code it cannot.

        Asked before the thread starts rather than discovered per claim. A
        deployment with no decision-model key can compose every other port, so
        ``deps_for`` raises only once a run has already been claimed — and a
        worker that claims, fails to compose, releases and immediately claims the
        same run again is a spin that looks like work. Refusing up front reports
        the same absence the composition root already recorded, once.
        """

        if self._ports.decider is None:
            return self._ports.unavailable.get("decider", "decider_unavailable")
        return None

    # --- one turn -----------------------------------------------------------

    async def claim_and_drive(self) -> WorkerTurn:
        """Claim the longest-claimable queued run and drive it once.

        Returns ``idle`` when the queue held nothing this worker could claim,
        which is the ordinary answer and not a failure. Exactly one run is claimed
        per call: concurrency is the caller's (``run_forever`` fans out), because
        a claim that is not driven is a lease held for nothing.
        """

        refusal = self.drivable()
        if refusal is not None:
            return WorkerTurn(disposition="refused", reason_code=refusal)
        lease = self._ports.leases.claim_next(
            worker_id=self._worker_id, ttl_seconds=self._ports.timings.ttl_seconds
        )
        if lease is None:
            return WorkerTurn(disposition="idle")
        return await self._drive(lease)

    async def _drive(self, lease: Lease) -> WorkerTurn:
        """Compose this run's deps and hand the lease to the driver."""

        run_id = lease.run_id
        try:
            deps = self._ports.deps_for(
                run_id=run_id,
                sessions=self._sessions,
                selection=self._selection_for(run_id),
            )
        except (PhaseUnavailableError, ConfigurationRequiredError) as error:
            # The one path that owns the lease's release: the guard inside
            # ``drive_run`` never came into existence, so nothing else will free
            # this run and it would sit leased for a whole TTL.
            self._ports.leases.release(lease=lease)
            reason = getattr(error, "reason_code", None) or "onboarding_deps_unavailable"
            LOGGER.warning(
                "onboarding run %s could not be composed for driving (%s)", run_id, reason
            )
            return WorkerTurn(disposition="refused", run_id=run_id, reason_code=str(reason))

        try:
            outcome = await drive_run(
                run_id=run_id, worker_id=self._worker_id, deps=deps, lease=lease
            )
        except Exception as error:
            # The lease is already released by the guard's ``__exit__``; what is
            # left is to make sure this run does not immediately re-claim into the
            # same crash. Deferred rather than removed: the failure may be
            # transient (an unreachable browser service), and removing the row
            # would silently drop a run nobody would ever pick up again.
            LOGGER.exception("onboarding run %s raised while being driven", run_id)
            self._record_driver_crash(run_id, error)
            self._defer(run_id)
            self._forget_session(run_id)
            return WorkerTurn(disposition="failed", run_id=run_id, reason_code="driver_raised")

        if outcome is None:  # drive_run Q4: someone else owns the run
            return WorkerTurn(disposition="fenced", run_id=run_id)

        self._settle(outcome)
        self._forget_session(run_id)
        return WorkerTurn(disposition="driven", run_id=run_id, outcome=outcome)

    def _settle(self, outcome: AutonomyOutcome) -> None:
        """Write the queue fact the driver deliberately does not write.

        A run that neither terminated nor waited is left exactly as the driver
        left it: it either deferred itself (``PhaseStep.yield``) or is due now and
        should be picked straight back up, and overwriting either with a backoff
        of this worker's own would be this module deciding a schedule the phase
        already decided.
        """

        phase = outcome.terminal_phase
        if phase in TERMINAL_PHASES:
            self._ports.queue.remove(run_id=outcome.run_id)
            LOGGER.info(
                "onboarding run %s finished at %s (%s); dequeued",
                outcome.run_id,
                phase,
                outcome.verdict,
            )
            return
        if phase in WAITING_PHASES:
            self._defer(outcome.run_id)
            LOGGER.info(
                "onboarding run %s is waiting at %s (%s); deferred %d second(s)",
                outcome.run_id,
                phase,
                outcome.reason_code,
                WAITING_BACKOFF_SECONDS,
            )

    def _record_driver_crash(self, run_id: str, error: BaseException) -> None:
        """Put a handler crash on the run's own timeline, not just in the log.

        Without this the run is deferred and re-claimed every
        :data:`WAITING_BACKOFF_SECONDS` forever while its timeline shows nothing
        at all: a crash escaping a handler commits no phase boundary, so it emits
        no ``OnboardingReasonCode``, and an operator reading the console sees a
        run that is simply not moving. The audit row is the only place the fact
        can be seen by someone who does not have the process log.

        Only the exception's *type* name is recorded. A provider's message can
        carry the page text, a URL, or a value that reached it, and this payload
        is rendered in the console; the message and traceback go to
        ``LOGGER.exception`` instead, which passes through the redacting filter.

        Best effort by construction: this runs on the failure path, and a ledger
        that is itself unwell must not turn a deferrable crash into an escaping
        one that skips ``_defer`` and leaves the run due immediately.
        """

        try:
            self._ports.ledger.append_audit_event(
                run_id=run_id,
                event_type="onboarding_driver_raised",
                payload={
                    "worker_id": self._worker_id,
                    "error_type": type(error).__name__,
                    "retry_in_seconds": WAITING_BACKOFF_SECONDS,
                },
            )
        except Exception:  # pragma: no cover - defensive, see docstring
            LOGGER.exception(
                "onboarding run %s could not record its driver crash on the timeline",
                run_id,
            )

    def _defer(self, run_id: str) -> None:
        """Push this run's ready time out by the waiting backoff."""

        self._ports.queue.defer(
            run_id=run_id,
            not_before=format_deadline(self._now() + timedelta(seconds=WAITING_BACKOFF_SECONDS)),
        )

    def _selection_for(self, run_id: str) -> ModelSelection | None:
        """The decision model this run was pinned to, or ``None`` for the chain.

        Read from the run's own row, so a worker that picks the run up after a
        restart uses the model the operator chose at creation rather than
        whatever the deployment's chain happens to lead with. An id this
        deployment can no longer serve — a key rotated out since the run was
        accepted — degrades to the chain rather than failing the run over a
        preference, which is the same rule ``deps_for`` applies one level down.
        """

        record = self._ports.ledger.get_run(run_id)
        if record is None:
            return None
        model_id = record.get("decision_model")
        if not isinstance(model_id, str) or not model_id:
            return None
        effort = record.get("decision_effort")
        try:
            return resolve_selection(
                self._settings,
                model_id=model_id,
                effort=effort if isinstance(effort, str) else None,
            )
        except ValueError:
            LOGGER.info(
                "onboarding run %s is pinned to a model this deployment cannot serve; "
                "driving it on the deployment chain",
                run_id,
            )
            return None

    def _forget_session(self, run_id: str) -> None:
        """Drop this process's handle on the run's session — never a release.

        The session belongs to the run: a CAPTCHA pause must keep the session that
        is holding the challenge (Requirement 11.4), and reclaiming an abandoned
        one is the service janitor's and ``reconcile_bound_sessions``' job. Duck
        typed because ``LoopSessionFactory`` is the port and ``forget`` is one
        implementation's lifecycle detail, not part of the contract.
        """

        forget = getattr(self._sessions, "forget", None)
        if callable(forget):
            try:
                forget(run_id)
            except Exception:  # pragma: no cover - a factory with a hostile forget
                LOGGER.warning("onboarding run %s could not release its session handle", run_id)

    # --- the loop -----------------------------------------------------------

    async def drain(self, *, limit: int | None = None) -> tuple[WorkerTurn, ...]:
        """Drive every claimable run once, up to ``max_concurrent_runs`` at a time.

        Stops at the first pass that claims nothing, so "the queue is empty" is
        observed rather than assumed. ``limit`` bounds the number of runs driven
        in one drain; it exists for the caller that wants one bounded sweep (a
        CLI, a test) rather than a thread.
        """

        turns: list[WorkerTurn] = []
        while limit is None or len(turns) < limit:
            width = self._max_concurrent
            if limit is not None:
                width = min(width, limit - len(turns))
            batch = await asyncio.gather(*(self.claim_and_drive() for _ in range(width)))
            turns.extend(batch)
            if all(turn.disposition in {"idle", "refused"} for turn in batch):
                break
            if any(turn.disposition == "refused" for turn in batch):
                break
        return tuple(turns)

    def start(self) -> bool:
        """Start the polling thread, or report why it will not run.

        Gated exactly like the takeover sweep: the deployment flag, then the
        composition's own answer to "can anything be driven at all". Returns
        ``False`` rather than raising because an API process that cannot drive
        onboarding must still serve every other route.
        """

        if not self._settings.onboarding_worker_enabled:
            LOGGER.info("the onboarding worker is disabled by configuration")
            return False
        refusal = self.drivable()
        if refusal is not None:
            LOGGER.warning("the onboarding worker cannot drive any run (%s)", refusal)
            return False
        if self._thread is not None and self._thread.is_alive():
            return True
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="onboarding-worker", daemon=True)
        self._thread.start()
        LOGGER.info(
            "onboarding worker %s started (%d concurrent run(s), %ds interval)",
            self._worker_id,
            self._max_concurrent,
            self._interval,
        )
        return True

    def stop(self, *, timeout: float = 30.0) -> None:
        """Stop polling and join the thread through its in-flight drive.

        The join is generous on purpose: a drive in flight holds a live lease and
        a bound browser session, and abandoning the thread mid-phase is exactly
        the crash the fencing token exists to recover from. Waiting lets the
        driver's guard release the lease the ordinary way.
        """

        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=timeout)

    def _loop(self) -> None:
        """Poll the queue on its own event loop until stopped.

        Its own loop, not the API's: a drive is minutes long and would otherwise
        share a loop with request handling. The deployment-acceptance wait is the
        same one every other sweep performs — an unaccepted revision must not
        drive a provider-visible effect (see ``ops.deploy.acceptance``).
        """

        settings = self._settings
        if self._stop.wait(max(1.0, float(settings.ops_automation_start_delay_seconds))):
            return
        if not wait_for_deployment_acceptance(settings, self._stop):
            return
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            while not self._stop.is_set():
                try:
                    loop.run_until_complete(self.drain(limit=self._max_concurrent))
                except Exception:  # pragma: no cover - a sweep must never end the thread
                    LOGGER.exception("the onboarding worker's sweep failed")
                # Jitter on top of the interval for the same reason the claim path
                # has it: workers waking on one cadence contend on the same
                # ``BEGIN IMMEDIATE`` every cycle.
                if self._stop.wait(self._interval + self._jitter()):
                    break
        finally:
            asyncio.set_event_loop(None)
            loop.close()


__all__ = [
    "WAITING_BACKOFF_SECONDS",
    "OnboardingWorker",
    "WorkerTurn",
    "default_worker_id",
]
