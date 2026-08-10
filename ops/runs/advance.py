"""Autonomous continuation of human gates the agent can resolve by itself.

Which gates qualify is decided by ``ops.access.gate_policy``, not here: this module owns
the sweep, the attempt budget, and the audit trail, while the policy owns the
classification. Anything the policy does not explicitly classify stays paused for
an owner, so an unreviewed gate can never advance a run.

CAPTCHA, phone OTP, device approval, billing, and hardware authenticators are
permanently human-only. See ``ops.access.gate_policy`` for the rationale behind each.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol

from pydantic import SecretStr

from ops.access.gate_policy import (
    PROFILE_DECLARABLE_GATES,
    GateResolution,
    ProfileGateAuthority,
    autonomous_gates,
    resolve_gate,
)
from ops.browser.link_log import log_event
from ops.core.config import Settings
from ops.core.storage import OperationsStorage
from ops.deploy.acceptance import wait_for_deployment_acceptance
from ops.runs.errors import CredentialSubmissionError, RunConflictError

if TYPE_CHECKING:  # Import-time cost paid only by the type checker.
    from ops.providers.profile_store import ProviderProfileStore

# Retained as the module's published view of the autonomous gate set. It is now
# derived from the declarative policy instead of being hard-coded empty, so the
# two can never disagree.
_AUTO_ADVANCEABLE_GATES: frozenset[str] = autonomous_gates()

# The durable fact this sweep writes when it hands a gate back to a person. The
# log line alone was invisible the moment the container was recycled, so an
# operator asking "why is this run still waiting?" had nothing to read.
ESCALATED_EVENT: Final = "autonomous_advance_escalated"

# The most run rows one sweep pass will page through. The scan is paged rather
# than capped at the newest 100 (see ``advance_autonomous_runs``), but "paged"
# must not mean "unbounded":
#
#   * one thread runs this sweep, idle reconciliation, and the staleness mark in
#     sequence (see ``_loop``), so a ``list_runs`` that ever stopped honouring
#     ``offset`` would spin here forever and silently take the other two sweeps
#     down with it — a worse stall than the one paging fixes; and
#   * a pass has to finish inside the sweep interval, or "every 20 seconds"
#     stops meaning anything once the ledger is years old.
#
# 10,000 rows is roughly two orders of magnitude past a 50-app catalog with
# retries, so it cannot re-create the blindness this paging exists to remove,
# and reaching it is logged rather than swallowed: a silent ceiling would be the
# same defect as the silent first page it replaced.
_MAX_SWEEP_ROWS: Final = 10_000


def _gate_budget_key(gate: str) -> str:
    """Namespace this sweep's budget so it cannot collide with another's.

    ``run_gate_attempts`` is keyed by ``(run_id, gate)`` and is shared by every
    sweep that spends a bounded number of attempts on a run. Prefixing keeps a
    gate name that two sweeps both recognize — ``email_otp`` is the obvious one —
    from having its budget spent twice over by whichever sweep ran first.
    """

    return f"advance:{gate}"


def _escalation_marker_key(gate: str, reason_code: str) -> str:
    """The ``run_gate_attempts`` key that makes one escalation record once-only.

    ``reusable_login_unavailable`` is re-derived on every pass — the run stays
    waiting and the vault stays empty — so a durable row written unconditionally
    would append one audit event every sweep interval for the life of the run.
    The attempts table is already a durable, atomically-incremented counter keyed
    by an arbitrary (run, name) pair, so the first spend returning 1 is the "this
    escalation has not been recorded yet" test, and it is race-free between two
    sweep threads in a way a read-then-write check would not be. A separate
    prefix from ``_gate_budget_key`` keeps this marker from spending the gate's
    real retry budget.
    """

    return f"advance_escalated:{reason_code}:{gate}"


class RunAdvanceContext(Protocol):
    """Run-service state and actions the autonomous sweep drives.

    The thread handle and stop event stay owned by the service (a test replaces
    ``_advance_stop`` directly), so they are read and written through this context
    instead of being duplicated here.
    """

    storage: OperationsStorage
    _settings: Settings | None
    _advance_thread: threading.Thread | None
    _advance_stop: threading.Event

    def _hitl_action_type(self, record: Mapping[str, object]) -> str | None: ...

    def _reusable_login_values(self, app_slug: str, account_ref: str) -> dict[str, SecretStr]: ...

    def resume_run(self, run_id: str, *, signal: str) -> dict[str, object] | None: ...

    def resolve_email_otp(
        self,
        run_id: str,
        *,
        max_attempts: int | None = None,
    ) -> dict[str, object] | None: ...

    def reconcile_idle_browser_runs(self, *, limit: int = 100) -> int: ...

    def mark_stale_runs(self, *, limit: int = 100) -> int: ...

    def _reconcile_stranded_runs(self) -> None: ...


class RunAdvanceService:
    """Sweep waiting runs and resume the ones no human is needed for."""

    def __init__(self, context: RunAdvanceContext) -> None:
        self._context = context
        # Opened on first profile-declarable gate and memoized, not in __init__:
        # a deployment that never reaches one should not create the file, and the
        # sweep is constructed on every service instance including ones that only
        # ever serve recipe-driven runs.
        self._profiles: ProviderProfileStore | None = None
        self._profiles_resolved = False
        self._profiles_lock = threading.Lock()

    def _profile_store(self) -> ProviderProfileStore | None:
        """The content-addressed profile store, or ``None`` if unreachable.

        Constructed here rather than read off the run service because the service
        holds none — ``api.service`` and ``ops.onboarding.composition`` each build
        their own from the same two facts, and this is the third caller that needs
        one. It is opened exactly as they do, so all three address the same file
        under the same tenant owner; a store scoped to one owner cannot read
        another's profile, which is what keeps this read from widening anything.

        Failure is not raised. Every caller treats ``None`` as "no authority",
        which withholds autonomy rather than granting it.
        """

        with self._profiles_lock:
            if self._profiles_resolved:
                return self._profiles
            self._profiles_resolved = True
            settings = self._context._settings
            if settings is None:
                return None
            try:
                from ops.onboarding.composition import PROFILE_DATABASE_NAME
                from ops.providers.profile_store import SQLiteProviderProfileStore

                self._profiles = SQLiteProviderProfileStore(
                    Path(self._context.storage.db_path).parent / PROFILE_DATABASE_NAME,
                    owner=settings.browser_service_owner,
                )
            except Exception:
                log_event("browser.autonomous_advance.profile_store_unavailable", level=30)
                self._profiles = None
            return self._profiles

    def _profile_authority(
        self,
        *,
        run_id: str,
        record: Mapping[str, object],
    ) -> ProfileGateAuthority | None:
        """Project the run's durable profile and admission decision onto the policy's shape.

        This is the call the sweep used to omit. It could not supply one before
        because ``ProfileGateAuthority.gate_url`` is the page the gate was observed
        on and nothing persisted it; the pause payload now records it (see
        ``ops.workflow.canonical_runtime``), so the last missing fact is durable.
        Substituting the profile's own signup URL was the tempting shortcut and is
        exactly what must not happen: it would make the domain-confinement check
        compare the profile against itself and pass vacuously.

        Every field comes from a row written before the gate was observed, and a
        missing or malformed one yields ``None`` rather than a partial authority.
        ``resolve_gate`` re-checks all six regardless — nothing is asserted here.
        """

        hitl = record.get("hitl_request")
        if not isinstance(hitl, Mapping):
            return None
        gate_url = hitl.get("gate_url")
        if not isinstance(gate_url, str) or not gate_url:
            # A run paused before this field existed. It stays human-only, which
            # is the same answer it has been getting all along.
            return None
        store = self._profile_store()
        if store is None:
            return None
        try:
            profile = store.get_for_run(run_id=run_id)
            if profile is None:
                return None
            decision = self._context.storage.read_admission_decision(run_id=run_id)
        except Exception:
            # A sweep that dies on one unreadable run stops advancing every other
            # one, so this is contained the same way ``_attempt`` contains a
            # resolver failure.
            log_event(
                "browser.autonomous_advance.profile_authority_unreadable",
                level=30,
                run_id=run_id,
            )
            return None
        if decision is None:
            return None
        return ProfileGateAuthority(
            profile_digest=profile.profile_digest,
            registrable_domain=profile.registrable_domain,
            gate_url=gate_url,
            admission_route=decision.route,
            admission_decided_by=decision.decided_by,
            admission_profile_digest=decision.profile_digest,
        )

    def start(self) -> None:
        """Start the sweep that auto-resumes machine-resolvable human gates.

        Deliberately independent of the email poller: that thread only starts when
        Gmail is configured, so autonomous login continuation would never have run
        on a deployment without an inbox.
        """

        context = self._context
        settings = context._settings or Settings.from_env()
        if context._advance_thread is not None and context._advance_thread.is_alive():
            return
        interval = max(5, int(getattr(settings, "autonomous_advance_interval_seconds", 20)))
        initial_delay = max(
            1.0,
            float(getattr(settings, "ops_automation_start_delay_seconds", 30.0)),
        )
        context._advance_stop.clear()
        thread = threading.Thread(
            target=self._loop,
            args=(interval, initial_delay),
            name="autonomous-advancer",
            daemon=True,
        )
        context._advance_thread = thread
        thread.start()

    def _loop(self, interval: int, initial_delay: float) -> None:
        # Reconciliation can contact the isolated browser service. Delay it until
        # after process startup, and make the delay interruptible so a candidate
        # rejected during deployment performs no provider call.
        if self._context._advance_stop.wait(initial_delay):
            return
        settings = self._context._settings or Settings.from_env()
        if not wait_for_deployment_acceptance(settings, self._context._advance_stop):
            return
        try:
            self._context._reconcile_stranded_runs()
        except Exception:  # pragma: no cover - the loop must never die
            pass
        while not self._context._advance_stop.wait(interval):
            try:
                self.advance_autonomous_runs()
            except Exception:  # pragma: no cover - the loop must never die
                pass
            try:
                self._context.reconcile_idle_browser_runs()
            except Exception:  # pragma: no cover - the loop must never die
                pass
            try:
                self._context.mark_stale_runs()
            except Exception:  # pragma: no cover - the loop must never die
                pass

    def advance_autonomous_runs(self, *, limit: int = 100) -> int:
        """Resolve every paused gate the policy classifies as autonomous.

        Returns how many runs were actually advanced. A gate the policy leaves
        ``human_only``, a run that has spent its attempt budget, and a login gate
        with no reusable credentials are all left paused for an owner rather than
        retried into failure.
        """

        context = self._context
        settings = context._settings or Settings.from_env()
        budget = int(getattr(settings, "max_autonomous_advances", 0))
        if budget <= 0:
            return 0
        advanced = 0
        offset = 0
        scanned = 0
        while True:
            # Paged, not a single newest-100 window. A paused gate is resolved
            # only by this sweep, so a run displaced from page one by newer runs
            # stayed paused forever — and one 50-app batch fills page one on its
            # own. ``list_runs`` orders by ``created_at``, which this sweep never
            # writes, so the paging is stable under its own mutations.
            records = context.storage.list_runs(limit=limit, offset=offset)
            if not records:
                break
            for record in records:
                if record.get("status") != "waiting_for_hitl":
                    continue
                run_id = str(record.get("run_id") or "")
                if not run_id:
                    continue
                app_slug = str(record.get("app_slug") or "unknown")
                action_type = context._hitl_action_type(record)
                # ``profile_authority`` is supplied now. It used to be omitted
                # because the URL the gate was observed on was not durable
                # anywhere; the pause payload records it, so the sweep can build
                # the same authority ``accept_legal_terms`` builds on the driver
                # path, and the two agree about what a profile may authorize.
                #
                # Built only for the gates a profile may ever authorize. This
                # sweep runs every few seconds over every waiting run, and the
                # authority costs two reads; for a gate outside
                # ``PROFILE_DECLARABLE_GATES`` the policy discards it in its first
                # clause, so paying for it would buy nothing. The narrowing is a
                # cost decision and not a second policy: the set is imported from
                # the policy rather than restated, so widening it there widens it
                # here with no edit.
                authority = (
                    self._profile_authority(run_id=run_id, record=record)
                    if action_type in PROFILE_DECLARABLE_GATES
                    else None
                )
                resolution = resolve_gate(
                    action_type, app_slug=app_slug, profile_authority=authority
                )
                if resolution == "human_only":
                    continue
                gate = str(action_type)
                budget_key = _gate_budget_key(gate)
                attempts = context.storage.gate_attempts(run_id, budget_key)
                if attempts >= budget:
                    # Log the exhaustion once, then stay quiet: this sweep runs
                    # every few seconds and must not fill the log with the same
                    # escalation.
                    if attempts == budget:
                        context.storage.spend_gate_attempt(run_id, budget_key)
                        self._escalate(
                            run_id,
                            gate,
                            "attempt_budget_exhausted",
                            attempts_spent=attempts,
                            budget=budget,
                        )
                    continue
                if resolution == "reusable_login" and not context._reusable_login_values(
                    app_slug,
                    str(record.get("browser_account_ref") or run_id),
                ):
                    # Nothing to inject: asking the worker again would just
                    # re-raise the same gate. The owner still needs to supply
                    # credentials once.
                    self._escalate(
                        run_id,
                        gate,
                        "reusable_login_unavailable",
                        attempts_spent=attempts,
                        budget=budget,
                    )
                    continue
                spent = context.storage.spend_gate_attempt(run_id, budget_key)
                if not self._attempt(run_id, resolution):
                    continue
                log_event(
                    "browser.autonomous_advance.resumed",
                    run_id=run_id,
                    gate=gate,
                    resolution=resolution,
                    attempt=spent,
                )
                advanced += 1
            offset += len(records)
            scanned += len(records)
            if len(records) < limit:
                break
            if scanned >= _MAX_SWEEP_ROWS:
                # Say so. Everything past this point is unswept until the next
                # pass, which is exactly the condition this sweep exists to
                # detect, so it is a warning and not a debug line.
                log_event(
                    "browser.autonomous_advance.scan_truncated",
                    level=30,
                    scanned=scanned,
                )
                break
        return advanced

    def _attempt(self, run_id: str, resolution: GateResolution) -> bool:
        """Drive one gate through its resolver; never raise into the sweep loop."""

        context = self._context
        try:
            if resolution == "emailed_verification":
                # The verification service owns recipient binding, sender
                # authentication, and the one-time resume injection.
                return context.resolve_email_otp(run_id) is not None
            # reusable_login and the two declared authorities (recipe_declared,
            # profile_declared) all continue the existing session; resume_run
            # injects any remembered credentials itself.
            context.resume_run(run_id, signal="completed")
            return True
        except (RunConflictError, CredentialSubmissionError, KeyError):
            # Another writer owns the run, or it already moved on.
            return False
        except Exception:
            log_event(
                "browser.autonomous_advance.error",
                level=40,
                run_id=run_id,
                resolution=resolution,
            )
            return False

    def _escalate(
        self,
        run_id: str,
        gate: str,
        reason_code: str,
        *,
        attempts_spent: int,
        budget: int,
    ) -> None:
        """Record that a gate is being handed back to an owner, with a cause.

        Durably as well as to the log. A stdout line is gone with the container,
        so a run that had exhausted its budget or had no credentials to inject was
        indistinguishable — in every operator surface — from one this sweep had
        simply not reached yet: both read as ``waiting_for_hitl`` with no stated
        cause, which is the stall this handed to a person with no way to see it.

        ``attempts_spent`` and ``budget`` are what turn the row from an assertion
        into evidence: "this run spent 3 of 3" answers *why nothing else will
        happen* without the reader having to know what the ceiling was configured
        to be at the time, which is a setting they cannot recover after the fact.
        Both are integers this sweep computed from its own attempts table and its
        own configuration — like ``gate`` and ``reason_code``, nothing here is
        derived from provider text or from a run-authored payload.

        The run's STATUS is deliberately untouched. It is already
        ``waiting_for_hitl``; the person it is waiting for is the same person, and
        the gate is the same gate. This adds the missing evidence, not a new pause.
        """

        log_event(
            "browser.autonomous_advance.escalated",
            run_id=run_id,
            gate=gate,
            reason_code=reason_code,
            attempts_spent=attempts_spent,
            budget=budget,
        )
        self._record_escalation(
            run_id,
            gate,
            reason_code,
            attempts_spent=attempts_spent,
            budget=budget,
        )

    def _record_escalation(
        self,
        run_id: str,
        gate: str,
        reason_code: str,
        *,
        attempts_spent: int,
        budget: int,
    ) -> None:
        """Write the escalation to the run's audit trail exactly once.

        Not ``record_escalation_audit``: that writer demands the full onboarding
        correlation set (committed phase, profile digest, correlation id) plus a
        reason code from the closed onboarding vocabulary, and this sweep holds a
        run row and a gate name — neither ``attempt_budget_exhausted`` nor
        ``reusable_login_unavailable`` is an ``OnboardingReasonCode``. Inventing
        the correlation fields to satisfy it would put fiction in the trail.

        ``gate`` is safe to write: it reached here only because ``resolve_gate``
        classified it as something other than ``human_only``, so it is one of the
        policy's own declared gate names and never text taken off a page. The two
        counters are safe for the stronger reason that they never left this
        process: one is read from the attempts table, the other from settings.

        A failed write must not end the sweep for the other runs — losing one
        escalation row is recoverable, and the next pass re-derives the same
        condition — but it is logged at warning so a trail that has silently
        stopped recording is visible rather than assumed.
        """

        storage = self._context.storage
        try:
            if storage.spend_gate_attempt(run_id, _escalation_marker_key(gate, reason_code)) != 1:
                return
            storage.append_audit_event(
                run_id=run_id,
                event_type=ESCALATED_EVENT,
                payload={
                    # The run id rides in the payload as well as in the row's own
                    # key: an event exported, forwarded, or read out of a joined
                    # projection must still say which run exhausted what.
                    "run_id": run_id,
                    "gate": gate,
                    "reason_code": reason_code,
                    "attempts_spent": attempts_spent,
                    "attempt_budget": budget,
                    # No provider was contacted and nothing was submitted: this
                    # event records a decision to stop, so the trail says so
                    # rather than leaving a reader to infer it.
                    "external_actions": False,
                },
            )
        except Exception:
            log_event(
                "browser.autonomous_advance.escalation_unrecorded",
                level=30,
                run_id=run_id,
                gate=gate,
                reason_code=reason_code,
            )


__all__ = [
    "ESCALATED_EVENT",
    "RunAdvanceContext",
    "RunAdvanceService",
]
