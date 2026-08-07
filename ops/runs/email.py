"""Provider-reply intake: poll the outreach thread, classify, and advance the run.

This closes the gated-outreach loop. The design constraint that shapes every piece
here is idempotency: background polling revisits the same runs forever, so acting
twice on one reply would mean duplicate timeline entries and, worse, a duplicate
follow-up email to a vendor. The loop therefore acts only on the latest
not-yet-processed INBOUND message, identified by the controlled counterpart
address, and remembers the message id it handled.

Credentials that arrive by email are stored as vault references only and merged
into the reference-only bundle; a rejection blocks the run. Both are recorded
through the single transition authority, never by writing a status directly.

The model here is an *input*, never an authority. Reply classification is asked
of ``ops.email.ai`` on the one governed inference chain (budget, per-attempt
timeout, circuit breaker, attempt sink), and every attempt it makes is recorded
on the ``reply_received`` audit event; when the chain has nothing usable to say
the deterministic ``ReplyClassifier`` answer stands, so an exhausted or
unconfigured chain degrades the classification rather than stopping the run.
Nothing consequential is left to the model alone: credentials only advance a run
when the vault broker actually produced references, and whether browser
onboarding may begin is decided by ``_browser_onboarding_ready`` from facts this
module extracted, with the model's own boolean recorded beside it as a hint.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final, Protocol, cast

from ops.core.config import Settings
from ops.core.inference import DecisionFailed, DecisionOutcome
from ops.core.models import CompanyProfile, OperationalResearch, OperationsRequest
from ops.core.state import RunStatus, validate_status_transition
from ops.core.storage import OperationsStorage
from ops.deploy.acceptance import wait_for_deployment_acceptance
from ops.email.verification import parse_received_at_ms
from ops.gmail.validation import parse_mailbox_address
from ops.gmail.worker import GmailWorker, SanitizedGmailMessage, SanitizedGmailThread
from ops.providers.errors import ProviderContractError, ProviderOperationError
from ops.runs.errors import CredentialSubmissionError, RunConflictError
from ops.runs.projections import _public_run, _strip_quoted_reply
from ops.runs.recipe_snapshot import RecipeSnapshotError, recipe_from_run
from ops.workflow.graph import DurableOperationsWorkflow
from ops.workflow.integrator import build_integrator_bundle

# The most run rows one reply-poll pass will page through while looking for runs
# that are actually waiting. The poller used to read ``list_runs(limit, offset=0)``
# and stop, which meant it only ever saw the NEWEST ``limit`` rows: once a
# ``waiting_for_reply`` run was pushed off page one by newer runs, its provider
# reply was never collected again and the run sat waiting forever with nothing in
# the logs to say why. Paging fixes that, but "paged" must not mean "unbounded" —
# this runs on the shared poller thread ahead of the reply intake, so a pass has
# to finish inside ``email_poll_interval_seconds`` no matter how old the ledger
# is. Same ceiling and same reasoning as ``ops/runs/advance.py``'s sweep bound.
_MAX_SCAN_ROWS: Final = 10_000

# How many rows one ``list_runs`` call fetches while scanning. Deliberately NOT
# ``limit``: ``limit`` is the shared-mailbox work budget (how many runs may be
# polled), and reusing it as the page size would have made a deployment with
# ``EMAIL_POLL_MAX_RUNS_PER_CYCLE=1`` issue one query per run in the ledger.
_SCAN_PAGE_SIZE: Final = 100


class RunEmailContext(Protocol):
    """Run-service state the reply-intake loop needs."""

    storage: OperationsStorage
    _settings: Settings | None
    _workflow: DurableOperationsWorkflow | None
    _gmail_worker: GmailWorker | None
    _email_poller_thread: threading.Thread | None

    @property
    def _email_poller_stop(self) -> Any: ...

    def _run_lock(self, run_id: str) -> Any: ...

    def poll_waiting_runs(self, *, limit: int = 100) -> int: ...

    def poll_email(self, run_id: str) -> dict[str, Any]: ...

    def resolve_pending_otps(
        self,
        *,
        limit: int = 1_000,
        max_attempts_per_run: int | None = None,
    ) -> int: ...


@dataclass(slots=True)
class _EmailModelAttempts:
    """One row per attempt of the email inference chain (reliability R4.3).

    Implements ``ops.core.inference.DecisionAttemptSink``. Provider name, typed
    outcome and latency only — never a prompt, a payload, or an answer — which is
    the same contract the browser loop's sink holds itself to.

    These rows ride in the ``reply_received`` audit event the intake transaction
    already writes, rather than in ``onboarding_decision_attempts``, because that
    table cannot hold them: its rows are keyed by an onboarding *phase* and its
    ``purpose`` column is constrained to ``("action", "plan")``
    (ops/core/storage.py:408), and a gated run waiting on a vendor reply has
    neither. Putting them in the audit event needs no migration and is enough to
    answer the question that was previously unanswerable in production — "why did
    this reply get classified by the heuristic instead of the model?" — because
    before the merge that failure raised one flat ``RuntimeError`` into a bare
    ``except`` and left nothing behind at all.
    """

    rows: list[dict[str, object]] = field(default_factory=list)

    def record_attempt(self, *, provider: str, outcome: DecisionOutcome, latency_ms: int) -> None:
        # Bounded by the chain itself (``max_providers``), but capped again here:
        # this list is serialized into a durable audit payload, and an audit row
        # must not be able to grow without a bound of its own.
        if len(self.rows) >= 10:
            return
        self.rows.append({"provider": provider, "outcome": outcome, "latency_ms": int(latency_ms)})


def _browser_onboarding_ready(
    *,
    classification: str,
    official_setup_urls: tuple[str, ...],
    credential_refs: Mapping[str, str],
) -> bool:
    """Whether this reply is what starts browser onboarding — the code's call.

    ``ReplyAnalysisAI.start_browser_onboarding`` is a boolean a *model* writes,
    and no model may decide that a browser session gets driven against a live
    third-party site. It is kept (the schema is published and another surface may
    read it) but demoted to a hint recorded beside this answer; the predicate is:

    * ``official_setup_urls`` is non-empty. These come from
      ``ReplyClassifier``'s regex over the sanitized body of the ONE
      Gmail-authenticated inbound message (ops/email/reply_classifier.py:91),
      never from ``ReplyAnalysisAI.setup_urls``, which is model-authored and can
      name a host the vendor never sent. "Approved" with nowhere to go is not a
      thing to open a browser for, and a fabricated URL must not become one.
    * no credential references arrived. If the vault broker already extracted a
      credential from this very message there is nothing left for a browser to
      obtain, and the run is on its way to ``completed``.
    * the classification is ``approved_setup_required``. This is the one conjunct
      the model can still influence, and only within the eleven-member enum, only
      when it validated, and only when the deterministic classifier was not the
      one that answered — the other two conjuncts are facts the code extracted.

    Recomputed here rather than read off ``heuristic.start_browser_onboarding``
    (ops/email/reply_classifier.py:207), which applies the same rule, because by
    this point ``cls`` may be the *model's* classification: reporting the
    heuristic's boolean beside a classification the heuristic did not make would
    put two disagreeing facts on one audit event. The rule is deliberately the
    classifier's own, so a deployment with no model configured behaves
    identically to one whose chain agreed with it.

    A true here is a *precondition*, not an authorization: whatever eventually
    consumes it still passes the browser host policy and the run's own gates.
    """

    return (
        classification == "approved_setup_required"
        and bool(official_setup_urls)
        and not credential_refs
    )


def _latest_exact_inbound(
    thread: SanitizedGmailThread,
    *,
    expected_sender: str,
) -> tuple[SanitizedGmailMessage | None, int]:
    """Select the newest Gmail-authenticated message from one exact RFC mailbox."""

    expected_mailbox = parse_mailbox_address(expected_sender)
    if expected_mailbox is None:
        return None, 0
    expected_key = expected_mailbox.casefold()
    matches: list[tuple[int, int, SanitizedGmailMessage]] = []
    for index, message in enumerate(thread.messages):
        sender = message.sender_mailbox
        if sender is None or sender.casefold() != expected_key or not message.sender_authenticated:
            continue
        received_at = parse_received_at_ms(message.sent_at) or 0
        matches.append((received_at, index, message))
    if not matches:
        return None, 0
    return max(matches, key=lambda item: (item[0], item[1]))[2], len(matches)


def _selected_message_thread(
    thread: SanitizedGmailThread,
    selected: SanitizedGmailMessage,
    *,
    credential_refs: tuple[tuple[str, str], ...],
) -> SanitizedGmailThread:
    """Build the classifier view ending at the authenticated selected reply."""

    first = thread.messages[0] if thread.messages else selected
    return SanitizedGmailThread(
        thread_id=thread.thread_id,
        messages=(first, selected),
        credential_refs=tuple(reference for _field, reference in credential_refs),
    )


class RunEmailService:
    """Own the reply poller thread and the per-run reply intake."""

    def __init__(self, context: RunEmailContext) -> None:
        self._context = context

    def start_poller(self) -> None:
        """Start the background thread that polls waiting runs for new replies."""

        context = self._context
        if context._gmail_worker is None:
            return
        if context._email_poller_thread is not None and context._email_poller_thread.is_alive():
            return
        settings = context._settings or Settings.from_env()
        interval = max(10, int(settings.email_poll_interval_seconds))
        initial_delay = max(1.0, float(settings.ops_automation_start_delay_seconds))
        cycle_limit = max(1, min(100, int(settings.email_poll_max_runs_per_cycle)))
        context._email_poller_stop.clear()
        thread = threading.Thread(
            target=self._poller_loop,
            args=(interval, initial_delay, cycle_limit),
            name="email-poller",
            daemon=True,
        )
        context._email_poller_thread = thread
        thread.start()

    def _poller_loop(self, interval: int, initial_delay: float, cycle_limit: int) -> None:
        # Starting the thread is side-effect free. The grace wait guarantees the
        # process startup call path performs no provider read, and is interruptible
        # so a rejected candidate can shut down without ever touching Gmail.
        if self._context._email_poller_stop.wait(initial_delay):
            return
        settings = self._context._settings or Settings.from_env()
        if not wait_for_deployment_acceptance(
            settings,
            self._context._email_poller_stop,
        ):
            return
        while not self._context._email_poller_stop.is_set():
            try:
                # One provider read batch per run and cycle. The next cycle is the
                # retry/backoff boundary, preventing one missing OTP from sleeping
                # inside this shared worker and starving outreach replies.
                self._context.resolve_pending_otps(
                    limit=cycle_limit,
                    max_attempts_per_run=1,
                )
            except Exception:  # pragma: no cover - the loop must never die
                pass
            try:
                self._context.poll_waiting_runs(limit=cycle_limit)
            except Exception:  # pragma: no cover - the loop must never die
                pass
            if self._context._email_poller_stop.wait(interval):
                break

    def poll_waiting_runs(self, *, limit: int = 100) -> int:
        """Poll runs awaiting a provider reply; returns how many were polled.

        Idempotent: poll_email acts only on a genuinely new inbound reply, so
        repeated cycles over the same runs are safe no-ops.

        ``limit`` is a *work* budget, not a scan window. It bounds how many runs
        this pass reads the shared mailbox for (``EMAIL_POLL_MAX_RUNS_PER_CYCLE``,
        "so one large backlog cannot starve the API or monopolize the connected
        Gmail account"). It used to double as the ``list_runs`` page size with
        ``offset=0``, which quietly made it a *visibility* window as well: only
        the newest ``limit`` rows were ever considered, so the moment a
        ``waiting_for_reply`` run was displaced off page one by newer runs its
        reply stopped being collected — permanently, and silently, because a run
        that is never polled also never reports a failure.

        Two halves to the fix, and both are needed:

        * the ledger is *scanned* in pages up to ``_MAX_SCAN_ROWS`` so a waiting
          run is found wherever it sits; and
        * the runs found are polled OLDEST first. ``list_runs`` orders newest
          first, so taking the first ``limit`` of the scan would have re-created
          the same starvation one level up — with more waiting runs than the
          budget allows, the same newest few would be polled every cycle forever
          while the oldest, the ones most likely to have a reply sitting unread,
          were never reached. Oldest-first drains: whatever is served completes
          and leaves the waiting set.
        """

        context = self._context
        if context._gmail_worker is None or limit <= 0:
            return 0
        # Only run ids are retained from the scan, so bounding it at 10k rows
        # costs a list of short strings even in the worst case where every row
        # is waiting.
        waiting: list[str] = []
        offset = 0
        while offset < _MAX_SCAN_ROWS:
            records = context.storage.list_runs(
                limit=min(_SCAN_PAGE_SIZE, _MAX_SCAN_ROWS - offset),
                offset=offset,
            )
            if not records:
                break
            for record in records:
                if record.get("state_engine") != "canonical_v1":
                    continue
                if record.get("status") not in {"waiting_for_reply", "outreach_sent"}:
                    continue
                run_id = str(record.get("run_id") or "")
                if run_id:
                    waiting.append(run_id)
            offset += len(records)
            if len(records) < _SCAN_PAGE_SIZE:
                break
        polled = 0
        attempted = 0
        for run_id in reversed(waiting):
            if attempted >= limit:
                break
            # The budget is spent on the ATTEMPT, not on the success. A failing
            # ``poll_email`` may already have hit the mailbox before it raised, so
            # counting only successes would let a backlog of failing runs make
            # unbounded provider reads in a single pass — the exact thing
            # ``EMAIL_POLL_MAX_RUNS_PER_CYCLE`` exists to prevent. The return value
            # still reports successful polls only.
            attempted += 1
            try:
                context.poll_email(run_id)
                polled += 1
            except Exception:
                # One unreadable run must not end the pass for the others.
                continue
        return polled

    def public_no_reply(self, record: Mapping[str, object]) -> dict[str, Any]:
        """Return the current run projection with a no-op reply marker."""

        public = _public_run(record)
        public["latest_reply_class"] = "no_reply"
        public["follow_up_sent"] = False
        # Same key on every receipt this method can return, so a caller never has
        # to tell "absent" from "false" to know whether to expect a browser leg.
        public["start_browser_onboarding"] = False
        return public

    def company_from_checkpoint(self, thread_id: str) -> CompanyProfile | None:
        """Read a company profile only through an explicitly injected legacy workflow.

        Production ``LocalRunService`` does not inject this adapter. Returns None
        when it is absent or its checkpoint is unavailable, in which case the
        loop falls back to the canonical record or deterministic classifier.
        """

        workflow = self._context._workflow
        if workflow is None or not thread_id:
            return None
        try:
            state = workflow.get_state(thread_id)
        except Exception:
            return None
        request_payload = state.get("request")
        if not isinstance(request_payload, Mapping):
            return None
        try:
            return OperationsRequest.model_validate(dict(request_payload)).company
        except Exception:
            return None

    def company_from_record(self, record: Mapping[str, object]) -> CompanyProfile | None:
        """Read canonical company data from the SQLite request snapshot.

        An explicitly injected workflow may provide legacy compatibility, but
        production does not initialize that reader. No canonical run depends on
        LangGraph or its encryption key.
        """

        request_payload = record.get("request")
        if isinstance(request_payload, Mapping):
            try:
                return OperationsRequest.model_validate(dict(request_payload)).company
            except Exception:
                return None
        if record.get("state_engine") == "canonical_v1":
            return None
        return self.company_from_checkpoint(str(record.get("thread_id") or ""))

    def email_credentials_bundle_change(
        self,
        record: Mapping[str, object],
        company: CompanyProfile | None,
        credential_refs: dict[str, str],
    ) -> dict[str, object]:
        """Merge emailed credential references into the run's reference-only bundle.

        If a bundle already exists, the new ``vault://`` references are merged in.
        When none exists yet and verified research + company are available, a
        reference-only IntegratorBundle is built so the developer still receives a
        usable handoff. Best-effort: any failure leaves the run completed without a
        bundle rather than breaking the email poll.
        """

        existing_bundle = record.get("integrator_bundle")
        if isinstance(existing_bundle, Mapping):
            merged: dict[str, object] = dict(existing_bundle)
            current_refs = merged.get("credential_refs")
            refs: dict[str, str] = (
                {str(k): str(v) for k, v in current_refs.items()}
                if isinstance(current_refs, Mapping)
                else {}
            )
            refs.update(credential_refs)
            merged["credential_refs"] = refs
            return {"integrator_bundle": merged}
        research_payload = record.get("operational_research")
        if company is None or not isinstance(research_payload, Mapping):
            return {}
        try:
            research = OperationalResearch.model_validate(dict(research_payload))
            bundle = build_integrator_bundle(
                research=research,
                company=company,
                credential_refs=credential_refs,
                validation=None,
                stage="awaiting_provider",
            )
            return {"integrator_bundle": bundle.model_dump(mode="json")}
        except Exception:
            return {}

    def poll_email(self, run_id: str) -> dict[str, Any]:
        """Fetch the outreach thread, classify the latest reply, and advance.

        Closes the gated-outreach loop: reads the Gmail thread by its persisted
        thread id, sanitizes and classifies the latest reply (offline), records a
        sanitized reply event, and moves the run forward. For a "more information
        required" reply it sends one bounded follow-up reply (up to
        ``max_outreach_rounds``) so the back-and-forth continues. Credentials in a
        reply are stored as vault references only; rejections block the run.
        """

        from ops.email.reply_classifier import ReplyClassifier

        context = self._context
        if context._gmail_worker is None:
            raise CredentialSubmissionError("gmail_not_configured")
        settings = context._settings or Settings.from_env()
        lock = context._run_lock(run_id)
        if not lock.acquire(blocking=False):
            raise RunConflictError(run_id, "poll_email")
        try:
            current = context.storage.get_run(run_id)
            if current is None:
                raise KeyError("run was not found")
            if current.get("state_engine") != "canonical_v1":
                raise CredentialSubmissionError("legacy_run_is_read_only")
            try:
                recipe = recipe_from_run(current)
            except RecipeSnapshotError as exc:
                raise CredentialSubmissionError(exc.reason_code) from None
            if recipe.route_kind != "gated":
                raise CredentialSubmissionError("run_is_not_gated")
            if current["status"] not in {"waiting_for_reply", "outreach_sent"}:
                raise CredentialSubmissionError("run_not_awaiting_reply")
            thread_id = current.get("gmail_thread_id")
            if not isinstance(thread_id, str) or not thread_id:
                raise CredentialSubmissionError("gmail_thread_missing")
            app_name = str(current.get("app_name") or "")

            from ops.email.ai import build_email_assistant

            thread = asyncio.run(context._gmail_worker.fetch_thread(thread_id))
            counterpart = settings.outreach_recipient_override
            if counterpart is None:
                # With a controlled sink, that sink is the thread counterpart.
                # With explicitly enabled live vendor email, the immutable
                # reviewed recipe contact is the counterpart. Never fall back to
                # an empty sender (which silently disables reply ingestion), and
                # never infer a sender from untrusted message prose.
                outreach = recipe.outreach
                counterpart = outreach.contact_email if outreach is not None else None
            if not counterpart:
                raise CredentialSubmissionError("outreach_counterpart_missing")
            inbound, rounds = _latest_exact_inbound(
                thread,
                expected_sender=counterpart,
            )
            if inbound is None:
                return self.public_no_reply(current)
            claim = asyncio.run(
                context._gmail_worker.claim_outreach_reply(
                    thread_id=thread_id,
                    message_id=inbound.message_id,
                    expected_sender=counterpart,
                    owner_run_id=run_id,
                    app_slug=recipe.app_slug,
                )
            )
            if claim.status != "acquired" or claim.claim_token is None:
                return self.public_no_reply(current)

            committed = False
            try:
                credential_refs = dict(claim.credential_refs)
                selected_thread = _selected_message_thread(
                    thread,
                    inbound,
                    credential_refs=claim.credential_refs,
                )
                reply_text = _strip_quoted_reply(inbound.sanitized_body)
                heuristic = asyncio.run(
                    ReplyClassifier().classify(
                        app_name=app_name,
                        sanitized_thread=selected_thread,
                    )
                )
                cls = heuristic.classification
                ai_reply_body: str | None = None
                classified_by = "heuristic"
                # The model's own browser-onboarding boolean, recorded but never
                # obeyed; see ``_browser_onboarding_ready``.
                model_start_hint: bool | None = None
                model_reason: str | None = None
                attempts = _EmailModelAttempts()
                assistant = build_email_assistant(settings, attempts=attempts)
                company = self.company_from_record(current)
                if (
                    reply_text
                    and not credential_refs
                    and assistant is not None
                    and company is not None
                ):
                    try:
                        ai = assistant.analyze_reply(
                            app_name=app_name,
                            company=company,
                            reply_text=reply_text,
                        )
                        cls = ai.classification
                        ai_reply_body = (ai.reply_body or "").strip() or None
                        model_start_hint = bool(ai.start_browser_onboarding)
                        classified_by = "llm"
                    except DecisionFailed as failure:
                        # The chain is bounded now, so the model giving up is a
                        # typed outcome rather than the silence it used to be: the
                        # reason code lands in the audit event below next to the
                        # per-provider attempt rows. Falling back to the offline
                        # classifier is still the right move — a vendor reply that
                        # no provider would classify must not park the run on a
                        # human — but it is no longer indistinguishable from a
                        # deployment that has no model configured at all.
                        classified_by = "heuristic"
                        model_reason = failure.reason_code
                    except Exception:
                        # Anything the chain did not classify itself, including a
                        # programming error it deliberately re-raises. Still
                        # swallowed, because the poller must survive every run:
                        # this is per-run intake and a raise here would strand the
                        # reply. It is no longer invisible, which was the actual
                        # defect — a wrong-shaped call now shows up as this code on
                        # the ``reply_received`` event of every polled run.
                        classified_by = "heuristic"
                        model_reason = "model_unusable"

                # The code owns whether a browser gets driven, not the model.
                start_browser_onboarding = _browser_onboarding_ready(
                    classification=cls,
                    official_setup_urls=heuristic.official_setup_urls,
                    credential_refs=credential_refs,
                )

                next_status: RunStatus = "waiting_for_reply"
                follow_up_sent = False
                if cls == "credentials_received" and credential_refs:
                    next_status = "credentials_ready"
                elif cls == "rejected":
                    next_status = "blocked"
                elif cls in {"more_information_required", "meeting_requested"} and (
                    rounds <= settings.max_outreach_rounds
                ):
                    follow_up_body = ai_reply_body or (
                        "Thank you for the quick response. To help us proceed with the API "
                        "integration, we have shared the requested details above and remain "
                        "available for any further information. Could you confirm the developer "
                        "access and credential issuance steps for production?"
                    )
                    try:
                        asyncio.run(
                            context._gmail_worker.reply(
                                thread_id,
                                follow_up_body,
                                idempotency_key=f"{run_id}:followup-{inbound.message_id}",
                            )
                        )
                        follow_up_sent = True
                    except (ProviderContractError, ProviderOperationError):
                        follow_up_sent = False

                with context.storage.unit_of_work() as transaction:
                    record = transaction.get_run(run_id)
                    if record is None:  # pragma: no cover - re-checked under lock
                        raise KeyError("run was not found")
                    revision = int(record.get("state_revision", 0) or 0) + 1
                    previous_status = cast(RunStatus, record["status"])
                    changes: dict[str, object] = {
                        "state_revision": revision,
                        "last_projected_revision": revision,
                        "external_actions": True,
                    }
                    if next_status == "credentials_ready" and credential_refs:
                        # Credentials arrived by email. Advance through the two legal
                        # hops (-> credentials_ready -> completed) and merge only the
                        # authenticated selected message's references.
                        validate_status_transition(
                            previous_status,
                            "credentials_ready",
                            "poll_email",
                        )
                        validate_status_transition(
                            "credentials_ready",
                            "completed",
                            "poll_email",
                        )
                        changes["status"] = "completed"
                        changes.update(
                            self.email_credentials_bundle_change(
                                record,
                                company,
                                credential_refs,
                            )
                        )
                    else:
                        validate_status_transition(
                            previous_status,
                            next_status,
                            "poll_email",
                        )
                        changes["status"] = next_status
                    updated = transaction.update_run(run_id, **changes)
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="reply_received",
                        payload={
                            "classification": cls,
                            "classified_by": classified_by,
                            "message_count": len(thread.messages),
                            "official_setup_urls": list(heuristic.official_setup_urls),
                            "required_next_action": heuristic.required_next_action,
                            "follow_up_sent": follow_up_sent,
                            "rounds": rounds,
                            "external_actions": True,
                            # The code's answer, then the model's, then why the
                            # model did not answer at all, then the chain itself.
                            # Kept as four separate keys deliberately: a run where
                            # the two booleans disagree is the one worth reading,
                            # and collapsing them would hide exactly that.
                            "start_browser_onboarding": start_browser_onboarding,
                            "model_start_browser_hint": model_start_hint,
                            "model_reason_code": model_reason,
                            "model_attempts": list(attempts.rows),
                        },
                    )
                committed = True
                public = _public_run(updated)
                # Non-persisted, non-secret classification for the caller's receipt.
                public["latest_reply_class"] = cls
                public["follow_up_sent"] = follow_up_sent
                # The code-owned predicate, so a caller reads the decision this
                # module made and never has to re-derive it from a model field.
                public["start_browser_onboarding"] = start_browser_onboarding
            except Exception:
                if not committed:
                    context._gmail_worker.release_outreach_reply(
                        thread_id=thread_id,
                        message_id=inbound.message_id,
                        owner_run_id=run_id,
                        claim_token=claim.claim_token,
                    )
                raise

            if not context._gmail_worker.complete_outreach_reply(
                thread_id=thread_id,
                message_id=inbound.message_id,
                owner_run_id=run_id,
                claim_token=claim.claim_token,
            ):
                # The run commit is authoritative and must not be rolled back here;
                # the global reservation remains closed to every other run.
                raise ProviderOperationError(
                    capability="Gmail outreach reply ingestion",
                    reason_code="ingestion_finalize_failed",
                )
            return public
        finally:
            lock.release()


__all__ = [
    "RunEmailContext",
    "RunEmailService",
]
