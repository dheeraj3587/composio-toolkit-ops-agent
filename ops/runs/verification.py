"""Emailed verification (one-time code or magic sign-in link) resolution.

A verification is resolved as ONE autonomous step: the secret is read from the
connected inbox, wrapped as a provider ``sensitive_data`` placeholder that is never
logged or persisted, and the SAME browser session is resumed so the agent types the
code or opens the link and continues.

Two properties are load-bearing and preserved exactly. Binding: a message is only
trusted for this run when it can be tied to it, and the reviewed sender and
link-host patterns come from the same per-app browser policy the navigation
boundary enforces, so this boundary can never authorize a host the browser would
refuse to open. Truthfulness: whenever the message cannot be found, bound, or is
stale, the run is left waiting for a human rather than advanced on a guess.

``resolve_email_verification`` deliberately reaches back through the context for
``_verification_binding`` and ``_fetch_bound_verification`` instead of calling this
module's own methods, so an instance-level override of either hook (which the tests
rely on) is still honored.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, cast

from pydantic import SecretStr

from ops.browser.link_log import log_event
from ops.core.config import Settings
from ops.core.storage import OperationsStorage
from ops.email.verification import (
    ResolvedVerification,
    VerificationDecision,
    VerificationEvidence,
    VerificationPurpose,
)
from ops.email.verification import link_host as verification_link_host
from ops.gmail.worker import GmailWorker
from ops.recipes.app_recipes import get_app_recipe
from ops.runs.errors import CredentialSubmissionError, RunConflictError


@dataclass(frozen=True, slots=True)
class _VerificationBinding:
    """The bindings available for consuming an emailed verification secret.

    Sender and link patterns are separate reviewed sets. This prevents a vendor's
    broad email-sending domain from silently becoming a browser-navigation grant.

    ``expected_recipient`` is ``None`` when this run's verification mailbox is not
    known yet, which downgrades the read to preference-only rather than pretending a
    binding exists.
    """

    app_slug: str
    expected_recipient: str | None
    reviewed_sender_patterns: tuple[str, ...]
    allowed_link_host_patterns: tuple[str, ...]


def _verification_backoff(base_delay: float, attempt: int) -> float:
    """Exponential backoff with bounded jitter for inbox polling.

    Jitter matters because several runs waiting on the same provider would otherwise
    poll in lockstep and burst against the shared per-account quota.
    """

    if base_delay <= 0:
        return 0.0
    delay = min(base_delay * (2**attempt), 30.0)
    return float(delay * (0.8 + 0.4 * random.random()))


def _verification_window_open(record: Mapping[str, object], max_age_seconds: int) -> bool:
    """Bound repeated inbox sweeps to the age of the waiting run.

    The per-call retry count is a polling batch size, not a lifetime budget. The
    previous in-memory counter permanently abandoned a still-fresh message after a
    few sweeps. ``verification_requested_at`` is persisted inside the active HITL
    challenge, so this remains bounded, restart-safe, and tied to that challenge.
    """

    requested_at_ms = _verification_requested_at_ms(record)
    if requested_at_ms is None:
        return False
    started = datetime.fromtimestamp(requested_at_ms / 1000, tz=UTC)
    now = datetime.now(UTC)
    return started - timedelta(seconds=60) <= now < started + timedelta(seconds=max_age_seconds)


def _verification_requested_at_ms(record: Mapping[str, object]) -> int | None:
    """Read the persisted timestamp for the exact browser challenge."""

    hitl = record.get("hitl_request")
    raw = hitl.get("verification_requested_at") if isinstance(hitl, Mapping) else None
    if not isinstance(raw, str) or not raw:
        return None
    try:
        started = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if started.tzinfo is None:
        started = started.replace(tzinfo=UTC)
    return int(started.astimezone(UTC).timestamp() * 1000)


class RunVerificationContext(Protocol):
    """Run-service state and hooks the verification flow uses."""

    storage: OperationsStorage
    _settings: Settings | None
    _gmail_worker: GmailWorker | None
    _otp_attempts: dict[str, int]

    @property
    def _email_poller_stop(self) -> Any: ...

    def _hitl_action_type(self, record: Any) -> str | None: ...

    def _reusable_login_values(self, app_slug: str, account_ref: str) -> dict[str, SecretStr]: ...

    def _staged_signup_login_values(
        self,
        *,
        app_slug: str,
        account_ref: str,
        run_id: str,
    ) -> dict[str, SecretStr]: ...

    def _verification_binding(
        self,
        app_slug: str,
        *,
        expected_recipient: str | None = None,
        account_ref: str | None = None,
    ) -> _VerificationBinding | None: ...

    def _fetch_bound_verification(
        self,
        *,
        run_id: str,
        purpose: str,
        binding: _VerificationBinding | None,
        verification_requested_at_ms: int,
    ) -> VerificationDecision | None: ...

    def resume_run(
        self,
        run_id: str,
        *,
        signal: str = "completed",
        browser_login: Any = None,
    ) -> dict[str, Any]: ...


class RunVerificationService:
    """Resolve emailed verifications and resume the waiting browser session."""

    def __init__(self, context: RunVerificationContext) -> None:
        self._context = context

    def resolve_pending_otps(
        self,
        *,
        limit: int = 1_000,
        max_attempts_per_run: int | None = None,
    ) -> int:
        """Autonomously resolve bounded runs waiting on an emailed login code."""

        context = self._context
        if context._gmail_worker is None or limit <= 0:
            return 0
        resolved = 0
        page_size = min(100, limit)
        for offset in range(0, limit, page_size):
            records = context.storage.list_runs(
                limit=min(page_size, limit - offset),
                offset=offset,
            )
            if not records:
                break
            for record in records:
                if record.get("status") != "waiting_for_hitl":
                    continue
                if context._hitl_action_type(record) != "email_otp":
                    continue
                run_id = str(record.get("run_id") or "")
                if not run_id:
                    continue
                try:
                    if (
                        self.resolve_email_otp(
                            run_id,
                            max_attempts=max_attempts_per_run,
                        )
                        is not None
                    ):
                        resolved += 1
                except Exception:
                    continue
            if len(records) < page_size:
                break
        return resolved

    def resolve_email_otp(
        self,
        run_id: str,
        *,
        max_attempts: int | None = None,
    ) -> dict[str, Any] | None:
        """Resolve an emailed LOGIN verification and resume the browser with it.

        Retained entry point for the ``email_otp`` human gate; the purpose-aware
        implementation lives in :meth:`resolve_email_verification`.
        """
        record = self._context.storage.get_run(run_id)
        request = record.get("request") if isinstance(record, dict) else None
        account_mode = request.get("account_mode") if isinstance(request, dict) else None
        purpose: VerificationPurpose = (
            "signup_confirmation" if account_mode == "create_account" else "login_verification"
        )
        return self.resolve_email_verification(
            run_id,
            purpose=purpose,
            max_attempts=max_attempts,
        )

    def resolve_email_verification(
        self,
        run_id: str,
        *,
        purpose: VerificationPurpose = "login_verification",
        expected_recipient: str | None = None,
        max_attempts: int | None = None,
    ) -> dict[str, Any] | None:
        """Read the verification email for a waiting run and resume the browser.

        Keeps the whole step in one autonomous task: the one-time secret is read
        from the connected inbox, wrapped as a provider ``sensitive_data``
        placeholder (never logged or persisted), and the SAME browser session is
        resumed so the agent types the code or opens the link and continues.

        ``purpose`` describes the flow this verification belongs to.
        ``expected_recipient`` lets a signup flow bind to the address it just
        registered, which is not yet the app's remembered sign-in email; when
        omitted, a signup reads its run-scoped staged identity and an existing
        account reads its remembered login email. Message consumption itself is
        global to the connected Gmail account, so no other run or purpose can
        replay the same immutable provider message id.

        A magic SIGN-IN LINK takes priority over a numeric code because providers
        such as HubSpot device verification send a one-time link that must be opened
        in the agent's own live session to finish signing in.

        Returns ``None`` - leaving the run truthfully waiting for a human - whenever
        the message cannot be found, cannot be bound to this run, or is stale.
        """

        context = self._context
        if context._gmail_worker is None:
            return None
        record = context.storage.get_run(run_id)
        if record is None or record.get("status") != "waiting_for_hitl":
            return None
        if context._hitl_action_type(record) != "email_otp":
            return None
        verification_requested_at_ms = _verification_requested_at_ms(record)
        if verification_requested_at_ms is None:
            log_event(
                "browser.verification.challenge_timestamp_missing",
                run_id=run_id,
            )
            return None
        settings = context._settings or Settings.from_env()
        configured_budget = max(
            1,
            int(getattr(settings, "gmail_verification_max_attempts", 3)),
        )
        budget = (
            configured_budget
            if max_attempts is None
            else min(configured_budget, max(1, int(max_attempts)))
        )
        max_age = max(
            1,
            int(getattr(settings, "gmail_verification_max_age_seconds", 900)),
        )
        if not _verification_window_open(record, max_age):
            return None
        context._otp_attempts[run_id] = context._otp_attempts.get(run_id, 0) + 1

        app_slug = str(record.get("app_slug") or "unknown")
        account_ref = str(record.get("browser_account_ref") or "") or None
        request = record.get("request")
        account_mode = request.get("account_mode") if isinstance(request, Mapping) else None
        if expected_recipient is None and account_mode == "create_account" and account_ref:
            staged = context._staged_signup_login_values(
                app_slug=app_slug,
                account_ref=account_ref,
                run_id=run_id,
            )
            signup_email = staged.get("login_email")
            if signup_email is not None:
                expected_recipient = signup_email.get_secret_value()
        binding = context._verification_binding(
            app_slug,
            expected_recipient=expected_recipient,
            account_ref=account_ref,
        )
        if (binding is None or binding.expected_recipient is None) and bool(
            getattr(settings, "gmail_verification_require_binding", False)
        ):
            # Fail closed: this deployment requires proof that the message belongs
            # to this run, and that proof is unavailable.
            log_event(
                "browser.verification.binding_required",
                run_id=run_id,
                app_slug=app_slug,
                purpose=purpose,
            )
            return None

        # The verification email routinely lags the browser request, so poll a few
        # times with jittered backoff. The wait is interruptible so a shutdown does
        # not have to sit through the whole window.
        decision: VerificationDecision | None = None
        base_delay = float(getattr(settings, "gmail_verification_poll_seconds", 5.0))
        for attempt in range(budget):
            decision = context._fetch_bound_verification(
                run_id=run_id,
                purpose=purpose,
                binding=binding,
                verification_requested_at_ms=verification_requested_at_ms,
            )
            if decision is not None and decision.is_resolved:
                break
            if attempt == budget - 1:
                break
            if context._email_poller_stop.wait(_verification_backoff(base_delay, attempt)):
                break

        if decision is None or decision.resolved is None:
            log_event(
                "browser.verification.unresolved",
                run_id=run_id,
                app_slug=app_slug,
                purpose=purpose,
                reason_code=(decision.reason_code if decision is not None else "unavailable"),
                recipient_bound=binding is not None and binding.expected_recipient is not None,
            )
            return None

        evidence = decision.resolved.evidence
        log_event(
            "browser.verification.resolved",
            run_id=run_id,
            app_slug=app_slug,
            purpose=purpose,
            # Deliberately not named "secret_*": the sanitized logger redacts any
            # field whose NAME looks credential-bearing, which would hide this
            # otherwise inert diagnostic.
            verification_kind=evidence.verification_kind,
            sender_domain=evidence.sender_domain or None,
            sender_authentication=evidence.sender_authentication,
            link_host=evidence.link_host or None,
            code_length=evidence.code_length or None,
            age_seconds=evidence.age_seconds,
            recipient_binding=evidence.recipient_binding,
            sender_reviewed=evidence.sender_reviewed,
        )
        field = "login_verification_url" if evidence.verification_kind == "link" else "login_otp"
        try:
            result = context.resume_run(
                run_id,
                signal="completed",
                browser_login={field: decision.resolved.secret},
            )
        except (CredentialSubmissionError, RunConflictError, KeyError):
            # These failures happen before the browser accepts the one-time value,
            # so the reservation can safely be retried.
            release = getattr(context._gmail_worker, "release_verification_claim", None)
            if callable(release):
                release(run_id=run_id, purpose=purpose, evidence=evidence)
            raise
        except Exception:
            # Transport/provider failures may occur after submission. Refuse replay
            # until an operator reconciles the provider state.
            mark_unknown = getattr(
                context._gmail_worker,
                "mark_verification_claim_outcome_unknown",
                None,
            )
            if callable(mark_unknown):
                mark_unknown(run_id=run_id, purpose=purpose, evidence=evidence)
            raise

        definite_pre_use_failure = bool(
            isinstance(result, dict)
            and result.get("status") == "configuration_required"
            and result.get("phase") in {"session_lost", "browser_unavailable"}
        )
        if definite_pre_use_failure:
            release = getattr(context._gmail_worker, "release_verification_claim", None)
            if callable(release):
                release(run_id=run_id, purpose=purpose, evidence=evidence)
        else:
            complete = getattr(context._gmail_worker, "complete_verification_claim", None)
            if callable(complete):
                complete(run_id=run_id, purpose=purpose, evidence=evidence)
        return result

    def verification_binding(
        self,
        app_slug: str,
        *,
        expected_recipient: str | None = None,
        account_ref: str | None = None,
    ) -> _VerificationBinding | None:
        """Resolve the bindings available for an emailed verification.

        Returns ``None`` only when the app has no reviewed host set at all, because
        without one there is nothing to restrict a magic link to. When a reviewed set
        exists but the run's recipient is unknown, a binding is still returned with
        ``expected_recipient=None``: the link host and sender preference still apply,
        but the strict recipient-bound path is not available.

        The expected recipient is the address the provider sends verification to -
        supplied explicitly by a signup flow for the identity it just registered, or
        otherwise the app's remembered sign-in email. Reviewed sender and link-host
        patterns come from the same per-app browser policy the navigation boundary
        enforces, so the email boundary can never authorize a host the browser would
        refuse to open.
        """

        from ops.browser.host_policy import get_browser_policy

        policy = get_browser_policy(app_slug)
        if policy is None:
            return None
        recipe = get_app_recipe(app_slug)
        browser = recipe.browser if recipe is not None else None
        fallback_patterns = (
            *policy.exact_hosts,
            *(f"*.{domain}" for domain in policy.vendor_wildcard_domains),
        )
        sender_patterns = (
            browser.verification_sender_domains
            if browser is not None and browser.verification_sender_domains
            else fallback_patterns
        )
        link_patterns = (
            browser.verification_link_hosts
            if browser is not None and browser.verification_link_hosts
            else fallback_patterns
        )
        if not sender_patterns or not link_patterns:
            return None
        recipient = (expected_recipient or "").strip() or None
        if recipient is None and account_ref is not None:
            recipient_secret = self._context._reusable_login_values(app_slug, account_ref).get(
                "login_email"
            )
            if recipient_secret is not None:
                recipient = recipient_secret.get_secret_value().strip() or None
        return _VerificationBinding(
            app_slug=app_slug,
            expected_recipient=recipient,
            reviewed_sender_patterns=tuple(sender_patterns),
            allowed_link_host_patterns=tuple(link_patterns),
        )

    def fetch_bound_verification(
        self,
        *,
        run_id: str,
        purpose: str,
        binding: _VerificationBinding | None,
        verification_requested_at_ms: int,
    ) -> VerificationDecision | None:
        """Read one verification message, preferring the fully bound path.

        With an exact recipient every check is mandatory (recency, recipient,
        reviewed sender, reviewed link host) and the message is claimed exactly once
        in the effect ledger, so one expired code can never be replayed in a loop.
        Without a recipient the legacy read is used: still under a real freshness
        bound, and still restricted to reviewed link hosts when the app has a
        reviewed set, but unable to prove the message belongs to this run.
        """

        worker = self._context._gmail_worker
        if worker is None:
            return None
        settings = self._context._settings or Settings.from_env()
        max_age = int(getattr(settings, "gmail_verification_max_age_seconds", 900))
        sender_patterns = binding.reviewed_sender_patterns if binding is not None else ()
        link_patterns = binding.allowed_link_host_patterns if binding is not None else ()
        if binding is not None and binding.expected_recipient is not None:
            try:
                return asyncio.run(
                    worker.fetch_verification(
                        purpose=cast("VerificationPurpose", purpose),
                        expected_recipient=binding.expected_recipient,
                        reviewed_sender_patterns=sender_patterns,
                        allowed_link_host_patterns=link_patterns,
                        run_id=run_id,
                        verification_requested_at_ms=verification_requested_at_ms,
                        max_age_seconds=max_age,
                    )
                )
            except Exception:
                log_event("browser.verification.error", level=40, run_id=run_id)
                return None
        return self.legacy_verification_read(
            worker,
            run_id=run_id,
            purpose=purpose,
            allowed_link_host_patterns=link_patterns,
            max_age_seconds=max_age,
            verification_requested_at_ms=verification_requested_at_ms,
        )

    def legacy_verification_read(
        self,
        worker: Any,
        *,
        run_id: str,
        purpose: str,
        allowed_link_host_patterns: tuple[str, ...] = (),
        max_age_seconds: int = 900,
        verification_requested_at_ms: int,
    ) -> VerificationDecision | None:
        """Preference-only inbox read for runs without an exact recipient binding."""

        link: str | None = None
        try:
            link = asyncio.run(
                worker.fetch_latest_login_link(
                    allowed_link_host_patterns=allowed_link_host_patterns,
                    max_age_seconds=max_age_seconds,
                    verification_requested_at_ms=verification_requested_at_ms,
                )
            )
        except Exception:
            link = None
        if link:
            return VerificationDecision(
                resolved=ResolvedVerification(
                    secret=SecretStr(link),
                    evidence=VerificationEvidence(
                        purpose=cast("VerificationPurpose", purpose),
                        verification_kind="link",
                        message_id=f"legacy:{run_id}"[:200],
                        recipient_binding="no_match",
                        sender_reviewed=False,
                        received_at_ms=0,
                        age_seconds=0,
                        link_host=verification_link_host(link),
                    ),
                ),
                reason_code="verification_resolved_unbound",
            )
        try:
            code = asyncio.run(
                worker.fetch_latest_otp(
                    max_age_seconds=max_age_seconds,
                    verification_requested_at_ms=verification_requested_at_ms,
                )
            )
        except Exception:
            code = None
        if code:
            return VerificationDecision(
                resolved=ResolvedVerification(
                    secret=SecretStr(code),
                    evidence=VerificationEvidence(
                        purpose=cast("VerificationPurpose", purpose),
                        verification_kind="code",
                        message_id=f"legacy:{run_id}"[:200],
                        recipient_binding="no_match",
                        sender_reviewed=False,
                        received_at_ms=0,
                        age_seconds=0,
                        code_length=len(code),
                    ),
                ),
                reason_code="verification_resolved_unbound",
            )
        return VerificationDecision(resolved=None, reason_code="verification_message_not_found")


__all__ = [
    "RunVerificationContext",
    "RunVerificationService",
]
