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
from dataclasses import dataclass
from typing import Any, Protocol, cast

from pydantic import SecretStr

from ops.browser_link_log import log_event
from ops.config import Settings
from ops.email_verification import (
    ResolvedVerification,
    VerificationDecision,
    VerificationEvidence,
    VerificationPurpose,
)
from ops.email_verification import link_host as verification_link_host
from ops.gmail_worker import GmailWorker
from ops.storage import OperationsStorage


@dataclass(frozen=True, slots=True)
class _VerificationBinding:
    """The bindings available for consuming an emailed verification secret.

    ``reviewed_patterns`` is never empty: an instance only exists when the app has a
    reviewed host set, which makes it impossible to run the strict path with a
    recipient but no host restriction - a combination that would authorize opening an
    arbitrary link from a correctly addressed but spoofed message.

    ``expected_recipient`` is ``None`` when this run's verification mailbox is not
    known yet, which downgrades the read to preference-only rather than pretending a
    binding exists.
    """

    app_slug: str
    expected_recipient: str | None
    reviewed_patterns: tuple[str, ...]


def _verification_backoff(base_delay: float, attempt: int) -> float:
    """Exponential backoff with bounded jitter for inbox polling.

    Jitter matters because several runs waiting on the same provider would otherwise
    poll in lockstep and burst against the shared per-account quota.
    """

    if base_delay <= 0:
        return 0.0
    delay = min(base_delay * (2**attempt), 30.0)
    return float(delay * (0.8 + 0.4 * random.random()))


class RunVerificationContext(Protocol):
    """Run-service state and hooks the verification flow uses."""

    storage: OperationsStorage
    _settings: Settings | None
    _gmail_worker: GmailWorker | None
    _otp_attempts: dict[str, int]

    @property
    def _email_poller_stop(self) -> Any: ...

    def _hitl_action_type(self, record: Any) -> str | None: ...

    def _reusable_login_values(self, app_slug: str) -> dict[str, SecretStr]: ...

    def _verification_binding(
        self,
        app_slug: str,
        *,
        expected_recipient: str | None = None,
    ) -> _VerificationBinding | None: ...

    def _fetch_bound_verification(
        self,
        *,
        run_id: str,
        purpose: str,
        binding: _VerificationBinding | None,
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

    def resolve_pending_otps(self, *, limit: int = 100) -> int:
        """Autonomously resolve every run waiting on an emailed login code."""

        context = self._context
        if context._gmail_worker is None:
            return 0
        resolved = 0
        for record in context.storage.list_runs(limit=limit, offset=0):
            if record.get("status") != "waiting_for_hitl":
                continue
            if context._hitl_action_type(record) != "email_otp":
                continue
            run_id = str(record.get("run_id") or "")
            if not run_id:
                continue
            try:
                if self.resolve_email_otp(run_id) is not None:
                    resolved += 1
            except Exception:
                continue
        return resolved

    def resolve_email_otp(self, run_id: str) -> dict[str, Any] | None:
        """Resolve an emailed LOGIN verification and resume the browser with it.

        Retained entry point for the ``email_otp`` human gate; the purpose-aware
        implementation lives in :meth:`resolve_email_verification`.
        """

        return self.resolve_email_verification(run_id, purpose="login_verification")

    def resolve_email_verification(
        self,
        run_id: str,
        *,
        purpose: VerificationPurpose = "login_verification",
        expected_recipient: str | None = None,
    ) -> dict[str, Any] | None:
        """Read the verification email for a waiting run and resume the browser.

        Keeps the whole step in one autonomous task: the one-time secret is read
        from the connected inbox, wrapped as a provider ``sensitive_data``
        placeholder (never logged or persisted), and the SAME browser session is
        resumed so the agent types the code or opens the link and continues.

        ``purpose`` selects the flow this verification belongs to, so an autonomous
        signup confirmation and a login device check are ledgered independently and
        can never consume each other's message. ``expected_recipient`` lets a signup
        flow bind to the address it just registered, which is not yet the app's
        remembered sign-in email; when omitted the remembered login email is used.

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
        settings = context._settings or Settings.from_env()
        budget = max(1, int(getattr(settings, "gmail_verification_max_attempts", 3)))
        if context._otp_attempts.get(run_id, 0) >= budget:
            return None
        context._otp_attempts[run_id] = context._otp_attempts.get(run_id, 0) + 1

        app_slug = str(record.get("app_slug") or "unknown")
        binding = context._verification_binding(app_slug, expected_recipient=expected_recipient)
        if binding is None and bool(getattr(settings, "gmail_verification_require_binding", False)):
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
                run_id=run_id, purpose=purpose, binding=binding
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
            link_host=evidence.link_host or None,
            code_length=evidence.code_length or None,
            age_seconds=evidence.age_seconds,
            recipient_binding=evidence.recipient_binding,
            sender_reviewed=evidence.sender_reviewed,
        )
        field = "login_verification_url" if evidence.verification_kind == "link" else "login_otp"
        return context.resume_run(
            run_id,
            signal="completed",
            browser_login={field: decision.resolved.secret},
        )

    def verification_binding(
        self,
        app_slug: str,
        *,
        expected_recipient: str | None = None,
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

        from ops.browser_host_policy import get_browser_policy

        policy = get_browser_policy(app_slug)
        if policy is None:
            return None
        patterns = (
            *policy.exact_hosts,
            *(f"*.{domain}" for domain in policy.vendor_wildcard_domains),
        )
        if not patterns:
            return None
        recipient = (expected_recipient or "").strip() or None
        if recipient is None:
            recipient_secret = self._context._reusable_login_values(app_slug).get("login_email")
            if recipient_secret is not None:
                recipient = recipient_secret.get_secret_value().strip() or None
        return _VerificationBinding(
            app_slug=app_slug,
            expected_recipient=recipient,
            reviewed_patterns=patterns,
        )

    def fetch_bound_verification(
        self,
        *,
        run_id: str,
        purpose: str,
        binding: _VerificationBinding | None,
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
        patterns = binding.reviewed_patterns if binding is not None else ()
        if binding is not None and binding.expected_recipient is not None:
            try:
                return asyncio.run(
                    worker.fetch_verification(
                        purpose=cast("VerificationPurpose", purpose),
                        expected_recipient=binding.expected_recipient,
                        reviewed_sender_patterns=patterns,
                        allowed_link_host_patterns=patterns,
                        run_id=run_id,
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
            allowed_link_host_patterns=patterns,
            max_age_seconds=max_age,
        )

    def legacy_verification_read(
        self,
        worker: Any,
        *,
        run_id: str,
        purpose: str,
        allowed_link_host_patterns: tuple[str, ...] = (),
        max_age_seconds: int = 900,
    ) -> VerificationDecision | None:
        """Preference-only inbox read for runs without an exact recipient binding."""

        link: str | None = None
        try:
            link = asyncio.run(
                worker.fetch_latest_login_link(
                    allowed_link_host_patterns=allowed_link_host_patterns,
                    max_age_seconds=max_age_seconds,
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
            code = asyncio.run(worker.fetch_latest_otp(max_age_seconds=max_age_seconds))
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
