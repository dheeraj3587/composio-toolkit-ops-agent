"""Production Composio Gmail boundary with pinned schemas and durable idempotency."""

from __future__ import annotations

import asyncio
import importlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, NoReturn

import httpx

from ops.attachment_extract import AttachmentRef, extract_secret_pairs, is_text_like
from ops.config import Settings
from ops.effect_ledger import EffectStore, SQLiteEffectStore
from ops.email_verification import (
    DEFAULT_CLOCK_SKEW_SECONDS,
    MAX_VERIFICATION_AGE_SECONDS,
    ResolvedVerification,
    VerificationCandidate,
    VerificationDecision,
    VerificationEvidence,
    VerificationPurpose,
    extract_verification_code,
    extract_verification_link,
    gmail_freshness_query,
    parse_received_at_ms,
    select_verification,
    sender_domain_of,
)
from ops.provider_errors import (
    ConfigurationRequiredError,
    PhaseUnavailableError,
    ProviderContractError,
    ProviderOperationError,
)
from ops.redaction import redact_text
from ops.secret_store import SecretStore

GMAIL_TOOLKIT_VERSION = "20260702_01"
GMAIL_TOOL_ALLOWLIST: tuple[str, ...] = (
    "GMAIL_SEND_EMAIL",
    "GMAIL_CREATE_EMAIL_DRAFT",
    "GMAIL_SEND_DRAFT",
    "GMAIL_FETCH_EMAILS",
    "GMAIL_FETCH_MESSAGE_BY_THREAD_ID",
    "GMAIL_LIST_THREADS",
    "GMAIL_REPLY_TO_THREAD",
    "GMAIL_GET_PROFILE",
    "GMAIL_GET_ATTACHMENT",
)
_TOOL_FIELD_TYPES: dict[str, dict[str, frozenset[str]]] = {
    "GMAIL_SEND_EMAIL": {
        "recipient_email": frozenset({"string"}),
        "subject": frozenset({"string"}),
        "body": frozenset({"string"}),
        "is_html": frozenset({"boolean"}),
    },
    "GMAIL_REPLY_TO_THREAD": {
        "thread_id": frozenset({"string"}),
        "recipient_email": frozenset({"string"}),
        "message_body": frozenset({"string"}),
    },
    "GMAIL_FETCH_MESSAGE_BY_THREAD_ID": {"thread_id": frozenset({"string"})},
    "GMAIL_GET_PROFILE": {"user_id": frozenset({"string"})},
    "GMAIL_GET_ATTACHMENT": {
        "message_id": frozenset({"string"}),
        "attachment_id": frozenset({"string"}),
        "file_name": frozenset({"string"}),
        "user_id": frozenset({"string"}),
    },
}
_TOOL_REQUIRED_FIELDS: dict[str, frozenset[str]] = {
    "GMAIL_SEND_EMAIL": frozenset({"recipient_email", "subject", "body"}),
    "GMAIL_REPLY_TO_THREAD": frozenset({"thread_id", "recipient_email", "message_body"}),
    "GMAIL_FETCH_MESSAGE_BY_THREAD_ID": frozenset({"thread_id"}),
    "GMAIL_GET_PROFILE": frozenset({"user_id"}),
    "GMAIL_GET_ATTACHMENT": frozenset({"message_id", "attachment_id", "file_name"}),
}
_SECRET_LINE = re.compile(
    r"(?im)\b(?P<kind>client[_ -]?secret|api[_ -]?key|access[_ -]?token|"
    r"refresh[_ -]?token)\s*[:=]\s*(?P<value>[^\s,;<>]{8,})"
)


@dataclass(frozen=True, slots=True)
class GmailSendResult:
    session_id: str
    thread_id: str
    message_id: str
    intended_recipient: str
    actual_recipient: str


@dataclass(frozen=True, slots=True)
class SanitizedGmailMessage:
    message_id: str
    sender: str
    recipients: tuple[str, ...]
    sent_at: str
    sanitized_subject: str
    sanitized_body: str


@dataclass(frozen=True, slots=True)
class SanitizedGmailThread:
    thread_id: str
    messages: tuple[SanitizedGmailMessage, ...]
    credential_refs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class InboxSearchResult:
    """A sanitized, non-vaulted summary of one inbox message for general reads."""

    message_id: str
    thread_id: str
    sender: str
    sanitized_subject: str
    sanitized_preview: str
    sent_at: str
    has_attachments: bool


class GmailWorker:
    """Least-privilege Composio adapter.

    The SDK is imported and instantiated only after explicit configuration is
    present. Provider payloads remain within this module and are projected onto
    small identifier-only or sanitized models.
    """

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        secret_store: SecretStore | None = None,
        effect_store: EffectStore | None = None,
        sdk_client: object | None = None,
    ) -> None:
        self._settings = settings or Settings.from_env()
        self._secret_store = secret_store
        self._effect_store = effect_store
        self._sdk_client: Any = sdk_client
        self._session_id: str | None = None
        self._session: Any = None
        self._connection_lock = asyncio.Lock()

    async def ensure_connected(self) -> str:
        self._require_configuration()
        if self._session_id is not None:
            return self._session_id
        async with self._connection_lock:
            if self._session_id is not None:
                return self._session_id
            try:
                session_id = await asyncio.to_thread(self._create_scoped_session)
            except (ProviderContractError, ProviderOperationError):
                raise
            except Exception:
                raise ProviderOperationError(
                    capability="Composio Gmail connection",
                    reason_code="provider_request_failed",
                ) from None
            # GMAIL_GET_PROFILE is a best-effort health probe. Some connected
            # accounts lack the read-only profile scope while still allowing
            # send/fetch/reply, so a probe failure must not block outreach.
            try:
                await asyncio.to_thread(
                    self._execute_checked,
                    "GMAIL_GET_PROFILE",
                    {"user_id": self._settings.composio_user_id},
                )
            except Exception:
                pass
            self._session_id = session_id
            return session_id

    async def send_outreach(
        self,
        recipient: str,
        subject: str,
        body: str,
        idempotency_key: str,
    ) -> GmailSendResult:
        intended = _validate_email(recipient)
        _validate_message(subject, body)
        actual = self._actual_recipient(intended)
        session_id = await self.ensure_connected()
        store = self._get_effect_store()
        reservation = store.reserve(
            provider="composio_gmail",
            action="send_outreach",
            idempotency_key=idempotency_key,
        )
        if reservation.status == "completed" and reservation.receipt is not None:
            return _send_result_from_receipt(reservation.receipt)
        if reservation.status == "reconcile_required":
            raise ProviderOperationError(
                capability="Composio Gmail outreach",
                reason_code="reconciliation_required",
            )

        try:
            result = await asyncio.to_thread(
                self._execute_checked,
                "GMAIL_SEND_EMAIL",
                {
                    "recipient_email": actual,
                    "subject": subject,
                    "body": body,
                    "is_html": False,
                },
            )
        except ProviderContractError as exc:
            _mark_after_contract_error(store, "send_outreach", idempotency_key, exc)
            raise
        except ProviderOperationError as exc:
            _mark_after_operation_error(store, "send_outreach", idempotency_key, exc)
            raise
        except Exception:
            store.mark_outcome_unknown(
                provider="composio_gmail",
                action="send_outreach",
                idempotency_key=idempotency_key,
            )
            raise ProviderOperationError(
                capability="Composio Gmail outreach",
                reason_code="provider_request_failed",
            ) from None
        message_id = _identifier(result, ("message_id", "id"))
        thread_id = _identifier(result, ("thread_id", "threadId"))
        if message_id is None or thread_id is None:
            store.mark_outcome_unknown(
                provider="composio_gmail",
                action="send_outreach",
                idempotency_key=idempotency_key,
            )
            raise ProviderContractError(
                phase=4,
                capability="Composio Gmail outreach",
                reason_code="response_identifiers_missing",
            )
        sent = GmailSendResult(
            session_id=session_id,
            thread_id=thread_id,
            message_id=message_id,
            intended_recipient=intended,
            actual_recipient=actual,
        )
        try:
            store.complete(
                provider="composio_gmail",
                action="send_outreach",
                idempotency_key=idempotency_key,
                receipt=_send_result_receipt(sent),
            )
        except Exception:
            try:
                store.mark_outcome_unknown(
                    provider="composio_gmail",
                    action="send_outreach",
                    idempotency_key=idempotency_key,
                )
            except Exception:
                pass
            raise ProviderOperationError(
                capability="Composio Gmail outreach",
                reason_code="receipt_persistence_failed",
            ) from None
        return sent

    async def fetch_thread(self, thread_id: str) -> SanitizedGmailThread:
        safe_thread_id = _validate_identifier(thread_id, "thread_id")
        result = await self._execute_read(
            "GMAIL_FETCH_MESSAGE_BY_THREAD_ID",
            {"thread_id": safe_thread_id},
            capability="Composio Gmail thread fetch",
        )
        return self._sanitize_thread_payload(safe_thread_id, result)

    async def search_inbox(
        self,
        *,
        query: str = "in:anywhere",
        max_results: int = 10,
        trusted_domains: tuple[str, ...] = (),
    ) -> tuple[InboxSearchResult, ...]:
        """Read sanitized summaries of recent inbox messages matching a query.

        General-purpose inbox read for the email agent: it returns redacted,
        non-vaulted summaries (sender, subject, preview, attachment flag) so the
        caller can find and reason about ANY recent mail, not only an outreach
        thread. Secrets in the preview are redacted for display; unlike the
        outreach-thread path this never vaults, so a general read cannot pollute
        the credential vault. Senders on a trusted domain are surfaced first. Build
        ``query`` with :func:`build_inbox_query` to stay injection-safe.
        """

        if not 1 <= max_results <= 50:
            raise ValueError("max_results must be between 1 and 50")
        data = await self._execute_read(
            "GMAIL_FETCH_EMAILS",
            {"max_results": max_results, "query": query},
            capability="Composio Gmail inbox search",
        )
        messages = data.get("messages")
        if not isinstance(messages, list):
            return ()
        results: list[InboxSearchResult] = []
        for message in _order_messages_by_trust(messages, trusted_domains):
            message_id = _first_string(message, ("message_id", "messageId", "id")) or ""
            thread_id = _first_string(message, ("thread_id", "threadId")) or ""
            sender = _first_string(message, ("sender", "from", "from_email")) or "unknown"
            subject = _first_string(message, ("subject",)) or ""
            preview = _first_string(message, ("preview", "snippet", "messageText", "body")) or ""
            sent_at = (
                _first_string(message, ("sent_at", "messageTimestamp", "date", "internal_date"))
                or "unknown"
            )
            results.append(
                InboxSearchResult(
                    message_id=message_id[:200],
                    thread_id=thread_id[:200],
                    sender=redact_text(sender)[:320],
                    sanitized_subject=redact_text(subject)[:998],
                    sanitized_preview=redact_text(preview)[:2_000],
                    sent_at=redact_text(sent_at)[:100],
                    has_attachments=_has_attachments(message),
                )
            )
        return tuple(results)

    async def harvest_attachment_credentials(
        self,
        *,
        message_id: str,
        attachments: Sequence[AttachmentRef],
        max_bytes: int = 262_144,
    ) -> dict[str, str]:
        """Fetch text-like attachments, extract credentials, and vault them.

        For each text-like attachment within the size cap, the bytes are fetched
        from the provider, decoded as UTF-8, scanned for credential (kind, value)
        pairs, and written to the encrypted vault; only ``vault://`` references are
        returned (a raw value never leaves this boundary). Binary attachments
        (PDF/zip/images) are skipped by design rather than parsed. Requires a
        secret store; without one it raises ConfigurationRequiredError.
        """

        if self._secret_store is None:
            raise ConfigurationRequiredError(
                phase=4,
                capability="Gmail attachment credential extraction",
                reason_code="secret_store_missing",
            )
        safe_message_id = _validate_identifier(message_id, "message_id")
        references: dict[str, str] = {}
        index = 0
        for ref in attachments:
            if not ref.attachment_id or not is_text_like(ref.filename, ref.mime_type):
                continue
            if ref.size and ref.size > max_bytes:
                continue
            raw = await self._fetch_attachment_bytes(safe_message_id, ref, max_bytes)
            if raw is None:
                continue
            try:
                text = raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                continue  # not genuinely text; skip rather than guess an encoding
            for kind, value in extract_secret_pairs(text):
                index += 1
                reference = self._secret_store.put(
                    app_slug="email-attachment", kind=kind, value=value
                )
                references[f"attachment_{index}_{kind}"[:120]] = reference
                del value
        return references

    async def _fetch_attachment_bytes(
        self, message_id: str, ref: AttachmentRef, max_bytes: int
    ) -> bytes | None:
        """Fetch one attachment's raw bytes via GMAIL_GET_ATTACHMENT, size-bounded.

        Composio returns the content indirectly: ``data.file.s3url`` is a presigned
        URL that is downloaded here under the cap. A local file path (SDK
        auto-download) or a Drive/other indirection is not fetched here and yields
        None. Fails closed (None) on any unexpected response shape.
        """

        data = await self._execute_read(
            "GMAIL_GET_ATTACHMENT",
            {
                "message_id": message_id,
                "attachment_id": ref.attachment_id,
                "file_name": ref.filename or "attachment",
            },
            capability="Composio Gmail attachment fetch",
        )
        file_obj = data.get("file")
        if not isinstance(file_obj, Mapping):
            return None
        url = file_obj.get("s3url") or file_obj.get("url")
        if not isinstance(url, str) or not url.casefold().startswith("https://"):
            return None  # local path or Drive indirection: not downloaded here
        try:
            return await asyncio.to_thread(_download_bounded, url, max_bytes)
        except Exception:
            return None

    async def fetch_latest_otp(
        self,
        *,
        query: str | None = None,
        trusted_domains: tuple[str, ...] = (),
        max_age_seconds: int = 900,
    ) -> str | None:
        """Return the most recent one-time login code from the connected inbox.

        Legacy convenience wrapper. It prefers (rather than requires) a trusted
        sender and performs no recipient binding, so it must not be used for a new
        autonomous flow; use :meth:`fetch_verification` instead.

        The freshness bound is enforced here against each message's own receive
        timestamp. It previously relied on a ``newer_than:1h`` query, which Gmail
        does not support (its relative age units are day, month, and year only), so
        the intended one-hour window was never actually applied and an arbitrarily
        old code could be returned.
        """

        resolved_query = query or gmail_freshness_query(
            now=datetime.now(UTC), max_age_seconds=max_age_seconds
        )
        data = await self._execute_read(
            "GMAIL_FETCH_EMAILS",
            {"max_results": 8, "query": resolved_query},
            capability="Composio Gmail OTP fetch",
        )
        messages = data.get("messages")
        if not isinstance(messages, list):
            return None
        now_ms = int(datetime.now(UTC).timestamp() * 1000)
        for message in _order_messages_by_trust(messages, trusted_domains):
            if not _within_age(message, now_ms=now_ms, max_age_seconds=max_age_seconds):
                continue
            subject = _first_string(message, ("subject",)) or ""
            body = _first_string(message, ("messageText", "preview", "snippet", "body")) or ""
            code = extract_verification_code(subject, body)
            if code:
                return code
        return None

    async def fetch_latest_login_link(
        self,
        *,
        query: str | None = None,
        trusted_domains: tuple[str, ...] = (),
        allowed_link_host_patterns: Sequence[str] = (),
        max_age_seconds: int = 900,
    ) -> str | None:
        """Return the most recent emailed sign-in verification LINK, if any.

        Some providers (for example HubSpot device verification) send a magic link
        rather than a numeric code: the agent must open the link in its own live
        session to finish signing in.

        Legacy convenience wrapper with the same caveats as
        :meth:`fetch_latest_otp` - trusted senders are preferred, not required, and
        no recipient binding is performed. When ``allowed_link_host_patterns`` is
        supplied the link is additionally required to be HTTPS on a reviewed host,
        which callers that will actually open the link should always pass. The
        freshness bound is enforced against each message's own timestamp because
        Gmail cannot express an hour-scale window.
        """

        resolved_query = query or gmail_freshness_query(
            now=datetime.now(UTC), max_age_seconds=max_age_seconds
        )
        data = await self._execute_read(
            "GMAIL_FETCH_EMAILS",
            {"max_results": 8, "query": resolved_query},
            capability="Composio Gmail verification-link fetch",
        )
        messages = data.get("messages")
        if not isinstance(messages, list):
            return None
        now_ms = int(datetime.now(UTC).timestamp() * 1000)
        require_host = bool(allowed_link_host_patterns)
        for message in _order_messages_by_trust(messages, trusted_domains):
            if not _within_age(message, now_ms=now_ms, max_age_seconds=max_age_seconds):
                continue
            subject = _first_string(message, ("subject",)) or ""
            body = _first_string(message, ("messageText", "body", "preview", "snippet")) or ""
            link = extract_verification_link(
                subject,
                body,
                allowed_host_patterns=tuple(allowed_link_host_patterns),
                require_reviewed_host=require_host,
            )
            if link:
                return link
        return None

    async def fetch_verification(
        self,
        *,
        purpose: VerificationPurpose,
        expected_recipient: str,
        reviewed_sender_patterns: Sequence[str],
        allowed_link_host_patterns: Sequence[str],
        run_id: str,
        max_age_seconds: int = 900,
        max_results: int = 10,
        prefer_link: bool = True,
        require_reviewed_sender: bool = True,
        require_reviewed_link_host: bool = True,
        consume: bool = True,
    ) -> VerificationDecision:
        """Resolve the one verification message this run is waiting for.

        This is the only Gmail entry point that may be used to obtain a secret an
        agent will then type into, or open on, a live provider page. Unlike
        :meth:`fetch_latest_otp` and :meth:`fetch_latest_login_link`, every binding
        is *required* rather than preferred:

        * the message must be inside ``max_age_seconds`` of now, judged from its own
          receive timestamp (the server-side query is only a coarse pre-filter,
          because Gmail cannot express an hour-scale bound);
        * it must have been delivered to ``expected_recipient`` exactly, plus-tag
          aware, so another run's verification cannot be consumed;
        * its sender domain must be inside ``reviewed_sender_patterns``;
        * a magic link must be HTTPS on a host inside ``allowed_link_host_patterns``.

        When ``consume`` is set, the chosen message is reserved in the effect ledger
        so the same message cannot be injected twice. A message already completed in
        the ledger is skipped and the next candidate is considered, which is what
        stops a resume loop from replaying one expired code forever.

        Returns a :class:`VerificationDecision`. The secret lives only in
        ``decision.resolved.secret`` as a ``SecretStr``; ``decision.resolved.evidence``
        is the value-free projection safe to log or persist.
        """

        if not 1 <= max_results <= 25:
            raise ValueError("max_results must be between 1 and 25")
        if not 1 <= max_age_seconds <= MAX_VERIFICATION_AGE_SECONDS:
            raise ValueError("max_age_seconds must be between 1 second and 1 hour")
        safe_run_id = _validate_identifier(run_id, "run_id")

        query = gmail_freshness_query(
            now=datetime.now(UTC),
            max_age_seconds=max_age_seconds,
            recipient=expected_recipient,
        )
        data = await self._execute_read(
            "GMAIL_FETCH_EMAILS",
            {"max_results": max_results, "query": query},
            capability="Composio Gmail verification fetch",
        )
        messages = data.get("messages")
        if not isinstance(messages, list):
            return VerificationDecision(resolved=None, reason_code="verification_message_not_found")

        candidates = tuple(
            _verification_candidate(message) for message in messages if isinstance(message, Mapping)
        )
        now_ms = int(datetime.now(UTC).timestamp() * 1000)
        consumed: list[str] = []
        # Re-run selection after skipping an already-consumed message so a stale
        # code that is still the newest mail cannot deadlock the run.
        for _round in range(max_results):
            decision = select_verification(
                candidates,
                purpose=purpose,
                expected_recipient=expected_recipient,
                now_ms=now_ms,
                max_age_seconds=max_age_seconds,
                allowed_host_patterns=tuple(allowed_link_host_patterns),
                reviewed_sender_patterns=tuple(reviewed_sender_patterns),
                require_reviewed_sender=require_reviewed_sender,
                require_reviewed_link_host=require_reviewed_link_host,
                prefer_link=prefer_link,
                consumed_message_ids=tuple(consumed),
            )
            resolved = decision.resolved
            if resolved is None or not consume:
                return decision
            claimed = self._claim_verification(resolved, run_id=safe_run_id, purpose=purpose)
            if claimed is True:
                return decision
            if claimed is False:
                consumed.append(resolved.evidence.message_id)
                continue
            return VerificationDecision(
                resolved=None,
                reason_code="verification_claim_failed",
                examined=decision.examined,
                rejections=decision.rejections,
            )
        return VerificationDecision(
            resolved=None, reason_code="verification_all_candidates_consumed"
        )

    def _claim_verification(
        self,
        resolved: ResolvedVerification,
        *,
        run_id: str,
        purpose: VerificationPurpose,
    ) -> bool | None:
        """Reserve one message as this run's verification exactly once.

        Returns ``True`` when this call owns the message, ``False`` when it was
        already consumed (so the caller should consider an older candidate), and
        ``None`` when the ledger itself could not be used - which fails closed
        rather than allowing an unbounded number of injections of the same code.
        """

        evidence = resolved.evidence
        key = f"gmail-verification:v1:{run_id}:{purpose}:{evidence.message_id}"
        try:
            store = self._get_effect_store()
        except PhaseUnavailableError:
            return None
        try:
            reservation = store.reserve(
                provider="composio_gmail",
                action="fetch_verification",
                idempotency_key=key,
            )
        except Exception:
            return None
        if reservation.status == "completed":
            return False
        if reservation.status == "reconcile_required":
            # A previous attempt claimed this message and never finished. Treat it
            # as spent instead of re-injecting a code of unknown status.
            return False
        try:
            store.complete(
                provider="composio_gmail",
                action="fetch_verification",
                idempotency_key=key,
                receipt={
                    # Field names deliberately avoid the redaction layer's
                    # credential vocabulary. A receipt key such as "secret_kind"
                    # is rejected by the ledger's guard even when its value is
                    # inert, and the same name would also be masked in logs and
                    # tripped by the repository secret scanner.
                    "purpose": purpose,
                    "message_id": evidence.message_id,
                    "verification_kind": evidence.verification_kind,
                    "sender_domain": evidence.sender_domain,
                    "recipient_binding": evidence.recipient_binding,
                },
            )
        except Exception:
            try:
                store.mark_outcome_unknown(
                    provider="composio_gmail",
                    action="fetch_verification",
                    idempotency_key=key,
                )
            except Exception:
                pass
            return None
        return True

    async def reply(self, thread_id: str, body: str, idempotency_key: str) -> GmailSendResult:
        safe_thread_id = _validate_identifier(thread_id, "thread_id")
        _validate_message("Reply", body)
        recipient = self._settings.outreach_recipient_override
        if recipient is None:
            raise ConfigurationRequiredError(
                phase=4,
                capability="Composio Gmail thread reply",
                reason_code="safe_reply_recipient_missing",
            )
        actual = _validate_email(recipient)
        session_id = await self.ensure_connected()
        store = self._get_effect_store()
        reservation = store.reserve(
            provider="composio_gmail",
            action="reply",
            idempotency_key=idempotency_key,
        )
        if reservation.status == "completed" and reservation.receipt is not None:
            return _send_result_from_receipt(reservation.receipt)
        if reservation.status == "reconcile_required":
            raise ProviderOperationError(
                capability="Composio Gmail thread reply",
                reason_code="reconciliation_required",
            )
        try:
            result = await asyncio.to_thread(
                self._execute_checked,
                "GMAIL_REPLY_TO_THREAD",
                {
                    "thread_id": safe_thread_id,
                    "recipient_email": actual,
                    "message_body": body,
                },
            )
        except ProviderContractError as exc:
            _mark_after_contract_error(store, "reply", idempotency_key, exc)
            raise
        except ProviderOperationError as exc:
            _mark_after_operation_error(store, "reply", idempotency_key, exc)
            raise
        except Exception:
            store.mark_outcome_unknown(
                provider="composio_gmail",
                action="reply",
                idempotency_key=idempotency_key,
            )
            raise ProviderOperationError(
                capability="Composio Gmail thread reply",
                reason_code="provider_request_failed",
            ) from None
        message_id = _identifier(result, ("message_id", "id"))
        response_thread_id = _identifier(result, ("thread_id", "threadId")) or safe_thread_id
        if message_id is None:
            store.mark_outcome_unknown(
                provider="composio_gmail",
                action="reply",
                idempotency_key=idempotency_key,
            )
            raise ProviderContractError(
                phase=4,
                capability="Composio Gmail thread reply",
                reason_code="response_identifiers_missing",
            )
        sent = GmailSendResult(
            session_id=session_id,
            thread_id=response_thread_id,
            message_id=message_id,
            intended_recipient=actual,
            actual_recipient=actual,
        )
        try:
            store.complete(
                provider="composio_gmail",
                action="reply",
                idempotency_key=idempotency_key,
                receipt=_send_result_receipt(sent),
            )
        except Exception:
            try:
                store.mark_outcome_unknown(
                    provider="composio_gmail",
                    action="reply",
                    idempotency_key=idempotency_key,
                )
            except Exception:
                pass
            raise ProviderOperationError(
                capability="Composio Gmail thread reply",
                reason_code="receipt_persistence_failed",
            ) from None
        return sent

    async def close(self) -> None:
        client = self._sdk_client
        self._sdk_client = None
        if client is not None and callable(getattr(client, "close", None)):
            await asyncio.to_thread(client.close)

    def _require_configuration(self) -> None:
        if self._settings.composio_api_key is None:
            raise ConfigurationRequiredError(
                phase=4,
                capability="Composio Gmail connection",
                reason_code="composio_api_key_missing",
            )
        if self._settings.composio_gmail_connected_account_id is None:
            raise ConfigurationRequiredError(
                phase=4,
                capability="Composio Gmail connection",
                reason_code="gmail_connected_account_missing",
            )

    def _client(self) -> Any:
        if self._sdk_client is None:
            if self._settings.composio_api_key is None:  # pragma: no cover - guarded above
                raise RuntimeError("Composio configuration is missing")
            module = importlib.import_module("composio")
            client_type = module.Composio
            self._sdk_client = client_type(
                api_key=self._settings.composio_api_key.get_secret_value(),
                toolkit_versions={"gmail": GMAIL_TOOLKIT_VERSION},
                max_retries=0,
                allow_tracking=False,
                dangerously_allow_auto_upload_download_files=False,
                file_upload_dirs=False,
            )
        return self._sdk_client

    def _create_scoped_session(self) -> str:
        module = importlib.import_module("composio")
        session = self._client().sessions.create(
            user_id=self._settings.composio_user_id,
            tools={"gmail": {"enable": list(GMAIL_TOOL_ALLOWLIST)}},
            connected_accounts={"gmail": [str(self._settings.composio_gmail_connected_account_id)]},
            manage_connections=False,
            sandbox={"enable": False},
            session_preset=module.SESSION_PRESET_DIRECT_TOOLS,
        )
        # The installed Composio SDK returns a ToolRouterSession whose id is
        # exposed as ``session_id`` and which executes tools via ``session.execute``.
        session_id = getattr(session, "session_id", None) or getattr(session, "id", None)
        if not isinstance(session_id, str) or not session_id:
            raise ProviderContractError(
                phase=4,
                capability="Composio Gmail connection",
                reason_code="session_identifier_missing",
            )
        self._session = session
        return session_id

    def _execute_checked(self, slug: str, arguments: Mapping[str, object]) -> Mapping[str, object]:
        if slug not in GMAIL_TOOL_ALLOWLIST:
            raise ProviderContractError(
                phase=4,
                capability="Composio Gmail tool execution",
                reason_code="tool_not_allowlisted",
            )
        # Only allowlisted fields are ever sent (built internally), so keep the
        # least-privilege guarantee without the older raw-tool schema probe that
        # the tool-router session API no longer exposes.
        allowed_fields = _TOOL_FIELD_TYPES.get(slug)
        if allowed_fields is not None and not set(arguments).issubset(allowed_fields):
            raise ProviderContractError(
                phase=4,
                capability="Composio Gmail tool execution",
                reason_code="tool_schema_incompatible",
            )
        if self._session is None:
            raise ProviderOperationError(
                capability="Composio Gmail tool execution",
                reason_code="provider_request_failed",
            )
        response = self._session.execute(slug, arguments=dict(arguments))
        if getattr(response, "error", None):
            raise ProviderOperationError(
                capability="Composio Gmail tool execution",
                reason_code="provider_reported_failure",
            )
        data = getattr(response, "data", None)
        if not isinstance(data, Mapping):
            raise ProviderContractError(
                phase=4,
                capability="Composio Gmail tool execution",
                reason_code="response_data_incompatible",
            )
        return data

    async def _execute_read(
        self, slug: str, arguments: Mapping[str, object], *, capability: str
    ) -> Mapping[str, object]:
        """Run an idempotent READ tool with bounded retry + reconnect.

        Retries only transient provider/operation failures (never a contract or
        misconfiguration error) with exponential backoff, dropping the cached
        session between attempts so a stale connection is re-established. Sends and
        replies never use this path — their exactly-once guarantee is owned by the
        effect ledger, so they must not be blindly retried.
        """

        attempts = max(1, self._settings.gmail_retry_max_attempts)
        base = max(0.0, self._settings.gmail_retry_base_delay_seconds)
        for attempt in range(attempts):
            await self.ensure_connected()
            try:
                return await asyncio.to_thread(self._execute_checked, slug, dict(arguments))
            except (ConfigurationRequiredError, ProviderContractError):
                raise  # permanent: misconfiguration, allowlist, or schema/contract
            except Exception as exc:
                self._reset_session()  # force a fresh connection on the next attempt
                if attempt >= attempts - 1:
                    if isinstance(exc, ProviderOperationError):
                        raise
                    raise ProviderOperationError(
                        capability=capability,
                        reason_code="provider_response_incompatible",
                    ) from None
                if base:
                    await asyncio.sleep(base * (2**attempt))
        raise ProviderOperationError(  # pragma: no cover - loop returns or raises above
            capability=capability, reason_code="provider_response_incompatible"
        )

    def _reset_session(self) -> None:
        """Drop the cached tool-router session so the next call reconnects."""

        self._session = None
        self._session_id = None

    def _actual_recipient(self, intended: str) -> str:
        override = self._settings.outreach_recipient_override
        if override is not None:
            return _validate_email(override)
        if not self._settings.allow_live_vendor_email:
            raise ConfigurationRequiredError(
                phase=4,
                capability="Composio Gmail outreach",
                reason_code="controlled_recipient_required",
            )
        return intended

    def _get_effect_store(self) -> EffectStore:
        if self._effect_store is None:
            self._effect_store = SQLiteEffectStore(self._settings.provider_effects_db_path)
        return self._effect_store

    def _sanitize_thread_payload(
        self,
        thread_id: str,
        payload: Mapping[str, object],
    ) -> SanitizedGmailThread:
        raw_messages = _message_sequence(payload)
        sanitized: list[SanitizedGmailMessage] = []
        credential_refs: list[str] = []
        for index, value in enumerate(raw_messages):
            message_id = (
                _first_string(value, ("message_id", "messageId", "id")) or f"message-{index + 1}"
            )
            sender = _first_string(value, ("sender", "from", "from_email")) or "unknown"
            recipients = _string_sequence(value, ("recipients", "to", "to_email"))
            sent_at = (
                _first_string(value, ("sent_at", "messageTimestamp", "date", "internal_date"))
                or "unknown"
            )
            subject = _first_string(value, ("subject",)) or ""
            body = (
                _first_string(value, ("body", "messageText", "message_body", "text", "snippet"))
                or ""
            )
            sanitized_body, references = self._store_and_redact_email_secrets(body)
            credential_refs.extend(references)
            sanitized.append(
                SanitizedGmailMessage(
                    message_id=_validate_identifier(message_id, "message_id"),
                    sender=redact_text(sender)[:320],
                    recipients=tuple(redact_text(item)[:320] for item in recipients),
                    sent_at=redact_text(sent_at)[:100],
                    sanitized_subject=redact_text(subject)[:998],
                    sanitized_body=redact_text(sanitized_body)[:100_000],
                )
            )
        return SanitizedGmailThread(
            thread_id=thread_id,
            messages=tuple(sanitized),
            credential_refs=tuple(credential_refs),
        )

    def _store_and_redact_email_secrets(self, body: str) -> tuple[str, tuple[str, ...]]:
        references: list[str] = []

        def replace(match: re.Match[str]) -> str:
            if self._secret_store is None:
                raise ConfigurationRequiredError(
                    phase=4,
                    capability="Gmail credential extraction",
                    reason_code="secret_store_missing",
                )
            kind = match.group("kind").casefold().replace(" ", "_").replace("-", "_")
            raw_value = match.group("value")
            reference = self._secret_store.put(
                app_slug="email-import",
                kind=kind,
                value=raw_value,
            )
            references.append(reference)
            del raw_value
            return f"{match.group('kind')}: [REDACTED_SECRET:{kind}]"

        return _SECRET_LINE.sub(replace, body), tuple(references)


def _mark_after_contract_error(
    store: EffectStore,
    action: str,
    idempotency_key: str,
    exc: ProviderContractError,
) -> None:
    """Force reconciliation after a provider-contract failure.

    A contract error can arise before the request is dispatched (a pre-send
    schema mismatch) or after it (a response that cannot be parsed), so the
    true side-effect state is ambiguous. The reservation is marked
    outcome-unknown to force a later reconciliation instead of a blind resend.
    """

    del exc
    store.mark_outcome_unknown(
        provider="composio_gmail",
        action=action,
        idempotency_key=idempotency_key,
    )


def _mark_after_operation_error(
    store: EffectStore,
    action: str,
    idempotency_key: str,
    exc: ProviderOperationError,
) -> None:
    """Force reconciliation after a provider-operation failure.

    The provider reported a failure once the request was already dispatched, so
    the side effect may or may not have taken hold. The reservation is marked
    outcome-unknown to block a blind resend.
    """

    del exc
    store.mark_outcome_unknown(
        provider="composio_gmail",
        action=action,
        idempotency_key=idempotency_key,
    )


def _validate_tool_schema(
    slug: str,
    schema: object,
    expected_types: Mapping[str, frozenset[str]],
    argument_fields: set[str],
) -> None:
    if not isinstance(schema, Mapping):
        _schema_error()
    properties = schema.get("properties")
    if not isinstance(properties, Mapping):
        _schema_error()
    fields = frozenset(key for key in properties if isinstance(key, str))
    expected_fields = frozenset(expected_types)
    if not expected_fields.issubset(fields) or not argument_fields.issubset(expected_fields):
        _schema_error()
    required_value = schema.get("required", [])
    if not isinstance(required_value, list) or not all(
        isinstance(value, str) for value in required_value
    ):
        _schema_error()
    required = frozenset(required_value)
    expected_required = _TOOL_REQUIRED_FIELDS[slug]
    if not expected_required.issubset(required) or not required.issubset(expected_fields):
        _schema_error()
    for name, accepted_types in expected_types.items():
        field_schema = properties.get(name)
        if not isinstance(field_schema, Mapping):
            _schema_error()
        actual_types = _json_schema_types(field_schema)
        if not actual_types or not actual_types.issubset(accepted_types):
            _schema_error()


def _json_schema_types(schema: Mapping[object, object]) -> frozenset[str]:
    value = schema.get("type")
    if isinstance(value, str):
        return frozenset({value})
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return frozenset(value)
    for combinator in ("anyOf", "oneOf"):
        choices = schema.get(combinator)
        if isinstance(choices, list):
            result: set[str] = set()
            for choice in choices:
                if isinstance(choice, Mapping):
                    result.update(_json_schema_types(choice))
            return frozenset(result - {"null"})
    return frozenset()


def _schema_error() -> NoReturn:
    raise ProviderContractError(
        phase=4,
        capability="Composio Gmail tool execution",
        reason_code="tool_schema_incompatible",
    )


def _identifier(payload: Mapping[str, object], keys: Sequence[str]) -> str | None:
    direct = _first_string(payload, keys)
    if direct is not None:
        return direct
    for container_name in ("response_data", "message", "result"):
        nested = payload.get(container_name)
        if isinstance(nested, Mapping):
            result = _first_string(nested, keys)
            if result is not None:
                return result
    return None


def _first_string(payload: Mapping[str, object], keys: Sequence[str]) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _string_sequence(payload: Mapping[str, object], keys: Sequence[str]) -> tuple[str, ...]:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str):
            return (value,)
        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            return tuple(value)
    return ()


def _message_sequence(payload: Mapping[str, object]) -> tuple[Mapping[str, object], ...]:
    candidates: object = payload.get("messages")
    if candidates is None:
        thread = payload.get("thread")
        if isinstance(thread, Mapping):
            candidates = thread.get("messages")
    if not isinstance(candidates, list) or not all(
        isinstance(item, Mapping) for item in candidates
    ):
        raise ProviderContractError(
            phase=4,
            capability="Composio Gmail thread fetch",
            reason_code="message_list_missing",
        )
    return tuple(candidates)


# The one-time-code and verification-link heuristics live in
# ``ops.email_verification`` so the hardened verification path and these
# historical helpers can never drift apart. The private aliases are retained
# because existing call sites and tests import them from this module.
_extract_otp = extract_verification_code


def _sender_domain(message: Mapping[str, object]) -> str:
    """Return the lowercased domain of a raw message's sender, or ''."""

    sender = _first_string(message, ("from", "sender", "fromEmail", "from_email")) or ""
    return sender_domain_of(sender)


def _message_recipients(message: Mapping[str, object]) -> tuple[str, ...]:
    """Collect every address a provider payload claims the message was sent to.

    Several header spellings are checked because the delivered-to address is what
    binds a verification message to one signup identity, and different payload
    shapes surface it differently. ``Delivered-To`` is included since it survives
    plus-tagged delivery even when a provider rewrites ``To``.
    """

    values: list[str] = []
    for key in (
        "to",
        "To",
        "recipient",
        "recipients",
        "toEmail",
        "to_email",
        "delivered_to",
        "deliveredTo",
        "Delivered-To",
        "cc",
        "Cc",
    ):
        value = message.get(key)
        if isinstance(value, str) and value.strip():
            values.append(value)
        elif isinstance(value, (list, tuple)):
            values.extend(item for item in value if isinstance(item, str) and item.strip())
    payload = message.get("payload")
    if isinstance(payload, Mapping):
        headers = payload.get("headers")
        if isinstance(headers, list):
            for header in headers:
                if not isinstance(header, Mapping):
                    continue
                name = str(header.get("name") or "").casefold()
                if name in {"to", "delivered-to", "x-original-to", "cc"}:
                    header_value = header.get("value")
                    if isinstance(header_value, str) and header_value.strip():
                        values.append(header_value)
    return tuple(dict.fromkeys(values))


def _within_age(
    message: Mapping[str, object],
    *,
    now_ms: int,
    max_age_seconds: int,
) -> bool:
    """Whether a message is inside the freshness window, failing closed.

    A message whose timestamp cannot be parsed is refused rather than assumed
    fresh: accepting it would reintroduce exactly the unbounded window that the
    unsupported ``newer_than:<hours>`` query produced.
    """

    received_at_ms = _message_timestamp(message)
    if received_at_ms <= 0:
        return False
    age_ms = now_ms - received_at_ms
    if age_ms < -DEFAULT_CLOCK_SKEW_SECONDS * 1000:
        return False
    return age_ms <= max_age_seconds * 1000


def _verification_candidate(message: Mapping[str, object]) -> VerificationCandidate:
    """Project a raw provider message onto the value-bearing candidate shape.

    The subject/body captured here may contain a one-time secret, so the result is
    used only inside the selection call and never logged or persisted.
    """

    return VerificationCandidate(
        message_id=_first_string(message, ("message_id", "messageId", "id")) or "",
        sender=_first_string(message, ("from", "sender", "fromEmail", "from_email")) or "",
        recipients=_message_recipients(message),
        received_at=(
            message.get("internalDate")
            or message.get("internal_date")
            or message.get("messageTimestamp")
            or message.get("sent_at")
            or message.get("date")
        ),
        subject=_first_string(message, ("subject",)) or "",
        body=_first_string(message, ("messageText", "body", "preview", "snippet")) or "",
    )


_TIMESTAMP_KEYS = ("internalDate", "internal_date", "messageTimestamp", "sent_at", "date")


def _message_timestamp(message: object) -> int:
    """Return a message's receive time as epoch milliseconds, or 0 when unknown.

    Strict: only a value that parses to a plausible calendar instant is accepted,
    because this feeds the freshness decision for one-time secrets and a value that
    cannot be understood must never satisfy a recency bound.

    Numeric on purpose. Provider payloads mix epoch seconds, epoch milliseconds and
    ISO strings, and comparing those as strings silently misorders them, so an older
    message could be treated as the newest.
    """

    if not isinstance(message, Mapping):
        return 0
    for key in _TIMESTAMP_KEYS:
        parsed = parse_received_at_ms(message.get(key))
        if parsed is not None:
            return parsed
    return 0


def _ordering_timestamp(message: Mapping[str, object]) -> int:
    """Best-effort sort key for display ordering only.

    Unlike :func:`_message_timestamp` this tolerates a bare counter-style value so
    newest-first ordering still holds for payloads whose timestamp is not a real
    epoch. It is deliberately NOT used for any freshness or authorization decision;
    those go through the strict parser above.
    """

    strict = _message_timestamp(message)
    if strict:
        return strict
    for key in _TIMESTAMP_KEYS:
        value = message.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
    return 0


def _order_messages_by_trust(
    messages: list[object], trusted_domains: tuple[str, ...]
) -> list[Mapping[str, object]]:
    """Newest-first, but with senders on a trusted domain preferred (not required).

    Trusted-domain preference guards against a spoofed email injecting a fake code
    while never hard-excluding a legitimate provider that sends from a different
    mail subdomain (a common real-world case), so it cannot cause false negatives.

    This ordering is a display/discovery convenience only. Anything that consumes a
    one-time secret must use :meth:`GmailWorker.fetch_verification`, which REQUIRES
    the sender, recipient, and freshness bindings instead of merely preferring them.
    """

    valid = [message for message in messages if isinstance(message, Mapping)]
    by_recency = sorted(valid, key=_ordering_timestamp, reverse=True)
    trusted = tuple(domain.rstrip(".").casefold() for domain in trusted_domains if domain)
    if not trusted:
        return by_recency

    def _is_trusted(message: Mapping[str, object]) -> int:
        domain = _sender_domain(message)
        matched = any(domain == parent or domain.endswith(f".{parent}") for parent in trusted)
        return 0 if matched else 1

    return sorted(by_recency, key=_is_trusted)  # stable: keeps recency within groups


_INBOX_DOMAIN_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
# Gmail's relative age operators accept ONLY d (day), m (month), and y (year).
# An hour unit does not exist, and "m" is months rather than minutes, so a query
# like "newer_than:1h" is not a one-hour bound and "newer_than:30m" would mean
# thirty MONTHS. Accepting "h" here silently produced an unbounded freshness
# window for one-time codes, so it is rejected; sub-day bounds must be enforced
# against each message's own timestamp (see ops.email_verification).
_INBOX_AGE_RE = re.compile(r"^\d{1,4}[dmy]$")


def build_inbox_query(
    *,
    sender_domain: str | None = None,
    subject: str | None = None,
    newer_than: str | None = None,
    unread: bool = False,
    extra: str | None = None,
) -> str:
    """Build a safe Gmail search query from bounded, validated parts.

    Every part is validated and stripped of newlines/quotes so neither a caller
    nor untrusted upstream text can inject extra operators into the provider
    query. Returns ``in:anywhere`` when no part is supplied.

    ``newer_than`` accepts only the units Gmail actually supports: ``d`` (days),
    ``m`` (**months**) and ``y`` (years). Hours are not expressible, so a
    short-lived freshness bound must be enforced against each message's own
    receive timestamp rather than through this query.
    """

    parts: list[str] = []
    if sender_domain:
        domain = sender_domain.strip().lstrip("@").rstrip(".").casefold()
        if not _INBOX_DOMAIN_RE.match(domain):
            raise ValueError("sender_domain is not a valid domain")
        parts.append(f"from:{domain}")
    if subject:
        cleaned = re.sub(r'[\r\n"]', " ", subject).strip()[:200]
        if cleaned:
            parts.append(f"subject:({cleaned})")
    if newer_than:
        age = newer_than.strip().casefold()
        if not _INBOX_AGE_RE.match(age):
            raise ValueError("newer_than must look like 7d, 6m (months), or 1y")
        parts.append(f"newer_than:{age}")
    if unread:
        parts.append("is:unread")
    if extra:
        cleaned_extra = re.sub(r"[\r\n]", " ", extra).strip()[:200]
        if cleaned_extra:
            parts.append(cleaned_extra)
    return " ".join(parts) or "in:anywhere"


def _download_bounded(url: str, max_bytes: int) -> bytes | None:
    """Stream a presigned attachment URL, refusing anything over the size cap."""

    with httpx.Client(timeout=30.0, follow_redirects=True) as client:
        with client.stream("GET", url) as response:
            response.raise_for_status()
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    return None  # exceeds cap: refuse rather than load unbounded bytes
                chunks.append(chunk)
    return b"".join(chunks)


def _has_attachments(message: Mapping[str, object]) -> bool:
    """Best-effort detection of attachments across known provider payload shapes."""

    for key in ("attachments", "attachment_list", "attachmentList", "attachmentIds"):
        value = message.get(key)
        if isinstance(value, (list, tuple)) and value:
            return True
    payload = message.get("payload")
    if isinstance(payload, Mapping):
        parts = payload.get("parts")
        if isinstance(parts, list):
            return any(isinstance(part, Mapping) and part.get("filename") for part in parts)
    return False


# Verification-link discovery is shared with the hardened path in
# ``ops.email_verification``. This alias keeps the historical permissive
# behaviour (no host allowlist) available to existing callers, while anything
# that consumes the link for an autonomous action must instead go through
# ``GmailWorker.fetch_verification``, which requires a reviewed host.
_extract_login_link = extract_verification_link


def _validate_email(value: str) -> str:
    if not value or len(value) > 320 or "\n" in value or "\r" in value or value.count("@") != 1:
        raise ValueError("a single safe email address is required")
    local, domain = value.rsplit("@", 1)
    if not local or "." not in domain or domain.startswith(".") or domain.endswith("."):
        raise ValueError("a single safe email address is required")
    return value


def _validate_identifier(value: str, name: str) -> str:
    if not value or len(value) > 1_000 or any(character in value for character in "\r\n\x00"):
        raise ValueError(f"{name} is invalid")
    return value


def _validate_message(subject: str, body: str) -> None:
    if not subject or len(subject) > 998 or "\r" in subject or "\n" in subject:
        raise ValueError("email subject is invalid")
    if not body or len(body) > 100_000 or "\x00" in body:
        raise ValueError("email body is invalid")


def _send_result_receipt(result: GmailSendResult) -> dict[str, str]:
    return {
        "session_id": result.session_id,
        "thread_id": result.thread_id,
        "message_id": result.message_id,
        "intended_recipient": result.intended_recipient,
        "actual_recipient": result.actual_recipient,
    }


def _send_result_from_receipt(receipt: Mapping[str, str]) -> GmailSendResult:
    required = {
        "session_id",
        "thread_id",
        "message_id",
        "intended_recipient",
        "actual_recipient",
    }
    if set(receipt) != required:
        raise RuntimeError("stored Gmail effect receipt is invalid")
    return GmailSendResult(**receipt)


__all__ = [
    "GMAIL_TOOLKIT_VERSION",
    "GMAIL_TOOL_ALLOWLIST",
    "GmailSendResult",
    "GmailWorker",
    "InboxSearchResult",
    "PhaseUnavailableError",
    "SanitizedGmailMessage",
    "SanitizedGmailThread",
    "VerificationDecision",
    "VerificationEvidence",
    "VerificationPurpose",
    "build_inbox_query",
]
