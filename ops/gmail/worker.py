"""Production Composio Gmail boundary with pinned schemas and durable idempotency."""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import re
import secrets
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from queue import Empty, Queue
from typing import Any, Literal

from ops.core.config import Settings
from ops.core.effect_ledger import EffectStore, SQLiteEffectStore
from ops.core.redaction import redact_text
from ops.core.secret_store import SecretStore, SQLiteSecretStore
from ops.email.attachment_extract import AttachmentRef, extract_secret_pairs, is_text_like
from ops.email.verification import (  # noqa: F401
    DEFAULT_CLOCK_SKEW_SECONDS,
    MAX_VERIFICATION_AGE_SECONDS,
    VERIFICATION_REQUEST_CLOCK_SKEW_SECONDS,
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
from ops.gmail.contract import (  # noqa: F401
    _TOOL_FIELD_TYPES,
    _TOOL_REQUIRED_FIELDS,
    _mark_after_contract_error,
    _mark_after_operation_error,
    _validate_tool_schema,
)
from ops.gmail.contract import GMAIL_TOOL_ALLOWLIST as GMAIL_TOOL_ALLOWLIST
from ops.gmail.contract import GMAIL_TOOLKIT_VERSION as GMAIL_TOOLKIT_VERSION
from ops.gmail.messages import (  # noqa: F401
    _SECRET_LINE,
    _download_bounded,
    _extract_login_link,
    _extract_otp,
    _first_string,
    _has_attachments,
    _identifier,
    _message_recipients,
    _message_sender_authenticated,
    _message_sequence,
    _message_timestamp,
    _order_messages_by_trust,
    _ordering_timestamp,
    _sender_domain,
    _string_sequence,
    _verification_candidate,
    _within_age,
)
from ops.gmail.models import GmailOutreachMessageClaim as GmailOutreachMessageClaim

# ``ops.gmail.worker`` remains the declared import home for the Gmail boundary, so
# every name it used to expose is re-exported here. run_service, run_email,
# run_verification, reply_classifier, graph and the tests import from this module.
from ops.gmail.models import GmailSendResult as GmailSendResult
from ops.gmail.models import InboxSearchResult as InboxSearchResult
from ops.gmail.models import SanitizedGmailMessage as SanitizedGmailMessage
from ops.gmail.models import SanitizedGmailThread as SanitizedGmailThread
from ops.gmail.models import _send_result_from_receipt, _send_result_receipt  # noqa: F401
from ops.gmail.queries import _INBOX_AGE_RE, _INBOX_DOMAIN_RE  # noqa: F401
from ops.gmail.queries import build_inbox_query as build_inbox_query
from ops.gmail.validation import (  # noqa: F401
    _validate_email,
    _validate_identifier,
    _validate_message,
    parse_mailbox_address,
)
from ops.providers.errors import (
    ConfigurationRequiredError,
    PhaseUnavailableError,
    ProviderContractError,
    ProviderOperationError,
)

GmailSignupPreflightStatus = Literal[
    "ready",
    "configuration_required",
    "timeout",
    "unavailable",
]


@dataclass(frozen=True, slots=True)
class GmailSignupPreflight:
    """Value-free result of the bounded Gmail signup capability probe."""

    status: GmailSignupPreflightStatus
    reason_code: str
    provider_read_attempted: bool

    @property
    def ready(self) -> bool:
        return self.status == "ready"


def _install_user_key_auth(client: Any, api_key: str) -> None:
    """Route the SDK through ``x-user-api-key`` instead of ``x-api-key``.

    The Composio backend accepts user-scoped keys (``uak_``) only on the
    ``x-user-api-key`` header; ``x-api-key`` is reserved for workspace keys.
    The installed SDK pins the credential to ``x-api-key`` at the HTTP layer,
    so swap the header at the transport for every request this client makes.
    The attribute chain is SDK-internal; leave the client untouched when the
    expected wrapper is absent (tests inject fake clients).
    """
    http_wrapper = getattr(client, "_client", None)
    if http_wrapper is None:
        return
    http_wrapper = getattr(http_wrapper, "_client", None)
    if http_wrapper is None or not callable(getattr(http_wrapper, "send", None)):
        return
    original_send = http_wrapper.send

    def send_with_user_key(request: Any, *args: Any, **kwargs: Any) -> Any:
        request.headers.pop("x-api-key", None)
        request.headers["x-user-api-key"] = api_key
        return original_send(request, *args, **kwargs)

    http_wrapper.send = send_with_user_key


def _gmail_effect_request_fingerprint(
    *,
    settings: Settings,
    action: str,
    values: Sequence[str],
) -> str:
    """Hash the exact Gmail mutation without persisting its body.

    The caller-supplied idempotency identity says *which logical effect* this is;
    this fingerprint proves a replay is asking for the same account, recipient,
    thread, subject and body.  Length-prefixing makes the encoding unambiguous.
    """

    digest = hashlib.sha256()
    components = (
        "gmail-effect-request-v1",
        str(settings.composio_gmail_connected_account_id or ""),
        settings.composio_gmail_user_id,
        action,
        *values,
    )
    for component in components:
        encoded = component.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _completed_gmail_effect(
    *,
    reservation_receipt: Mapping[str, str] | None,
    request_fingerprint: str,
    capability: str,
) -> GmailSendResult:
    """Validate a completed receipt before treating it as an exact replay."""

    if reservation_receipt is None or not secrets.compare_digest(
        reservation_receipt.get("request_fingerprint", ""),
        request_fingerprint,
    ):
        raise ProviderOperationError(
            capability=capability,
            reason_code="idempotency_payload_mismatch",
        )
    try:
        return _send_result_from_receipt(reservation_receipt)
    except Exception:
        raise ProviderOperationError(
            capability=capability,
            reason_code="reconciliation_required",
        ) from None


def _gmail_profile_mailbox(payload: Mapping[str, object]) -> str | None:
    """Extract one exact mailbox from the pinned Gmail profile response.

    Composio toolkit revisions have used both Gmail's native ``emailAddress``
    spelling and normalized snake-case names. Only one parsed RFC mailbox is
    accepted, and no value is included in the caller-visible readiness result.
    """

    candidates: list[object] = [
        payload.get("emailAddress"),
        payload.get("email_address"),
        payload.get("email"),
    ]
    for container_name in ("profile", "user", "response_data", "result"):
        nested = payload.get(container_name)
        if isinstance(nested, Mapping):
            candidates.extend(
                (
                    nested.get("emailAddress"),
                    nested.get("email_address"),
                    nested.get("email"),
                )
            )
    parsed = {
        mailbox.casefold()
        for candidate in candidates
        if isinstance(candidate, str) and (mailbox := parse_mailbox_address(candidate)) is not None
    }
    if len(parsed) != 1:
        return None
    return next(iter(parsed))


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
        self._signup_preflight_lock = threading.Lock()
        self._signup_preflight_thread: threading.Thread | None = None

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
                    {"user_id": "me"},
                )
            except Exception:
                pass
            self._session_id = session_id
            return session_id

    async def preflight_signup_inbox(
        self,
        *,
        timeout_seconds: float = 10.0,
    ) -> GmailSignupPreflight:
        """Prove the configured signup mailbox can execute a bounded inbox read.

        The probe first reads the connected account's Gmail profile and requires
        its mailbox to equal ``GMAIL_SIGNUP_ADDRESS``. It then calls the exact
        ``GMAIL_FETCH_EMAILS`` tool used by signup verification with a random
        RFC-822 message-id query that should never match. Provider payloads never
        leave this boundary: the method records only a sanitized reason code.
        A dedicated, isolated probe thread places a strict deadline on the
        caller-visible operation. The Composio SDK is synchronous underneath, so
        Python cannot forcibly stop an already-running provider call; a late
        return is discarded and cannot mutate this worker's live session.
        """

        if not 1.0 <= timeout_seconds <= 30.0:
            raise ValueError("timeout_seconds must be between 1 and 30")
        try:
            self._require_configuration()
        except ConfigurationRequiredError as exc:
            return GmailSignupPreflight(
                status="configuration_required",
                reason_code=exc.reason_code,
                provider_read_attempted=False,
            )
        if self._settings.gmail_signup_address is None:
            return GmailSignupPreflight(
                status="configuration_required",
                reason_code="gmail_signup_address_missing",
                provider_read_attempted=False,
            )

        nonce = secrets.token_urlsafe(18)
        query = f"in:anywhere rfc822msgid:<ops-signup-preflight-{nonce}@invalid.invalid>"
        results: Queue[GmailSignupPreflight] = Queue(maxsize=1)
        read_started = threading.Event()

        # The Composio SDK is synchronous. Running it through ``asyncio.to_thread``
        # and wrapping that future in ``wait_for`` looks bounded, but
        # ``asyncio.run`` waits for its default executor during shutdown and can
        # therefore still block the HTTP caller indefinitely. A dedicated daemon
        # probe gives the public operation a real wall-clock deadline. The probe
        # uses isolated session state so a late provider return cannot clobber the
        # live worker after this call has timed out.
        with self._signup_preflight_lock:
            active = self._signup_preflight_thread
            if active is not None and active.is_alive():
                return GmailSignupPreflight(
                    status="unavailable",
                    reason_code="gmail_signup_preflight_in_progress",
                    provider_read_attempted=True,
                )
            thread = threading.Thread(
                target=self._run_signup_preflight_probe,
                kwargs={
                    "query": query,
                    "results": results,
                    "read_started": read_started,
                },
                name="gmail-signup-preflight",
                daemon=True,
            )
            self._signup_preflight_thread = thread
            try:
                thread.start()
            except RuntimeError:
                self._signup_preflight_thread = None
                return GmailSignupPreflight(
                    status="unavailable",
                    reason_code="gmail_signup_preflight_failed",
                    provider_read_attempted=False,
                )

        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                return results.get_nowait()
            except Empty:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return GmailSignupPreflight(
                        status="timeout",
                        reason_code="gmail_signup_preflight_timeout",
                        provider_read_attempted=read_started.is_set(),
                    )
                await asyncio.sleep(min(0.025, remaining))

    def _run_signup_preflight_probe(
        self,
        *,
        query: str,
        results: Queue[GmailSignupPreflight],
        read_started: threading.Event,
    ) -> None:
        """Execute the synchronous provider probe and publish only a safe result."""

        owns_client = self._sdk_client is None
        probe = GmailWorker(
            settings=self._settings,
            secret_store=None,
            effect_store=None,
            sdk_client=self._sdk_client,
        )
        try:
            result = probe._execute_signup_preflight_query(query, read_started=read_started)
        except Exception:
            result = GmailSignupPreflight(
                status="unavailable",
                reason_code="gmail_signup_preflight_failed",
                provider_read_attempted=True,
            )
        # The queue never receives the provider response, query, or message data.
        try:
            results.put_nowait(result)
        except Exception:
            pass
        if owns_client:
            client = probe._sdk_client
            if client is not None and callable(getattr(client, "close", None)):
                try:
                    client.close()
                except Exception:
                    pass

    def _execute_signup_preflight_query(
        self,
        query: str,
        *,
        read_started: threading.Event,
    ) -> GmailSignupPreflight:
        """Run the exact read synchronously inside the isolated probe thread."""

        attempted = False
        attempts = max(1, self._settings.gmail_retry_max_attempts)
        base = max(0.0, self._settings.gmail_retry_base_delay_seconds)
        for attempt in range(attempts):
            try:
                self._create_scoped_session()
                attempted = True
                read_started.set()
                profile = self._execute_checked(
                    "GMAIL_GET_PROFILE",
                    {"user_id": "me"},
                )
                profile_mailbox = _gmail_profile_mailbox(profile)
                del profile
                signup_address = self._settings.gmail_signup_address
                if signup_address is None:
                    return GmailSignupPreflight(
                        status="configuration_required",
                        reason_code="gmail_signup_address_missing",
                        provider_read_attempted=True,
                    )
                configured_mailbox = parse_mailbox_address(signup_address.get_secret_value())
                if profile_mailbox is None:
                    return GmailSignupPreflight(
                        status="unavailable",
                        reason_code="gmail_signup_profile_incompatible",
                        provider_read_attempted=True,
                    )
                if configured_mailbox is None or not secrets.compare_digest(
                    profile_mailbox.casefold(),
                    configured_mailbox.casefold(),
                ):
                    return GmailSignupPreflight(
                        status="configuration_required",
                        reason_code="gmail_signup_mailbox_mismatch",
                        provider_read_attempted=True,
                    )
                payload = self._execute_checked(
                    "GMAIL_FETCH_EMAILS",
                    {"max_results": 1, "query": query},
                )
                messages = payload.get("messages")
                # Do not retain, sanitize, summarize, count, or return message data.
                del payload
                if not isinstance(messages, list):
                    return GmailSignupPreflight(
                        status="unavailable",
                        reason_code="gmail_signup_preflight_response_incompatible",
                        provider_read_attempted=True,
                    )
                if messages:
                    return GmailSignupPreflight(
                        status="unavailable",
                        reason_code="gmail_signup_preflight_filter_unreliable",
                        provider_read_attempted=True,
                    )
                return GmailSignupPreflight(
                    status="ready",
                    reason_code="gmail_signup_inbox_ready",
                    provider_read_attempted=True,
                )
            except ConfigurationRequiredError as exc:
                return GmailSignupPreflight(
                    status="configuration_required",
                    reason_code=exc.reason_code,
                    provider_read_attempted=attempted,
                )
            except ProviderContractError:
                return GmailSignupPreflight(
                    status="unavailable",
                    reason_code="gmail_signup_preflight_failed",
                    provider_read_attempted=attempted,
                )
            except Exception:
                self._reset_session()
                if attempt >= attempts - 1:
                    break
                if base:
                    time.sleep(base * (2**attempt))
        return GmailSignupPreflight(
            status="unavailable",
            reason_code="gmail_signup_preflight_failed",
            provider_read_attempted=attempted,
        )

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
        request_fingerprint = _gmail_effect_request_fingerprint(
            settings=self._settings,
            action="send_outreach",
            values=(intended, actual, subject, body),
        )
        store = self._get_effect_store()
        reservation = store.reserve(
            provider="composio_gmail",
            action="send_outreach",
            idempotency_key=idempotency_key,
        )
        if reservation.status == "completed":
            return _completed_gmail_effect(
                reservation_receipt=reservation.receipt,
                request_fingerprint=request_fingerprint,
                capability="Composio Gmail outreach",
            )
        if reservation.status == "reconcile_required":
            raise ProviderOperationError(
                capability="Composio Gmail outreach",
                reason_code="reconciliation_required",
            )

        try:
            session_id = await self.ensure_connected()
        except Exception:
            # Session creation happens before GMAIL_SEND_EMAIL is dispatched, so
            # this reservation is safe to retry after a definite connect failure.
            try:
                store.mark_failed(
                    provider="composio_gmail",
                    action="send_outreach",
                    idempotency_key=idempotency_key,
                )
            except Exception:
                pass
            raise
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
                receipt=_send_result_receipt(
                    sent,
                    request_fingerprint=request_fingerprint,
                ),
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
        """Fetch and redact a thread without writing to the credential vault."""

        safe_thread_id = _validate_identifier(thread_id, "thread_id")
        result = await self._execute_read(
            "GMAIL_FETCH_MESSAGE_BY_THREAD_ID",
            {"thread_id": safe_thread_id},
            capability="Composio Gmail thread fetch",
        )
        return self._sanitize_thread_payload(safe_thread_id, result)

    async def claim_outreach_reply(
        self,
        *,
        thread_id: str,
        message_id: str,
        expected_sender: str,
        owner_run_id: str,
        app_slug: str,
    ) -> GmailOutreachMessageClaim:
        """Authenticate and durably claim one immutable inbound reply.

        The raw body never leaves this boundary. The exact RFC mailbox parsed
        from ``From`` must match ``expected_sender`` before credential-shaped
        values are extracted. Reservation metadata and encrypted vault rows are
        committed atomically by :class:`SQLiteSecretStore`.
        """

        if not isinstance(self._secret_store, SQLiteSecretStore):
            raise ConfigurationRequiredError(
                phase=4,
                capability="Gmail outreach reply ingestion",
                reason_code="atomic_secret_store_required",
            )
        connected_account_id = self._settings.composio_gmail_connected_account_id
        if not isinstance(connected_account_id, str) or not connected_account_id:
            raise ConfigurationRequiredError(
                phase=4,
                capability="Gmail outreach reply ingestion",
                reason_code="gmail_connected_account_missing",
            )
        safe_thread_id = _validate_identifier(thread_id, "thread_id")
        safe_message_id = _validate_identifier(message_id, "message_id")
        safe_run_id = _validate_identifier(owner_run_id, "run_id")
        expected_mailbox = parse_mailbox_address(expected_sender)
        if expected_mailbox is None:
            raise ConfigurationRequiredError(
                phase=4,
                capability="Gmail outreach reply ingestion",
                reason_code="controlled_recipient_invalid",
            )

        payload = await self._execute_read(
            "GMAIL_FETCH_MESSAGE_BY_THREAD_ID",
            {"thread_id": safe_thread_id},
            capability="Composio Gmail thread fetch",
        )
        matching = [
            message
            for message in _message_sequence(payload)
            if _first_string(message, ("message_id", "messageId", "id")) == safe_message_id
        ]
        if len(matching) != 1:
            raise ProviderContractError(
                phase=4,
                capability="Gmail outreach reply ingestion",
                reason_code=(
                    "message_identifier_missing" if not matching else "message_identifier_ambiguous"
                ),
            )
        selected = matching[0]
        raw_sender = _first_string(selected, ("sender", "from", "fromEmail", "from_email")) or ""
        selected_mailbox = parse_mailbox_address(raw_sender)
        if selected_mailbox is None or selected_mailbox.casefold() != expected_mailbox.casefold():
            raise ProviderContractError(
                phase=4,
                capability="Gmail outreach reply ingestion",
                reason_code="message_sender_mismatch",
            )
        # A matching From mailbox is attacker-controlled text.  Gmail's own
        # aligned DMARC/DKIM/SPF (or validated ARC) evidence is mandatory before
        # either classifying this reply or vaulting credential-shaped values.
        # This is intentionally not coupled to the legacy verification toggle:
        # credential-bearing outreach ingestion must never have an unauthenticated
        # compatibility mode.
        if not _message_sender_authenticated(selected):
            raise ProviderContractError(
                phase=4,
                capability="Gmail outreach reply ingestion",
                reason_code="message_sender_authentication_failed",
            )
        body = (
            _first_string(
                selected,
                ("body", "messageText", "message_body", "text", "snippet"),
            )
            or ""
        )
        credentials = self._extract_email_secrets(body)
        reservation = self._secret_store.begin_gmail_message_ingestion(
            connected_account_id=connected_account_id,
            thread_id=safe_thread_id,
            message_id=safe_message_id,
            owner_run_id=safe_run_id,
            app_slug=app_slug,
            credentials=credentials,
        )
        return GmailOutreachMessageClaim(
            status=reservation.status,
            message_id=safe_message_id,
            credential_refs=reservation.credential_refs,
            claim_token=reservation.claim_token,
        )

    def complete_outreach_reply(
        self,
        *,
        thread_id: str,
        message_id: str,
        owner_run_id: str,
        claim_token: str,
    ) -> bool:
        """Finalize a message claim after the canonical run transition commits."""

        store = self._secret_store
        connected_account_id = self._settings.composio_gmail_connected_account_id
        if not isinstance(store, SQLiteSecretStore) or not isinstance(connected_account_id, str):
            return False
        try:
            return store.complete_gmail_message_ingestion(
                connected_account_id=connected_account_id,
                thread_id=thread_id,
                message_id=message_id,
                owner_run_id=owner_run_id,
                claim_token=claim_token,
            )
        except Exception:
            return False

    def release_outreach_reply(
        self,
        *,
        thread_id: str,
        message_id: str,
        owner_run_id: str,
        claim_token: str,
    ) -> bool:
        """Release a claim after a definite local pre-commit failure."""

        store = self._secret_store
        connected_account_id = self._settings.composio_gmail_connected_account_id
        if not isinstance(store, SQLiteSecretStore) or not isinstance(connected_account_id, str):
            return False
        try:
            return store.release_gmail_message_ingestion(
                connected_account_id=connected_account_id,
                thread_id=thread_id,
                message_id=message_id,
                owner_run_id=owner_run_id,
                claim_token=claim_token,
            )
        except Exception:
            return False

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
            safe_subject, safe_preview = self._sanitize_email_display(subject, preview)
            sent_at = (
                _first_string(message, ("sent_at", "messageTimestamp", "date", "internal_date"))
                or "unknown"
            )
            results.append(
                InboxSearchResult(
                    message_id=message_id[:200],
                    thread_id=thread_id[:200],
                    sender=redact_text(sender)[:320],
                    sanitized_subject=safe_subject[:998],
                    sanitized_preview=safe_preview[:2_000],
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
        verification_requested_at_ms: int | None = None,
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
            if (
                self._settings.gmail_verification_require_authenticated_sender
                and not _message_sender_authenticated(message)
            ):
                continue
            if verification_requested_at_ms is not None:
                received_at_ms = parse_received_at_ms(_message_timestamp(message))
                if (
                    received_at_ms is None
                    or received_at_ms
                    < verification_requested_at_ms - VERIFICATION_REQUEST_CLOCK_SKEW_SECONDS * 1000
                ):
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
        verification_requested_at_ms: int | None = None,
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
            if (
                self._settings.gmail_verification_require_authenticated_sender
                and not _message_sender_authenticated(message)
            ):
                continue
            if verification_requested_at_ms is not None:
                received_at_ms = parse_received_at_ms(_message_timestamp(message))
                if (
                    received_at_ms is None
                    or received_at_ms
                    < verification_requested_at_ms - VERIFICATION_REQUEST_CLOCK_SKEW_SECONDS * 1000
                ):
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

    async def fetch_verification_candidates(
        self,
        *,
        query: str,
        max_results: int,
    ) -> tuple[VerificationCandidate, ...]:
        """Run one bounded inbox read and project it onto verification candidates.

        The read half of verification only. The untrusted provider payload stays
        inside this module, and the caller receives the same
        ``VerificationCandidate`` shape :meth:`fetch_verification` selects over —
        authentication headers, recipients, subject and body included — so sender
        authentication and link confinement remain decidable downstream.

        Selection, recipient binding and claiming are deliberately NOT done here:
        the ``VerificationProvider`` adapter in
        ``ops.gmail.verification_provider`` binds and orders the result, and the
        verification service applies ``select_verification``. A missing message
        list is an empty read, not an error.
        """

        if not 1 <= max_results <= 25:
            raise ValueError("max_results must be between 1 and 25")
        data = await self._execute_read(
            "GMAIL_FETCH_EMAILS",
            {"max_results": max_results, "query": query},
            capability="Composio Gmail verification fetch",
        )
        messages = data.get("messages")
        if not isinstance(messages, list):
            return ()
        return tuple(
            _verification_candidate(message) for message in messages if isinstance(message, Mapping)
        )

    async def fetch_verification(
        self,
        *,
        purpose: VerificationPurpose,
        expected_recipient: str,
        reviewed_sender_patterns: Sequence[str],
        allowed_link_host_patterns: Sequence[str],
        run_id: str,
        verification_requested_at_ms: int,
        max_age_seconds: int = 900,
        max_results: int = 10,
        prefer_link: bool = True,
        require_reviewed_sender: bool = True,
        require_authenticated_sender: bool | None = None,
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
        * by production default, Gmail must report aligned DMARC, DKIM, or SPF
          authentication (or a validated ARC chain) for that sender;
        * a magic link must be HTTPS on a host inside ``allowed_link_host_patterns``.

        When ``consume`` is set, the chosen immutable message id is reserved
        globally for this connected Gmail account. A different run or purpose
        therefore cannot inject the same message. A claimed message is skipped
        and the next candidate is considered, which also stops a resume loop from
        replaying one expired code forever.

        Returns a :class:`VerificationDecision`. The secret lives only in
        ``decision.resolved.secret`` as a ``SecretStr``; ``decision.resolved.evidence``
        is the value-free projection safe to log or persist.
        """

        if not 1 <= max_results <= 25:
            raise ValueError("max_results must be between 1 and 25")
        if not 1 <= max_age_seconds <= MAX_VERIFICATION_AGE_SECONDS:
            raise ValueError("max_age_seconds must be between 1 second and 1 hour")
        safe_run_id = _validate_identifier(run_id, "run_id")
        authenticated_sender_required = (
            self._settings.gmail_verification_require_authenticated_sender
            if require_authenticated_sender is None
            else bool(require_authenticated_sender)
        )
        now_ms = int(datetime.now(UTC).timestamp() * 1000)
        if (
            not isinstance(verification_requested_at_ms, int)
            or verification_requested_at_ms <= 0
            or verification_requested_at_ms > now_ms + DEFAULT_CLOCK_SKEW_SECONDS * 1000
        ):
            raise ValueError("verification_requested_at_ms is invalid")

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
                require_authenticated_sender=authenticated_sender_required,
                require_reviewed_link_host=require_reviewed_link_host,
                prefer_link=prefer_link,
                consumed_message_ids=tuple(consumed),
                verification_requested_at_ms=verification_requested_at_ms,
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
        """Reserve one message until the browser acknowledges using it.

        Returns ``True`` when this call owns the message, ``False`` when it was
        already consumed or has an unresolved prior claim (so the caller should
        consider an older candidate), and
        ``None`` when the ledger itself could not be used - which fails closed
        rather than allowing an unbounded number of injections of the same code.

        The reservation deliberately remains pending here. The run coordinator
        completes it only after the browser accepts the resume, releases it on a
        definite pre-use failure, and marks it outcome-unknown when delivery may
        have occurred. Completing during inbox fetch used to lose a valid code
        whenever the subsequent browser RPC failed before injection.
        """

        evidence = resolved.evidence
        key = self._verification_claim_key(
            message_id=evidence.message_id,
        )
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
        return True

    @staticmethod
    def _verification_message_id(message_id: str) -> str:
        safe_message_id = _validate_identifier(message_id, "message_id")
        return safe_message_id

    def _verification_claim_key(self, *, message_id: str) -> str:
        """Bind a claim globally to one connected Gmail account and message."""

        account_id = self._settings.composio_gmail_connected_account_id
        if not isinstance(account_id, str) or not account_id:
            raise ValueError("connected Gmail account is required")
        account_scope = hashlib.sha256(
            f"gmail-connected-account:v1\0{account_id}".encode()
        ).hexdigest()
        safe_message_id = self._verification_message_id(message_id)
        message_scope = hashlib.sha256(f"gmail-message:v1\0{safe_message_id}".encode()).hexdigest()
        return f"gmail-verification:v2:{account_scope}:{message_scope}"

    def complete_verification_claim(
        self,
        *,
        run_id: str,
        purpose: VerificationPurpose,
        evidence: VerificationEvidence,
    ) -> bool:
        """Mark a reserved message used after browser resume was acknowledged."""

        key = self._verification_claim_key(
            message_id=evidence.message_id,
        )
        _validate_identifier(run_id, "run_id")
        try:
            store = self._get_effect_store()
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
                    "sender_authentication": evidence.sender_authentication,
                    "recipient_binding": evidence.recipient_binding,
                },
            )
        except Exception:
            try:
                store = self._get_effect_store()
                store.mark_outcome_unknown(
                    provider="composio_gmail",
                    action="fetch_verification",
                    idempotency_key=key,
                )
            except Exception:
                pass
            return False
        return True

    def release_verification_claim(
        self,
        *,
        run_id: str,
        purpose: VerificationPurpose,
        evidence: VerificationEvidence,
    ) -> bool:
        """Release a claim only when the secret definitely was not submitted."""

        key = self._verification_claim_key(
            message_id=evidence.message_id,
        )
        _validate_identifier(run_id, "run_id")
        try:
            self._get_effect_store().mark_failed(
                provider="composio_gmail",
                action="fetch_verification",
                idempotency_key=key,
            )
        except Exception:
            return False
        return True

    def mark_verification_claim_outcome_unknown(
        self,
        *,
        run_id: str,
        purpose: VerificationPurpose,
        evidence: VerificationEvidence,
    ) -> bool:
        """Prevent replay when browser delivery may have happened."""

        key = self._verification_claim_key(
            message_id=evidence.message_id,
        )
        _validate_identifier(run_id, "run_id")
        try:
            self._get_effect_store().mark_outcome_unknown(
                provider="composio_gmail",
                action="fetch_verification",
                idempotency_key=key,
            )
        except Exception:
            return False
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
        request_fingerprint = _gmail_effect_request_fingerprint(
            settings=self._settings,
            action="reply",
            values=(safe_thread_id, actual, body),
        )
        store = self._get_effect_store()
        reservation = store.reserve(
            provider="composio_gmail",
            action="reply",
            idempotency_key=idempotency_key,
        )
        if reservation.status == "completed":
            return _completed_gmail_effect(
                reservation_receipt=reservation.receipt,
                request_fingerprint=request_fingerprint,
                capability="Composio Gmail thread reply",
            )
        if reservation.status == "reconcile_required":
            raise ProviderOperationError(
                capability="Composio Gmail thread reply",
                reason_code="reconciliation_required",
            )
        try:
            session_id = await self.ensure_connected()
        except Exception:
            try:
                store.mark_failed(
                    provider="composio_gmail",
                    action="reply",
                    idempotency_key=idempotency_key,
                )
            except Exception:
                pass
            raise
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
                receipt=_send_result_receipt(
                    sent,
                    request_fingerprint=request_fingerprint,
                ),
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
        if self._settings.composio_gmail_api_key is None:
            raise ConfigurationRequiredError(
                phase=4,
                capability="Composio Gmail connection",
                reason_code="composio_gmail_api_key_missing",
            )
        if self._settings.composio_gmail_connected_account_id is None:
            raise ConfigurationRequiredError(
                phase=4,
                capability="Composio Gmail connection",
                reason_code="gmail_connected_account_missing",
            )

    def _client(self) -> Any:
        if self._sdk_client is None:
            if self._settings.composio_gmail_api_key is None:  # pragma: no cover - guarded above
                raise RuntimeError("Composio configuration is missing")
            module = importlib.import_module("composio")
            client_type = module.Composio
            self._sdk_client = client_type(
                api_key=self._settings.composio_gmail_api_key.get_secret_value(),
                toolkit_versions={"gmail": GMAIL_TOOLKIT_VERSION},
                max_retries=0,
                allow_tracking=False,
                dangerously_allow_auto_upload_download_files=False,
                file_upload_dirs=False,
            )
            _install_user_key_auth(
                self._sdk_client,
                self._settings.composio_gmail_api_key.get_secret_value(),
            )
        return self._sdk_client

    def _create_scoped_session(self) -> str:
        module = importlib.import_module("composio")
        session = self._client().sessions.create(
            user_id=self._settings.composio_gmail_user_id,
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
        """Project an untrusted provider thread without any persistence side effect."""

        raw_messages = _message_sequence(payload)
        sanitized: list[SanitizedGmailMessage] = []
        for index, value in enumerate(raw_messages):
            message_id = (
                _first_string(value, ("message_id", "messageId", "id")) or f"message-{index + 1}"
            )
            sender = (
                _first_string(value, ("sender", "from", "fromEmail", "from_email")) or "unknown"
            )
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
            sanitized_subject, sanitized_body = self._sanitize_email_display(subject, body)
            sanitized.append(
                SanitizedGmailMessage(
                    message_id=_validate_identifier(message_id, "message_id"),
                    sender=redact_text(sender)[:320],
                    recipients=tuple(redact_text(item)[:320] for item in recipients),
                    sent_at=redact_text(sent_at)[:100],
                    sanitized_subject=sanitized_subject[:998],
                    sanitized_body=sanitized_body[:100_000],
                    sender_mailbox=parse_mailbox_address(sender),
                    sender_authenticated=_message_sender_authenticated(value),
                )
            )
        return SanitizedGmailThread(
            thread_id=thread_id,
            messages=tuple(sanitized),
            credential_refs=(),
        )

    @staticmethod
    def _redact_email_secrets(body: str) -> str:
        """Redact credential-shaped lines without vaulting during a read."""

        def replace(match: re.Match[str]) -> str:
            kind = match.group("kind").casefold().replace(" ", "_").replace("-", "_")
            return f"{match.group('kind')}: [REDACTED_SECRET:{kind}]"

        return _SECRET_LINE.sub(replace, body)

    @classmethod
    def _sanitize_email_display(cls, subject: str, body: str) -> tuple[str, str]:
        """Return display-safe mail text with credentials and one-time values removed."""

        safe_subject = subject
        safe_body = cls._redact_email_secrets(body)

        # Verification links often carry their value in an opaque path segment or
        # a provider-specific query name that the generic redactor cannot know.
        # Remove the complete selected link before any inbox/thread projection.
        link = extract_verification_link(subject, body)
        if link:
            for representation in (link, link.replace("&", "&amp;")):
                safe_subject = safe_subject.replace(
                    representation,
                    "[REDACTED_VERIFICATION_LINK]",
                )
                safe_body = safe_body.replace(
                    representation,
                    "[REDACTED_VERIFICATION_LINK]",
                )

        code = extract_verification_code(subject, body)
        if code:
            if code.isdigit():
                # Match both compact and the common 123-456 / 123 456 display
                # forms without placing the value in a log or model.
                pattern = re.compile(r"(?<!\w)" + r"[\s-]?".join(map(re.escape, code)) + r"(?!\w)")
            else:
                pattern = re.compile(rf"(?<!\w){re.escape(code)}(?!\w)")
            safe_subject = pattern.sub("[REDACTED_VERIFICATION_CODE]", safe_subject)
            safe_body = pattern.sub("[REDACTED_VERIFICATION_CODE]", safe_body)

        return redact_text(safe_subject), redact_text(safe_body)

    @staticmethod
    def _extract_email_secrets(body: str) -> tuple[tuple[str, str], ...]:
        """Extract bounded unique credentials from one already-authenticated body."""

        pairs: list[tuple[str, str]] = []
        seen_values: set[str] = set()
        for match in _SECRET_LINE.finditer(body):
            raw_value = match.group("value")
            if raw_value in seen_values:
                continue
            seen_values.add(raw_value)
            kind = match.group("kind").casefold().replace(" ", "_").replace("-", "_")
            pairs.append((kind, raw_value))
        return tuple(pairs)


__all__ = [
    "GMAIL_TOOLKIT_VERSION",
    "GMAIL_TOOL_ALLOWLIST",
    "GmailSignupPreflight",
    "GmailSignupPreflightStatus",
    "GmailSendResult",
    "GmailOutreachMessageClaim",
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
