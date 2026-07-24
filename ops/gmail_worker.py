"""Production Composio Gmail boundary with pinned schemas and durable idempotency."""

from __future__ import annotations

import asyncio
import importlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, NoReturn

from ops.config import Settings
from ops.effect_ledger import EffectStore, SQLiteEffectStore
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
}
_TOOL_REQUIRED_FIELDS: dict[str, frozenset[str]] = {
    "GMAIL_SEND_EMAIL": frozenset({"recipient_email", "subject", "body"}),
    "GMAIL_REPLY_TO_THREAD": frozenset({"thread_id", "recipient_email", "message_body"}),
    "GMAIL_FETCH_MESSAGE_BY_THREAD_ID": frozenset({"thread_id"}),
    "GMAIL_GET_PROFILE": frozenset({"user_id"}),
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

    async def fetch_latest_otp(
        self,
        *,
        query: str = "newer_than:1h in:anywhere",
        trusted_domains: tuple[str, ...] = (),
    ) -> str | None:
        """Return the most recent one-time login code from the connected inbox.

        Reads recent messages (raw, never logged), prefers senders on a trusted
        domain when one is supplied, finds the newest message whose subject/body is
        a verification/OTP email, and extracts the code with hardened, false-
        positive-resistant heuristics. The value is a short-lived secret: it is
        returned only to be injected as a Browser Use ``sensitive_data``
        placeholder and is never persisted, logged, or sent to an LLM.
        """

        data = await self._execute_read(
            "GMAIL_FETCH_EMAILS",
            {"max_results": 8, "query": query},
            capability="Composio Gmail OTP fetch",
        )
        messages = data.get("messages")
        if not isinstance(messages, list):
            return None
        for message in _order_messages_by_trust(messages, trusted_domains):
            subject = _first_string(message, ("subject",)) or ""
            body = _first_string(message, ("messageText", "preview", "snippet", "body")) or ""
            code = _extract_otp(subject, body)
            if code:
                return code
        return None

    async def fetch_latest_login_link(
        self,
        *,
        query: str = "newer_than:1h in:anywhere",
        trusted_domains: tuple[str, ...] = (),
    ) -> str | None:
        """Return the most recent emailed sign-in verification LINK, if any.

        Some providers (e.g. HubSpot device verification) send a magic link rather
        than a numeric code: the agent must open the link in its own live session
        to complete sign-in. This reads recent messages, prefers senders on a
        trusted domain when one is supplied, finds the newest sign-in verification
        email, and extracts the verification URL. The URL is a short-lived secret
        returned only to be injected as a Browser Use ``sensitive_data``
        placeholder; it is never persisted or logged.
        """

        data = await self._execute_read(
            "GMAIL_FETCH_EMAILS",
            {"max_results": 8, "query": query},
            capability="Composio Gmail verification-link fetch",
        )
        messages = data.get("messages")
        if not isinstance(messages, list):
            return None
        for message in _order_messages_by_trust(messages, trusted_domains):
            subject = _first_string(message, ("subject",)) or ""
            body = _first_string(message, ("messageText", "body", "preview", "snippet")) or ""
            link = _extract_login_link(subject, body)
            if link:
                return link
        return None

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


# Cue words a genuine one-time code sits next to. Word-bounded so "pin" does not
# match inside "shipping" and "code" does not match inside "encoded". Used both as
# the presence gate and for proximity scoring.
_OTP_CUE = re.compile(
    r"\b(?:one[\s-]?time|verification|verify|security|confirmation|confirm|access|"
    r"log[\s-]?in|login|sign[\s-]?in|authentication|auth|passcode|otp|pin|code)\b",
    re.IGNORECASE,
)
# A numeric code: 4-8 digits, optionally split once by a single space or hyphen
# ("123-456", "123 456"); never embedded in a longer number, word, URL, path,
# decimal, or version. A trailing sentence period is allowed (the code may end a
# sentence), but a "." or "-" or "/" FOLLOWED BY A DIGIT is not (that is a
# decimal/version/IP/path, not a code).
_OTP_CANDIDATE = re.compile(r"(?<![\w./-])(\d{3}[\s-]\d{3}|\d{4,8})(?![\w]|[./-]\d)")
# An alphanumeric code, trusted ONLY when directly attached to an explicit cue word.
# The cue is case-insensitive; the code stays uppercase-only so it cannot match a
# lowercase prose word.
_OTP_ALNUM_NEAR = re.compile(r"(?i:code|otp|passcode|pin)\b[^0-9A-Za-z]{0,12}([A-Z0-9]{5,8})\b")
_OTP_YEARISH = re.compile(r"^(?:19|20)\d{2}$")


def _normalize_code(token: str) -> str:
    return re.sub(r"[\s-]", "", token)


def _plausible_numeric_code(norm: str) -> bool:
    if not norm.isdigit() or not 4 <= len(norm) <= 8:
        return False
    if len(norm) == 4 and _OTP_YEARISH.match(norm):
        return False  # a bare 4-digit year is almost never an issued one-time code
    if len(set(norm)) == 1:
        return False  # 0000 / 111111: implausible as an issued code
    return True


def _extract_otp(subject: str, body: str) -> str | None:
    """Extract a one-time verification code from an OTP/verification email.

    Deterministic and local by design: a code is a short-lived secret and is never
    sent to an LLM. Hardened against false positives — a numeric candidate is
    accepted only when it sits near a verification cue, subject-line codes are
    strongly preferred, split codes ("123-456") are normalized, and 4-digit years
    or repeated-digit runs are rejected. Returns None rather than guessing when no
    candidate is clearly a code.
    """

    text = f"{subject}\n{body}"
    cue_positions = [match.start() for match in _OTP_CUE.finditer(text)]
    if not cue_positions:
        return None
    # An alphanumeric code attached to an explicit cue word wins outright.
    alnum = _OTP_ALNUM_NEAR.search(text)
    if alnum and not alnum.group(1).isdigit():
        return alnum.group(1)
    subject_boundary = len(subject) + 1
    best: str | None = None
    best_distance = 10**9
    for match in _OTP_CANDIDATE.finditer(text):
        norm = _normalize_code(match.group(1))
        if not _plausible_numeric_code(norm):
            continue
        distance = min(abs(match.start() - pos) for pos in cue_positions)
        if match.start() < subject_boundary:
            distance = min(distance, 15)  # subject codes frequently stand alone
        if distance < best_distance:
            best, best_distance = norm, distance
    # Require the winning candidate to be reasonably near a cue; otherwise decline.
    if best is not None and best_distance <= 60:
        return best
    return None


def _sender_domain(message: Mapping[str, object]) -> str:
    """Return the lowercased domain of a raw message's sender, or ''."""

    sender = _first_string(message, ("from", "sender", "fromEmail", "from_email")) or ""
    match = re.search(r"@([A-Za-z0-9.-]+)", sender)
    return match.group(1).rstrip(".").casefold() if match else ""


def _message_timestamp(message: object) -> str:
    if isinstance(message, Mapping):
        value = message.get("messageTimestamp") or message.get("internal_date")
        return str(value) if value else ""
    return ""


def _order_messages_by_trust(
    messages: list[object], trusted_domains: tuple[str, ...]
) -> list[Mapping[str, object]]:
    """Newest-first, but with senders on a trusted domain preferred (not required).

    Trusted-domain preference guards against a spoofed email injecting a fake code
    while never hard-excluding a legitimate provider that sends from a different
    mail subdomain (a common real-world case), so it cannot cause false negatives.
    """

    valid = [message for message in messages if isinstance(message, Mapping)]
    by_recency = sorted(valid, key=_message_timestamp, reverse=True)
    trusted = tuple(domain.rstrip(".").casefold() for domain in trusted_domains if domain)
    if not trusted:
        return by_recency

    def _is_trusted(message: Mapping[str, object]) -> int:
        domain = _sender_domain(message)
        matched = any(domain == parent or domain.endswith(f".{parent}") for parent in trusted)
        return 0 if matched else 1

    return sorted(by_recency, key=_is_trusted)  # stable: keeps recency within groups


_INBOX_DOMAIN_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_INBOX_AGE_RE = re.compile(r"^\d{1,4}[dhmy]$")


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
            raise ValueError("newer_than must look like 7d, 24h, 30m, or 1y")
        parts.append(f"newer_than:{age}")
    if unread:
        parts.append("is:unread")
    if extra:
        cleaned_extra = re.sub(r"[\r\n]", " ", extra).strip()[:200]
        if cleaned_extra:
            parts.append(cleaned_extra)
    return " ".join(parts) or "in:anywhere"


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


# A sign-in email is one whose subject/body is about confirming a login/device.
_LOGIN_EMAIL_KEYWORDS = (
    "verify",
    "verification",
    "confirm",
    "sign in",
    "sign-in",
    "log in",
    "login",
    "new device",
    "new login",
    "activate",
    "authenticate",
    "secure your account",
    "it's you",
    "it is you",
)
# URL tokens that mark the actual sign-in/verification link (not a footer/help link).
_LOGIN_LINK_HINTS = (
    "notification-station",
    "notifications/cta",
    "/cta/",
    "deliverymethod",
    "login-verify",
    "login_verify",
    "verify-email",
    "verify_email",
    "email-verification",
    "verification",
    "verify",
    "confirm",
    "secure-login",
    "signin",
    "sign-in",
    "one-time",
    "onetime",
    "magiclink",
    "magic-link",
    "activate",
    "sso",
    "auth",
    "token",
)
_URL_RE = re.compile(r"https?://[^\s\"'<>)\]}]+", re.IGNORECASE)
# Footer/marketing links to ignore when several URLs are present.
_LINK_STOPWORDS = (
    "unsubscribe",
    "privacy",
    "/legal",
    "terms",
    "help.",
    "/help",
    "support.",
    "cookie",
    "preferences",
    "manage-preferences",
)
# Static assets and open/click tracking that are never the sign-in link.
_LINK_ASSET_MARKERS = (
    "hsappstatic.net",
    "/emailimages/",
    "hubspotlinks.com",
    "/cto/",
    "sib.googleusercontent",
    "list-manage",
    "/track",
    "/open?",
    "pixel",
)
_ASSET_SUFFIXES = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".css",
    ".ico",
    ".woff",
    ".woff2",
    ".webp",
)


def _extract_login_link(subject: str, body: str) -> str | None:
    """Extract a sign-in/verification magic link from a login email.

    Returns the most likely verification URL and never a static asset, tracking
    pixel, or marketing/footer link. Only emails that read like a sign-in
    confirmation are considered, so ordinary mail is ignored.
    """

    text = f"{subject}\n{body}"
    lowered_text = text.casefold()
    if not any(keyword in lowered_text for keyword in _LOGIN_EMAIL_KEYWORDS):
        return None
    # HTML bodies may still be entity-encoded; normalize the common ampersand.
    normalized = body.replace("&amp;", "&")
    candidates: list[str] = []
    for match in _URL_RE.finditer(normalized):
        url = match.group(0).rstrip(".,);]}'\"")
        low = url.casefold()
        if any(stop in low for stop in _LINK_STOPWORDS):
            continue
        if any(marker in low for marker in _LINK_ASSET_MARKERS):
            continue
        if low.split("?", 1)[0].endswith(_ASSET_SUFFIXES):
            continue
        candidates.append(url)
    if not candidates:
        return None
    # Prefer a URL whose path/query clearly marks it as the sign-in link.
    for url in candidates:
        if any(hint in url.casefold() for hint in _LOGIN_LINK_HINTS):
            return url
    # Otherwise fall back to the first real (non-asset, non-footer) link.
    return candidates[0]


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
    "build_inbox_query",
]
