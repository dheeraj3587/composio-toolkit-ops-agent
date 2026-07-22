"""Production Composio Gmail boundary with pinned schemas and durable idempotency."""

from __future__ import annotations

import asyncio
import importlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import SecretStr

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
        self._sdk_client = sdk_client
        self._session_id: str | None = None
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
                await asyncio.to_thread(
                    self._execute_checked,
                    "GMAIL_GET_PROFILE",
                    {"user_id": self._settings.composio_user_id},
                )
            except (ProviderContractError, ProviderOperationError):
                raise
            except Exception:
                raise ProviderOperationError(
                    capability="Composio Gmail connection",
                    reason_code="provider_request_failed",
                ) from None
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
        await self.ensure_connected()
        try:
            result = await asyncio.to_thread(
                self._execute_checked,
                "GMAIL_FETCH_MESSAGE_BY_THREAD_ID",
                {"thread_id": safe_thread_id},
            )
            return self._sanitize_thread_payload(safe_thread_id, result)
        except (ConfigurationRequiredError, ProviderContractError, ProviderOperationError):
            raise
        except Exception:
            raise ProviderOperationError(
                capability="Composio Gmail thread fetch",
                reason_code="provider_response_incompatible",
            ) from None

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
            client_type = getattr(module, "Composio")
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
            connected_accounts={
                "gmail": [str(self._settings.composio_gmail_connected_account_id)]
            },
            manage_connections=False,
            sandbox={"enable": False},
            session_preset=getattr(module, "SESSION_PRESET_DIRECT_TOOLS"),
        )
        session_id = getattr(session, "id", None)
        if not isinstance(session_id, str) or not session_id:
            raise ProviderContractError(
                phase=4,
                capability="Composio Gmail connection",
                reason_code="session_identifier_missing",
            )
        return session_id

    def _execute_checked(self, slug: str, arguments: Mapping[str, object]) -> Mapping[str, object]:
        if slug not in GMAIL_TOOL_ALLOWLIST:
            raise ProviderContractError(
                phase=4,
                capability="Composio Gmail tool execution",
                reason_code="tool_not_allowlisted",
            )
        expected = _TOOL_FIELD_TYPES.get(slug)
        if expected is not None:
            tool = self._client().tools.get_raw_composio_tool_by_slug(slug)
            _validate_tool_schema(
                slug,
                getattr(tool, "input_parameters", None),
                expected,
                set(arguments),
            )
        response = self._client().tools.execute(
            slug,
            dict(arguments),
            connected_account_id=self._settings.composio_gmail_connected_account_id,
            user_id=self._settings.composio_user_id,
            version=GMAIL_TOOLKIT_VERSION,
        )
        if getattr(response, "successful", False) is not True:
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
            message_id = _first_string(value, ("message_id", "id")) or f"message-{index + 1}"
            sender = _first_string(value, ("sender", "from", "from_email")) or "unknown"
            recipients = _string_sequence(value, ("recipients", "to", "to_email"))
            sent_at = _first_string(value, ("sent_at", "date", "internal_date")) or "unknown"
            subject = _first_string(value, ("subject",)) or ""
            body = _first_string(value, ("body", "message_body", "text", "snippet")) or ""
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


def _schema_error() -> None:
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
    if not isinstance(candidates, list) or not all(isinstance(item, Mapping) for item in candidates):
        raise ProviderContractError(
            phase=4,
            capability="Composio Gmail thread fetch",
            reason_code="message_list_missing",
        )
    return tuple(candidates)


def _validate_email(value: str) -> str:
    if (
        not value
        or len(value) > 320
        or "\n" in value
        or "\r" in value
        or value.count("@") != 1
    ):
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
    "PhaseUnavailableError",
    "SanitizedGmailMessage",
    "SanitizedGmailThread",
]
