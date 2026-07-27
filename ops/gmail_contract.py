"""The pinned Composio Gmail tool contract, and how a contract breach is reported.

The allowlist and the per-tool field/required-field maps are a PIN, not documentation.
Composio can change a tool's schema underneath us, so every call's schema is validated
against these expectations first and a mismatch fails closed as a contract error rather
than sending a malformed request to a real vendor mailbox.

The toolkit version is part of that pin: it is what makes a schema drift attributable
to a specific toolkit release instead of appearing as a random runtime failure.

The two effect-ledger markers distinguish the failure kinds that matter for a retry. A
contract error means nothing was attempted, so the effect can be re-armed safely. An
operation error means the provider was reached and the outcome may be unknown, which
must NOT be silently retried into a duplicate send.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import NoReturn

from ops.effect_ledger import EffectStore
from ops.provider_errors import ProviderContractError, ProviderOperationError

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
