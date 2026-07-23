"""Deterministic secret redaction for persistence, UI payloads, and logs."""

from __future__ import annotations

import logging
import re
import traceback
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, SecretBytes, SecretStr

REDACTED = "[REDACTED]"

_VAULT_REFERENCE = re.compile(r"^vault://[a-z0-9-]+/[a-z0-9_-]+/[A-Za-z0-9_-]+$")
_SENSITIVE_KEY = re.compile(
    r"(?ix)(?:^|[_-])(?:"
    r"api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|"
    r"oauth[_-]?(?:client[_-]?)?secret|(?:session|id|auth|oauth)[_-]?token|"
    r"authorization|password|passwd|private[_-]?key|totp(?:[_-]?seed)?|"
    r"cookie|session[_-]?cookie|credentials?|login[_-]?email|token|secret|key"
    r")(?:$|[_-])"
)
_SENSITIVE_CODE_KEY = re.compile(
    r"(?ix)^(?:code|(?:oauth|auth|authorization|verification|device|totp)[_-]?code|"
    r"one[_-]?time[_-]?code)$"
)

_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
    re.DOTALL,
)
_AUTHORIZATION = re.compile(r"(?im)(\bauthorization\s*[:=]\s*)([^\r\n,;}]+)")
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\."
    r"[A-Za-z0-9_-]{5,}(?![A-Za-z0-9_-])"
)
_ASSIGNMENT = re.compile(
    r"(?ix)(\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|"
    r"refresh[_-]?token|oauth[_-]?(?:client[_-]?)?secret|"
    r"(?:session|id|auth|oauth)[_-]?token|password|passwd|private[_-]?key|"
    r"totp[_-]?seed|oauth[_-]?code|credentials?|token|secret|key|code)"
    r"\b\s*[:=]\s*)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;&}]+)"
)
_TOKEN_QUERY = re.compile(
    r"(?ix)([?&#](?:token|code|key|secret|credentials?|password|api[_-]?key|"
    r"client[_-]?secret|access[_-]?token|refresh[_-]?token|"
    r"(?:session|id|auth|oauth)[_-]?token|authorization|jwt|signature|sig)=)"
    r"([^&#\s]+)"
)
_PROVIDER_KEY = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"(?:sk|rk)-(?:live-|test-)?[A-Za-z0-9_-]{12,}|"
    r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{12,}|"
    r"gh[pousr]_[A-Za-z0-9]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"AIza[A-Za-z0-9_-]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"(?:AKIA|ASIA)[0-9A-Z]{16}|"
    r"pplx-[A-Za-z0-9_-]{12,}|"
    r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"
    r")(?![A-Za-z0-9])"
)


def is_vault_reference(value: object) -> bool:
    """Return whether a value is a syntactically safe opaque reference."""

    return isinstance(value, str) and _VAULT_REFERENCE.fullmatch(value) is not None


def _is_reference_payload(value: object, *, key: str) -> bool:
    if is_vault_reference(value):
        return True
    return (
        key.casefold().endswith("_refs")
        and isinstance(value, Mapping)
        and all(is_vault_reference(reference) for reference in value.values())
    )


def _is_sensitive_key(key: str) -> bool:
    """Classify credential-bearing field names without hiding benign reason codes."""

    return _SENSITIVE_KEY.search(key) is not None or _SENSITIVE_CODE_KEY.fullmatch(key) is not None


def redact_text(value: str) -> str:
    """Replace recognized secret material while retaining useful context."""

    redacted = _PRIVATE_KEY.sub(REDACTED, value)
    redacted = _AUTHORIZATION.sub(lambda match: match.group(1) + REDACTED, redacted)
    redacted = _BEARER.sub(f"Bearer {REDACTED}", redacted)
    redacted = _JWT.sub(REDACTED, redacted)
    redacted = _ASSIGNMENT.sub(
        lambda match: match.group(1) + REDACTED,
        redacted,
    )
    redacted = _TOKEN_QUERY.sub(
        lambda match: match.group(1) + REDACTED,
        redacted,
    )
    return _PROVIDER_KEY.sub(REDACTED, redacted)


def redact_data(value: Any, *, key: str | None = None) -> Any:
    """Recursively sanitize common Python/JSON structures.

    A vault reference is safe to retain even under a key such as
    ``client_secret`` because the reference is the intended public boundary.
    """

    if isinstance(value, (SecretStr, SecretBytes)):
        return REDACTED
    if key is not None and _is_sensitive_key(key) and not _is_reference_payload(value, key=key):
        return REDACTED
    if isinstance(value, BaseModel):
        return redact_data(value.model_dump(mode="json"), key=key)
    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}
        for item_key, item_value in value.items():
            if isinstance(item_key, str):
                raw_key = item_key
            elif item_key is None or isinstance(item_key, (bool, int, float)):
                raw_key = str(item_key)
            else:
                # Arbitrary keys can execute attacker-controlled ``__str__``
                # methods and are not valid JSON contract keys. Reject both
                # the key and its associated value conservatively.
                sanitized["[REDACTED_KEY]"] = REDACTED
                continue
            safe_key = redact_text(raw_key)
            if safe_key != raw_key:
                safe_key = "[REDACTED_KEY]"
            sanitized[safe_key] = redact_data(item_value, key=raw_key)
        return sanitized
    if isinstance(value, tuple):
        return tuple(redact_data(item) for item in value)
    if isinstance(value, list):
        return [redact_data(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return [redact_data(item) for item in value]
    if isinstance(value, bytes):
        return REDACTED
    if isinstance(value, str):
        return value if is_vault_reference(value) else redact_text(value)
    if isinstance(value, BaseException):
        return redact_text(str(value))
    if value is None or isinstance(value, (bool, int, float)):
        return value
    # Persistence and logging accept JSON-safe primitives only. Unknown
    # objects must not reach json.dumps(default=str), where repr/str could
    # disclose arbitrary fields.
    return REDACTED


class RedactingFilter(logging.Filter):
    """Logging filter that sanitizes messages, arguments, and extra fields."""

    _standard_attributes = frozenset(logging.makeLogRecord({}).__dict__) | {"message", "asctime"}

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_data(record.msg)
        record.args = redact_data(record.args)
        if record.exc_info is not None:
            formatted = "".join(traceback.format_exception(*record.exc_info))
            record.exc_info = None
            record.exc_text = redact_text(formatted)
        elif record.exc_text is not None:
            record.exc_text = redact_text(record.exc_text)
        if record.stack_info is not None:
            record.stack_info = redact_text(record.stack_info)
        for name, value in tuple(record.__dict__.items()):
            if name not in self._standard_attributes:
                record.__dict__[name] = redact_data(value, key=name)
        return True


def install_redacting_filter(logger: logging.Logger | None = None) -> RedactingFilter:
    """Attach one reusable redaction filter to an application logger.

    Calling this again is safe and also protects handlers that were attached
    after the first application-startup call.
    """

    target = logger or logging.getLogger()
    redacting_filter = next(
        (item for item in target.filters if isinstance(item, RedactingFilter)),
        None,
    )
    if redacting_filter is None:
        redacting_filter = RedactingFilter()
        target.addFilter(redacting_filter)
    for handler in target.handlers:
        if not any(isinstance(item, RedactingFilter) for item in handler.filters):
            handler.addFilter(redacting_filter)
    return redacting_filter
