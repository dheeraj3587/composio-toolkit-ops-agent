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
    r"cookie|session[_-]?cookie|credentials?|token|secret|key|"
    # Plural forms, and the reviewed login-secret names. These are spelled out
    # one by one on purpose. The tempting fix is to relax the trailing boundary
    # to ``(?:s?(?:$|[_-]))``, but that also matches ``field_keys`` -- the key
    # name of the ops/browser/link_log.py helper that exists specifically to log
    # credential field NAMES safely -- and collapsing it to [REDACTED] would
    # destroy the one diagnostic that says which field a login step filled.
    r"api[_-]?keys|access[_-]?tokens|refresh[_-]?tokens|tokens|secrets|"
    r"passwords|passwds|cookies|credential[_-]?refs|"
    r"otp|login[_-]?otp|passcode|one[_-]?time[_-]?password|"
    r"login[_-]?verification[_-]?url|magic[_-]?link"
    r")(?:$|[_-])"
)
_SENSITIVE_CODE_KEY = re.compile(
    r"(?ix)^(?:code|(?:oauth|auth|authorization|verification|device|totp)[_-]?code|"
    r"one[_-]?time[_-]?code)$"
)

# These exact keys describe policy or public navigation metadata; they never hold
# credential values. Values still pass through ``redact_text`` recursively, so a
# provider key accidentally embedded in either field remains redacted.
_SAFE_CREDENTIAL_METADATA_KEYS = frozenset(
    {
        "credential_creation_policy",
        "credential_management_url",
    }
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
    r"(?ix)(\[?[\"']?\b(?:(?:[a-z0-9]+[_-]+)*(?:"
    r"api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|"
    r"oauth[_-]?(?:client[_-]?)?secret|(?:session|id|auth|oauth)[_-]?token|"
    r"password|passwd|private[_-]?key|totp[_-]?seed|credentials?|token|secret|key"
    r")|oauth[_-]?code|authorization[_-]?code|verification[_-]?code|"
    r"device[_-]?code|totp[_-]?code|one[_-]?time[_-]?code|code)"
    # The name may be quoted, as it is in every JSON body and in Python's own
    # dict repr. Without the optional quote wrapper the whole branch failed to
    # match a quoted api_key field and the value passed through untouched.
    r"\b[\"']?\]?\s*[:=]\s*)"
    # The value class must exclude quotes, or a quoted value swallows its own
    # closing quote and everything up to the next delimiter.
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;&}\"']+)"
)
# A cookie header carries session material under a name the key matcher never
# sees, because the name lives inside the header value rather than in a field.
_SET_COOKIE = re.compile(r"(?im)^(\s*set-cookie\s*:\s*)(.+)$")
_COOKIE_HEADER = re.compile(r"(?im)^(\s*cookie\s*:\s*)(.+)$")
# A single-use link is a credential in URL-path form. Only paths whose segment
# names one of these flows are touched, so ordinary navigation URLs -- the ones
# an operator actually needs to read in a failure -- stay intact.
_LINK_TOKEN_PATH = re.compile(
    r"(?i)(/(?:magic|magic[_-]?link|verify|verification|confirm|activate|invite|"
    r"reset|set[_-]?password|token|auth)/)([A-Za-z0-9._~-]{12,})"
)
_TOKEN_QUERY = re.compile(
    r"(?ix)([?&#](?:token|code|key|secret|credentials?|password|api[_-]?key|"
    r"client[_-]?secret|access[_-]?token|refresh[_-]?token|"
    r"(?:session|id|auth|oauth)[_-]?token|authorization|jwt|signature|sig|"
    # One-time material arrives as a query parameter far more often than as a
    # field, and none of these names contain "token", "code" or "key".
    r"otp|passcode|one[_-]?time[_-]?password|verification|verify|confirmation|"
    r"invite|activation|magic|nonce|state)=)"
    r"([^&#\s]+)"
)
_PROVIDER_KEY = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"(?:sk|rk)-(?:live-|test-)?[A-Za-z0-9_-]{12,}|"
    # ``sk_<opaque>`` with no live/test infix is the shape Inception issues, and
    # Mercury is the first provider in every inference chain here, so this is the
    # key most likely to appear in a provider error. The old alternation required
    # the infix and let the deployment's own primary credential through in clear.
    r"(?:sk|rk)_(?:live_|test_)?[A-Za-z0-9]{16,}|"
    r"gh[pousr]_[A-Za-z0-9]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"AIza[A-Za-z0-9_-]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"(?:AKIA|ASIA)[0-9A-Z]{16}|"
    r"pplx-[A-Za-z0-9_-]{12,}|"
    r"gsk_[A-Za-z0-9_-]{16,}|"
    r"sk-or-v1-[A-Za-z0-9_-]{16,}|"
    r"ydc-sk-[A-Za-z0-9_-]{16,}|"
    r"bu_[A-Za-z0-9_-]{16,}|"
    r"ak_[A-Za-z0-9_-]{16,}|"
    r"csk-[A-Za-z0-9_-]{16,}|"
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

    if key.casefold() in _SAFE_CREDENTIAL_METADATA_KEYS:
        return False
    return _SENSITIVE_KEY.search(key) is not None or _SENSITIVE_CODE_KEY.fullmatch(key) is not None


def redact_text(value: str) -> str:
    """Replace recognized secret material while retaining useful context."""

    redacted = _PRIVATE_KEY.sub(REDACTED, value)
    redacted = _AUTHORIZATION.sub(lambda match: match.group(1) + REDACTED, redacted)
    # Whole-header replacement: a cookie header's session material is not an
    # assignment the field matchers can see, and its own name is the only part
    # worth keeping.
    redacted = _SET_COOKIE.sub(lambda match: match.group(1) + REDACTED, redacted)
    redacted = _COOKIE_HEADER.sub(lambda match: match.group(1) + REDACTED, redacted)
    redacted = _BEARER.sub(f"Bearer {REDACTED}", redacted)
    redacted = _JWT.sub(REDACTED, redacted)
    redacted = _LINK_TOKEN_PATH.sub(lambda match: match.group(1) + REDACTED, redacted)
    redacted = _ASSIGNMENT.sub(
        lambda match: match.group(1) + REDACTED,
        redacted,
    )
    redacted = _TOKEN_QUERY.sub(
        lambda match: match.group(1) + REDACTED,
        redacted,
    )
    return _PROVIDER_KEY.sub(REDACTED, redacted)


CYCLE = "[CYCLE]"
DEPTH_EXCEEDED = "[DEPTH_EXCEEDED]"

# A log record's ``extra`` is arbitrary caller-supplied structure, so recursion
# depth here is attacker-influenced rather than bounded by a schema. Unbounded
# recursion raised RecursionError from inside the logging filter, which aborts
# the emit and -- worse -- can surface the unredacted record through logging's
# own error path. Both guards degrade to a marker instead of raising.
_MAX_DEPTH = 24


def redact_data(value: Any, *, key: str | None = None) -> Any:
    """Recursively sanitize common Python/JSON structures.

    A vault reference is safe to retain even under a key such as
    ``client_secret`` because the reference is the intended public boundary.
    """

    return _redact_data(value, key=key, depth=0, seen=frozenset())


def _redact_data(value: Any, *, key: str | None, depth: int, seen: frozenset[int]) -> Any:
    if depth > _MAX_DEPTH:
        return DEPTH_EXCEEDED
    if isinstance(value, (Mapping, list, tuple, set, frozenset, BaseModel)):
        if id(value) in seen:
            return CYCLE
        seen = seen | {id(value)}

    def recurse(item: Any, *, key: str | None = None) -> Any:
        return _redact_data(item, key=key, depth=depth + 1, seen=seen)

    if isinstance(value, (SecretStr, SecretBytes)):
        return REDACTED
    # Absence is not secret material. Preserve it before key-name classification so
    # an intentionally inapplicable field (for example OAuth URLs in an API-key
    # handoff) remains null instead of becoming the misleading string "[REDACTED]".
    if value is None:
        return None
    if key is not None and _is_sensitive_key(key) and not _is_reference_payload(value, key=key):
        return REDACTED
    if isinstance(value, BaseModel):
        return recurse(value.model_dump(mode="json"), key=key)
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
            sanitized[safe_key] = recurse(item_value, key=raw_key)
        return sanitized
    if isinstance(value, tuple):
        return tuple(recurse(item) for item in value)
    if isinstance(value, list):
        return [recurse(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return [recurse(item) for item in value]
    if isinstance(value, bytes):
        return REDACTED
    if isinstance(value, str):
        return value if is_vault_reference(value) else redact_text(value)
    if isinstance(value, BaseException):
        return redact_text(str(value))
    if isinstance(value, (bool, int, float)):
        return value
    # Persistence and logging accept JSON-safe primitives only. Unknown
    # objects must not reach json.dumps(default=str), where repr/str could
    # disclose arbitrary fields.
    return REDACTED


class RedactingFilter(logging.Filter):
    """Logging filter that sanitizes messages, arguments, and extra fields."""

    _standard_attributes = frozenset(logging.makeLogRecord({}).__dict__) | {"message", "asctime"}

    def filter(self, record: logging.LogRecord) -> bool:
        original_message = record.msg
        record.msg = redact_data(original_message)
        message_was_sanitized = not (
            isinstance(original_message, str) and record.msg == original_message
        )
        if message_was_sanitized:
            # A sensitive assignment in a %-style format string may consume its
            # placeholder (for example ``TOKEN=%s`` -> ``TOKEN=[REDACTED]``).
            # Retaining the original args would make logging raise and its internal
            # error report can print the unredacted Arguments tuple to stderr.
            # Drop args whenever the message template itself was sanitized.
            record.args = ()
        else:
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
