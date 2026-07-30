"""Reading an untrusted Gmail payload: identity, recency, recipients, trust order.

Every function here treats the provider payload as untrusted and shape-unstable, which
is why each one probes several key spellings and returns a safe default instead of
raising. A single unexpected field must not abort an outreach sweep across a hundred
apps.

Two rules carry real weight. Recency is enforced from the message's own timestamp with
an explicit clock-skew allowance, so a stale verification email can never be replayed
as a fresh one. And ordering is by TRUST rather than arrival: a message from a reviewed
sender outranks a newer message from an unknown one, so a lookalike email that lands
after the genuine one cannot win the selection.

Secret-bearing lines are recognized by shape so their values can be vaulted and
redacted before anything is stored; the raw value never leaves this boundary.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

import httpx

from ops.email.verification import (
    DEFAULT_CLOCK_SKEW_SECONDS,
    VerificationCandidate,
    extract_verification_code,
    extract_verification_link,
    parse_received_at_ms,
    sender_authentication_method,
    sender_domain_of,
)
from ops.providers.errors import ProviderContractError

_SECRET_LINE = re.compile(
    r"(?im)\b(?P<kind>client[_ -]?secret|api[_ -]?key|access[_ -]?token|"
    r"refresh[_ -]?token)\s*[:=]\s*(?P<value>[^\s,;<>]{8,})"
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
# ``ops.email.verification`` so the hardened verification path and these
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


def _message_header_values(
    message: Mapping[str, object],
    name: str,
) -> tuple[str, ...]:
    """Collect one RFC header across the provider's known payload shapes."""

    normalized_name = name.casefold()
    key_aliases = {
        "authentication-results": (
            "Authentication-Results",
            "authentication-results",
            "authentication_results",
            "authenticationResults",
        ),
        "arc-authentication-results": (
            "ARC-Authentication-Results",
            "arc-authentication-results",
            "arc_authentication_results",
            "arcAuthenticationResults",
        ),
        "arc-seal": (
            "ARC-Seal",
            "arc-seal",
            "arc_seal",
            "arcSeal",
        ),
    }.get(normalized_name, (name,))
    values: list[str] = []
    for key in key_aliases:
        value = message.get(key)
        if isinstance(value, str) and value.strip():
            values.append(value)
        elif isinstance(value, (list, tuple)):
            values.extend(item for item in value if isinstance(item, str) and item.strip())
    for container in (message, message.get("payload")):
        if not isinstance(container, Mapping):
            continue
        headers = container.get("headers")
        if isinstance(headers, Mapping):
            for key, value in headers.items():
                if str(key).casefold() != normalized_name:
                    continue
                if isinstance(value, str) and value.strip():
                    values.append(value)
                elif isinstance(value, (list, tuple)):
                    values.extend(item for item in value if isinstance(item, str) and item.strip())
        elif isinstance(headers, list):
            for header in headers:
                if not isinstance(header, Mapping):
                    continue
                if str(header.get("name") or "").casefold() != normalized_name:
                    continue
                value = header.get("value")
                if isinstance(value, str) and value.strip():
                    values.append(value)
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
        authentication_results=_message_header_values(message, "Authentication-Results"),
        arc_authentication_results=_message_header_values(
            message,
            "ARC-Authentication-Results",
        ),
        arc_seals=_message_header_values(message, "ARC-Seal"),
    )


def _message_sender_authenticated(message: Mapping[str, object]) -> bool:
    """Whether Gmail supplied aligned sender-authentication evidence."""

    candidate = _verification_candidate(message)
    method, _reason = sender_authentication_method(
        candidate,
        sender_domain=sender_domain_of(candidate.sender),
    )
    return method != "none"


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
# ``ops.email.verification``. This alias keeps the historical permissive
# behaviour (no host allowlist) available to existing callers, while anything
# that consumes the link for an autonomous action must instead go through
# ``GmailWorker.fetch_verification``, which requires a reviewed host.
_extract_login_link = extract_verification_link
