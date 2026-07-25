"""The single data-loss-prevention boundary for model input.

EVERY page-derived value must pass through this module before it can reach an
inference backend: the current URL, page title, accessible names, labels,
placeholders, element text, and any reason/summary derived from the page.

Design rules (fail closed):

* URLs lose their query string and fragment entirely, and suspicious path
  segments are replaced — a token in a path or an unknown query parameter is a
  real leak vector.
* Known provider-key shapes, bearer tokens, authorization codes, JWTs and
  high-entropy blobs are redacted wherever they appear.
* Element names that describe a credential are replaced with a SEMANTIC
  placeholder (``<secret-field:password>``) so the model still understands the
  page structure without ever seeing the value or a value-shaped name.
* Text sourced from credential outputs, copy controls, ``code``/``pre`` blocks or
  secret-bearing ``contenteditable`` regions is dropped entirely rather than
  redacted, because those are exactly where a rendered credential lives.

Nothing here logs, persists, or returns the raw input: callers receive only the
sanitized projection. Prompts are never written to logs, traces or checkpoints.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlsplit, urlunsplit

REDACTED = "[REDACTED]"
SECRET_FIELD = "<secret-field:{kind}>"
DROPPED = "[DROPPED_SENSITIVE_REGION]"

# Element/tag origins whose text is never forwarded, even redacted: a rendered
# credential, a "copy token" control, or a code block showing a key.
UNSAFE_TEXT_ORIGINS = frozenset(
    {"code", "pre", "samp", "kbd", "textarea", "contenteditable", "copy-control", "credential"}
)

# --- Known provider-key and token shapes (documented public prefixes) ---------
_PROVIDER_KEY_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{8,}\b"),  # Stripe-style
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),  # OpenAI-style
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{8,}\b"),  # Slack
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"),  # GitHub
    re.compile(r"\bAC[0-9a-fA-F]{30,}\b"),  # Twilio Account SID
    re.compile(r"\bAKIA[0-9A-Z]{12,}\b"),  # AWS access key id
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),  # Google API key
    re.compile(r"\bcsk-[A-Za-z0-9]{8,}\b"),  # Cerebras-style
    re.compile(r"\bgsk_[A-Za-z0-9]{8,}\b"),  # Groq-style
    re.compile(r"\b[0-9a-f]{40}\b"),  # 40-hex personal tokens (e.g. Pipedrive)
    re.compile(r"\b[0-9a-f]{32}\b"),  # 32-hex api keys
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b")
_BEARER = re.compile(r"(?i)\b(bearer|token|apikey|api[_-]key|secret|password)\b\s*[:=]?\s*\S{6,}")
_AUTH_CODE = re.compile(r"(?i)\b(?:code|state|access_token|id_token|refresh_token)=[^\s&]{6,}")

# Field names that indicate a credential input; the value is never shown anyway,
# but the NAME is replaced so a value-shaped name cannot leak either.
_SECRET_NAME = re.compile(
    r"(?i)pass(?:word|phrase)?|secret|token|otp|one[-_ ]?time|cvv|card|credential|api[-_ ]?key"
    r"|private[-_ ]?key|client[-_ ]?secret|auth"
)
# Path segments that look like an identifier/secret rather than a route name.
_SUSPICIOUS_SEGMENT = re.compile(r"^[A-Za-z0-9_-]{20,}$")
_HEX_SEGMENT = re.compile(r"^[0-9a-fA-F]{16,}$")


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def is_high_entropy(value: str, *, min_length: int = 20, threshold: float = 3.6) -> bool:
    """True when a token looks like random key material rather than prose.

    Prose has low per-character entropy; base64/hex secrets are high. The length
    floor avoids flagging ordinary short words.
    """

    candidate = value.strip()
    if len(candidate) < min_length or " " in candidate:
        return False
    # Require a mix that looks encoded rather than a long dictionary word.
    if not re.search(r"[0-9]", candidate) and not re.search(r"[_\-+/=]", candidate):
        if candidate.isalpha() and candidate.islower():
            return False
    return _shannon_entropy(candidate) >= threshold


def redact_secrets(text: str, *, max_length: int = 2_000) -> str:
    """Redact provider keys, tokens, auth codes and high-entropy blobs in text."""

    if not text:
        return ""
    cleaned = text[:max_length]
    for pattern in _PROVIDER_KEY_PATTERNS:
        cleaned = pattern.sub(REDACTED, cleaned)
    cleaned = _JWT.sub(REDACTED, cleaned)
    cleaned = _AUTH_CODE.sub(REDACTED, cleaned)
    cleaned = _BEARER.sub(REDACTED, cleaned)
    # Finally, sweep any remaining high-entropy token.
    parts = re.split(r"(\s+)", cleaned)
    for index, part in enumerate(parts):
        stripped = part.strip(".,;:!?()[]{}\"'<>")
        if stripped and stripped != REDACTED and is_high_entropy(stripped):
            parts[index] = part.replace(stripped, REDACTED)
    return "".join(parts)


def sanitize_url(url: str) -> str:
    """Return an https origin+path with NO query or fragment and safe segments.

    A query string or fragment can carry an OAuth code or token, so both are
    dropped unconditionally rather than filtered. Identifier-looking path segments
    are replaced so a token embedded in a path cannot leak.
    """

    if not url:
        return ""
    parsed = urlsplit(url)
    if not parsed.scheme or not parsed.netloc:
        # Not a URL: treat as free text so secrets are still redacted.
        return redact_secrets(url, max_length=300)
    host = (parsed.hostname or "").casefold()
    segments: list[str] = []
    for segment in (parsed.path or "").split("/"):
        if not segment:
            continue
        if (
            _SUSPICIOUS_SEGMENT.match(segment)
            or _HEX_SEGMENT.match(segment)
            or is_high_entropy(segment, min_length=16)
        ):
            segments.append(REDACTED)
        else:
            segments.append(redact_secrets(segment, max_length=120))
    path = "/" + "/".join(segments) if segments else "/"
    # Query and fragment are intentionally dropped (empty strings below).
    return urlunsplit((parsed.scheme, host, path, "", ""))


def sanitize_element_name(name: str, *, element_type: str = "", origin: str = "") -> str:
    """Sanitize an accessible name/label/placeholder for model consumption.

    A credential-describing name becomes a semantic placeholder, so the model can
    still reason about page structure ("there is a password field here") without
    receiving a value or a value-shaped string.
    """

    if origin.casefold() in UNSAFE_TEXT_ORIGINS:
        return DROPPED
    combined = f"{name} {element_type}"
    if _SECRET_NAME.search(combined):
        kind = _secret_kind(combined)
        return SECRET_FIELD.format(kind=kind)
    return redact_secrets(name, max_length=120)


def _secret_kind(text: str) -> str:
    lowered = text.casefold()
    for needle, kind in (
        ("password", "password"),
        ("passphrase", "password"),
        ("otp", "otp"),
        ("one-time", "otp"),
        ("one time", "otp"),
        ("client secret", "client_secret"),
        ("api key", "api_key"),
        ("api_key", "api_key"),
        ("apikey", "api_key"),
        ("private key", "private_key"),
        ("token", "token"),
        ("credential", "credential"),
        ("cvv", "card"),
        ("card", "card"),
        ("secret", "secret"),
        ("auth", "auth"),
    ):
        if needle in lowered:
            return kind
    return "secret"


def sanitize_page_text(text: str, *, origin: str = "", max_length: int = 2_000) -> str:
    """Sanitize visible page text. Unsafe origins are DROPPED, not redacted."""

    if origin.casefold() in UNSAFE_TEXT_ORIGINS:
        return DROPPED
    return redact_secrets(text, max_length=max_length)


def sanitize_reason(text: str, *, max_length: int = 300) -> str:
    """Sanitize a page-derived reason/summary before it is stored or surfaced."""

    return redact_secrets(text, max_length=max_length)


def contains_secret_material(text: str) -> bool:
    """True when text still looks like it carries credential material.

    Used as a belt-and-braces assertion at the inference boundary: a prompt that
    trips this is refused rather than sent.
    """

    if not text:
        return False
    for pattern in _PROVIDER_KEY_PATTERNS:
        if pattern.search(text):
            return True
    if _JWT.search(text) or _AUTH_CODE.search(text):
        return True
    return any(
        is_high_entropy(token.strip(".,;:!?()[]{}\"'<>"))
        for token in re.split(r"\s+", text)
        if token
    )


__all__ = [
    "DROPPED",
    "REDACTED",
    "SECRET_FIELD",
    "UNSAFE_TEXT_ORIGINS",
    "contains_secret_material",
    "is_high_entropy",
    "redact_secrets",
    "sanitize_element_name",
    "sanitize_page_text",
    "sanitize_reason",
    "sanitize_url",
]
