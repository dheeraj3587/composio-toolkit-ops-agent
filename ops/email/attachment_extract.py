"""Pure, offline helpers for detecting credentials inside email attachments.

No network or provider I/O lives here: these functions project a provider
message's attachment list into a typed shape, decide which attachments are safe
text-like candidates, and extract credential ``(kind, value)`` pairs from decoded
text. The GmailWorker owns fetching bytes and vaulting; this module never sees a
secret store and never persists anything, which keeps it trivially testable.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

# Text-like attachments we will parse for credentials. Binary formats (pdf, zip,
# images, office docs) are intentionally NOT parsed here — they are flagged for
# manual review instead of pulled through a binary parser/dependency.
_TEXT_EXTENSIONS = (
    ".txt",
    ".json",
    ".csv",
    ".tsv",
    ".env",
    ".yaml",
    ".yml",
    ".xml",
    ".ini",
    ".cfg",
    ".conf",
    ".properties",
    ".md",
    ".log",
)
_TEXT_MIME_PREFIXES = ("text/",)
_TEXT_MIME_EXACT = (
    "application/json",
    "application/xml",
    "application/x-yaml",
    "application/yaml",
    "application/x-www-form-urlencoded",
)

# Keys whose value is treated as a credential when found in KEY=VALUE / KEY: VALUE
# lines or JSON objects. Word-bounded and case-insensitive.
_CRED_KEY = re.compile(
    r"(?i)(client[_-]?secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|"
    r"secret[_-]?key|auth[_-]?token|bearer[_-]?token|private[_-]?key|"
    r"password|passwd|secret|token)"
)
# A single KEY=VALUE or KEY: VALUE line. Value must be reasonably credential-shaped
# (>= 6 non-space chars) to avoid capturing prose.
_KV_LINE = re.compile(
    r"(?im)^[\s\"']*(?P<key>[A-Za-z0-9_.\- ]{2,60}?)[\s\"']*[:=]\s*"
    r"(?P<value>[^\s,;#]{6,})\s*$"
)


@dataclass(frozen=True, slots=True)
class AttachmentRef:
    """A provider-agnostic reference to one message attachment."""

    attachment_id: str
    filename: str
    mime_type: str
    size: int


def _string(value: object) -> str:
    return value if isinstance(value, str) else ""


def _int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def parse_attachment_list(message: Mapping[str, object]) -> tuple[AttachmentRef, ...]:
    """Project a fetched message's attachment references into typed refs.

    Tolerates both the convenience ``attachmentList``/``attachment_list`` arrays
    (camel or snake case) and the raw Gmail ``payload.parts[]`` MIME tree, since
    Composio exposes either depending on the fetch mode.
    """

    refs: list[AttachmentRef] = []
    seen: set[str] = set()

    raw_list = message.get("attachmentList")
    if not isinstance(raw_list, list):
        raw_list = message.get("attachment_list")
    if isinstance(raw_list, list):
        for item in raw_list:
            if not isinstance(item, Mapping):
                continue
            attachment_id = _string(item.get("attachmentId") or item.get("attachment_id"))
            filename = _string(item.get("filename") or item.get("file_name") or item.get("name"))
            if not attachment_id or attachment_id in seen:
                continue
            seen.add(attachment_id)
            refs.append(
                AttachmentRef(
                    attachment_id=attachment_id,
                    filename=filename,
                    mime_type=_string(item.get("mimeType") or item.get("mime_type")),
                    size=_int(item.get("size")),
                )
            )

    payload = message.get("payload")
    if isinstance(payload, Mapping):
        parts = payload.get("parts")
        if isinstance(parts, Sequence):
            for part in parts:
                if not isinstance(part, Mapping):
                    continue
                body = part.get("body")
                attachment_id = ""
                size = 0
                if isinstance(body, Mapping):
                    attachment_id = _string(body.get("attachmentId") or body.get("attachment_id"))
                    size = _int(body.get("size"))
                if not attachment_id or attachment_id in seen:
                    continue
                seen.add(attachment_id)
                refs.append(
                    AttachmentRef(
                        attachment_id=attachment_id,
                        filename=_string(part.get("filename")),
                        mime_type=_string(part.get("mimeType") or part.get("mime_type")),
                        size=size,
                    )
                )
    return tuple(refs)


def is_text_like(filename: str, mime_type: str) -> bool:
    """True when an attachment is a text format we will parse for credentials."""

    mime = (mime_type or "").split(";")[0].strip().casefold()
    if mime in _TEXT_MIME_EXACT or any(mime.startswith(prefix) for prefix in _TEXT_MIME_PREFIXES):
        return True
    lowered = (filename or "").casefold()
    return any(lowered.endswith(ext) for ext in _TEXT_EXTENSIONS)


def _normalize_kind(key: str) -> str:
    match = _CRED_KEY.search(key)
    base = (match.group(0) if match else key).casefold()
    slug = re.sub(r"[^a-z0-9]+", "_", base).strip("_")
    return slug or "secret"


def _walk_json(node: object, out: list[tuple[str, str]]) -> None:
    if isinstance(node, Mapping):
        for key, value in node.items():
            if isinstance(key, str) and _CRED_KEY.search(key) and isinstance(value, str) and value:
                out.append((_normalize_kind(key), value))
            else:
                _walk_json(value, out)
    elif isinstance(node, list):
        for item in node:
            _walk_json(item, out)


def extract_secret_pairs(text: str) -> tuple[tuple[str, str], ...]:
    """Extract ``(kind, value)`` credential pairs from decoded attachment text.

    Scans JSON structure (credential-named keys) and line-based ``KEY=VALUE`` /
    ``KEY: VALUE`` pairs where the key names a credential. De-duplicated by value.
    Returns pairs only; the caller vaults them and emits references.
    """

    pairs: list[tuple[str, str]] = []
    stripped = text.strip()
    if stripped[:1] in "{[":
        try:
            _walk_json(json.loads(stripped), pairs)
        except (json.JSONDecodeError, ValueError):
            pass
    for match in _KV_LINE.finditer(text):
        key = match.group("key")
        if not _CRED_KEY.search(key):
            continue
        value = match.group("value").strip().strip("\"'")
        if value:
            pairs.append((_normalize_kind(key), value))

    seen_values: set[str] = set()
    unique: list[tuple[str, str]] = []
    for kind, value in pairs:
        if value in seen_values:
            continue
        seen_values.add(value)
        unique.append((kind, value))
    return tuple(unique)


__all__ = [
    "AttachmentRef",
    "extract_secret_pairs",
    "is_text_like",
    "parse_attachment_list",
]
