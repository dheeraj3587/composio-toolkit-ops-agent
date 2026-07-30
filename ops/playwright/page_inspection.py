"""A bounded, secret-free view of the live page for one decision step.

Everything here reads the DOM and returns only accessibility-relevant, non-secret
facts. That restriction is the module's reason to exist: the action loop and the
decision backends see pages exclusively through these helpers, so if they cannot
observe a secret, neither can anything downstream of them.

Concretely: an element's VALUE is never read for a credential-shaped field, the
accessible name is sanitized at the source so a credential-describing label becomes
a semantic placeholder, and cookies, storage and headers are never touched. The
page fingerprint is derived from the path plus role/name pairs only, so it can be
logged and compared without carrying page content.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from ops.browser.decider import SnapshotElement
from ops.core.model_input_dlp import sanitize_element_name


@dataclass(frozen=True, slots=True)
class PageInspection:
    """A bounded, secret-free view of the current page for one decision step."""

    url: str
    title: str
    visible_text: str
    elements: tuple[SnapshotElement, ...]
    locators: tuple[Any, ...]
    fingerprint: str
    # Monotonic DOM generation this inspection was taken at (item 3).
    generation: int = 0

    def accessible_names(self) -> tuple[str, ...]:
        return tuple(element.name for element in self.elements if element.name)


# --- small helpers (kept module-level for unit testing) -----------------------
async def _describe_element(locator: Any) -> dict[str, object]:
    """Describe ONE element with accessibility-relevant, non-secret attributes.

    Collects role/tag, accessible name, input type, and whether a NON-secret field
    is filled. It never reads an input's value, cookies, storage, or headers.
    """

    async def _attr(name: str) -> str:
        try:
            value = await locator.get_attribute(name, timeout=2_000)
        except Exception:
            return ""
        return value if isinstance(value, str) else ""

    tag = ""
    try:
        tag = str(await locator.evaluate("el => el.tagName.toLowerCase()")) or ""
    except Exception:
        tag = ""
    element_type = await _attr("type")
    # Accessible name, preferring the sources Playwright/ARIA recommend.
    name = await _attr("aria-label") or await _attr("placeholder") or await _attr("title")
    if not name:
        try:
            text = await locator.inner_text(timeout=2_000)
            name = text.strip()[:120] if isinstance(text, str) else ""
        except Exception:
            name = ""
    role = await _attr("role") or tag or "element"
    field_name = await _attr("name")
    secretish = bool(_SECRETISH_FIELD.search(f"{name} {element_type} {field_name}"))
    # Sanitize the accessible name at the source: a credential-describing name
    # becomes a semantic placeholder, and any token-shaped text is redacted.
    origin = "contenteditable" if tag == "div" and await _attr("contenteditable") else tag
    name = sanitize_element_name(name, element_type=element_type, origin=origin, role=tag or role)
    value_present = False
    if not secretish and tag in {"input", "textarea"}:
        try:
            current = await locator.input_value(timeout=2_000)
            value_present = bool(isinstance(current, str) and current)
        except Exception:
            value_present = False
    return {
        "role": role,
        "tag": tag,
        "name": name,
        "type": element_type,
        "value_present": value_present,
    }


_SECRETISH_FIELD = re.compile(r"(?i)pass|secret|token|otp|code|cvv|card|credential|api.?key")


def _fingerprint(url: str, elements: Sequence[SnapshotElement]) -> str:
    """A stable, non-secret signature of the current page state."""

    parts = [urlsplit(url).path or "/"]
    parts.extend(f"{element.role}:{element.name}" for element in elements[:15])
    return "|".join(parts)[:2_000]


def _page_url(page: Any) -> str:
    url = getattr(page, "url", "")
    return url if isinstance(url, str) and url else "https://unknown.invalid/"


async def _visible_text(page: Any, *, limit: int = 20_000) -> str:
    """Best-effort visible body text, bounded. Used only for signal matching."""

    try:
        text = await page.inner_text("body", timeout=5_000)
    except Exception:
        return ""
    return text[:limit] if isinstance(text, str) else ""
