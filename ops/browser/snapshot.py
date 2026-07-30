"""Ranked, bounded, accessibility-facing page snapshot with frame support.

Phase 1 took "the first 40 DOM nodes" of the main frame. That both missed the
element the agent needed and wasted budget on irrelevant chrome. This module
instead collects accessibility-facing facts (role, accessible name, label,
placeholder, visibility, enabled/checked/selected/expanded state, a SAFE href
path, a reviewed test id, the frame path, and a nearby heading) and then RANKS
elements by checkpoint relevance, actionability, visibility, role importance and
viewport proximity before truncating.

Raw HTML is never collected and never sent anywhere. Values are never read —
only the boolean fact that a field is filled, and never for a secret-ish field.
Frames are walked only when their origin is reviewed.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any
from urllib.parse import urlsplit

from ops.browser.decider import MAX_ELEMENTS, SnapshotElement, build_snapshot
from ops.browser.host_policy import host_matches_patterns
from ops.core.model_input_dlp import sanitize_element_name

# One bounded selector for interactive/consequential elements (never full HTML).
INTERACTIVE_SELECTOR = (
    "a, button, input, select, textarea, "
    "[role='button'], [role='link'], [role='menuitem'], [role='tab'], [role='checkbox'], "
    "[role='combobox'], [contenteditable='true']"
)
# Reviewed test-id attributes, in priority order.
_TEST_ID_ATTRS = ("data-testid", "data-test-id", "data-test", "data-qa")
# Per-frame collection cap so one huge frame cannot crowd out the others.
_PER_FRAME_CAP = 60
# Total raw candidates considered before ranking/truncation.
_RAW_CAP = 200

_ROLE_IMPORTANCE: dict[str, int] = {
    "button": 40,
    "a": 34,
    "link": 34,
    "input": 32,
    "select": 30,
    "textarea": 26,
    "menuitem": 24,
    "tab": 20,
}


def _normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip()


def frame_host(frame: Any) -> str:
    """The frame's host, or "" when it cannot be determined."""

    try:
        url = frame.url
    except Exception:
        return ""
    if not isinstance(url, str) or not url:
        return ""
    return (urlsplit(url).hostname or "").rstrip(".").casefold()


def frame_chain(frame: Any) -> tuple[str, ...]:
    """The chain of frame HOSTS from the outermost child down to ``frame``.

    The main frame yields ``()`` so a main-frame element's identity is unchanged
    from Phase 1. Each nested frame contributes its host, which is exactly what
    the reviewed-origin check needs.
    """

    chain: list[str] = []
    current = frame
    seen = 0
    while current is not None and seen < 8:
        try:
            parent = current.parent_frame
        except Exception:
            parent = None
        if parent is None:
            break  # `current` is the main frame; do not include it
        host = frame_host(current)
        chain.append(host or "unknown")
        current = parent
        seen += 1
    return tuple(reversed(chain))


async def _describe(locator: Any, frame_path: tuple[str, ...]) -> dict[str, object]:
    """Collect accessibility-facing facts for ONE element (no raw HTML, no values)."""

    raw: dict[str, object] = {"frame_path": list(frame_path)}

    async def _attr(name: str) -> str:
        try:
            value = await locator.get_attribute(name, timeout=1_000)
        except Exception:
            return ""
        return value if isinstance(value, str) else ""

    tag = ""
    try:
        tag = str(await locator.evaluate("el => el.tagName.toLowerCase()")).strip()
    except Exception:
        tag = ""
    role = (await _attr("role")) or tag or "element"
    raw["role"] = role
    raw["tag"] = tag
    raw["type"] = await _attr("type")

    # Accessible name: aria-label, then the associated label text, then the
    # element's own text, then placeholder/name/title.
    name = await _attr("aria-label")
    if not name:
        try:
            name = str(await locator.inner_text(timeout=1_000)).strip()
        except Exception:
            name = ""
    if not name:
        name = (await _attr("placeholder")) or (await _attr("name")) or (await _attr("title"))
    # Single DLP boundary for every page-derived label.
    raw["name"] = sanitize_element_name(name[:200], element_type=str(raw["type"]), role=role)

    for attr in _TEST_ID_ATTRS:
        value = await _attr(attr)
        if value:
            raw["test_id"] = value
            break

    href = await _attr("href")
    if href:
        # PATH ONLY: a query string or fragment could carry a token.
        try:
            raw["href_path"] = urlsplit(href).path or "/"
        except Exception:
            raw["href_path"] = None

    for state_attr, key in (("aria-checked", "checked"), ("aria-expanded", "expanded")):
        value = await _attr(state_attr)
        if value:
            raw[key] = value

    try:
        raw["visible"] = bool(await locator.is_visible())
    except Exception:
        raw["visible"] = False
    try:
        raw["enabled"] = bool(await locator.is_enabled())
    except Exception:
        raw["enabled"] = False

    element_type = str(raw.get("type") or "").casefold()
    if element_type in {"checkbox", "radio"} or role.casefold() == "checkbox":
        try:
            raw["checked"] = bool(await locator.is_checked())
        except Exception:
            pass
    if tag == "option" or role.casefold() == "option":
        try:
            raw["selected"] = bool(await locator.evaluate("el => !!el.selected"))
        except Exception:
            pass
    # For a NON-secret <select>, record the currently selected option's LABEL.
    # The interactive snapshot deliberately does not collect <option> elements, so
    # without this a select_option action had no reliable state to verify against.
    if tag == "select" and not bool(raw.get("secretish")):
        try:
            selected_label = await locator.locator("option:checked").inner_text(timeout=1_000)
        except Exception:
            selected_label = ""
        raw["selected_label"] = (
            sanitize_element_name(selected_label[:120], role="option") if selected_label else None
        )

    try:
        value = await locator.input_value(timeout=1_000)
        raw["value_present"] = bool(value)
    except Exception:
        raw["value_present"] = False

    # Nearest preceding heading: a stable, human-meaningful anchor.
    try:
        heading = await locator.evaluate(
            "el => { let n = el; while (n) { let p = n.previousElementSibling; "
            "while (p) { if (/^H[1-6]$/.test(p.tagName)) return p.innerText; "
            "p = p.previousElementSibling; } n = n.parentElement; } return ''; }"
        )
        if isinstance(heading, str) and heading.strip():
            raw["nearby_heading"] = heading.strip()[:120]
    except Exception:
        pass

    try:
        box = await locator.bounding_box()
        if isinstance(box, dict):
            raw["_top"] = float(box.get("y") or 0.0)
    except Exception:
        raw["_top"] = 10_000.0
    return raw


async def collect_raw_elements(
    page: Any, *, reviewed_patterns: Sequence[str], include_frames: bool = True
) -> list[dict[str, object]]:
    """Collect raw element facts from the main frame plus REVIEWED frames only."""

    frames: list[Any] = []
    try:
        frames.append(page.main_frame)
    except Exception:
        return []
    if include_frames:
        try:
            for frame in page.frames:
                if frame is page.main_frame:
                    continue
                host = frame_host(frame)
                # A frame whose origin is not reviewed is not inspected at all.
                if host and host_matches_patterns(host, tuple(reviewed_patterns)):
                    frames.append(frame)
        except Exception:
            pass

    raw: list[dict[str, object]] = []
    for frame in frames:
        path = frame_chain(frame)
        try:
            handles = frame.locator(INTERACTIVE_SELECTOR)
            total = min(int(await handles.count()), _PER_FRAME_CAP)
        except Exception:
            continue
        for index in range(total):
            if len(raw) >= _RAW_CAP:
                return raw
            try:
                described = await _describe(handles.nth(index), path)
            except Exception:
                continue
            described["_locator"] = handles.nth(index)
            raw.append(described)
    return raw


def rank_raw_elements(
    raw: Sequence[dict[str, object]],
    *,
    checkpoint_signals: Sequence[str],
    limit: int = MAX_ELEMENTS,
) -> list[dict[str, object]]:
    """Rank by checkpoint relevance, actionability, visibility, role, viewport."""

    needles = [_normalize(s) for s in checkpoint_signals if str(s).strip()]

    def _score(item: dict[str, object]) -> float:
        name = _normalize(str(item.get("name") or ""))
        role = str(item.get("role") or "").casefold()
        score = 0.0
        # Checkpoint relevance dominates.
        for needle in needles:
            if needle and needle in name:
                score += 120.0
                break
        if item.get("visible"):
            score += 30.0
        if item.get("enabled"):
            score += 20.0
        score += float(_ROLE_IMPORTANCE.get(role, 8))
        if item.get("test_id"):
            score += 12.0  # a stable identity is worth surfacing
        # Viewport proximity: nearer the top scores higher (bounded).
        raw_top = item.get("_top")
        top = float(raw_top) if isinstance(raw_top, (int, float)) else 10_000.0
        score += max(0.0, 25.0 - min(top, 5_000.0) / 200.0)
        return score

    return sorted(raw, key=_score, reverse=True)[:limit]


async def build_ranked_snapshot(
    page: Any,
    *,
    reviewed_patterns: Sequence[str],
    checkpoint_signals: Sequence[str] = (),
    limit: int = MAX_ELEMENTS,
    include_frames: bool = True,
) -> tuple[tuple[SnapshotElement, ...], tuple[Any, ...]]:
    """Return (snapshot elements, matching locators) — bounded and ranked."""

    raw = await collect_raw_elements(
        page, reviewed_patterns=reviewed_patterns, include_frames=include_frames
    )
    ranked = rank_raw_elements(raw, checkpoint_signals=checkpoint_signals, limit=limit)
    locators = tuple(item.pop("_locator", None) for item in ranked)
    for item in ranked:
        item.pop("_top", None)
    elements = build_snapshot(ranked)
    return elements, locators


__all__ = [
    "INTERACTIVE_SELECTOR",
    "build_ranked_snapshot",
    "collect_raw_elements",
    "frame_chain",
    "frame_host",
    "rank_raw_elements",
]
