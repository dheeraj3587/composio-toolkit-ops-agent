"""Whether a page may be captured at all, and how a capture is masked.

Screenshots are the one place the worker turns page content into a stored artifact,
so every rule here is a refusal rule.

Detection is STRUCTURAL, not substring-based: a secret-ish input, or a region the
snapshot already dropped as unsafe, means a credential could be rendered on this
page. The plain-text check additionally covers code/pre blocks, textareas,
contenteditable regions and custom components carrying data-secret or
data-credential, which masking selectors alone would miss.

Everything fails CLOSED. If the DOM cannot be inspected, the page is treated as
sensitive. If masking cannot be applied, NO screenshot is returned rather than an
unmasked one. Login inputs are capturable only because the mask covers every
editable value — not just fields whose names look secret, since an email or user
identifier is account data too — while a plain-text secret elsewhere on the page
remains a hard refusal.
"""

from __future__ import annotations

from typing import Any

from ops.core.model_input_dlp import DROPPED, contains_secret_material
from ops.playwright.page_inspection import PageInspection

_MAX_SCREENSHOT_BYTES = 4_000_000


_CREDENTIAL_SURFACE_SELECTOR = (
    "input[type='password'], input[name*='token' i], input[name*='secret' i], "
    "input[name*='key' i], input[name*='otp' i], code, pre, samp, kbd, textarea, "
    "[data-secret], [data-credential], [contenteditable='true']"
)


def _looks_credential_bearing(inspection: PageInspection) -> bool:
    """True when the inspected page structurally exposes credential material.

    Structural, not substring-based: a secret-ish INPUT, or a dropped unsafe region
    in the snapshot, means a credential could be rendered on this page.
    """

    if any(element.secretish for element in inspection.elements):
        return True
    if DROPPED in inspection.visible_text:
        return True
    return any(DROPPED in element.name for element in inspection.elements)


async def _has_credential_content(page: Any) -> bool:
    """Structural check for credential-bearing surfaces before any capture.

    Covers plain-text tokens in code/pre, textarea, contenteditable and custom
    components carrying data-secret/data-credential — cases that masking selectors
    alone would miss. Fails CLOSED when safety cannot be established.
    """

    try:
        locator = page.locator(_CREDENTIAL_SURFACE_SELECTOR)
        if int(await locator.count()) > 0:
            return True
    except Exception:
        return True  # cannot prove safety -> treat as sensitive
    try:
        text = await page.inner_text("body", timeout=3_000)
    except Exception:
        return True
    return contains_secret_material(text if isinstance(text, str) else "")


async def _has_unmasked_secret_content(page: Any) -> bool:
    """Return true only when page text itself may expose credential material.

    Login inputs are safe to capture only because ``_masked_screenshot`` masks
    every form field. Plain-text secrets elsewhere in the page remain a hard
    refusal, and inspection errors fail closed.
    """

    try:
        text = await page.inner_text("body", timeout=3_000)
    except Exception:
        return True
    return contains_secret_material(text if isinstance(text, str) else "")


async def _masked_screenshot(page: Any) -> bytes | None:
    """Screenshot the viewport with every credential-bearing field masked.

    If masking cannot be applied, NO screenshot is returned — never an unmasked one.
    """

    try:
        masks = [
            # Mask every editable value, not only fields whose names look secret.
            # Email/user identifiers are account data too.
            page.locator("input"),
            page.locator("textarea"),
            page.locator("[contenteditable='true']"),
            page.locator("[data-secret]"),
            page.locator("[data-credential]"),
        ]
        data = await page.screenshot(type="png", full_page=False, mask=masks, timeout=15_000)
    except Exception:
        return None
    if not isinstance(data, bytes) or not data or len(data) > _MAX_SCREENSHOT_BYTES:
        return None
    return data
