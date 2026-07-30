"""Document-start masking for secrets rendered on the headed browser desktop.

Playwright's screenshot ``mask=`` option protects PNG screenshots, but it cannot
protect the X11 pixels streamed by x11vnc/noVNC. The live desktop therefore needs
its own browser-enforced boundary: reviewed selectors are installed as CSS at
document start for every page and child frame in the context.

The CSS changes presentation only. Automatic capture can still read the reviewed
DOM property after the browser service has revoked every live-view capability.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

_MAX_LIVE_MASK_SELECTORS = 30

# Registered on BrowserContext, so it runs before vendor scripts on every
# navigation and in every child frame. The observer is armed before the parser can
# add credential nodes, keeping the style in place before Chromium paints them.
_LIVE_PIXEL_MASK_SCRIPT = r"""
(selectors) => {
  const styleId = "codex-reviewed-secret-mask";
  if (!Array.isArray(selectors) || selectors.length === 0 || selectors.length > 30) {
    return false;
  }
  for (const selector of selectors) {
    if (typeof selector !== "string" || selector.length === 0 || selector.length > 2000) {
      return false;
    }
    try {
      document.querySelector(selector);
    } catch (_error) {
      return false;
    }
  }

  const install = () => {
    if (document.getElementById(styleId)) {
      return true;
    }
    const parent = document.head || document.documentElement;
    if (!parent) {
      return false;
    }
    const style = document.createElement("style");
    style.id = styleId;
    style.setAttribute("data-live-secret-boundary", "masked");
    style.textContent = selectors.map((selector) => `${selector} {
      color: transparent !important;
      background-color: #1f2937 !important;
      border-color: #374151 !important;
      caret-color: transparent !important;
      text-shadow: none !important;
      -webkit-text-security: disc !important;
    }
    ${selector}::selection {
      color: transparent !important;
      background-color: #1f2937 !important;
    }`).join("\n");
    parent.prepend(style);
    return true;
  };

  if (install()) {
    return true;
  }
  const observer = new MutationObserver(() => {
    if (install()) {
      observer.disconnect();
    }
  });
  observer.observe(document, {childList: true, subtree: true});
  return true;
}
"""


async def install_live_pixel_mask(
    *,
    context: Any,
    page: Any,
    selectors: Sequence[str],
) -> bool:
    """Install and verify the persistent headed-desktop mask before navigation.

    ``context.add_init_script`` protects all future documents, popups and child
    frames. Evaluating the same function on the current blank document validates
    every selector and proves the style can be installed before the service makes
    the session attachable. Any uncertainty fails closed.
    """

    reviewed = tuple(selectors)
    if (
        not reviewed
        or len(reviewed) > _MAX_LIVE_MASK_SELECTORS
        or any(not isinstance(selector, str) or not selector for selector in reviewed)
    ):
        return False
    try:
        # BrowserContext.add_init_script has no separate argument channel. Encode
        # the trusted recipe strings as JSON into a document-start invocation;
        # never interpolate them as executable JavaScript source.
        encoded = json.dumps(list(reviewed), ensure_ascii=True, separators=(",", ":"))
        await context.add_init_script(script=f"({_LIVE_PIXEL_MASK_SCRIPT})({encoded});")
        installed = await page.evaluate(_LIVE_PIXEL_MASK_SCRIPT, list(reviewed))
    except Exception:
        return False
    return installed is True


__all__ = ["install_live_pixel_mask"]
