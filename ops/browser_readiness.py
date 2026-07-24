"""Real Chromium readiness probe for the self-hosted browser provider.

A Python import check is not evidence: ``pip install playwright`` succeeds without
any browser binary, so the only honest readiness signal is actually launching
Chromium, opening a page, and taking a screenshot. This module is both the
container HEALTHCHECK entrypoint (``python -m ops.browser_readiness``) and the
function the API's provider-aware health report calls.
"""

from __future__ import annotations

import asyncio
import importlib
import sys
from dataclasses import dataclass
from typing import Literal

from ops.config import Settings

ReadinessStatus = Literal["ready", "not_configured", "unavailable"]


@dataclass(frozen=True, slots=True)
class BrowserReadiness:
    """A sanitized readiness verdict (never a path, URL, or credential)."""

    status: ReadinessStatus
    reason_code: str
    detail: str

    @property
    def ok(self) -> bool:
        return self.status == "ready"


def browser_configuration_state(settings: Settings) -> bool:
    """Whether the SELECTED browser provider is configured to run.

    Shared by wiring, health, and retry eligibility so a Playwright deployment is
    never judged by whether a Browser Use key exists.
    """

    if getattr(settings, "browser_provider", "browser_use") == "playwright":
        return bool(settings.allow_live_browser)
    return bool(settings.allow_live_browser and settings.browser_use_api_key is not None)


async def probe_playwright(*, timeout_seconds: float = 30.0) -> BrowserReadiness:
    """Launch Chromium, render a local page, and screenshot it.

    Uses no network and no allowlisted host, so it is safe to run as a health check.
    """

    try:
        module = importlib.import_module("playwright.async_api")
    except ImportError:
        return BrowserReadiness(
            status="unavailable",
            reason_code="playwright_not_installed",
            detail="The playwright package is not installed in this image.",
        )

    settings = Settings.from_env()
    args = ["--disable-dev-shm-usage"]
    if bool(getattr(settings, "playwright_disable_sandbox", False)):
        args.append("--no-sandbox")

    async def _run() -> BrowserReadiness:
        playwright = await module.async_playwright().start()
        try:
            browser = await playwright.chromium.launch(headless=True, args=args)
        except Exception as exc:
            from ops.playwright_worker import _launch_reason_code

            return BrowserReadiness(
                status="unavailable",
                reason_code=_launch_reason_code(exc),
                detail="Chromium could not be launched in this environment.",
            )
        try:
            page = await browser.new_page()
            await page.set_content("<title>readiness</title><h1>ok</h1>")
            title = await page.title()
            image = await page.screenshot(type="png")
            if title != "readiness" or not isinstance(image, bytes) or not image:
                return BrowserReadiness(
                    status="unavailable",
                    reason_code="browser_render_failed",
                    detail="Chromium launched but could not render or capture a page.",
                )
            return BrowserReadiness(
                status="ready",
                reason_code="chromium_launch_verified",
                detail="Chromium launched, rendered a page, and captured a screenshot.",
            )
        finally:
            try:
                await browser.close()
            finally:
                await playwright.stop()

    try:
        return await asyncio.wait_for(_run(), timeout=timeout_seconds)
    except TimeoutError:
        return BrowserReadiness(
            status="unavailable",
            reason_code="browser_launch_timeout",
            detail="Chromium did not become ready within the probe timeout.",
        )
    except Exception as exc:
        return BrowserReadiness(
            status="unavailable",
            reason_code="browser_launch_failed",
            detail=f"Readiness probe failed ({type(exc).__name__}).",
        )


def main() -> int:
    """HEALTHCHECK entrypoint: exit 0 only when Chromium genuinely launches."""

    verdict = asyncio.run(probe_playwright())
    print(f"{verdict.status}: {verdict.reason_code} — {verdict.detail}")
    return 0 if verdict.ok else 1


if __name__ == "__main__":  # pragma: no cover - container entrypoint
    sys.exit(main())


__all__ = [
    "BrowserReadiness",
    "ReadinessStatus",
    "browser_configuration_state",
    "main",
    "probe_playwright",
]
