"""Shared Chromium harness for the Phase 4 real-browser suite.

Two design points matter here.

**Tests must not silently skip in CI.** A browser suite that quietly skips when
Chromium is missing is worse than no suite: it reports green while testing nothing.
So ``require_chromium`` FAILS when ``REQUIRE_REAL_BROWSER_TESTS=1`` (set by the
browser-image CI job) and only skips in a developer environment without Chromium.

**Guards under test must be the production ones.** ``browser_page`` installs
``ops.playwright_worker.make_route_handler`` — the real staged-egress guard — rather
than a test reimplementation, so what is verified is the shipping code path.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import pytest

from tests.browser_app.server import BrowserTestApp

# Set by the browser-image CI job. When set, an absent Chromium is a FAILURE.
REQUIRE_ENV_VAR = "REQUIRE_REAL_BROWSER_TESTS"


def real_browser_required() -> bool:
    return (os.environ.get(REQUIRE_ENV_VAR) or "").strip().casefold() in {"1", "true", "yes", "on"}


def require_chromium(exc: BaseException) -> None:
    """Fail in CI, skip locally.

    The distinction is the whole point: the browser-image job must never report
    success because the browser was missing.
    """

    message = f"Chromium could not launch: {type(exc).__name__}: {exc}"
    if real_browser_required():
        pytest.fail(
            f"{message}. {REQUIRE_ENV_VAR} is set, so a missing or broken Chromium is "
            "a hard failure rather than a skip."
        )
    pytest.skip(message)


@dataclass(slots=True)
class BrowserFixture:
    """A live page plus the observations a test needs to assert on."""

    app: BrowserTestApp
    browser: Any
    context: Any
    page: Any
    # URLs the production guard aborted, recorded by the guard wrapper.
    blocked_urls: list[str]
    # URLs the guard allowed through.
    allowed_urls: list[str]

    def blocked_hosts(self) -> set[str]:
        from urllib.parse import urlsplit

        return {urlsplit(url).hostname or "" for url in self.blocked_urls}


@asynccontextmanager
async def browser_page(
    app: BrowserTestApp,
    *,
    install_guard: bool = True,
    patterns: tuple[str, ...] | None = None,
    stage_provider: Callable[[], str] | None = None,
    accept_downloads: bool = True,
) -> AsyncIterator[BrowserFixture]:
    """Launch Chromium against the test app with the REAL egress guard installed."""

    from playwright.async_api import async_playwright

    from ops.playwright_worker import make_route_handler

    allow = patterns if patterns is not None else app.host_patterns
    blocked: list[str] = []
    allowed: list[str] = []

    async with async_playwright() as playwright:
        try:
            browser = await playwright.chromium.launch(headless=True, args=app.launch_args)
        except Exception as exc:
            require_chromium(exc)
            raise  # pragma: no cover - require_chromium always raises
        context = await browser.new_context(
            ignore_https_errors=True,
            accept_downloads=accept_downloads,
            service_workers="block",
        )
        try:
            if install_guard:
                production_handler = make_route_handler(
                    allow, stage_provider=stage_provider or (lambda: "pre_auth")
                )

                async def _observing_handler(route: Any) -> None:
                    """Wrap the production handler to observe its verdict.

                    The decision is entirely the production handler's; this only
                    records which way it went by watching whether abort or continue
                    was called.
                    """

                    url = route.request.url
                    verdict: dict[str, str] = {}
                    original_abort = route.abort
                    original_continue = route.continue_

                    async def _abort(*args: Any, **kwargs: Any) -> None:
                        verdict["outcome"] = "abort"
                        await original_abort(*args, **kwargs)

                    async def _continue(*args: Any, **kwargs: Any) -> None:
                        verdict["outcome"] = "continue"
                        await original_continue(*args, **kwargs)

                    route.abort = _abort  # type: ignore[method-assign]
                    route.continue_ = _continue  # type: ignore[method-assign]
                    await production_handler(route)
                    if verdict.get("outcome") == "abort":
                        blocked.append(url)
                    else:
                        allowed.append(url)

                await context.route("**/*", _observing_handler)

            page = await context.new_page()
            yield BrowserFixture(
                app=app,
                browser=browser,
                context=context,
                page=page,
                blocked_urls=blocked,
                allowed_urls=allowed,
            )
        finally:
            await context.close()
            await browser.close()


__all__ = [
    "REQUIRE_ENV_VAR",
    "BrowserFixture",
    "browser_page",
    "real_browser_required",
    "require_chromium",
]
