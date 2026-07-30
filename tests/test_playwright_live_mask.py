"""Offline checks for the headed-browser pixel mask."""

from __future__ import annotations

import asyncio

from ops.playwright.live_mask import install_live_pixel_mask


class _Context:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.script = ""

    async def add_init_script(self, *, script: str) -> None:
        self.events.append("document_start_mask")
        self.script = script


class _Page:
    def __init__(self, events: list[str], *, installed: bool = True) -> None:
        self.events = events
        self.installed = installed
        self.selectors: list[str] = []

    async def evaluate(self, _script: str, selectors: list[str]) -> bool:
        self.events.append("current_document_mask_verified")
        self.selectors = selectors
        return self.installed


def test_recipe_selectors_are_bound_at_document_start_and_verified() -> None:
    events: list[str] = []
    context = _Context(events)
    page = _Page(events)
    selectors = ("input[type='password']", "input[name='api_token']")

    installed = asyncio.run(
        install_live_pixel_mask(context=context, page=page, selectors=selectors)
    )

    assert installed is True
    assert events == ["document_start_mask", "current_document_mask_verified"]
    assert page.selectors == list(selectors)
    # The BrowserContext script is self-contained for future pages/frames; values
    # are JSON encoded rather than interpolated as executable source.
    assert "input[name='api_token']" in context.script
    assert "data-live-secret-boundary" in context.script


def test_mask_installation_fails_closed_when_verification_fails() -> None:
    events: list[str] = []
    installed = asyncio.run(
        install_live_pixel_mask(
            context=_Context(events),
            page=_Page(events, installed=False),
            selectors=("input[name='api_token']",),
        )
    )

    assert installed is False
