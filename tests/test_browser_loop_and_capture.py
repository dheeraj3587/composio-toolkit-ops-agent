"""Phase B completion: persistent browser loop, deterministic capture, live view.

The loop test is the important one: it proves a Playwright session created in one
``asyncio.run`` call is still usable from a SEPARATE ``asyncio.run`` call — the
exact pattern the orchestrator uses per graph node, and the blocker for wiring the
harness into a real run.
"""

from __future__ import annotations

import asyncio

import pytest

from ops.browser_loop import BrowserLoop, BrowserLoopClosedError, shared_browser_loop
from ops.config import Settings
from ops.playwright_worker import PlaywrightBrowserWorker


# --- BrowserLoop: one loop, usable from many caller loops ---------------------
def test_loop_runs_coroutine_from_separate_caller_loops() -> None:
    loop = BrowserLoop()
    try:

        async def _identify() -> int:
            return id(asyncio.get_running_loop())

        first = asyncio.run(loop.run(_identify()))
        second = asyncio.run(loop.run(_identify()))
        # Both ran on the SAME dedicated loop despite two different caller loops.
        assert first == second
        # ...and that loop is not either caller's loop.
        assert first != id(asyncio.new_event_loop())
    finally:
        loop.close()


def test_loop_run_sync_works_without_a_caller_loop() -> None:
    loop = BrowserLoop()
    try:

        async def _add() -> int:
            return 40 + 2

        assert loop.run_sync(_add()) == 42
    finally:
        loop.close()


def test_loop_rejects_work_after_close() -> None:
    loop = BrowserLoop()
    loop.close()

    async def _noop() -> None:
        return None

    coro = _noop()
    try:
        with pytest.raises(BrowserLoopClosedError):
            loop.run_sync(coro)
    finally:
        coro.close()  # never scheduled: close it so no "never awaited" warning


def test_shared_loop_is_a_singleton() -> None:
    assert shared_browser_loop() is shared_browser_loop()


# --- live: a real Chromium session spans separate asyncio.run calls ------------
def _worker() -> PlaywrightBrowserWorker:
    return PlaywrightBrowserWorker(settings=Settings(allow_live_browser=True))


def test_live_session_survives_separate_event_loops() -> None:
    """start() in one loop, then drive + screenshot + stop from OTHER loops."""

    worker = _worker()
    try:
        context = asyncio.run(worker.start(None))
    except Exception as exc:
        pytest.skip(f"Chromium not launchable: {type(exc).__name__}")

    session = worker._sessions[context.session_id]

    # A SECOND, independent caller loop drives the same session.
    async def _use() -> str:
        async def _set() -> str:
            await session.page.set_content("<title>Across Loops</title><h1>ok</h1>")
            return await session.page.title()

        return await worker._loop.run(_set())

    assert asyncio.run(_use()) == "Across Loops"

    # A THIRD caller loop captures the live-view screenshot.
    assert asyncio.run(worker.refresh_live_view(session)) is True
    latest = worker.latest_screenshot(context.session_id)
    assert latest is not None
    image, taken_at = latest
    assert image.startswith(b"\x89PNG") and taken_at  # real PNG bytes

    # A FOURTH caller loop tears it down.
    asyncio.run(worker.stop(context))
    assert context.session_id not in worker._sessions


# --- capture: vault-only, spec-driven, fails closed ---------------------------
class _FakeStore:
    def __init__(self) -> None:
        self.puts: list[tuple[str, str, str]] = []

    def put(self, *, app_slug: str, kind: str, value: str) -> str:
        self.puts.append((app_slug, kind, value))
        return f"vault://{app_slug}/{kind}/ref1"


def test_capture_returns_none_without_spec_or_store() -> None:
    worker = _worker()
    # Unknown app (no capture spec) and no session -> None, never an exception.
    assert asyncio.run(worker.auto_capture_credentials("missing", "no-such-app")) is None


_TOKEN = "a" * 40


def _serve_pipedrive(worker: PlaywrightBrowserWorker, handle: str, body: str) -> None:
    """Route the allowlisted Pipedrive host to controlled HTML (no real vendor)."""

    session = worker._sessions[handle]
    session.patterns = ("app.pipedrive.com", "*.pipedrive.com")

    async def _stub() -> None:
        async def _handler(route: object) -> None:
            await route.fulfill(  # type: ignore[attr-defined]
                status=200, content_type="text/html", body=body
            )

        await session.context.route("https://app.pipedrive.com/**", _handler)

    asyncio.run(worker._loop.run(_stub()))


def _credential_page(token: str = _TOKEN) -> str:
    # Satisfies the reviewed spec: expected heading "API" plus the reviewed
    # input[name='api_token'] selector. A decoy input must NOT be chosen.
    return (
        "<html><body><h1>API</h1>"
        "<input name='unrelated' value='not-a-token'>"
        f"<input name='api_token' readonly value='{token}'>"
        "</body></html>"
    )


def test_live_capture_uses_reviewed_selector_and_vaults_reference() -> None:
    """The reviewed selector + heading + path prefix must all be satisfied."""

    worker = _worker()
    store = _FakeStore()
    try:
        context = asyncio.run(worker.start(None))
    except Exception as exc:
        pytest.skip(f"Chromium not launchable: {type(exc).__name__}")

    _serve_pipedrive(worker, context.session_id, _credential_page())
    refs = asyncio.run(worker.auto_capture_credentials(context.session_id, "pipedrive", store))
    asyncio.run(worker.stop(context))

    assert refs == {"api_token": "vault://pipedrive/api_token/ref1"}
    # The raw value went ONLY to the vault, and the decoy input was not chosen.
    assert store.puts == [("pipedrive", "api_token", _TOKEN)]


def test_live_capture_fails_when_expected_heading_is_absent() -> None:
    """Wrong page (no reviewed heading) must capture nothing, even with a token."""

    worker = _worker()
    store = _FakeStore()
    try:
        context = asyncio.run(worker.start(None))
    except Exception as exc:
        pytest.skip(f"Chromium not launchable: {type(exc).__name__}")

    _serve_pipedrive(
        worker,
        context.session_id,
        f"<html><body><h1>Billing</h1><input name='api_token' value='{_TOKEN}'></body></html>",
    )
    refs = asyncio.run(worker.auto_capture_credentials(context.session_id, "pipedrive", store))
    asyncio.run(worker.stop(context))

    assert refs is None and store.puts == []


def test_live_capture_rejects_a_partial_pattern_match() -> None:
    """fullmatch: a 40-hex substring inside a longer value is not the token."""

    worker = _worker()
    store = _FakeStore()
    try:
        context = asyncio.run(worker.start(None))
    except Exception as exc:
        pytest.skip(f"Chromium not launchable: {type(exc).__name__}")

    _serve_pipedrive(
        worker,
        context.session_id,
        f"<html><body><h1>API</h1><input name='api_token' value='prefix-{_TOKEN}-suffix'>"
        "</body></html>",
    )
    refs = asyncio.run(worker.auto_capture_credentials(context.session_id, "pipedrive", store))
    asyncio.run(worker.stop(context))

    assert refs is None and store.puts == []
