"""A dedicated thread owning one persistent asyncio event loop for Playwright.

Playwright's async objects (browser, context, page) are bound to the event loop
that created them. The orchestrator runs each graph node in its own
``asyncio.run`` loop, so a browser session created in one node cannot be driven
from the next without this indirection — the same class of bug the Browser Use
worker hit ("Event loop is closed" / "bound to a different loop").

``BrowserLoop`` owns a single long-lived loop on a background thread. Every
Playwright coroutine is submitted to that one loop with
``run_coroutine_threadsafe`` and awaited from the caller, so ALL browser objects
are created and used on the same loop for the whole session lifetime, regardless
of how many short-lived caller loops come and go.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Coroutine
from typing import Any, TypeVar

T = TypeVar("T")

_DEFAULT_TIMEOUT = 180.0


class BrowserLoopClosedError(RuntimeError):
    """Raised when work is submitted to an already-closed loop."""


class BrowserLoop:
    """A process-wide, lazily started event loop on a daemon thread."""

    def __init__(self) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._closed = False

    def _ensure_started(self) -> asyncio.AbstractEventLoop:
        with self._lock:
            if self._closed:
                raise BrowserLoopClosedError("the browser loop is closed")
            if self._loop is not None:
                return self._loop
            ready = threading.Event()
            loop_holder: dict[str, asyncio.AbstractEventLoop] = {}

            def _run() -> None:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop_holder["loop"] = loop
                ready.set()
                loop.run_forever()

            thread = threading.Thread(target=_run, name="browser-loop", daemon=True)
            thread.start()
            if not ready.wait(timeout=10.0):  # pragma: no cover - startup failure
                raise RuntimeError("the browser loop failed to start")
            self._loop = loop_holder["loop"]
            self._thread = thread
            return self._loop

    @property
    def is_running(self) -> bool:
        return self._loop is not None and not self._closed

    async def run(self, coro: Coroutine[Any, Any, T], *, timeout: float = _DEFAULT_TIMEOUT) -> T:
        """Run ``coro`` on the dedicated loop and await its result here.

        Awaitable from ANY caller loop (or none). The coroutine itself always
        executes on the single browser loop, so Playwright objects stay valid.
        """

        loop = self._ensure_started()
        future = asyncio.run_coroutine_threadsafe(coro, loop)
        try:
            return await asyncio.wrap_future(future)
        except asyncio.CancelledError:  # pragma: no cover - cooperative cancel
            future.cancel()
            raise

    def run_sync(self, coro: Coroutine[Any, Any, T], *, timeout: float = _DEFAULT_TIMEOUT) -> T:
        """Blocking variant for synchronous callers (no caller loop required)."""

        loop = self._ensure_started()
        return asyncio.run_coroutine_threadsafe(coro, loop).result(timeout)

    def close(self) -> None:
        """Stop the loop and join its thread. Idempotent."""

        with self._lock:
            loop, thread = self._loop, self._thread
            self._loop = self._thread = None
            self._closed = True
        if loop is not None:
            loop.call_soon_threadsafe(loop.stop)
        if thread is not None:
            thread.join(timeout=10.0)
        if loop is not None:
            try:
                loop.close()
            except Exception:  # pragma: no cover - already closed
                pass


_SHARED = BrowserLoop()


def shared_browser_loop() -> BrowserLoop:
    """The process-wide browser loop shared by all Playwright sessions."""

    return _SHARED


__all__ = ["BrowserLoop", "BrowserLoopClosedError", "shared_browser_loop"]
