"""Behavioral tests for the bounded Playwright action loop and its guards.

Real Chromium against controlled in-memory pages (routed, no vendor contact), so
these prove actual behavior rather than asserting on source text. They skip only
when Chromium cannot launch at all; the browser-image CI job fails instead of
skipping.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from ops.browser_egress import EgressStage
from ops.browser_loop import BrowserLoop, BrowserOperationTimeout
from ops.config import Settings
from ops.models import OperationalResearch
from ops.playwright_worker import (
    PlaywrightBrowserWorker,
    detect_human_gate,
)
from tests.browser_app.harness import require_chromium

_HOST = "app.pipedrive.com"
_PATTERNS = (_HOST, f"*.{_HOST.split('.', 1)[1]}")
_TOKEN = "b" * 40


def _worker(**overrides: object) -> PlaywrightBrowserWorker:
    settings = Settings(allow_live_browser=True, **overrides)  # type: ignore[arg-type]
    return PlaywrightBrowserWorker(settings=settings)


def _research(slug: str = "pipedrive") -> OperationalResearch:
    return OperationalResearch.model_validate(
        {
            "app_name": "Pipedrive",
            "app_slug": slug,
            "api_available": True,
            "api_type": "REST",
            "api_base_url": None,
            "auth_methods": ["API Key"],
            "authorization_url": None,
            "token_url": None,
            "credential_fields": [],
            "scopes": [],
            "developer_portal_url": "https://developers.pipedrive.com/",
            "signup_url": "https://www.pipedrive.com/signup",
            "access_route": "self_serve",
            "production_approval_required": None,
            "contact_email": None,
            "contact_url": None,
            "evidence_urls": ["https://developers.pipedrive.com/docs"],
            "confidence": 0.9,
        }
    )


def _synthetic_trace(
    *, success: object, checkpoints: object, start_path: str = "/settings/api"
) -> object:
    """Build an in-test v2 trace so the state machine can be exercised without a
    conservative catalog checkpoint short-circuiting to HITL."""

    from ops.browser_api_trace_catalog import BrowserApiTrace

    return BrowserApiTrace(
        position=3,
        app_slug="pipedrive",
        app_name="Pipedrive",
        access_model="self_serve",
        start_url=f"https://{_HOST}{start_path}",
        evidence_url="https://developers.pipedrive.com/docs",
        credential_goal="API token page",
        checkpoints=tuple(checkpoints),  # type: ignore[arg-type]
        success_signals=("API token field label is visible",),
        success=success,  # type: ignore[arg-type]
    )


def _install_trace(monkeypatch: object, trace: object) -> None:
    import ops.playwright_worker as worker_module

    monkeypatch.setattr(worker_module, "get_browser_api_trace", lambda slug: trace)  # type: ignore[attr-defined]


def _start(worker: PlaywrightBrowserWorker) -> object:
    try:
        return asyncio.run(worker.start(None))
    except Exception as exc:  # pragma: no cover - environment without Chromium
        require_chromium(exc)


def _route_pages(worker: PlaywrightBrowserWorker, handle: str, pages: dict[str, str]) -> None:
    """Serve controlled HTML per URL path on the allowlisted host.

    Playwright evaluates the MOST RECENTLY added route first, and
    ``navigate_onboarding`` installs the ``**/*`` host guard itself. The guard is
    therefore pre-installed here so this stub is registered after it and wins,
    while still exercising the real guard for any other host.
    """

    session = worker._sessions[handle]
    session.patterns = _PATTERNS

    async def _install() -> None:
        async def _handler(route: object) -> None:
            url = route.request.url  # type: ignore[attr-defined]
            path = url.split(_HOST, 1)[1].split("?")[0] if _HOST in url else "/"
            body = pages.get(path, pages.get("*", "<html><body><h1>Unknown</h1></body></html>"))
            await route.fulfill(status=200, content_type="text/html", body=body)  # type: ignore[attr-defined]

        # PAGE-level routes are consulted before context-level ones, so this stub
        # still wins after navigate_onboarding installs its context host guard.
        # That guarantees these tests never reach the real vendor.
        await session.page.route(f"https://{_HOST}/**", _handler)

    asyncio.run(worker._loop.run(_install()))


# --- Action loop: login -> submit -> settings -> credential page ---------------
def test_loop_submits_login_follows_checkpoints_and_verifies_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A full deterministic path: the loop must submit the login form, then report
    the credential page ONLY when the structured success predicate is proven."""

    from ops.browser_api_trace_catalog import BrowserApiTraceStep, CheckpointPredicate

    _install_trace(
        monkeypatch,
        _synthetic_trace(
            checkpoints=(
                BrowserApiTraceStep(
                    order=1,
                    instruction="Reach the API token page.",
                    expected_signals=("API",),
                    completion=CheckpointPredicate(visible_text_contains=("API token",)),
                ),
            ),
            success=CheckpointPredicate(
                url_path_contains=("/done",), visible_text_contains=("API token",)
            ),
        ),
    )

    worker = _worker()
    context = _start(worker)
    handle = context.session_id  # type: ignore[attr-defined]

    # Serve a login wall at the start URL; after submit the app shows the API
    # settings page (path /done) carrying the structured success evidence.
    login = (
        "<html><body><h1>Sign in</h1><form action='/done' method='get'>"
        "<input type='email' name='email'>"
        "<input type='password' name='password'>"
        "<button type='submit'>Sign in</button>"
        "</form></body></html>"
    )
    settings_page = (
        "<html><body><h1>API</h1>"
        "<p>The API token field label is visible on this settings page.</p>"
        f"<input name='api_token' readonly value='{_TOKEN}'>"
        "</body></html>"
    )
    _route_pages(worker, handle, {"/settings/api": login, "*": settings_page})

    observation = asyncio.run(
        worker.navigate_onboarding(
            context,  # type: ignore[arg-type]
            _research(),
            sensitive_data={"login_email": "ops@example.test", "login_password": "pw-not-logged"},
        )
    )
    assert worker._sessions[handle].egress.stage is EgressStage.CREDENTIAL_SURFACE
    asyncio.run(worker.stop(context))  # type: ignore[arg-type]

    # Success is declared ONLY from the structured predicate (path + label).
    assert observation.status == "credential_page_ready"
    assert "structured success predicate" in observation.non_secret_notes[0]


def test_initial_login_requires_credentials_then_resume_injects_them_in_same_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A trace mentioning CAPTCHA must not mislabel an ordinary login form.

    The first pass has no secrets and pauses as ``login_required``. Supplying
    credentials on Resume must inject them before generic HITL inspection and
    reach the reviewed target in the original Chromium context.
    """

    from ops.browser_api_trace_catalog import BrowserApiTraceStep, CheckpointPredicate

    _install_trace(
        monkeypatch,
        _synthetic_trace(
            checkpoints=(
                BrowserApiTraceStep(
                    order=1,
                    instruction="Complete login and any CAPTCHA, then open API settings.",
                    expected_signals=("API",),
                    requires_hitl=True,
                ),
            ),
            success=CheckpointPredicate(
                url_path_contains=("/done",), visible_text_contains=("API token",)
            ),
        ),
    )

    worker = _worker()
    context = _start(worker)
    handle = context.session_id  # type: ignore[attr-defined]
    session_before = worker._sessions[handle]
    login = (
        "<html><body><h1>Sign in</h1><form action='/done' method='get'>"
        "<input type='email' name='email'>"
        "<input type='password' name='password'>"
        "<button type='submit'>Sign in</button>"
        "</form><iframe title='reCAPTCHA' "
        "src='/recaptcha/api2/anchor?size=invisible'></iframe></body></html>"
    )
    credential_page = (
        "<html><body><h1>API token</h1>"
        "<p>API token controls</p>"
        f"<input name='api_token' readonly value='{_TOKEN}'>"
        "</body></html>"
    )
    _route_pages(worker, handle, {"/settings/api": login, "*": credential_page})

    first = asyncio.run(worker.navigate_onboarding(context, _research()))  # type: ignore[arg-type]
    assert first.status == "human_action_required"
    assert first.human_action_type == "login_required"
    assert first.reason_code == "login_required"

    resumed = asyncio.run(
        worker.resume_after_hitl(
            context,  # type: ignore[arg-type]
            "human_completed",
            _research(),
            sensitive_data={
                "login_email": "ops@example.test",
                "login_password": "pw-not-logged",
            },
        )
    )
    assert worker._sessions[handle] is session_before
    asyncio.run(worker.stop(context))  # type: ignore[arg-type]

    assert resumed.status == "credential_page_ready"
    assert resumed.current_url.endswith("/done")


def test_pre_auth_challenge_does_not_consume_post_hitl_target_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A target probe redirected to CAPTCHA must preserve the post-HITL retry."""

    from ops.browser_api_trace_catalog import BrowserApiTraceStep, CheckpointPredicate

    _install_trace(
        monkeypatch,
        _synthetic_trace(
            checkpoints=(
                BrowserApiTraceStep(
                    order=1,
                    instruction="Reach API settings after authentication.",
                    expected_signals=("API token",),
                ),
            ),
            success=CheckpointPredicate(
                url_path_contains=("/settings/api",),
                visible_text_contains=("API token",),
            ),
        ),
    )

    worker = _worker()
    context = _start(worker)
    handle = context.session_id  # type: ignore[attr-defined]
    session = worker._sessions[handle]
    session.patterns = _PATTERNS
    settings_visits = 0

    login = (
        "<html><body><h1>Sign in</h1><form action='/home' method='get'>"
        "<input type='email' name='email'>"
        "<input type='password' name='password'>"
        "<button type='submit'>Sign in</button>"
        "</form></body></html>"
    )
    challenge = (
        "<html><body><h1>Verify this login</h1>"
        "<iframe title='reCAPTCHA challenge' src='/recaptcha' "
        "style='width:300px;height:200px'></iframe>"
        "</body></html>"
    )
    home = "<html><body><h1>Welcome back</h1></body></html>"
    credential_page = (
        "<html><body><h1>API token</h1>"
        "<p>API token controls</p>"
        f"<input name='api_token' readonly value='{_TOKEN}'>"
        "</body></html>"
    )

    async def _install() -> None:
        async def _handler(route: object) -> None:
            nonlocal settings_visits
            url = route.request.url  # type: ignore[attr-defined]
            path = url.split(_HOST, 1)[1].split("?")[0] if _HOST in url else "/"
            if path == "/settings/api":
                settings_visits += 1
                body = (login, challenge, credential_page)[min(settings_visits - 1, 2)]
            elif path == "/recaptcha":
                body = "<html><body>Challenge</body></html>"
            else:
                body = home
            await route.fulfill(status=200, content_type="text/html", body=body)  # type: ignore[attr-defined]

        await session.page.route(f"https://{_HOST}/**", _handler)

    asyncio.run(worker._loop.run(_install()))

    first = asyncio.run(
        worker.navigate_onboarding(
            context,  # type: ignore[arg-type]
            _research(),
            sensitive_data={
                "login_email": "ops@example.test",
                "login_password": "pw-not-logged",
            },
        )
    )
    assert first.status == "human_action_required"
    assert first.human_action_type == "captcha"
    assert session.pre_auth_target_probed is True
    assert session.post_login_target_retried is False
    assert settings_visits == 2

    async def _complete_challenge() -> None:
        await session.page.goto(
            f"https://{_HOST}/home", wait_until="domcontentloaded", timeout=20_000
        )

    asyncio.run(worker._loop.run(_complete_challenge()))
    resumed = asyncio.run(
        worker.resume_after_hitl(
            context,  # type: ignore[arg-type]
            "captcha_completed",
            _research(),
        )
    )
    assert session.post_login_target_retried is True
    assert settings_visits == 3
    asyncio.run(worker.stop(context))  # type: ignore[arg-type]

    assert resumed.status == "credential_page_ready"
    assert resumed.current_url.endswith("/settings/api")


def test_login_bound_navigation_enters_authentication_stage_before_first_document(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reviewed IdP documents needed by the login shell must not be blocked pre-auth."""

    worker = _worker()
    context = _start(worker)
    handle = context.session_id  # type: ignore[attr-defined]
    session = worker._sessions[handle]
    observed_stages: list[EgressStage] = []
    original_goto = session.page.goto

    async def _recording_goto(*args: object, **kwargs: object) -> object:
        observed_stages.append(session.egress.stage)
        return await original_goto(*args, **kwargs)

    monkeypatch.setattr(session.page, "goto", _recording_goto)
    _route_pages(
        worker,
        handle,
        {
            "/settings/api": (
                "<html><body><form><input type='email'><input type='password'>"
                "<button type='submit'>Sign in</button></form></body></html>"
            )
        },
    )

    asyncio.run(
        worker.navigate_onboarding(
            context,  # type: ignore[arg-type]
            _research(),
            sensitive_data={
                "login_email": "ops@example.test",
                "login_password": "pw",  # pragma: allowlist secret
            },
        )
    )
    asyncio.run(worker.stop(context))  # type: ignore[arg-type]

    assert observed_stages
    assert observed_stages[0] is EgressStage.AUTHENTICATING


def test_loop_reports_hitl_for_a_captcha_page() -> None:
    worker = _worker()
    context = _start(worker)
    handle = context.session_id  # type: ignore[attr-defined]
    _route_pages(
        worker,
        handle,
        {
            "/settings/api": (
                "<html><body><h1>Security check</h1><button>I'm not a robot</button></body></html>"
            )
        },
    )

    observation = asyncio.run(worker.navigate_onboarding(context, _research()))  # type: ignore[arg-type]
    asyncio.run(worker.stop(context))  # type: ignore[arg-type]

    assert observation.status == "human_action_required"
    assert observation.human_action_type == "captcha"


def test_loop_stops_on_repeated_state_without_inference(monkeypatch: pytest.MonkeyPatch) -> None:
    """No inference configured + an AMBIGUOUS checkpoint -> bounded, honest HITL."""

    from ops.browser_api_trace_catalog import BrowserApiTraceStep, CheckpointPredicate

    _install_trace(
        monkeypatch,
        _synthetic_trace(
            checkpoints=(
                BrowserApiTraceStep(
                    order=1,
                    instruction="Open the API area.",
                    expected_signals=("API",),
                    completion=CheckpointPredicate(visible_text_contains=("unreachable-token",)),
                ),
            ),
            # A success that never matches this page, so the loop must plan instead.
            success=CheckpointPredicate(
                url_path_contains=("/never",), visible_text_contains=("unreachable-token",)
            ),
        ),
    )

    worker = _worker()
    assert worker._inference is None  # no provider keys in this Settings
    context = _start(worker)
    handle = context.session_id  # type: ignore[attr-defined]
    # Two "API" links -> the deterministic match is ambiguous (zero unique hit).
    _route_pages(
        worker,
        handle,
        {
            "/settings/api": (
                "<html><body><h1>Settings</h1>"
                "<a href='/x'>API access</a><a href='/y'>API tokens</a></body></html>"
            )
        },
    )

    observation = asyncio.run(worker.navigate_onboarding(context, _research()))  # type: ignore[arg-type]
    asyncio.run(worker.stop(context))  # type: ignore[arg-type]

    assert observation.status == "human_action_required"
    assert "ambiguous" in (observation.human_instruction or "").casefold()


def test_model_cannot_declare_success_without_a_reviewed_signal() -> None:
    """report_credential_page is re-verified; an unproven claim is discarded."""

    worker = _worker()
    context = _start(worker)
    handle = context.session_id  # type: ignore[attr-defined]
    _route_pages(worker, handle, {"/settings/api": "<html><body><h1>Dashboard</h1></body></html>"})
    session = worker._sessions[handle]
    session.patterns = _PATTERNS
    session.app_slug = "pipedrive"

    async def _load() -> None:
        await session.page.goto(
            f"https://{_HOST}/settings/api", wait_until="domcontentloaded", timeout=20_000
        )

    asyncio.run(worker._loop.run(_load()))

    from ops.browser_api_trace_catalog import get_browser_api_trace

    trace = get_browser_api_trace("pipedrive")
    assert trace is not None
    # Success can ONLY come from verify_credential_page, which requires reviewed
    # structural evidence. A Dashboard page has none, so it returns None.
    result = asyncio.run(worker.verify_credential_page(session, trace))
    asyncio.run(worker.stop(context))  # type: ignore[arg-type]
    assert result is None


def test_snapshot_from_a_real_page_excludes_secret_values() -> None:
    worker = _worker()
    context = _start(worker)
    handle = context.session_id  # type: ignore[attr-defined]
    _route_pages(
        worker,
        handle,
        {
            "/settings/api": "<html><body>"
            "<input type='password' name='password' value='hunter2'>"
            f"<input name='api_token' value='{_TOKEN}'>"
            "<input type='email' name='email' value='ops@example.test'>"
            "</body></html>"
        },
    )
    session = worker._sessions[handle]
    session.patterns = _PATTERNS

    async def _load() -> None:
        await session.page.goto(
            f"https://{_HOST}/settings/api", wait_until="domcontentloaded", timeout=20_000
        )

    asyncio.run(worker._loop.run(_load()))
    inspection = asyncio.run(worker._inspect_page(session))
    asyncio.run(worker.stop(context))  # type: ignore[arg-type]

    rendered = "\n".join(element.render() for element in inspection.elements)
    # No secret value appears anywhere in the model-visible snapshot.
    assert "hunter2" not in rendered and _TOKEN not in rendered
    assert "hunter2" not in inspection.fingerprint and _TOKEN not in inspection.fingerprint
    # Secret-ish fields are flagged so the validator can refuse model typing.
    secret_flags = [element.secretish for element in inspection.elements]
    assert any(secret_flags)


# --- Human gate detection is STRUCTURAL, not substring-based (item 8) ---------
def _inspection(elements: tuple, *, text: str = "", title: str = "") -> object:
    from ops.playwright_worker import PageInspection

    return PageInspection(
        url=f"https://{_HOST}/x",
        title=title,
        visible_text=text,
        elements=elements,
        locators=(),
        fingerprint="f",
    )


def _snap(*specs: dict) -> tuple:
    from ops.browser_decider import build_snapshot

    return build_snapshot(list(specs))


def test_footer_terms_of_service_link_does_not_trigger_hitl() -> None:
    # A footer LINK is not a consent control: the old substring rule halted here.
    inspection = _inspection(
        _snap({"tag": "a", "name": "Terms of Service"}),
        text="By using this site you accept the Terms of Service.",
    )
    assert detect_human_gate(inspection) is None


def test_passive_recaptcha_badge_does_not_trigger_hitl() -> None:
    # The badge is a non-actionable div, not an interactive challenge.
    inspection = _inspection(
        _snap({"tag": "div", "name": "protected by reCAPTCHA"}),
        text="This site is protected by reCAPTCHA and the Google Privacy Policy.",
    )
    assert detect_human_gate(inspection) is None


def test_interactive_captcha_triggers_hitl() -> None:
    inspection = _inspection(
        _snap({"tag": "iframe", "name": "reCAPTCHA challenge"}), text="Security check"
    )
    gate = detect_human_gate(inspection)
    assert gate is not None and gate.human_action_type == "captcha"


def test_captcha_checkbox_control_triggers_hitl() -> None:
    inspection = _inspection(_snap({"tag": "button", "name": "I'm not a robot"}))
    gate = detect_human_gate(inspection)
    assert gate is not None and gate.human_action_type == "captcha"


def test_real_otp_input_field_triggers_hitl() -> None:
    inspection = _inspection(
        _snap({"tag": "input", "type": "text", "name": "One-time code"}),
        text="Enter the code we sent you",
    )
    gate = detect_human_gate(inspection)
    assert gate is not None and gate.human_action_type == "email_otp"


def test_prose_mentioning_a_code_without_an_input_does_not_trigger_hitl() -> None:
    # Marketing copy that merely says "verification code" must not halt the run.
    inspection = _inspection(
        _snap({"tag": "a", "name": "Learn about verification codes"}),
        text="Read how we use a verification code to protect your account.",
    )
    assert detect_human_gate(inspection) is None


def test_account_selection_interface_triggers_hitl() -> None:
    inspection = _inspection(_snap({"tag": "button", "name": "Choose an account"}))
    gate = detect_human_gate(inspection)
    assert gate is not None and gate.human_action_type == "account_selection"


def test_billing_control_triggers_hitl() -> None:
    inspection = _inspection(_snap({"tag": "button", "name": "Add payment method"}))
    gate = detect_human_gate(inspection)
    assert gate is not None and gate.human_action_type == "billing"


def test_explicit_consent_button_triggers_hitl() -> None:
    inspection = _inspection(_snap({"tag": "button", "name": "I agree"}))
    gate = detect_human_gate(inspection)
    assert gate is not None and gate.human_action_type == "legal_acceptance"


def test_passkey_control_triggers_hitl() -> None:
    inspection = _inspection(_snap({"tag": "button", "name": "Use your passkey"}))
    gate = detect_human_gate(inspection)
    assert gate is not None and gate.human_action_type == "passkey"


def test_detect_human_gate_returns_none_on_a_normal_page() -> None:
    inspection = _inspection(
        _snap({"tag": "a", "name": "Deals"}, {"tag": "a", "name": "Contacts"}),
        text="Your workspace settings",
        title="Settings",
    )
    assert detect_human_gate(inspection) is None


# --- Capacity: race-free admission --------------------------------------------
def test_concurrent_starts_cannot_exceed_capacity() -> None:
    """Two simultaneous starts with max=1: exactly one is admitted."""

    worker = _worker(playwright_max_sessions=1)

    async def _both() -> list[object]:
        return await asyncio.gather(worker.start(None), worker.start(None), return_exceptions=True)

    results = asyncio.run(_both())
    if all(isinstance(item, Exception) for item in results):
        # Route through the shared helper so this FAILS (not skips) in CI.
        first = next(item for item in results if isinstance(item, Exception))
        require_chromium(first)

    admitted = [item for item in results if not isinstance(item, Exception)]
    refused = [item for item in results if isinstance(item, Exception)]
    assert len(admitted) == 1 and len(refused) == 1
    assert "capacity" in str(refused[0]).casefold()
    for context in admitted:
        asyncio.run(worker.stop(context))  # type: ignore[arg-type]


def test_capacity_is_released_after_teardown() -> None:
    worker = _worker(playwright_max_sessions=1)
    first = _start(worker)
    asyncio.run(worker.stop(first))  # type: ignore[arg-type]
    # The slot came back, so a second session can start.
    second = _start(worker)
    asyncio.run(worker.stop(second))  # type: ignore[arg-type]


def test_capacity_is_not_released_twice() -> None:
    worker = _worker(playwright_max_sessions=2)
    context = _start(worker)
    session = worker._sessions[context.session_id]  # type: ignore[attr-defined]
    asyncio.run(worker.stop(context))  # type: ignore[arg-type]
    assert session.capacity_released is True
    worker._release_capacity(session)  # idempotent: must not over-release
    # Both slots remain acquirable exactly twice.
    a = _start(worker)
    b = _start(worker)
    asyncio.run(worker.stop(a))  # type: ignore[arg-type]
    asyncio.run(worker.stop(b))  # type: ignore[arg-type]


# --- TTL: expiry runs without another session starting ------------------------
def test_janitor_reaps_an_expired_session() -> None:
    worker = _worker()
    context = _start(worker)
    handle = context.session_id  # type: ignore[attr-defined]
    session = worker._sessions[handle]
    # Force expiry by ageing the activity clock past the inactivity window.
    session.last_active_at = datetime.now(UTC) - timedelta(hours=1)

    reaped = worker._reap_expired()  # what the janitor thread calls on its interval

    assert handle in reaped
    assert handle not in worker._sessions
    assert session.capacity_released is True


def test_operations_refresh_last_active_at() -> None:
    worker = _worker()
    context = _start(worker)
    session = worker._sessions[context.session_id]  # type: ignore[attr-defined]
    session.patterns = _PATTERNS
    session.last_active_at = datetime.now(UTC) - timedelta(minutes=5)
    before = session.last_active_at

    asyncio.run(worker._inspect_page(session))
    asyncio.run(worker.stop(context))  # type: ignore[arg-type]

    assert session.last_active_at > before


# --- Loop cancellation semantics ----------------------------------------------
def test_run_sync_timeout_cancels_the_coroutine() -> None:
    loop = BrowserLoop()
    cancelled = threading_event()

    async def _hang() -> None:
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    try:
        with pytest.raises(BrowserOperationTimeout):
            loop.run_sync(_hang(), timeout=0.25)
        # The scheduled task must actually be cancelled, not left running.
        assert cancelled.wait(timeout=5.0) is True
    finally:
        loop.close()


def test_async_run_timeout_cancels_the_coroutine() -> None:
    loop = BrowserLoop()
    cancelled = threading_event()

    async def _hang() -> None:
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    try:
        with pytest.raises(BrowserOperationTimeout):
            asyncio.run(loop.run(_hang(), timeout=0.25))
        assert cancelled.wait(timeout=5.0) is True
    finally:
        loop.close()


def threading_event() -> object:
    import threading

    return threading.Event()


# --- The LLM decision path must ACTUALLY execute (regression) ------------------
class _RecordingBackend:
    """A fake inference backend that picks the first offered candidate id."""

    name = "recording"

    def __init__(self) -> None:
        self.prompts: list[str] = []

    def generate_json(self, prompt: str, schema: object) -> dict:
        import re

        self.prompts.append(prompt)
        ids = re.findall(r"\b(c_[0-9a-f]{12})\b", prompt)
        if not ids:
            return {"decision": "report_hitl", "candidate_id": None, "reason": "no options"}
        return {"decision": "select_candidate", "candidate_id": ids[0], "reason": "picked"}


def test_llm_decision_path_is_actually_reached_on_an_ambiguous_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression for a real break: two DLP/guard bugs made the model path
    unreachable, so the loop silently degraded to HITL on every ambiguous page and
    the brain was never invoked. This asserts the model is genuinely consulted."""

    from ops.browser_api_trace_catalog import BrowserApiTraceStep, CheckpointPredicate
    from ops.inference import JsonInference

    _install_trace(
        monkeypatch,
        _synthetic_trace(
            checkpoints=(
                BrowserApiTraceStep(
                    order=1,
                    instruction="Open the API area.",
                    expected_signals=("API",),
                    completion=CheckpointPredicate(visible_text_contains=("unreachable-token",)),
                ),
            ),
            success=CheckpointPredicate(
                url_path_contains=("/never",), visible_text_contains=("unreachable-token",)
            ),
        ),
    )

    backend = _RecordingBackend()
    worker = _worker()
    worker._inference = JsonInference([backend])
    context = _start(worker)
    handle = context.session_id  # type: ignore[attr-defined]
    # Two equally plausible "API" links -> deterministic matching must decline.
    _route_pages(
        worker,
        handle,
        {
            "/settings/api": (
                "<html><body><h1>Settings</h1>"
                "<a href='/x'>API access</a><a href='/y'>API tokens</a>"
                "</body></html>"
            )
        },
    )

    asyncio.run(worker.navigate_onboarding(context, _research()))  # type: ignore[arg-type]
    asyncio.run(worker.stop(context))  # type: ignore[arg-type]

    assert backend.prompts, "the model path was never reached"
    prompt = backend.prompts[0]
    # The model is offered opaque candidate ids and fenced, selector-free page text.
    assert "CANDIDATES:" in prompt
    assert "<<<PAGE>>>" in prompt and "<<<END_PAGE>>>" in prompt
    assert "input[" not in prompt and "nth(" not in prompt
    # A legitimate navigation label survives DLP so the agent can still navigate.
    assert "API tokens" in prompt


def test_dlp_boundary_still_blocks_a_prompt_carrying_secret_material() -> None:
    """The guard that broke the path must still fire on a genuine leak."""

    from ops.model_input_dlp import contains_secret_material

    assert contains_secret_material("token " + "a1b2c3d4e5" * 4) is True
    # ...but not on ordinary prompt scaffolding or a normal URL.
    assert contains_secret_material("https://app.pipedrive.com/settings/api") is False
    assert contains_secret_material('{"decision": "select_candidate"}') is False
