"""Phase 1 tests: login state machine, OTP, magic link, approved values, and the
structured checkpoint state machine.

Login/OTP tests drive REAL Chromium against a local deterministic test app whose
routes are served in-memory via Playwright routing (no network, no vendor). They
skip only when Chromium cannot launch. Predicate/resolver tests are pure.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from ops.browser_api_trace_catalog import BrowserApiTraceStep, CheckpointPredicate
from ops.browser_candidates import (
    APPROVED_VALUE_REFS,
    generate_candidates,
)
from ops.browser_decider import SnapshotElement, build_snapshot
from ops.browser_login import (
    drive_login,
    inject_otp,
    inspect_after_login_submit,
    inspect_login,
    magic_link_is_safe,
    normalize_resume_signal,
)
from ops.config import Settings
from ops.playwright_worker import (
    ApprovedBrowserValueResolver,
    PageInspection,
    checkpoint_satisfied,
    predicate_satisfied,
)
from tests.browser_app.harness import require_chromium

_HOST = "app.pipedrive.com"
_PATTERNS = (_HOST, "*.pipedrive.com")


def _login_inspection(state: str, reason: str) -> Any:
    from ops.browser_login import LoginInspection

    return LoginInspection(
        state=state,
        email_field=None,
        password_field=None,
        otp_fields=(),
        submit_control=None,
        current_url=f"https://{_HOST}/login",
        reason_code=reason,
    )


# --- Local deterministic test application (routed HTML per path) ----------------
_APP: dict[str, str] = {
    "/login": (
        "<html><body><h1>Sign in</h1>"
        "<form action='/home' method='get'>"
        "<input type='email' name='email' autocomplete='username'>"
        "<input type='password' name='password'>"
        "<button type='submit'>Sign in</button>"
        "</form></body></html>"
    ),
    "/email-first": (
        "<html><body><h1>Sign in</h1>"
        "<form action='/password' method='get'>"
        "<input type='email' name='email' autocomplete='username'>"
        "<button type='submit'>Continue</button>"
        "</form></body></html>"
    ),
    "/password": (
        "<html><body><h1>Enter password</h1>"
        "<form action='/home' method='get'>"
        "<input type='password' name='password'>"
        "<button type='submit'>Log in</button>"
        "</form></body></html>"
    ),
    "/otp-single": (
        "<html><body><h1>Verify</h1>"
        "<form action='/home' method='get'>"
        "<input autocomplete='one-time-code' name='otp' inputmode='numeric'>"
        "<button type='submit'>Verify</button>"
        "</form></body></html>"
    ),
    "/otp-multiple": (
        "<html><body><h1>Verify</h1><form action='/home' method='get'>"
        + "".join(f"<input name='code{i}' inputmode='numeric' maxlength='1'>" for i in range(6))
        + "<button type='submit'>Verify</button></form></body></html>"
    ),
    "/bad-login": (
        "<html><body><h1>Sign in</h1>"
        "<p class='error'>Your password is incorrect. Please try again.</p>"
        "<form action='/home' method='get'>"
        "<input type='email' name='email'>"
        "<input type='password' name='password'>"
        "<button type='submit'>Sign in</button>"
        "</form></body></html>"
    ),
    "/double-password": (
        "<html><body><h1>Two forms</h1>"
        "<form><input type='password' name='p1'></form>"
        "<form><input type='password' name='p2'></form>"
        "</body></html>"
    ),
    "/home": "<html><body><h1>Welcome back</h1><a href='/settings'>Settings</a></body></html>",
    "/settings": "<html><body><h1>Settings</h1><a href='/developers'>Developers</a></body></html>",
    "/developers": "<html><body><h1>Developers</h1><a href='/api-keys'>API keys</a></body></html>",
    "/api-keys": (
        "<html><body><h1>API keys</h1>"
        "<p>Your API token field label is shown here.</p>"
        "<input name='api_token' readonly value='tok'></body></html>"
    ),
}


async def _serve(page: Any) -> None:
    async def _handler(route: Any) -> None:
        url = route.request.url
        path = url.split(_HOST, 1)[1].split("?")[0] if _HOST in url else "/"
        body = _APP.get(path, "<html><body><h1>Unknown</h1></body></html>")
        await route.fulfill(status=200, content_type="text/html", body=body)

    await page.route(f"https://{_HOST}/**", _handler)


def _run(path: str, coro_factory: Any) -> Any:
    """Launch Chromium, serve the test app, navigate to ``path``, run ``coro_factory(page)``."""

    async def _main() -> Any:
        from playwright.async_api import async_playwright

        async with async_playwright() as p:
            try:
                browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
            except Exception as exc:  # pragma: no cover - no Chromium
                require_chromium(exc)
            page = await browser.new_page()
            await _serve(page)
            await page.goto(f"https://{_HOST}{path}", wait_until="domcontentloaded", timeout=20_000)
            try:
                return await coro_factory(page)
            finally:
                await browser.close()

    return asyncio.run(_main())


def test_post_submit_visible_challenge_is_typed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ops.browser_login as login_module

    async def unchanged(*args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        return _login_inspection("credentials_ready", "credentials_ready")

    class _Item:
        async def is_visible(self) -> bool:
            return True

    class _Locator:
        async def count(self) -> int:
            return 1

        def nth(self, index: int) -> _Item:
            assert index == 0
            return _Item()

    class _Page:
        def locator(self, selector: str) -> _Locator:
            assert "recaptcha" in selector
            return _Locator()

    monkeypatch.setattr(login_module, "wait_for_login_state_change", unchanged)
    result = asyncio.run(
        inspect_after_login_submit(
            _Page(), previous="credentials_ready", patterns=_PATTERNS, timeout_seconds=0.5
        )
    )
    assert result.state == "unknown"
    assert result.reason_code == "captcha_required"


def test_post_submit_unchanged_form_requires_provider_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ops.browser_login as login_module

    async def unchanged(*args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        return _login_inspection("credentials_ready", "credentials_ready")

    class _Locator:
        async def count(self) -> int:
            return 0

    class _Page:
        def locator(self, selector: str) -> _Locator:
            assert "recaptcha" in selector
            return _Locator()

    monkeypatch.setattr(login_module, "wait_for_login_state_change", unchanged)
    result = asyncio.run(
        inspect_after_login_submit(
            _Page(), previous="credentials_ready", patterns=_PATTERNS, timeout_seconds=0.5
        )
    )
    assert result.reason_code == "login_verification_required"


# --- Login state machine -------------------------------------------------------
def test_single_page_login_completes() -> None:
    """Login submits and lands on the post-login page.

    The state is deliberately NOT asserted to be ``authenticated``: the absence of
    login fields is no longer treated as proof of a successful login (an error page
    or a loading skeleton looks identical). ``authenticated`` must come from a
    reviewed checkpoint predicate, so the observable result here is the navigation.
    """

    async def _c(page: Any) -> object:
        result = await drive_login(
            page, {"login_email": "ops@example.test", "login_password": "pw"}, _PATTERNS
        )
        return result.state, page.url

    state, url = _run("/login", _c)
    # Progress was made off the login form.
    assert state not in {"credentials_ready", "authentication_failed"}
    assert "/home" in url


def test_email_first_login_completes() -> None:
    """Email-first login walks email -> password -> post-login page."""

    async def _c(page: Any) -> object:
        result = await drive_login(
            page, {"login_email": "ops@example.test", "login_password": "pw"}, _PATTERNS
        )
        return result.state, page.url

    state, url = _run("/email-first", _c)
    assert state not in {"email_required", "password_required", "authentication_failed"}
    assert "/home" in url


def test_incorrect_credentials_produce_authentication_failed() -> None:
    async def _c(page: Any) -> object:
        return (await inspect_login(page, _PATTERNS)).state

    assert _run("/bad-login", _c) == "authentication_failed"


def test_multiple_password_forms_require_hitl() -> None:
    async def _c(page: Any) -> object:
        inspection = await inspect_login(page, _PATTERNS)
        return inspection.state, inspection.reason_code

    state, reason = _run("/double-password", _c)
    assert state == "unknown"
    assert reason == "multiple_password_forms"


def test_single_field_otp_works() -> None:
    async def _c(page: Any) -> object:
        inspection = await inspect_login(page, _PATTERNS)
        assert inspection.state == "otp_required"
        ok = await inject_otp(page, "123456", inspection)
        return ok, page.url

    ok, url = _run("/otp-single", _c)
    assert ok is True
    assert "/home" in url


def test_multi_field_otp_works() -> None:
    async def _c(page: Any) -> object:
        inspection = await inspect_login(page, _PATTERNS)
        assert inspection.state == "otp_required"
        ok = await inject_otp(page, "654321", inspection)
        return ok, page.url

    ok, url = _run("/otp-multiple", _c)
    assert ok is True
    assert "/home" in url


def test_absent_login_surface_is_not_claimed_as_authenticated() -> None:
    """A page with no login controls must report ``unknown``, not ``authenticated``.

    This is the corrected contract: inferring a successful login from the mere
    absence of login fields would classify an error page, a loading skeleton or a
    blank page as authenticated. Authentication evidence has to come from a reviewed
    checkpoint predicate instead.
    """

    async def _c(page: Any) -> object:
        inspection = await inspect_login(page, _PATTERNS)
        return inspection.state, inspection.reason_code

    state, reason = _run("/home", _c)
    assert state == "unknown"
    assert reason == "no_recognized_login_surface"


# --- Magic link safety (pure) --------------------------------------------------
def test_unsafe_magic_link_is_blocked() -> None:
    assert (
        magic_link_is_safe("http://app.pipedrive.com/verify?t=x", _PATTERNS) is False
    )  # not https
    assert magic_link_is_safe("https://evil.example/verify?t=x", _PATTERNS) is False  # off host
    assert magic_link_is_safe("https://user:pw@app.pipedrive.com/v", _PATTERNS) is False  # userinfo
    assert magic_link_is_safe("https://app.pipedrive.com/verify?t=x", _PATTERNS) is True


def test_resume_signals_fail_closed_on_unknown() -> None:
    assert normalize_resume_signal("otp_available") == "otp_available"
    assert normalize_resume_signal("human_completed") == "human_completed"
    assert normalize_resume_signal("please just continue") is None
    assert normalize_resume_signal(None) is None


# --- Approved non-secret values ------------------------------------------------
def test_approved_value_resolves_non_secret() -> None:
    settings = Settings(
        company_legal_name="Acme Inc",
        company_website="https://acme.test",
        company_use_case="Sync deals",
        company_expected_volume="1000/day",
    )
    resolver = ApprovedBrowserValueResolver(settings)
    assert resolver.resolve("company_name") == "Acme Inc"
    assert resolver.resolve("company_website") == "https://acme.test"
    assert resolver.resolve("use_case") == "Sync deals"
    assert resolver.resolve("expected_volume") == "1000/day"
    assert resolver.resolve("application_name") == "Acme Inc integration"


def test_resolver_never_emits_a_secret_or_unknown_ref() -> None:
    settings = Settings(company_legal_name="vault://co/x/y token")  # secret-shaped
    resolver = ApprovedBrowserValueResolver(settings)
    assert resolver.resolve("company_name") is None  # secret-shaped -> refused
    assert resolver.resolve("password") is None  # not an approved ref
    assert resolver.resolve("api_key") is None


def test_approved_value_can_be_typed_as_a_candidate() -> None:
    elements = build_snapshot([{"tag": "input", "type": "text", "name": "Company name"}])
    candidates = generate_candidates(
        elements=elements,
        checkpoint_signals=("Company",),
        checkpoint_order=1,
        trace_version="2.0",
        expected_postcondition="done",
        allow_value_refs=("company_name",),
    )
    # Phase 2 renamed the value action "type" -> "fill"; both remain valid literals.
    typed = [c for c in candidates if c.action in {"fill", "type"}]
    assert typed and typed[0].value_ref == "company_name"
    assert "company_name" in APPROVED_VALUE_REFS


def test_unapproved_value_reference_produces_no_candidate() -> None:
    elements = build_snapshot([{"tag": "input", "type": "text", "name": "Company"}])
    candidates = generate_candidates(
        elements=elements,
        checkpoint_signals=("Company",),
        checkpoint_order=1,
        trace_version="2.0",
        expected_postcondition="done",
        allow_value_refs=("arbitrary_free_text",),
    )
    assert [c for c in candidates if c.action in {"fill", "type"}] == []


# --- Structured checkpoint state machine (pure) --------------------------------
def _inspection(
    url: str, *, title: str = "", text: str = "", names: tuple[str, ...] = ()
) -> PageInspection:
    elements = tuple(SnapshotElement(index=i, role="link", name=n) for i, n in enumerate(names))
    return PageInspection(
        url=url, title=title, visible_text=text, elements=elements, locators=(), fingerprint="fp"
    )


def test_checkpoint_advances_only_when_predicate_passes() -> None:
    checkpoint = BrowserApiTraceStep(
        order=1,
        instruction="Reach API token page",
        expected_signals=("API",),
        completion=CheckpointPredicate(
            url_path_contains=("/api-keys",), visible_text_contains=("API token",)
        ),
    )
    passing = _inspection(f"https://{_HOST}/api-keys", text="Your API token is here")
    failing = _inspection(f"https://{_HOST}/api-keys", text="no credential here")
    assert checkpoint_satisfied(checkpoint, passing) is True
    assert checkpoint_satisfied(checkpoint, failing) is False


def test_url_change_alone_does_not_satisfy_a_predicate() -> None:
    # The URL matches but the required label is absent -> NOT satisfied.
    predicate = CheckpointPredicate(
        url_path_contains=("/api-keys",), visible_text_contains=("API token",)
    )
    only_url = _inspection(f"https://{_HOST}/api-keys", text="Dashboard")
    assert predicate_satisfied(predicate, only_url) is False


def test_required_accessible_name_and_forbidden_text() -> None:
    predicate = CheckpointPredicate(
        required_accessible_names=("Create API key",), forbidden_text=("error",)
    )
    ok = _inspection(f"https://{_HOST}/x", names=("Create API key",))
    forbidden = _inspection(
        f"https://{_HOST}/x", text="an error occurred", names=("Create API key",)
    )
    missing = _inspection(f"https://{_HOST}/x", names=("Something else",))
    assert predicate_satisfied(predicate, ok) is True
    assert predicate_satisfied(predicate, forbidden) is False  # forbidden text blocks
    assert predicate_satisfied(predicate, missing) is False  # required name absent


def test_empty_predicate_never_proves_progress() -> None:
    assert predicate_satisfied(CheckpointPredicate(), _inspection(f"https://{_HOST}/x")) is False


# ============================================= P0-2: login result propagation
class TestLoginResultPropagation:
    """A deterministic login verdict must stop the loop before the LLM, with an
    accurate typed reason — never be discarded."""

    @staticmethod
    def _worker() -> Any:
        from ops.config import Settings
        from ops.playwright_worker import PlaywrightBrowserWorker

        return PlaywrightBrowserWorker(
            settings=Settings(allow_live_browser=True, browser_provider="playwright")
        )

    @staticmethod
    def _session() -> Any:
        import asyncio as _asyncio

        from ops.playwright_worker import _PwSession

        return _PwSession(None, None, None, None, _asyncio.Lock(), patterns=_PATTERNS)

    def _disposition(self, state: str, reason: str, *, had_credentials: bool = True) -> Any:
        from ops.browser_login import LoginInspection

        worker = self._worker()
        result = LoginInspection(
            state=state,  # type: ignore[arg-type]
            email_field=None,
            password_field=None,
            otp_fields=(),
            submit_control=None,
            current_url="https://app.pipedrive.com/login",
            reason_code=reason,
        )
        return worker._observation_from_login_result(
            self._session(), result, had_credentials=had_credentials
        )

    def test_authentication_failure_is_a_typed_failed_observation(self) -> None:
        obs = self._disposition("authentication_failed", "authentication_failed")
        assert obs is not None
        assert obs.status == "failed"
        assert obs.reason_code == "authentication_failed"

    def test_unreviewed_frame_is_a_failure(self) -> None:
        obs = self._disposition("unknown", "login_frame_unreviewed")
        assert obs is not None
        assert obs.status == "failed"
        assert obs.reason_code == "login_frame_unreviewed"

    def test_blocked_magic_link_is_a_failure(self) -> None:
        obs = self._disposition("magic_link_required", "verification_link_blocked")
        assert obs is not None
        assert obs.status == "failed"
        assert obs.reason_code == "verification_link_blocked"

    def test_ambiguous_surfaces_become_typed_hitl(self) -> None:
        for reason in ("multiple_login_surfaces", "multiple_password_forms", "login_origin_unsafe"):
            obs = self._disposition("unknown", reason)
            assert obs is not None
            assert obs.status == "human_action_required"
            assert obs.reason_code == reason

    def test_otp_required_is_typed_hitl(self) -> None:
        obs = self._disposition("otp_required", "otp_required")
        assert obs is not None
        assert obs.status == "human_action_required"
        assert obs.reason_code == "otp_required"
        assert obs.human_action_type == "email_otp"

    def test_otp_surface_mismatch_stops_with_a_reason(self) -> None:
        obs = self._disposition("unknown", "otp_surface_not_verified")
        assert obs is not None
        assert obs.status == "human_action_required"
        assert obs.reason_code == "otp_surface_not_verified"

    def test_account_selection_is_typed_hitl(self) -> None:
        obs = self._disposition("account_selection_required", "account_selection_required")
        assert obs is not None
        assert obs.human_action_type == "account_selection"

    def test_login_still_on_form_with_credentials_is_incomplete(self) -> None:
        obs = self._disposition("credentials_ready", "credentials_ready")
        assert obs is not None
        assert obs.status == "failed"
        assert obs.reason_code == "login_incomplete"

    def test_visible_captcha_becomes_a_bounded_interactive_handoff(self) -> None:
        worker = self._worker()
        session = self._session()
        result = _login_inspection("unknown", "captcha_required")

        first = worker._observation_from_login_result(session, result, had_credentials=True)
        second = worker._observation_from_login_result(session, result, had_credentials=True)
        exhausted = worker._observation_from_login_result(session, result, had_credentials=True)

        assert first is not None and first.status == "human_action_required"
        assert first.human_action_type == "captcha"
        assert second is not None and second.status == "human_action_required"
        assert exhausted is not None and exhausted.status == "failed"
        assert exhausted.reason_code == "login_incomplete"

    def test_provider_verification_is_not_mislabeled_as_bad_credentials(self) -> None:
        obs = self._disposition("unknown", "login_verification_required")
        assert obs is not None
        assert obs.status == "human_action_required"
        assert obs.reason_code == "login_verification_required"
        assert obs.human_action_type == "provider_verification"

    def test_all_login_handoffs_share_the_two_pause_budget(self) -> None:
        worker = self._worker()
        session = self._session()
        otp = _login_inspection("otp_required", "otp_required")
        account = _login_inspection("account_selection_required", "account_selection_required")

        first = worker._observation_from_login_result(session, otp, had_credentials=False)
        second = worker._observation_from_login_result(session, account, had_credentials=False)
        exhausted = worker._observation_from_login_result(session, otp, had_credentials=False)

        assert first is not None and first.status == "human_action_required"
        assert second is not None and second.status == "human_action_required"
        assert exhausted is not None and exhausted.reason_code == "login_incomplete"

    def test_resume_checks_a_form_hiding_captcha_before_target_retry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import ops.playwright_worker as worker_module
        from ops.browser_api_trace_catalog import get_browser_api_trace

        worker = self._worker()
        session = self._session()
        session.app_slug = "pipedrive"
        trace = get_browser_api_trace("pipedrive")
        assert trace is not None

        async def no_success(*args: Any, **kwargs: Any) -> None:
            del args, kwargs
            return None

        async def no_surface(*args: Any, **kwargs: Any) -> Any:
            del args, kwargs
            return _login_inspection("unknown", "no_recognized_login_surface")

        async def challenge(*args: Any, **kwargs: Any) -> bool:
            del args, kwargs
            return True

        async def must_not_retry(*args: Any, **kwargs: Any) -> bool:
            del args, kwargs
            raise AssertionError("visible CAPTCHA must be handled before navigation")

        monkeypatch.setattr(worker, "verify_credential_page", no_success)
        monkeypatch.setattr(worker, "_retry_reviewed_target_after_login", must_not_retry)
        monkeypatch.setattr(worker_module, "inspect_login", no_surface)
        monkeypatch.setattr(worker_module, "visible_login_challenge", challenge)

        result = asyncio.run(worker._resume_login_after_hitl(session, trace))
        assert result is not None
        assert result.status == "human_action_required"
        assert result.reason_code == "captcha_required"

    def test_no_recognized_surface_continues_the_loop(self) -> None:
        # None means "let the trace predicate decide", not "authenticated".
        assert self._disposition("unknown", "no_recognized_login_surface") is None

    def test_reason_codes_contain_no_page_or_exception_text(self) -> None:
        obs = self._disposition("otp_required", "otp_required")
        assert obs is not None and obs.reason_code is not None
        import re as _re

        assert _re.fullmatch(r"[a-z0-9_:-]+", obs.reason_code)

    def test_reason_code_field_rejects_page_text(self) -> None:
        from ops.browser_worker import BrowserObservation

        with pytest.raises(ValueError, match="reason code is invalid"):
            BrowserObservation(
                status="failed",
                current_url="https://app.pipedrive.com/x",
                page_title="x",
                reason_code="Your password (from the page) is wrong!",
            )
