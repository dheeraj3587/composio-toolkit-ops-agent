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

_HOST = "app.pipedrive.com"
_PATTERNS = (_HOST, "*.pipedrive.com")

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
                pytest.skip(f"Chromium not launchable: {type(exc).__name__}")
            page = await browser.new_page()
            await _serve(page)
            await page.goto(f"https://{_HOST}{path}", wait_until="domcontentloaded", timeout=20_000)
            try:
                return await coro_factory(page)
            finally:
                await browser.close()

    return asyncio.run(_main())


# --- Login state machine -------------------------------------------------------
def test_single_page_login_completes() -> None:
    async def _c(page: Any) -> object:
        result = await drive_login(
            page, {"login_email": "ops@example.test", "login_password": "pw"}, _PATTERNS
        )
        return result.state, page.url

    state, url = _run("/login", _c)
    assert state == "authenticated"
    assert "/home" in url


def test_email_first_login_completes() -> None:
    async def _c(page: Any) -> object:
        result = await drive_login(
            page, {"login_email": "ops@example.test", "login_password": "pw"}, _PATTERNS
        )
        return result.state, page.url

    state, url = _run("/email-first", _c)
    assert state == "authenticated"
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


def test_authenticated_home_is_detected() -> None:
    async def _c(page: Any) -> object:
        return (await inspect_login(page, _PATTERNS)).state

    assert _run("/home", _c) == "authenticated"


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
