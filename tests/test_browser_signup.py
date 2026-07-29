"""Deterministic signup contracts against a local routed Chromium page.

No request reaches Pipedrive.  The fixtures model only the reviewed structural
contract: an email-only acceptance-bearing entry followed by a password/details
form on another exact allowed host.
"""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlsplit

import pytest

import ops.browser_signup as signup_module
from ops.app_recipes import get_app_recipe
from ops.browser_signup import (
    SignupResult,
    SignupSessionState,
    drive_signup,
    signup_secret_continuation_ready,
)
from tests.browser_app.harness import require_chromium

_PATTERNS = ("www.pipedrive.com", "app.pipedrive.com")
_REGISTER = """
<html><body>
  <form action="https://app.pipedrive.com/signup/details" method="post">
    <label>Enter your work email <input type="email" name="email" required></label>
    <p>By signing up, you accept our Pipedrive Terms of Service and Privacy Notice.</p>
    <label><input type="checkbox" name="marketing"> Product updates</label>
    <button type="submit">Sign up in two minutes</button>
  </form>
  <script>
    window.submitCount = 0;
    document.querySelector("form").addEventListener("submit", () => {
      window.submitCount += 1;
    });
  </script>
</body></html>
"""
_DETAILS = """
<html><body>
  <form action="https://app.pipedrive.com/welcome" method="post">
    <label>Password <input type="password" name="password" required></label>
    <label>Confirm password
      <input type="password" name="password_confirmation" required>
    </label>
    <label>Company <input name="organization" autocomplete="organization" required></label>
    <button type="submit">Create workspace</button>
  </form>
</body></html>
"""
_WELCOME = "<html><body><h1>Workspace ready</h1></body></html>"
_GENERIC_LEGAL = """
<html><body>
  <form action="/generic-legal" method="post">
    <input type="email" name="email" required>
    <input type="password" name="password" required>
    <p>By creating an account, you accept the Terms and Privacy Policy.</p>
    <button type="submit">Start</button>
  </form>
  <script>
    window.submitCount = 0;
    document.querySelector("form").addEventListener("submit", () => {
      window.submitCount += 1;
    });
  </script>
</body></html>
"""
_UNCHANGED = """
<html><body>
  <p class="error">That account cannot be created.</p>
  <form action="/unchanged" method="post">
    <input type="email" name="email" required>
    <input type="password" name="password" required>
    <button type="submit">Create account</button>
  </form>
</body></html>
"""


async def _serve(page: Any) -> None:
    async def handler(route: Any) -> None:
        parsed = urlsplit(route.request.url)
        body = {
            "/en/register": _REGISTER,
            "/signup/details": _DETAILS,
            "/welcome": _WELCOME,
            "/generic-legal": _GENERIC_LEGAL,
            "/unchanged": _UNCHANGED,
        }.get(parsed.path, "<html><body><h1>Unknown</h1></body></html>")
        await route.fulfill(status=200, content_type="text/html", body=body)

    await page.route("https://www.pipedrive.com/**", handler)
    await page.route("https://app.pipedrive.com/**", handler)


def _run(path: str, callback: Any) -> Any:
    async def main() -> Any:
        from playwright.async_api import async_playwright

        async with async_playwright() as playwright:
            try:
                browser = await playwright.chromium.launch(headless=True, args=["--no-sandbox"])
            except Exception as exc:  # pragma: no cover - environment dependent
                require_chromium(exc)
            page = await browser.new_page()
            await _serve(page)
            await page.goto(
                f"https://www.pipedrive.com{path}",
                wait_until="domcontentloaded",
                timeout=20_000,
            )
            try:
                return await callback(page)
            finally:
                await browser.close()

    return asyncio.run(main())


def _pipedrive_policy() -> Any:
    recipe = get_app_recipe("pipedrive")
    assert recipe is not None and recipe.browser is not None
    assert recipe.browser.signup is not None
    return recipe.browser.signup


class _FakePage:
    def __init__(self, url: str) -> None:
        self.url = url

    def locator(self, selector: str) -> object:
        del selector
        return object()


class _FakeSurface:
    frame_url = "https://www.pipedrive.com/en/register"


class _FakeEmail:
    def __init__(self) -> None:
        self.filled = False

    async def fill(self, value: str, timeout: int) -> None:
        del value, timeout
        self.filled = True

    async def evaluate(self, script: str) -> bool:
        del script
        return self.filled


class _FakeSubmit:
    def __init__(self) -> None:
        self.clicked = False

    async def inner_text(self, timeout: int) -> str:
        del timeout
        return "Sign up in two minutes"

    async def get_attribute(self, name: str, timeout: int) -> None:
        del name, timeout
        return None

    async def click(self, timeout: int) -> None:
        del timeout
        self.clicked = True


def _patch_email_entry(
    monkeypatch: pytest.MonkeyPatch,
    *,
    email: _FakeEmail,
    submit: _FakeSubmit,
) -> None:
    async def email_surface(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
        del args, kwargs
        return [(_FakeSurface(), object(), email)]

    async def allowed(*args: object, **kwargs: object) -> bool:
        del args, kwargs
        return True

    async def no_gate(*args: object, **kwargs: object) -> None:
        del args, kwargs
        return None

    async def no_required(*args: object, **kwargs: object) -> bool:
        del args, kwargs
        return False

    async def exact_submit(*args: object, **kwargs: object) -> tuple[str, object]:
        del args, kwargs
        return "unique", submit

    monkeypatch.setattr(signup_module, "navigation_allowed", lambda *args: True)
    monkeypatch.setattr(signup_module, "_email_only_surfaces", email_surface)
    monkeypatch.setattr(signup_module, "_form_action_allowed", allowed)
    monkeypatch.setattr(signup_module, "_human_gate_before_fill", no_gate)
    monkeypatch.setattr(signup_module, "_unfilled_required_control", no_required)
    monkeypatch.setattr(signup_module, "_exact_submit", exact_submit)


def test_email_first_policy_never_clicks_acceptance_submit_without_chromium(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    email = _FakeEmail()
    submit = _FakeSubmit()
    _patch_email_entry(monkeypatch, email=email, submit=submit)
    state = SignupSessionState()

    result = asyncio.run(
        drive_signup(
            page=_FakePage("https://www.pipedrive.com/en/register"),
            patterns=_PATTERNS,
            sensitive_data={"login_email": "ops@example.test"},
            approved_fields=None,
            state=state,
            signup_policy=_pipedrive_policy(),
        )
    )

    assert result.reason_code == "legal_acceptance_required"
    assert result.action_type == "legal_acceptance"
    assert email.filled is True
    assert submit.clicked is False
    assert state.pending_submit_path == "/en/register"


def test_unchanged_human_resume_does_not_complete_email_step_without_chromium(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = SignupSessionState(
        email_step_filled=True,
        human_submit_pending=True,
        pending_submit_path="/en/register",
    )

    async def no_password(*args: object, **kwargs: object) -> list[object]:
        del args, kwargs
        return []

    async def unverified(*args: object, **kwargs: object) -> SignupResult:
        del args, kwargs
        return SignupResult(
            status="human_action_required",
            reason_code="signup_postcondition_unverified",
            action_type="provider_verification",
        )

    monkeypatch.setattr(signup_module, "navigation_allowed", lambda *args: True)
    monkeypatch.setattr(signup_module, "_password_continuation_surfaces", no_password)
    monkeypatch.setattr(signup_module, "_classify_after_submit", unverified)
    result = asyncio.run(
        drive_signup(
            page=_FakePage("https://www.pipedrive.com/en/register"),
            patterns=_PATTERNS,
            sensitive_data={"login_email": "ops@example.test"},
            approved_fields=None,
            state=state,
            signup_policy=_pipedrive_policy(),
            resume_signal="human_completed",
        )
    )

    assert result.reason_code == "legal_submission_not_observed"
    assert state.email_step_completed is False
    assert state.human_submit_pending is True


def test_allowed_path_transition_completes_human_email_step_without_chromium(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = SignupSessionState(
        email_step_filled=True,
        human_submit_pending=True,
        pending_submit_path="/en/register",
    )

    async def no_password(*args: object, **kwargs: object) -> list[object]:
        del args, kwargs
        return []

    async def transitioned(*args: object, **kwargs: object) -> SignupResult:
        del args, kwargs
        return SignupResult(status="continue", reason_code="signup_step_transition_verified")

    monkeypatch.setattr(signup_module, "navigation_allowed", lambda *args: True)
    monkeypatch.setattr(signup_module, "_password_continuation_surfaces", no_password)
    monkeypatch.setattr(signup_module, "_classify_after_submit", transitioned)
    result = asyncio.run(
        drive_signup(
            page=_FakePage("https://app.pipedrive.com/signup/details"),
            patterns=_PATTERNS,
            sensitive_data={"login_email": "ops@example.test"},
            approved_fields=None,
            state=state,
            signup_policy=_pipedrive_policy(),
            resume_signal="human_completed",
        )
    )

    assert result.status == "continue"
    assert state.email_step_completed is True
    assert state.legal_reviewed is True
    assert state.submitted_path == "/en/register"


def test_implicit_legal_acceptance_detection_is_phrase_bounded() -> None:
    class Form:
        def __init__(self, text: str) -> None:
            self.text = text

        async def inner_text(self, timeout: int) -> str:
            del timeout
            return self.text

    assert asyncio.run(
        signup_module._form_implies_legal_acceptance(
            Form("By signing up, you accept the Terms of Service.")
        )
    )
    assert not asyncio.run(
        signup_module._form_implies_legal_acceptance(Form("Read our Privacy Policy."))
    )


def test_generic_postcondition_requires_path_transition_without_chromium(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def no_challenge(*args: object, **kwargs: object) -> bool:
        del args, kwargs
        return False

    async def no_login(*args: object, **kwargs: object) -> None:
        del args, kwargs
        return None

    async def no_controls(*args: object, **kwargs: object) -> list[object]:
        del args, kwargs
        return []

    monkeypatch.setattr(signup_module, "navigation_allowed", lambda *args: True)
    monkeypatch.setattr(signup_module, "visible_login_challenge", no_challenge)
    monkeypatch.setattr(signup_module, "inspect_login", no_login)
    monkeypatch.setattr(signup_module, "_visible_enabled", no_controls)

    unchanged = asyncio.run(
        signup_module._classify_after_submit(
            _FakePage("https://app.pipedrive.com/signup"),
            _PATTERNS,
            before_path="/signup",
        )
    )
    transitioned = asyncio.run(
        signup_module._classify_after_submit(
            _FakePage("https://app.pipedrive.com/welcome"),
            _PATTERNS,
            before_path="/signup",
        )
    )
    assert unchanged.reason_code == "signup_postcondition_unverified"
    assert transitioned.reason_code == "signup_step_transition_verified"


def test_password_cannot_bypass_email_first_details_step() -> None:
    email_complete = SignupSessionState(email_step_completed=True)
    assert not signup_secret_continuation_ready(
        email_complete,
        {  # pragma: allowlist secret
            "login_email": "ops@example.test",
            "login_password": "generated-test-value",  # pragma: allowlist secret
        },
    )
    assert signup_secret_continuation_ready(email_complete, {"login_otp": "123456"})
    assert signup_secret_continuation_ready(
        SignupSessionState(submit_attempted=True),
        {  # pragma: allowlist secret
            "login_email": "ops@example.test",
            "login_password": "generated-test-value",  # pragma: allowlist secret
        },
    )


def test_pipedrive_entry_is_filled_but_never_legally_submitted() -> None:
    async def callback(page: Any) -> tuple[object, ...]:
        state = SignupSessionState()
        first = await drive_signup(
            page=page,
            patterns=_PATTERNS,
            sensitive_data={
                "login_email": "ops@example.test",
                "login_password": "generated-test-value",  # pragma: allowlist secret
            },
            approved_fields={"company_name": "Example Company"},
            state=state,
            signup_policy=_pipedrive_policy(),
        )
        first_count = await page.evaluate("window.submitCount")
        email_present = await page.locator("input[type='email']").evaluate(
            "element => Boolean(element.value)"
        )
        unchanged_resume = await drive_signup(
            page=page,
            patterns=_PATTERNS,
            sensitive_data={
                "login_email": "ops@example.test",
                "login_password": "generated-test-value",  # pragma: allowlist secret
            },
            approved_fields={"company_name": "Example Company"},
            state=state,
            signup_policy=_pipedrive_policy(),
            resume_signal="human_completed",
        )
        return first, first_count, email_present, unchanged_resume, state

    first, submit_count, email_present, unchanged_resume, state = _run("/en/register", callback)
    assert first.status == "human_action_required"
    assert first.reason_code == "legal_acceptance_required"
    assert first.action_type == "legal_acceptance"
    assert submit_count == 0
    assert email_present is True
    assert unchanged_resume.status == "human_action_required"
    assert unchanged_resume.reason_code == "legal_submission_not_observed"
    assert state.email_step_completed is False
    assert state.submit_attempted is False


def test_pipedrive_human_legal_submit_advances_to_password_details() -> None:
    async def callback(page: Any) -> tuple[object, str, bool, bool]:
        state = SignupSessionState()
        first = await drive_signup(
            page=page,
            patterns=_PATTERNS,
            sensitive_data={
                "login_email": "ops@example.test",
                "login_password": "generated-test-value",  # pragma: allowlist secret
            },
            approved_fields={"company_name": "Example Company"},
            state=state,
            signup_policy=_pipedrive_policy(),
        )
        assert first.reason_code == "legal_acceptance_required"

        # This click represents the human-owned action in a local deterministic
        # fixture. The production worker never performs this acceptance-bearing click.
        await page.locator("button[type='submit']").click()
        await page.wait_for_load_state("domcontentloaded")
        resumed = await drive_signup(
            page=page,
            patterns=_PATTERNS,
            sensitive_data={
                "login_email": "ops@example.test",
                "login_password": "generated-test-value",  # pragma: allowlist secret
            },
            approved_fields={"company_name": "Example Company"},
            state=state,
            signup_policy=_pipedrive_policy(),
            resume_signal="human_completed",
        )
        return resumed, page.url, state.email_step_completed, state.legal_reviewed

    result, url, email_completed, legal_reviewed = _run("/en/register", callback)
    assert result.status == "continue"
    assert result.reason_code == "signup_step_transition_verified"
    assert urlsplit(url).path == "/welcome"
    assert email_completed is True
    assert legal_reviewed is True


def test_generic_signup_detects_implicit_legal_acceptance_prose() -> None:
    async def callback(page: Any) -> tuple[object, int]:
        result = await drive_signup(
            page=page,
            patterns=_PATTERNS,
            sensitive_data={
                "login_email": "ops@example.test",
                "login_password": "generated-test-value",  # pragma: allowlist secret
            },
            approved_fields=None,
            state=SignupSessionState(),
        )
        return result, await page.evaluate("window.submitCount")

    result, submit_count = _run("/generic-legal", callback)
    assert result.status == "human_action_required"
    assert result.reason_code == "legal_acceptance_required"
    assert submit_count == 0


def test_generic_signup_requires_positive_path_postcondition() -> None:
    async def callback(page: Any) -> object:
        return await drive_signup(
            page=page,
            patterns=_PATTERNS,
            sensitive_data={
                "login_email": "ops@example.test",
                "login_password": "generated-test-value",  # pragma: allowlist secret
            },
            approved_fields=None,
            state=SignupSessionState(),
        )

    result = _run("/unchanged", callback)
    assert result.status == "human_action_required"
    assert result.reason_code == "signup_postcondition_unverified"
    assert result.action_type == "provider_verification"
