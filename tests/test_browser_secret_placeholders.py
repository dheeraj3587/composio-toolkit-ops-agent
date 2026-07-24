"""Browser Use v3 login-secret injection uses bare ``x_`` placeholder keys.

Regression for the bug where the agent typed the literal string
``<secret>login_email</secret>`` into a provider login form because the Cloud
substitutes a ``sensitive_data`` value only when the agent types the exact
placeholder KEY. The task must reference bare ``x_``-prefixed keys and the
payload sent to the provider must use those same keys.
"""

from __future__ import annotations

from ops.browser_worker import _render_browser_task, to_browser_sensitive_data


def test_mapper_renames_typed_keys_and_drops_non_typed() -> None:
    mapped = to_browser_sensitive_data(
        {
            "login_email": "owner@example.com",
            "login_password": "s3cret-pw",  # pragma: allowlist secret
            "login_otp": "123456",
            "login_verification_url": "https://app.example.com/verify?t=abc",
        }
    )
    assert mapped == {
        "x_login_email": "owner@example.com",
        "x_login_password": "s3cret-pw",  # pragma: allowlist secret
        "x_login_otp": "123456",
    }


def test_mapper_returns_none_when_no_typed_credentials() -> None:
    assert to_browser_sensitive_data(None) is None
    assert to_browser_sensitive_data({}) is None
    # A one-time sign-in URL is navigated to, not typed, so it injects nothing.
    assert to_browser_sensitive_data({"login_verification_url": "https://x.test"}) is None


def test_login_task_uses_bare_x_placeholders_never_secret_wrapper() -> None:
    task = _render_browser_task(
        "https://app.pipedrive.com/login",
        ("app.pipedrive.com", "developers.pipedrive.com"),
        None,
        ("login_email", "login_password"),
    )
    # The Cloud substitutes only on an exact bare-key match.
    assert "x_login_email" in task
    assert "x_login_password" in task
    assert "type exactly x_login_email" in task
    # The literal wrapper that caused the bug must be gone entirely.
    assert "<secret>" not in task


def test_otp_task_uses_bare_x_placeholder() -> None:
    task = _render_browser_task(
        "https://app.pipedrive.com/login",
        ("app.pipedrive.com",),
        None,
        ("login_email", "login_password", "login_otp"),
    )
    assert "x_login_otp" in task
    assert "<secret>" not in task


def test_task_without_login_has_no_placeholder_leakage() -> None:
    task = _render_browser_task("https://app.hubspot.com/login", ("app.hubspot.com",), None)
    assert "x_login_email" not in task
    assert "<secret>" not in task
