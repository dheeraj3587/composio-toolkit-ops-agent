"""Offline coverage for the shared account-aware browser entry selector."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from ops.browser.target_selection import (
    derive_account_state,
    sanitize_target_url,
    select_browser_target,
)
from ops.browser.worker import is_allowed_browser_url
from ops.playwright.worker import select_initial_target

_ALLOWED = ("app.example.test",)


def _research() -> SimpleNamespace:
    return SimpleNamespace(
        credential_management_url="https://app.example.test/settings/credentials",
        developer_portal_url="https://app.example.test/developers",
        login_url="https://app.example.test/login",
        signup_url="https://app.example.test/signup",
        api_base_url="https://app.example.test/api",
        evidence_urls=("https://app.example.test/docs",),
        operational_url_claims=(
            SimpleNamespace(
                field="credential_management_url",
                url="https://app.example.test/settings/credentials",
            ),
            SimpleNamespace(
                field="developer_portal_url", url="https://app.example.test/developers"
            ),
            SimpleNamespace(field="login_url", url="https://app.example.test/login"),
            SimpleNamespace(field="signup_url", url="https://app.example.test/signup"),
        ),
    )


@pytest.mark.parametrize(
    ("account_state", "expected"),
    [
        ("authenticated", "https://app.example.test/settings/credentials"),
        ("existing_account", "https://app.example.test/login"),
        ("account_creation_required", "https://app.example.test/signup"),
        ("unknown", "https://app.example.test/login"),
    ],
)
def test_shared_selector_applies_the_required_state_order(
    account_state: str, expected: str
) -> None:
    target = select_browser_target(
        research=_research(),
        trace=SimpleNamespace(start_url="https://app.example.test/trace-start"),
        allowed_domains=_ALLOWED,
        account_state=account_state,  # type: ignore[arg-type]
        is_allowed_url=is_allowed_browser_url,
        fallback_mode="playwright",
    )
    assert target == expected


def test_playwright_delegates_to_the_shared_ordering() -> None:
    target = select_initial_target(
        _research(),
        SimpleNamespace(start_url="https://app.example.test/trace-start"),
        _ALLOWED,
        account_state="authenticated",
    )
    assert target == "https://app.example.test/settings/credentials"


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"restored_storage_state": True}, "authenticated"),
        ({"sensitive_data": {"login_email": "owner@example.test"}}, "existing_account"),
        ({"account_creation_requested": True}, "account_creation_required"),
        ({}, "unknown"),
    ],
)
def test_account_state_uses_only_trusted_local_facts(
    kwargs: dict[str, object], expected: str
) -> None:
    assert derive_account_state(**kwargs) == expected  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "url",
    [
        "http://app.example.test/login",
        "https://owner:password@app.example.test/login",
        "https://app.example.test/login#fragment",
        "https://app.example.test/login?access_token=secret",
        "https://app.example.test/login?api_key=secret",
    ],
)
def test_selected_targets_reject_unsafe_url_components(url: str) -> None:
    assert sanitize_target_url(url) is None


def test_verified_claim_beats_an_unverified_preferred_field() -> None:
    research = _research()
    research.login_url = "https://app.example.test/unverified-login"
    target = select_browser_target(
        research=research,
        trace=SimpleNamespace(start_url="https://app.example.test/trace-start"),
        allowed_domains=_ALLOWED,
        account_state="existing_account",
        is_allowed_url=is_allowed_browser_url,
        fallback_mode="browser_use",
    )
    assert target == "https://app.example.test/login"
