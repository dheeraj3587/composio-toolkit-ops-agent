"""Tests for the general inbox read/search capability, the safe query builder,
and the richer reply classes.

The inbox read is a general-purpose, sanitized, NON-vaulting projection: it must
redact secrets for display, never store them, surface trusted senders first, and
flag attachments. The query builder must be injection-safe.
"""

from __future__ import annotations

import asyncio
import sys
import types

import pytest
from pydantic import SecretStr

from ops.core.config import Settings
from ops.email.reply_classifier import ReplyClassifier
from ops.gmail.worker import (
    GmailWorker,
    SanitizedGmailMessage,
    SanitizedGmailThread,
    build_inbox_query,
)


# --- Offline fake Composio client that returns canned inbox messages ----------
class _Resp:
    def __init__(self, data: dict[str, object]) -> None:
        self.successful = True
        self.error = None
        self.data = data


class _Session:
    def __init__(self, session_id: str, messages: list[dict[str, object]]) -> None:
        self.session_id = session_id
        self.id = session_id
        self._messages = messages

    def execute(
        self, slug: str, arguments: dict[str, object] | None = None, **kwargs: object
    ) -> _Resp:
        del arguments, kwargs
        if slug == "GMAIL_GET_PROFILE":
            return _Resp({"email": "ops-bot@example.test"})
        if slug == "GMAIL_FETCH_EMAILS":
            return _Resp({"messages": self._messages})
        return _Resp({})


class _Sessions:
    def __init__(self, messages: list[dict[str, object]]) -> None:
        self._messages = messages

    def create(self, **kwargs: object) -> _Session:
        del kwargs
        return _Session("session-abc123", self._messages)


class _FakeComposio:
    def __init__(self, messages: list[dict[str, object]]) -> None:
        self.sessions = _Sessions(messages)

    def close(self) -> None:  # pragma: no cover - parity with the real client
        return None


@pytest.fixture(autouse=True)
def _fake_composio_module(monkeypatch: pytest.MonkeyPatch) -> None:
    module = types.SimpleNamespace(SESSION_PRESET_DIRECT_TOOLS="direct_tools")
    monkeypatch.setitem(sys.modules, "composio", module)


def _settings() -> Settings:
    return Settings(
        composio_gmail_api_key=SecretStr("test-key"),  # pragma: allowlist secret
        composio_gmail_connected_account_id="gmail-acct-1",
        outreach_recipient_override="controlled@example.test",
    )


def _worker(messages: list[dict[str, object]]) -> GmailWorker:
    return GmailWorker(settings=_settings(), sdk_client=_FakeComposio(messages))


# --- search_inbox: sanitized, non-vaulting, trust-ordered ---------------------
def test_search_inbox_redacts_and_flags_attachments() -> None:
    messages: list[dict[str, object]] = [
        {
            "id": "m1",
            "threadId": "t1",
            "from": "Stripe <no-reply@stripe.com>",
            "subject": "Your API access",
            "snippet": "Here is your api_key: sk_live_super_secret_value_123",
            "internal_date": "500",
            "attachments": [{"filename": "keys.pdf"}],
        }
    ]
    results = asyncio.run(_worker(messages).search_inbox(query="in:anywhere"))
    assert len(results) == 1
    result = results[0]
    assert result.message_id == "m1" and result.thread_id == "t1"
    assert result.has_attachments is True
    # The secret value must be redacted for display and never surfaced verbatim.
    assert "sk_live_super_secret_value_123" not in result.sanitized_preview
    assert "REDACT" in result.sanitized_preview.upper()


def test_search_inbox_never_projects_one_time_codes_or_magic_links() -> None:
    messages: list[dict[str, object]] = [
        {
            "id": "otp",
            "threadId": "otp-thread",
            "from": "security@example.test",
            "subject": "Your verification code is 481920",
            "snippet": "Enter 481-920 to sign in.",
            "internalDate": "500",
        },
        {
            "id": "link",
            "threadId": "link-thread",
            "from": "security@example.test",
            "subject": "Verify your sign in",
            "snippet": "Open https://app.example.test/verify/opaque-magic-value",
            "internalDate": "400",
        },
    ]

    results = asyncio.run(_worker(messages).search_inbox(query="in:anywhere"))
    rendered = " ".join(
        f"{result.sanitized_subject} {result.sanitized_preview}" for result in results
    )
    assert "481920" not in rendered
    assert "481-920" not in rendered
    assert "opaque-magic-value" not in rendered
    assert "REDACTED_VERIFICATION_CODE" in rendered
    assert "REDACTED_VERIFICATION_LINK" in rendered


def test_search_inbox_prefers_trusted_domain() -> None:
    messages: list[dict[str, object]] = [
        {"id": "a", "from": "x@spam.example", "internal_date": "900", "subject": "newest"},
        {"id": "b", "from": "y@mail.usepylon.com", "internal_date": "100", "subject": "trusted"},
    ]
    results = asyncio.run(
        _worker(messages).search_inbox(query="in:anywhere", trusted_domains=("usepylon.com",))
    )
    assert results[0].message_id == "b"  # trusted surfaced first despite being older


def test_search_inbox_rejects_out_of_range_max_results() -> None:
    with pytest.raises(ValueError):
        asyncio.run(_worker([]).search_inbox(max_results=0))
    with pytest.raises(ValueError):
        asyncio.run(_worker([]).search_inbox(max_results=999))


# --- build_inbox_query: injection-safe -----------------------------------------
def test_build_inbox_query_composes_validated_parts() -> None:
    query = build_inbox_query(
        sender_domain="stripe.com", subject="API access", newer_than="7d", unread=True
    )
    assert query == 'from:stripe.com subject:"API access" newer_than:7d is:unread'


def test_build_inbox_query_defaults_to_anywhere() -> None:
    assert build_inbox_query() == "in:anywhere"


def test_build_inbox_query_strips_injection_attempts() -> None:
    # Newlines/quotes in the subject cannot inject extra operators.
    query = build_inbox_query(subject='hi"\nfrom:attacker.com')
    assert "\n" not in query
    assert query == 'subject:"hi from:attacker.com"'


def test_build_inbox_query_rejects_arbitrary_extra_operators() -> None:
    assert build_inbox_query(extra="has:attachment") == "has:attachment"
    with pytest.raises(ValueError):
        build_inbox_query(extra="in:anywhere OR from:attacker.example")


@pytest.mark.parametrize("bad", ["nonsense", "7x", "d7", "10", ""])
def test_build_inbox_query_rejects_bad_newer_than(bad: str) -> None:
    if bad == "":
        # Empty is simply ignored, not an error.
        assert build_inbox_query(newer_than=bad) == "in:anywhere"
    else:
        with pytest.raises(ValueError):
            build_inbox_query(newer_than=bad)


def test_build_inbox_query_rejects_bad_sender_domain() -> None:
    with pytest.raises(ValueError):
        build_inbox_query(sender_domain="not a domain!")


# --- Richer reply classes -------------------------------------------------------
def _thread(reply_body: str) -> SanitizedGmailThread:
    return SanitizedGmailThread(
        thread_id="t1",
        messages=(
            SanitizedGmailMessage(
                message_id="m1",
                sender="us@example.test",
                recipients=("vendor@acme.test",),
                sent_at="1",
                sanitized_subject="API access request",
                sanitized_body="Our outreach asking for developer API access.",
            ),
            SanitizedGmailMessage(
                message_id="m2",
                sender="vendor@acme.test",
                recipients=("us@example.test",),
                sent_at="2",
                sanitized_subject="Re: API access request",
                sanitized_body=reply_body,
            ),
        ),
    )


@pytest.mark.parametrize(
    ("reply", "expected"),
    [
        ("Please verify your email address before we can proceed.", "verify_email_first"),
        (
            "Thanks — we're experiencing a high volume of requests; we'll get back to you.",
            "rate_limited",
        ),
        (
            "I've forwarded your request; please reach out to our developer relations team.",
            "wrong_contact",
        ),
    ],
)
def test_reply_classifier_recognizes_new_classes(reply: str, expected: str) -> None:
    classification = asyncio.run(
        ReplyClassifier().classify(app_name="Acme", sanitized_thread=_thread(reply))
    )
    assert classification.classification == expected
    assert classification.start_browser_onboarding is False


def test_reply_classifier_still_detects_credentials_and_rejection() -> None:
    creds = asyncio.run(
        ReplyClassifier().classify(
            app_name="Acme",
            sanitized_thread=_thread("Here is your key: [REDACTED_SECRET:api_key]"),
        )
    )
    assert creds.classification == "credentials_received"
    rejected = asyncio.run(
        ReplyClassifier().classify(
            app_name="Acme",
            sanitized_thread=_thread("Unfortunately we cannot provide API access at this time."),
        )
    )
    assert rejected.classification == "rejected"
