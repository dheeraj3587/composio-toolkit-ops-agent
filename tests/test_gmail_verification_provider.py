"""One happy-path check of the Gmail adapter against a fake Composio client.

Exercises the path that matters: a run-bound query reaches Gmail through the
existing tool-execution path, the bound message crosses the port, and the claim
ladder is the vault's — acquired once, then completed for every later caller
(Requirements 7.2, 7.16, 7.17, 7.22).
"""

from __future__ import annotations

import sys
import types
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from ops.core.config import Settings
from ops.core.secret_store import SQLiteSecretStore
from ops.email.verification_provider import VerificationProvider, VerificationQuery
from ops.gmail.verification_provider import GmailVerificationProvider
from ops.gmail.worker import GmailWorker

_IDENTITY = "ops.signup+hubspot@gmail.com"


class _Response:
    def __init__(self, data: object) -> None:
        self.successful = True
        self.error = None
        self.data = data


class _Session:
    def __init__(self, client: _FakeComposio) -> None:
        self.session_id = "session-1"
        self._client = client

    def execute(self, slug: str, arguments: dict | None = None, **kwargs: object) -> _Response:
        del kwargs
        if slug == "GMAIL_FETCH_EMAILS":
            self._client.queries.append(str((arguments or {}).get("query") or ""))
            return _Response({"messages": list(self._client.messages)})
        return _Response({})


class _Sessions:
    def __init__(self, client: _FakeComposio) -> None:
        self._client = client

    def create(self, **kwargs: object) -> _Session:
        del kwargs
        return _Session(self._client)


class _FakeComposio:
    def __init__(self, messages: list[dict[str, object]]) -> None:
        self.messages = messages
        self.queries: list[str] = []
        self.sessions = _Sessions(self)


@pytest.fixture(autouse=True)
def _fake_composio_module(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(
        sys.modules,
        "composio",
        types.SimpleNamespace(SESSION_PRESET_DIRECT_TOOLS="direct_tools"),
    )


async def test_the_adapter_answers_a_bound_query_and_claims_a_message_once(
    tmp_path: Path,
) -> None:
    now_ms = int(datetime.now(UTC).timestamp() * 1000)
    settings = Settings(
        composio_gmail_api_key=SecretStr("test-key"),  # pragma: allowlist secret
        composio_gmail_connected_account_id="gmail-acct-1",
        gmail_retry_max_attempts=1,
        gmail_retry_base_delay_seconds=0.0,
    )
    client = _FakeComposio(
        [
            {
                "id": "msg-1",
                "from": "no-reply@hubspot.com",
                "to": _IDENTITY,
                "subject": "Verify your email",
                "messageText": "Confirm: https://app.hubspot.com/verify-email?token=abc",
                "internalDate": str(now_ms - 60_000),
                "Authentication-Results": (
                    "mx.google.com; dkim=pass header.i=@hubspot.com; "
                    "dmarc=pass header.from=hubspot.com"
                ),
            },
            {
                # Another run's alias: must not cross the port.
                "id": "msg-2",
                "from": "no-reply@hubspot.com",
                "to": "ops.signup+other@gmail.com",
                "subject": "Verify your email",
                "messageText": "Confirm: https://app.hubspot.com/verify-email?token=xyz",
                "internalDate": str(now_ms - 30_000),
            },
        ]
    )
    store = SQLiteSecretStore(tmp_path / "vault.db", Fernet.generate_key())
    provider: VerificationProvider = GmailVerificationProvider(
        settings=settings,
        store=store,
        worker=GmailWorker(settings=settings, sdk_client=client),
    )
    query = VerificationQuery(
        expected_recipient=_IDENTITY,
        sender_domains=("hubspot.com",),
        purpose="signup_confirmation",
        not_before_ms=now_ms - 300_000,
        max_age_seconds=900,
        allowed_link_hosts=("app.hubspot.com", "*.hubspot.com"),
    )

    assert provider.is_configured() is True
    candidates = await provider.search(query)
    assert [candidate.message_id for candidate in candidates] == ["msg-1"]
    # Gmail has no hour unit, so the server-side clause stays a coarse date bound.
    assert client.queries[0].startswith("after:")
    assert f'to:"{_IDENTITY}"' in client.queries[0]

    acquired = await provider.claim(message_id="msg-1", run_id="run-001")
    assert acquired.status == "acquired"
    assert acquired.claim_token is not None

    contended = await provider.claim(message_id="msg-1", run_id="run-002")
    assert contended.status == "completed"

    await provider.settle(
        message_id="msg-1",
        run_id="run-001",
        claim_token=acquired.claim_token,
    )
    assert (await provider.claim(message_id="msg-1", run_id="run-001")).status == "completed"
