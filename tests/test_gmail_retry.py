"""Tests for bounded retry + reconnect on transient Composio Gmail READ failures.

Reads must survive a transient provider blip by reconnecting and retrying; a
permanent contract error must fail fast without retrying; sends never use this
path (their exactly-once guarantee is the effect ledger's job).
"""

from __future__ import annotations

import asyncio
import sys
import types

import pytest
from pydantic import SecretStr

from ops.config import Settings
from ops.gmail_worker import GmailWorker
from ops.provider_errors import ProviderContractError, ProviderOperationError

_MESSAGES = [
    {
        "id": "m1",
        "from": "a@b.test",
        "subject": "code",
        "snippet": "code 123456",
        "internal_date": "1",
    }
]


class _Resp:
    def __init__(self, successful: bool, data: object) -> None:
        self.successful = successful
        self.error = None if successful else "provider reported failure"
        self.data = data


class _FlakySession:
    # Fail counter lives on the parent client so it is SHARED across reconnects,
    # simulating a provider that recovers after N total read attempts.
    def __init__(self, session_id: str, client: _FakeComposio) -> None:
        self.session_id = session_id
        self.id = session_id
        self._client = client

    def execute(self, slug: str, arguments: dict | None = None, **kwargs: object) -> _Resp:
        del arguments, kwargs
        if slug == "GMAIL_GET_PROFILE":
            return _Resp(True, {"email": "ops@example.test"})
        if slug == "GMAIL_FETCH_EMAILS":
            self._client.fetch_calls += 1
            if self._client.fetch_calls <= self._client.fail_times:
                if self._client.mode == "raise":
                    raise RuntimeError("transient network blip")
                if self._client.mode == "error":
                    return _Resp(False, {})
                if self._client.mode == "contract":
                    return _Resp(True, "not-a-mapping")
            return _Resp(True, {"messages": _MESSAGES})
        return _Resp(True, {})


class _Sessions:
    def __init__(self, client: _FakeComposio) -> None:
        self._client = client
        self.create_calls = 0

    def create(self, **kwargs: object) -> _FlakySession:
        del kwargs
        self.create_calls += 1
        return _FlakySession(f"session-{self.create_calls}", self._client)


class _FakeComposio:
    def __init__(self, *, fail_times: int, mode: str) -> None:
        self.fetch_calls = 0
        self.fail_times = fail_times
        self.mode = mode
        self.sessions = _Sessions(self)

    def close(self) -> None:  # pragma: no cover
        return None


@pytest.fixture(autouse=True)
def _fake_composio_module(monkeypatch: pytest.MonkeyPatch) -> None:
    module = types.SimpleNamespace(SESSION_PRESET_DIRECT_TOOLS="direct_tools")
    monkeypatch.setitem(sys.modules, "composio", module)


def _worker(*, fail_times: int, mode: str, attempts: int = 3) -> tuple[GmailWorker, _FakeComposio]:
    settings = Settings(
        composio_api_key=SecretStr("test-key"),  # pragma: allowlist secret
        composio_gmail_connected_account_id="gmail-acct-1",
        outreach_recipient_override="controlled@example.test",
        gmail_retry_max_attempts=attempts,
        gmail_retry_base_delay_seconds=0.0,  # no sleeping in tests
    )
    client = _FakeComposio(fail_times=fail_times, mode=mode)
    return GmailWorker(settings=settings, sdk_client=client), client


def test_read_retries_transient_then_succeeds() -> None:
    worker, client = _worker(fail_times=2, mode="raise", attempts=3)
    results = asyncio.run(worker.search_inbox(query="in:anywhere"))
    assert len(results) == 1
    # Reconnected on each retry: a fresh session per attempt (3 total).
    assert client.sessions.create_calls == 3


def test_read_retries_provider_reported_failure_then_succeeds() -> None:
    worker, client = _worker(fail_times=1, mode="error", attempts=3)
    results = asyncio.run(worker.search_inbox(query="in:anywhere"))
    assert len(results) == 1
    assert client.sessions.create_calls == 2


def test_read_exhausts_attempts_and_raises_operation_error() -> None:
    worker, client = _worker(fail_times=99, mode="raise", attempts=3)
    with pytest.raises(ProviderOperationError):
        asyncio.run(worker.search_inbox(query="in:anywhere"))
    assert client.sessions.create_calls == 3  # all attempts used


def test_contract_error_is_not_retried() -> None:
    worker, client = _worker(fail_times=99, mode="contract", attempts=3)
    with pytest.raises(ProviderContractError):
        asyncio.run(worker.search_inbox(query="in:anywhere"))
    # A permanent contract error fails fast: connected once, no retry loop.
    assert client.sessions.create_calls == 1
