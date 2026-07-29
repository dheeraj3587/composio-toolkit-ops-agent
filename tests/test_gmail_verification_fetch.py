"""End-to-end tests for ``GmailWorker.fetch_verification``.

This is the only Gmail entry point permitted to supply a secret that an agent will
type into, or open on, a live provider page, so the tests assert the mandatory
bindings and the at-most-once claim rather than just the happy path.
"""

from __future__ import annotations

import asyncio
import sys
import types
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import SecretStr

from ops.config import Settings
from ops.effect_ledger import SQLiteEffectStore
from ops.gmail_worker import GmailWorker

_IDENTITY = "ops.signup+hubspot@gmail.com"
_REVIEWED = ("hubspot.com", "app.hubspot.com", "*.hubspot.com")


def _now_ms() -> int:
    return int(datetime.now(UTC).timestamp() * 1000)


def _message(
    *,
    message_id: str = "m1",
    sender: str = "noreply@hubspot.com",
    to: str = _IDENTITY,
    age_seconds: int = 60,
    subject: str = "Verify your email",
    body: str = "Confirm: https://app.hubspot.com/verify-email?token=secrettoken",
    authentication_results: str | None = (
        "mx.google.com; dkim=pass header.i=@hubspot.com; "
        "spf=pass smtp.mailfrom=hubspot.com; "
        "dmarc=pass header.from=hubspot.com"
    ),
) -> dict[str, object]:
    message: dict[str, object] = {
        "id": message_id,
        "from": sender,
        "to": to,
        "subject": subject,
        "messageText": body,
        "internalDate": str(_now_ms() - age_seconds * 1000),
    }
    if authentication_results is not None:
        message["Authentication-Results"] = authentication_results
    return message


class _Resp:
    def __init__(self, data: object) -> None:
        self.successful = True
        self.error = None
        self.data = data


class _Session:
    def __init__(self, session_id: str, client: _FakeComposio) -> None:
        self.session_id = session_id
        self.id = session_id
        self._client = client

    def execute(self, slug: str, arguments: dict | None = None, **kwargs: object) -> _Resp:
        del kwargs
        if slug == "GMAIL_GET_PROFILE":
            return _Resp({"email": "ops@example.test"})
        if slug == "GMAIL_FETCH_EMAILS":
            self._client.queries.append(str((arguments or {}).get("query") or ""))
            return _Resp({"messages": list(self._client.messages)})
        return _Resp({})


class _Sessions:
    def __init__(self, client: _FakeComposio) -> None:
        self._client = client
        self.create_calls = 0

    def create(self, **kwargs: object) -> _Session:
        del kwargs
        self.create_calls += 1
        return _Session(f"session-{self.create_calls}", self._client)


class _FakeComposio:
    def __init__(self, messages: list[dict[str, object]]) -> None:
        self.messages = messages
        self.queries: list[str] = []
        self.sessions = _Sessions(self)

    def close(self) -> None:  # pragma: no cover - never used in these tests
        return None


@pytest.fixture(autouse=True)
def _fake_composio_module(monkeypatch: pytest.MonkeyPatch) -> None:
    module = types.SimpleNamespace(SESSION_PRESET_DIRECT_TOOLS="direct_tools")
    monkeypatch.setitem(sys.modules, "composio", module)


def _worker(
    messages: list[dict[str, object]],
    tmp_path: Path,
    *,
    connected_account_id: str = "gmail-acct-1",
    effect_store: SQLiteEffectStore | None = None,
) -> tuple[GmailWorker, _FakeComposio]:
    settings = Settings(
        composio_gmail_api_key=SecretStr("test-key"),  # pragma: allowlist secret
        composio_gmail_connected_account_id=connected_account_id,
        outreach_recipient_override="controlled@example.test",
        gmail_retry_max_attempts=1,
        gmail_retry_base_delay_seconds=0.0,
    )
    client = _FakeComposio(messages)
    worker = GmailWorker(
        settings=settings,
        sdk_client=client,
        effect_store=effect_store or SQLiteEffectStore(tmp_path / "effects.db"),
    )
    return worker, client


def _fetch(worker: GmailWorker, **overrides: object):
    kwargs: dict[str, object] = {
        "purpose": "signup_confirmation",
        "expected_recipient": _IDENTITY,
        "reviewed_sender_patterns": _REVIEWED,
        "allowed_link_host_patterns": _REVIEWED,
        "run_id": "run_verify_1",
        "verification_requested_at_ms": _now_ms() - 120_000,
    }
    kwargs.update(overrides)
    return asyncio.run(worker.fetch_verification(**kwargs))  # type: ignore[arg-type]


def test_resolves_a_bound_verification_link(tmp_path: Path) -> None:
    worker, _client = _worker([_message()], tmp_path)
    decision = _fetch(worker)
    assert decision.resolved is not None
    assert decision.reason_code == "verification_resolved"
    assert decision.resolved.evidence.verification_kind == "link"
    assert decision.resolved.evidence.link_host == "app.hubspot.com"
    assert decision.resolved.evidence.recipient_binding == "exact"
    assert (
        decision.resolved.secret.get_secret_value()
        == "https://app.hubspot.com/verify-email?token=secrettoken"
    )


def test_server_query_uses_a_valid_gmail_operator(tmp_path: Path) -> None:
    worker, client = _worker([_message()], tmp_path)
    _fetch(worker)
    assert client.queries, "the worker must issue a search"
    query = client.queries[0]
    # Gmail has no hour unit, so an hour-scale bound must not be expressed here.
    assert "newer_than" not in query
    assert query.startswith("after:")
    assert f'to:"{_IDENTITY}"' in query


def test_same_message_is_claimed_only_once(tmp_path: Path) -> None:
    worker, _client = _worker([_message()], tmp_path)
    first = _fetch(worker)
    second = _fetch(worker)
    assert first.resolved is not None
    assert second.resolved is None
    # The second poll finds only the message it already spent, and says so
    # explicitly rather than silently re-injecting an expired code.
    assert second.reason_code == "verification_already_consumed"


def test_claim_uses_the_complete_bounded_immutable_message_id(tmp_path: Path) -> None:
    first_id = f"{'a' * 900}1"
    second_id = f"{'a' * 900}2"
    worker, client = _worker([_message(message_id=first_id)], tmp_path)
    first = _fetch(worker, run_id="run_a")
    assert first.resolved is not None
    assert first.resolved.evidence.message_id == first_id

    client.messages = [_message(message_id=second_id)]
    second = _fetch(worker, run_id="run_b")
    assert second.resolved is not None
    assert second.resolved.evidence.message_id == second_id


def test_claim_is_retriable_only_after_definite_pre_use_release(tmp_path: Path) -> None:
    worker, _client = _worker([_message()], tmp_path)
    first = _fetch(worker)
    assert first.resolved is not None

    assert worker.release_verification_claim(
        run_id="run_verify_1",
        purpose="signup_confirmation",
        evidence=first.resolved.evidence,
    )
    retry = _fetch(worker)
    assert retry.resolved is not None
    assert worker.complete_verification_claim(
        run_id="run_verify_1",
        purpose="signup_confirmation",
        evidence=retry.resolved.evidence,
    )

    consumed = _fetch(worker)
    assert consumed.resolved is None
    assert consumed.reason_code == "verification_already_consumed"


def test_claim_skips_a_used_message_and_falls_back_to_an_older_one(
    tmp_path: Path,
) -> None:
    newest = _message(
        message_id="newest",
        age_seconds=30,
        body="Confirm: https://app.hubspot.com/verify-email?token=first",
    )
    older = _message(
        message_id="older",
        age_seconds=120,
        body="Confirm: https://app.hubspot.com/verify-email?token=second",
    )
    worker, _client = _worker([newest, older], tmp_path)
    first = _fetch(worker)
    second = _fetch(worker)
    assert first.resolved is not None and first.resolved.evidence.message_id == "newest"
    assert second.resolved is not None and second.resolved.evidence.message_id == "older"


def test_claim_is_global_across_runs_for_the_connected_account(tmp_path: Path) -> None:
    worker, _client = _worker([_message()], tmp_path)
    first = _fetch(worker, run_id="run_a")
    second = _fetch(worker, run_id="run_b")
    # The immutable provider message belongs to the connected Gmail account, not
    # to whichever run happened to poll it. A second run cannot replay it.
    assert first.resolved is not None
    assert second.resolved is None
    assert second.reason_code == "verification_already_consumed"


def test_claim_scope_isolated_between_connected_gmail_accounts(tmp_path: Path) -> None:
    effects = SQLiteEffectStore(tmp_path / "effects.db")
    first_worker, _ = _worker(
        [_message()],
        tmp_path,
        connected_account_id="gmail-acct-1",
        effect_store=effects,
    )
    second_worker, _ = _worker(
        [_message()],
        tmp_path,
        connected_account_id="gmail-acct-2",
        effect_store=effects,
    )
    assert _fetch(first_worker, run_id="run_a").resolved is not None
    assert _fetch(second_worker, run_id="run_b").resolved is not None


def test_stale_message_is_refused_even_though_the_query_returned_it(
    tmp_path: Path,
) -> None:
    # The coarse day-granularity server query legitimately returns yesterday's
    # mail; the in-code bound is what protects the one-time secret.
    worker, _client = _worker([_message(age_seconds=7_200)], tmp_path)
    decision = _fetch(
        worker,
        max_age_seconds=900,
        verification_requested_at_ms=_now_ms() - 8_000_000,
    )
    assert decision.resolved is None
    assert decision.reason_code == "verification_message_stale"


def test_message_before_current_challenge_is_refused(tmp_path: Path) -> None:
    worker, _client = _worker([_message(age_seconds=180)], tmp_path)
    decision = _fetch(
        worker,
        verification_requested_at_ms=_now_ms() - 60_000,
    )
    assert decision.resolved is None
    assert decision.reason_code == "verification_precedes_current_challenge"


def test_message_for_another_signup_tag_is_refused(tmp_path: Path) -> None:
    worker, _client = _worker([_message(to="ops.signup+slack@gmail.com")], tmp_path)
    decision = _fetch(worker)
    assert decision.resolved is None
    assert decision.reason_code == "verification_recipient_tag_conflict"


def test_untagged_delivery_cannot_be_claimed_by_a_tagged_signup(
    tmp_path: Path,
) -> None:
    worker, _client = _worker([_message(to="ops.signup@gmail.com")], tmp_path)
    decision = _fetch(worker)
    assert decision.resolved is None
    assert decision.reason_code == "verification_recipient_tag_missing"


def test_spoofed_sender_is_refused(tmp_path: Path) -> None:
    worker, _client = _worker([_message(sender="noreply@hubsp0t-security.test")], tmp_path)
    decision = _fetch(worker)
    assert decision.resolved is None
    assert decision.reason_code == "verification_sender_not_reviewed"


def test_missing_sender_authentication_evidence_fails_closed(tmp_path: Path) -> None:
    worker, _client = _worker(
        [_message(authentication_results=None)],
        tmp_path,
    )
    decision = _fetch(worker)
    assert decision.resolved is None
    assert decision.reason_code == "verification_sender_authentication_missing"


def test_failed_or_unaligned_sender_authentication_fails_closed(tmp_path: Path) -> None:
    worker, _client = _worker(
        [
            _message(
                authentication_results=(
                    "mx.google.com; dkim=fail header.d=hubspot.com; "
                    "spf=pass smtp.mailfrom=attacker.example; "
                    "dmarc=fail header.from=hubspot.com"
                )
            )
        ],
        tmp_path,
    )
    decision = _fetch(worker)
    assert decision.resolved is None
    assert decision.reason_code == "verification_sender_authentication_failed"


def test_link_to_an_unreviewed_host_is_refused(tmp_path: Path) -> None:
    worker, _client = _worker(
        [_message(body="Confirm: https://hubspot-verify.attacker.test/go?token=x")],
        tmp_path,
    )
    decision = _fetch(worker)
    assert decision.resolved is None
    assert decision.reason_code == "verification_secret_absent"


def test_code_is_used_when_the_provider_sends_no_link(tmp_path: Path) -> None:
    worker, _client = _worker(
        [_message(subject="Your verification code is 481920", body="Enter it to continue.")],
        tmp_path,
    )
    decision = _fetch(worker)
    assert decision.resolved is not None
    assert decision.resolved.evidence.verification_kind == "code"
    assert decision.resolved.secret.get_secret_value() == "481920"


def test_empty_inbox_reports_not_found(tmp_path: Path) -> None:
    worker, _client = _worker([], tmp_path)
    decision = _fetch(worker)
    assert decision.resolved is None
    assert decision.reason_code == "verification_message_not_found"


def test_out_of_range_arguments_are_rejected_before_any_provider_call(
    tmp_path: Path,
) -> None:
    worker, client = _worker([_message()], tmp_path)
    with pytest.raises(ValueError):
        _fetch(worker, max_age_seconds=3_601)
    with pytest.raises(ValueError):
        _fetch(worker, max_results=0)
    assert client.queries == []


def test_recipient_binding_reads_the_delivered_to_header(tmp_path: Path) -> None:
    message = _message(to="")
    message["payload"] = {
        "headers": [
            {"name": "Delivered-To", "value": _IDENTITY},
            {"name": "Subject", "value": "Verify your email"},
        ]
    }
    worker, _client = _worker([message], tmp_path)
    decision = _fetch(worker)
    assert decision.resolved is not None
    assert decision.resolved.evidence.recipient_binding == "exact"


def test_evidence_is_safe_to_persist(tmp_path: Path) -> None:
    worker, _client = _worker([_message()], tmp_path)
    decision = _fetch(worker)
    assert decision.resolved is not None
    serialized = decision.resolved.evidence.model_dump_json()
    assert "secrettoken" not in serialized
    assert "token=" not in serialized
