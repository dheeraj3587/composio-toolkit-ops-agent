"""Security regressions for Gmail outreach reply ingestion."""

from __future__ import annotations

import asyncio
import sqlite3
import sys
import types
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from ops.core.config import Settings
from ops.core.models import CompanyProfile, OperationsRequest
from ops.core.secret_store import SQLiteSecretStore
from ops.core.storage import OperationsStorage
from ops.gmail.models import (
    GmailOutreachMessageClaim,
    SanitizedGmailMessage,
    SanitizedGmailThread,
)
from ops.gmail.validation import _validate_email, _validate_identifier, parse_mailbox_address
from ops.gmail.worker import GmailWorker
from ops.providers.errors import ProviderContractError
from ops.runs.email import _latest_exact_inbound
from ops.runs.service import RunService

CONTROLLED = "controlled@example.test"
VALID_SECRET = "valid-provider-key-123456"  # pragma: allowlist secret
ATTACKER_SECRET = "attacker-key-must-not-vault"  # pragma: allowlist secret
AUTHENTICATED_CONTROLLED_SENDER = (
    "mx.google.com; dkim=pass header.d=example.test; "
    "spf=pass smtp.mailfrom=example.test; "
    "dmarc=pass header.from=example.test"
)


class _Response:
    def __init__(self, data: dict[str, object]) -> None:
        self.error = None
        self.data = data


class _Session:
    session_id = "session-outreach"
    id = session_id

    def __init__(self, thread_payload: dict[str, object]) -> None:
        self._thread_payload = thread_payload

    def execute(self, slug: str, arguments: dict[str, object]) -> _Response:
        del arguments
        if slug == "GMAIL_GET_PROFILE":
            return _Response({"email": "ops@example.test"})
        if slug == "GMAIL_FETCH_MESSAGE_BY_THREAD_ID":
            return _Response(self._thread_payload)
        raise AssertionError(f"unexpected Gmail tool: {slug}")


class _Sessions:
    def __init__(self, thread_payload: dict[str, object]) -> None:
        self._thread_payload = thread_payload

    def create(self, **kwargs: object) -> _Session:
        del kwargs
        return _Session(self._thread_payload)


class _FakeComposio:
    def __init__(self, thread_payload: dict[str, object]) -> None:
        self.sessions = _Sessions(thread_payload)


@pytest.fixture(autouse=True)
def _fake_composio_module(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(
        sys.modules,
        "composio",
        types.SimpleNamespace(SESSION_PRESET_DIRECT_TOOLS="direct_tools"),
    )


def _vault(tmp_path: Path) -> SQLiteSecretStore:
    return SQLiteSecretStore(tmp_path / "vault.db", Fernet.generate_key())


def _settings() -> Settings:
    return Settings(
        composio_gmail_api_key=SecretStr("offline-test-key"),  # pragma: allowlist secret
        composio_gmail_connected_account_id="gmail-account-1",
        outreach_recipient_override=CONTROLLED,
        gmail_retry_base_delay_seconds=0.0,
    )


def _payload() -> dict[str, object]:
    return {
        "messages": [
            {
                "id": "sent-1",
                "from": "Ops <ops@example.test>",
                "to": CONTROLLED,
                "date": "2026-07-29T08:00:00Z",
                "body": "Please provide API access.",
            },
            {
                "id": "forged-1",
                "from": f'"{CONTROLLED}" <attacker@example.test>',
                "to": "ops@example.test",
                "date": "2026-07-29T08:01:00Z",
                "body": f"api_key: {ATTACKER_SECRET}",
            },
            {
                "id": "reply-1",
                "from": f"Controlled Sink <{CONTROLLED}>",
                "to": "ops@example.test",
                "date": "2026-07-29T08:02:00Z",
                "body": f"api_key: {VALID_SECRET}",
                "Authentication-Results": AUTHENTICATED_CONTROLLED_SENDER,
            },
        ]
    }


def _worker(tmp_path: Path) -> tuple[GmailWorker, SQLiteSecretStore]:
    vault = _vault(tmp_path)
    return (
        GmailWorker(
            settings=_settings(),
            secret_store=vault,
            sdk_client=_FakeComposio(_payload()),
        ),
        vault,
    )


def _counts(vault: SQLiteSecretStore) -> tuple[int, int]:
    with sqlite3.connect(vault.db_path) as connection:
        vault_count = int(connection.execute("SELECT COUNT(*) FROM vault_entries").fetchone()[0])
        ingestion_count = int(
            connection.execute("SELECT COUNT(*) FROM gmail_message_ingestions").fetchone()[0]
        )
    return vault_count, ingestion_count


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("Vendor <vendor@example.test>", "vendor@example.test"),
        ("vendor@example.test", "vendor@example.test"),
        ('"vendor@example.test" <attacker@example.test>', "attacker@example.test"),
        ("one@example.test, two@example.test", None),
        ("Team: vendor@example.test;", None),
        ("vendor@example.test\r\nBcc: attacker@example.test", None),
    ],
)
def test_parse_mailbox_address_requires_one_rfc_mailbox(
    header: str,
    expected: str | None,
) -> None:
    assert parse_mailbox_address(header) == expected


@pytest.mark.parametrize(
    "value",
    (
        "recipient@example.test\tBcc:attacker",
        ".recipient@example.test",
        "recipient..alias@example.test",
        "recipient@example..test",
        "recipient@-example.test",
        "recipient@example.test\x00",
    ),
)
def test_recipient_validation_rejects_header_and_domain_ambiguity(value: str) -> None:
    with pytest.raises(ValueError):
        _validate_email(value)


def test_identifier_validation_rejects_nonprinting_provider_values() -> None:
    with pytest.raises(ValueError):
        _validate_identifier("message\tidentifier", "message_id")


def test_operations_request_drops_legacy_per_run_outreach_sink() -> None:
    request = OperationsRequest(
        app_name="Close",
        company=CompanyProfile(
            legal_name="Example Labs",
            website="https://example.com",
            work_email_ref="vault://company/work_email/profile_1",
            use_case="Request reviewed production API access.",
        ),
        outreach_recipient_override="untrusted@example.test",
    )

    assert "outreach_recipient_override" not in OperationsRequest.model_fields
    assert "outreach_recipient_override" not in request.model_dump()


def test_fetch_thread_is_side_effect_free_and_exposes_parsed_sender(
    tmp_path: Path,
) -> None:
    worker, vault = _worker(tmp_path)

    thread = asyncio.run(worker.fetch_thread("thread-1"))

    assert _counts(vault) == (0, 0)
    assert thread.credential_refs == ()
    assert thread.messages[-1].sender_mailbox == CONTROLLED
    assert thread.messages[-1].sender_authenticated is True
    assert VALID_SECRET not in thread.messages[-1].sanitized_body
    assert "[REDACTED]" in thread.messages[-1].sanitized_body


def test_only_selected_exact_sender_message_is_vaulted_once(tmp_path: Path) -> None:
    worker, vault = _worker(tmp_path)

    with pytest.raises(ProviderContractError) as forged:
        asyncio.run(
            worker.claim_outreach_reply(
                thread_id="thread-1",
                message_id="forged-1",
                expected_sender=CONTROLLED,
                owner_run_id="run-owner-1",
                app_slug="close",
            )
        )
    assert forged.value.reason_code == "message_sender_mismatch"
    assert _counts(vault) == (0, 0)

    claim = asyncio.run(
        worker.claim_outreach_reply(
            thread_id="thread-1",
            message_id="reply-1",
            expected_sender=CONTROLLED,
            owner_run_id="run-owner-1",
            app_slug="close",
        )
    )

    assert claim.status == "acquired"
    assert claim.claim_token is not None
    assert len(claim.credential_refs) == 1
    reference = claim.credential_refs[0][1]
    assert vault.get(reference) == VALID_SECRET
    assert vault.get(reference) != ATTACKER_SECRET
    assert _counts(vault) == (1, 1)
    assert worker.complete_outreach_reply(
        thread_id="thread-1",
        message_id="reply-1",
        owner_run_id="run-owner-1",
        claim_token=claim.claim_token,
    )

    replay = asyncio.run(
        worker.claim_outreach_reply(
            thread_id="thread-1",
            message_id="reply-1",
            expected_sender=CONTROLLED,
            owner_run_id="run-other",
            app_slug="close",
        )
    )
    assert replay.status == "completed"
    assert replay.credential_refs == ()
    assert replay.claim_token is None
    assert _counts(vault) == (1, 1)


def test_exact_from_mailbox_without_gmail_authentication_cannot_be_ingested(
    tmp_path: Path,
) -> None:
    payload = _payload()
    messages = payload["messages"]
    assert isinstance(messages, list)
    reply = messages[-1]
    assert isinstance(reply, dict)
    reply.pop("Authentication-Results")
    vault = _vault(tmp_path)
    worker = GmailWorker(
        settings=_settings(),
        secret_store=vault,
        sdk_client=_FakeComposio(payload),
    )

    with pytest.raises(ProviderContractError) as raised:
        asyncio.run(
            worker.claim_outreach_reply(
                thread_id="thread-1",
                message_id="reply-1",
                expected_sender=CONTROLLED,
                owner_run_id="run-owner-1",
                app_slug="close",
            )
        )

    assert raised.value.reason_code == "message_sender_authentication_failed"
    assert _counts(vault) == (0, 0)


def test_atomic_ingestion_lease_recovers_without_orphan_or_duplicate_rows(
    tmp_path: Path,
) -> None:
    vault = _vault(tmp_path)
    arguments = {
        "connected_account_id": "gmail-account-1",
        "thread_id": "thread-1",
        "message_id": "reply-1",
        "owner_run_id": "run-owner-1",
        "app_slug": "close",
        "credentials": (("api_key", VALID_SECRET),),
    }

    first = vault.begin_gmail_message_ingestion(**arguments)
    assert first.status == "acquired"
    assert first.claim_token is not None
    assert _counts(vault) == (1, 1)

    concurrent = vault.begin_gmail_message_ingestion(**arguments)
    assert concurrent.status == "busy"
    assert concurrent.credential_refs == ()

    with sqlite3.connect(vault.db_path) as connection:
        connection.execute(
            """
            UPDATE gmail_message_ingestions
            SET lease_expires_at = '2000-01-01T00:00:00+00:00'
            """
        )

    recovered = vault.begin_gmail_message_ingestion(**arguments)
    assert recovered.status == "acquired"
    assert recovered.claim_token is not None
    assert recovered.credential_refs == first.credential_refs
    assert _counts(vault) == (1, 1)
    assert vault.complete_gmail_message_ingestion(
        connected_account_id="gmail-account-1",
        thread_id="thread-1",
        message_id="reply-1",
        owner_run_id="run-owner-1",
        claim_token=recovered.claim_token,
    )

    duplicate = vault.begin_gmail_message_ingestion(**{**arguments, "owner_run_id": "run-owner-2"})
    assert duplicate.status == "completed"
    assert _counts(vault) == (1, 1)


def test_latest_inbound_uses_exact_mailbox_not_sender_substring() -> None:
    messages = (
        SanitizedGmailMessage(
            message_id="forged",
            sender=f'"{CONTROLLED}" <attacker@example.test>',
            recipients=(),
            sent_at="2026-07-29T08:03:00Z",
            sanitized_subject="",
            sanitized_body="forged",
            sender_mailbox="attacker@example.test",
        ),
        SanitizedGmailMessage(
            message_id="spoofed-exact-from",
            sender=CONTROLLED,
            recipients=(),
            sent_at="2026-07-29T08:04:00Z",
            sanitized_subject="",
            sanitized_body="unauthenticated",
            sender_mailbox=CONTROLLED,
            sender_authenticated=False,
        ),
        SanitizedGmailMessage(
            message_id="valid-old",
            sender=f"Sink <{CONTROLLED}>",
            recipients=(),
            sent_at="2026-07-29T08:01:00Z",
            sanitized_subject="",
            sanitized_body="old",
            sender_mailbox=CONTROLLED,
            sender_authenticated=True,
        ),
        SanitizedGmailMessage(
            message_id="valid-new",
            sender=CONTROLLED,
            recipients=(),
            sent_at="2026-07-29T08:02:00Z",
            sanitized_subject="",
            sanitized_body="new",
            sender_mailbox=CONTROLLED,
            sender_authenticated=True,
        ),
    )
    selected, rounds = _latest_exact_inbound(
        SanitizedGmailThread(thread_id="thread-1", messages=messages),
        expected_sender=CONTROLLED,
    )

    assert selected is not None
    assert selected.message_id == "valid-new"
    assert rounds == 2


class _RunEmailGmail:
    def __init__(
        self,
        thread: SanitizedGmailThread,
        *,
        expected_sender: str = CONTROLLED,
    ) -> None:
        self.thread = thread
        self.expected_sender = expected_sender
        self.claimed_message_ids: list[str] = []
        self.completed_message_ids: list[str] = []
        self.released_message_ids: list[str] = []

    async def fetch_thread(self, thread_id: str) -> SanitizedGmailThread:
        assert thread_id == self.thread.thread_id
        return self.thread

    async def claim_outreach_reply(
        self,
        *,
        thread_id: str,
        message_id: str,
        expected_sender: str,
        owner_run_id: str,
        app_slug: str,
    ) -> GmailOutreachMessageClaim:
        assert thread_id == self.thread.thread_id
        assert expected_sender == self.expected_sender
        assert owner_run_id.startswith("run_")
        assert app_slug == "close"
        self.claimed_message_ids.append(message_id)
        return GmailOutreachMessageClaim(
            status="acquired",
            message_id=message_id,
            claim_token="claim_token_that_is_long_enough",
        )

    def complete_outreach_reply(
        self,
        *,
        thread_id: str,
        message_id: str,
        owner_run_id: str,
        claim_token: str,
    ) -> bool:
        del thread_id, owner_run_id, claim_token
        self.completed_message_ids.append(message_id)
        return True

    def release_outreach_reply(
        self,
        *,
        thread_id: str,
        message_id: str,
        owner_run_id: str,
        claim_token: str,
    ) -> bool:
        del thread_id, owner_run_id, claim_token
        self.released_message_ids.append(message_id)
        return True


@pytest.mark.parametrize(
    ("recipient_override", "expected_sender"),
    (
        (CONTROLLED, CONTROLLED),
        (None, "support@close.com"),
    ),
)
def test_poll_email_claims_and_classifies_only_exact_authenticated_sender(
    tmp_path: Path,
    recipient_override: str | None,
    expected_sender: str,
) -> None:
    service = RunService(
        storage=OperationsStorage(tmp_path / "ops.db"),
        settings=Settings(
            outreach_recipient_override=recipient_override,
            allow_live_vendor_email=recipient_override is None,
        ),
    )
    service.initialize()
    created = service.create_run(
        OperationsRequest(
            app_name="Close",
            company=CompanyProfile(
                legal_name="Example Labs",
                website="https://example.com",
                work_email_ref="vault://company/work_email/profile_1",
                use_case="Request reviewed production API access.",
            ),
        ),
        execution_mode="plan_only",
    )
    run_id = str(created["run_id"])
    service.storage.update_run(
        run_id,
        status="waiting_for_reply",
        gmail_thread_id="thread-1",
    )
    gmail = _RunEmailGmail(
        SanitizedGmailThread(
            thread_id="thread-1",
            messages=(
                SanitizedGmailMessage(
                    message_id="sent-1",
                    sender="ops@example.test",
                    recipients=(expected_sender,),
                    sent_at="2026-07-29T08:00:00Z",
                    sanitized_subject="Request",
                    sanitized_body="Please provide access.",
                    sender_mailbox="ops@example.test",
                ),
                SanitizedGmailMessage(
                    message_id="forged-newer",
                    sender=f'"{expected_sender}" <attacker@example.test>',
                    recipients=("ops@example.test",),
                    sent_at="2026-07-29T08:03:00Z",
                    sanitized_subject="Re: Request",
                    sanitized_body="Your request was rejected.",
                    sender_mailbox="attacker@example.test",
                ),
                SanitizedGmailMessage(
                    message_id="valid-reply",
                    sender=f"Counterpart <{expected_sender}>",
                    recipients=("ops@example.test",),
                    sent_at="2026-07-29T08:02:00Z",
                    sanitized_subject="Re: Request",
                    sanitized_body="Unfortunately we cannot provide API access.",
                    sender_mailbox=expected_sender,
                    sender_authenticated=True,
                ),
            ),
        ),
        expected_sender=expected_sender,
    )
    service._gmail_worker = gmail  # type: ignore[assignment]

    result = service.poll_email(run_id)

    assert result["status"] == "blocked"
    assert result["latest_reply_class"] == "rejected"
    assert gmail.claimed_message_ids == ["valid-reply"]
    assert gmail.completed_message_ids == ["valid-reply"]
    assert gmail.released_message_ids == []
    reply_events = [
        event for event in service.get_timeline(run_id) if event["event_type"] == "reply_received"
    ]
    assert len(reply_events) == 1
