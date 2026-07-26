"""Tests for attachment credential extraction: the pure parsing/detection core
and the GmailWorker harvest path (with the s3url download mocked)."""

from __future__ import annotations

import asyncio
import sys
import types

import pytest
from pydantic import SecretStr

import ops.gmail_worker as gmail_worker
from ops.attachment_extract import (
    AttachmentRef,
    extract_secret_pairs,
    is_text_like,
    parse_attachment_list,
)
from ops.config import Settings
from ops.gmail_worker import GmailWorker


# --- Pure core: attachment list projection ------------------------------------
def test_parse_attachment_list_camel_and_snake_case() -> None:
    message = {
        "attachmentList": [
            {
                "attachmentId": "att1",
                "filename": "keys.json",
                "mimeType": "application/json",
                "size": 40,
            },
            {
                "attachment_id": "att2",
                "file_name": "photo.png",
                "mime_type": "image/png",
                "size": 900,
            },
        ]
    }
    refs = parse_attachment_list(message)
    assert [r.attachment_id for r in refs] == ["att1", "att2"]
    assert refs[0].filename == "keys.json" and refs[0].mime_type == "application/json"


def test_parse_attachment_list_falls_back_to_payload_parts() -> None:
    message = {
        "payload": {
            "parts": [
                {
                    "filename": "creds.txt",
                    "mimeType": "text/plain",
                    "body": {"attachmentId": "p1", "size": 12},
                },
                {
                    "filename": "",
                    "mimeType": "text/html",
                    "body": {},
                },  # inline part, no attachment id
            ]
        }
    }
    refs = parse_attachment_list(message)
    assert len(refs) == 1 and refs[0].attachment_id == "p1" and refs[0].filename == "creds.txt"


# --- Pure core: text-like detection -------------------------------------------
@pytest.mark.parametrize(
    ("filename", "mime", "expected"),
    [
        ("keys.json", "application/json", True),
        ("creds.env", "", True),
        ("notes.txt", "text/plain", True),
        ("logo.png", "image/png", False),
        ("contract.pdf", "application/pdf", False),
        ("archive.zip", "application/zip", False),
    ],
)
def test_is_text_like(filename: str, mime: str, expected: bool) -> None:
    assert is_text_like(filename, mime) is expected


# --- Pure core: secret pair extraction ----------------------------------------
def test_extract_secret_pairs_from_env_style_text() -> None:
    text = "API_KEY=sk_live_abcdef123456\nnote: hello\nclient_secret: shhh_very_secret_value\n"  # pragma: allowlist secret
    pairs = dict(extract_secret_pairs(text))
    assert pairs["api_key"] == "sk_live_abcdef123456"  # pragma: allowlist secret
    assert pairs["client_secret"] == "shhh_very_secret_value"
    assert "hello" not in pairs.values()  # a non-credential line is ignored


def test_extract_secret_pairs_from_json_and_dedupes() -> None:
    text = '{"apiKey": "tok_ABCDEFGHIJK", "nested": {"access_token": "tok_ABCDEFGHIJK"}, "team": "ops"}'
    pairs = extract_secret_pairs(text)
    # Same value under two credential keys collapses to a single pair.
    assert len(pairs) == 1 and pairs[0][1] == "tok_ABCDEFGHIJK"


def test_extract_secret_pairs_ignores_non_credentials() -> None:
    assert extract_secret_pairs("name: Ada Lovelace\ncity: London\n") == ()


# --- Harvest path (GmailWorker) with mocked s3url download --------------------
class _Resp:
    def __init__(self, data: object) -> None:
        self.successful = True
        self.error = None
        self.data = data


class _Session:
    def execute(self, slug: str, arguments: dict | None = None, **kwargs: object) -> _Resp:
        del arguments, kwargs
        if slug == "GMAIL_GET_PROFILE":
            return _Resp({"email": "ops@example.test"})
        if slug == "GMAIL_GET_ATTACHMENT":
            return _Resp({"file": {"s3url": "https://s3.example/att", "name": "keys.txt"}})
        return _Resp({})


class _Sessions:
    def create(self, **kwargs: object) -> _Session:
        del kwargs
        _Session.session_id = "s1"  # type: ignore[attr-defined]
        session = _Session()
        session.session_id = "s1"  # type: ignore[attr-defined]
        session.id = "s1"  # type: ignore[attr-defined]
        return session


class _FakeComposio:
    def __init__(self) -> None:
        self.sessions = _Sessions()

    def close(self) -> None:  # pragma: no cover
        return None


class _FakeSecretStore:
    def __init__(self) -> None:
        self.puts: list[tuple[str, str, str]] = []

    def put(self, *, app_slug: str, kind: str, value: str) -> str:
        self.puts.append((app_slug, kind, value))
        return f"vault://{app_slug}/{kind}/{len(self.puts)}"


@pytest.fixture(autouse=True)
def _fake_composio_module(monkeypatch: pytest.MonkeyPatch) -> None:
    module = types.SimpleNamespace(SESSION_PRESET_DIRECT_TOOLS="direct_tools")
    monkeypatch.setitem(sys.modules, "composio", module)


def _settings() -> Settings:
    return Settings(
        composio_api_key=SecretStr("test-key"),  # pragma: allowlist secret
        composio_gmail_connected_account_id="gmail-acct-1",
        outreach_recipient_override="controlled@example.test",
        gmail_retry_base_delay_seconds=0.0,
    )


def test_harvest_attachment_credentials_vaults_only_text_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    downloads: list[str] = []

    def _fake_download(url: str, max_bytes: int) -> bytes:
        downloads.append(url)
        return b"API_KEY=sk_live_abcdef123456\nclient_secret: shhh_very_secret_value\n"  # pragma: allowlist secret

    monkeypatch.setattr(gmail_worker, "_download_bounded", _fake_download)

    store = _FakeSecretStore()
    worker = GmailWorker(settings=_settings(), secret_store=store, sdk_client=_FakeComposio())
    attachments = [
        AttachmentRef("att1", "keys.txt", "text/plain", 80),
        AttachmentRef("att2", "logo.png", "image/png", 4096),  # binary -> skipped
        AttachmentRef("att3", "big.txt", "text/plain", 10_000_000),  # oversize -> skipped
    ]
    refs = asyncio.run(
        worker.harvest_attachment_credentials(message_id="m1", attachments=attachments)
    )

    # Only the one text attachment under the cap was downloaded.
    assert downloads == ["https://s3.example/att"]
    # Two credentials vaulted; the returned map holds only vault:// references.
    assert len(refs) == 2
    assert all(ref.startswith("vault://email-attachment/") for ref in refs.values())
    vaulted_values = {value for _, _, value in store.puts}
    expected_api_key = "sk_live_abcdef123456"  # pragma: allowlist secret
    expected_client_secret = "shhh_very_secret_value"  # pragma: allowlist secret
    assert vaulted_values == {expected_api_key, expected_client_secret}


def test_harvest_requires_secret_store() -> None:
    from ops.provider_errors import ConfigurationRequiredError

    worker = GmailWorker(settings=_settings(), sdk_client=_FakeComposio())
    with pytest.raises(ConfigurationRequiredError):
        asyncio.run(
            worker.harvest_attachment_credentials(
                message_id="m1", attachments=[AttachmentRef("a", "k.txt", "text/plain", 10)]
            )
        )
