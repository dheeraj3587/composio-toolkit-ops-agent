"""Offline contract tests for the provider-neutral gated outreach boundary."""

from __future__ import annotations

import asyncio
import sys
import types
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import cast

import pytest
from pydantic import SecretStr

from ops.app_recipes import AppRecipe, get_app_recipe
from ops.config import Settings
from ops.effect_ledger import SQLiteEffectStore
from ops.gated_route import GatedRoute, GatedRoutePolicyError
from ops.gmail_models import GmailSendResult
from ops.gmail_worker import GmailWorker
from ops.models import CompanyProfile, OperationsRequest
from ops.provider_errors import ConfigurationRequiredError, ProviderOperationError

VENDOR = "reviewed-contact@vendor.example"
CONTROLLED_SINK = "controlled-sink@example.test"
REQUEST_OVERRIDE = "untrusted-request-override@example.test"


@dataclass(frozen=True, slots=True)
class _SendCall:
    recipient: str
    subject: str
    body: str
    effect_identity: str


class _RecordingGmail:
    def __init__(
        self,
        *,
        actual_recipient: str = CONTROLLED_SINK,
        session_id: str = "session-safe",
    ) -> None:
        self.calls: list[_SendCall] = []
        self._actual_recipient = actual_recipient
        self._session_id = session_id

    async def send_outreach(
        self,
        recipient: str,
        subject: str,
        body: str,
        idempotency_key: str,
    ) -> GmailSendResult:
        self.calls.append(_SendCall(recipient, subject, body, idempotency_key))
        return GmailSendResult(
            session_id=self._session_id,
            thread_id="thread-safe",
            message_id="message-safe",
            intended_recipient=recipient,
            actual_recipient=self._actual_recipient,
        )


def _company() -> CompanyProfile:
    return CompanyProfile(
        legal_name="Example Labs, Inc.",
        website="https://example.com",
        work_email_ref="vault://company/work_email/profile_1",
        use_case=(
            "Automate authorized customer support; api_key=sk-test-abcdefghijklmnopqrstuv"  # pragma: allowlist secret
        ),
    )


def _request(app_name: str = "Close") -> OperationsRequest:
    return OperationsRequest(
        app_name=app_name,
        company=_company(),
        outreach_recipient_override=REQUEST_OVERRIDE,
    )


def _recipe(*, contact_email: str | None = VENDOR, contact_url: str | None = None) -> AppRecipe:
    base = get_app_recipe("close")
    assert base is not None and base.outreach is not None
    payload = base.model_dump(mode="python")
    outreach = dict(payload["outreach"])
    outreach.update({"contact_email": contact_email, "contact_url": contact_url})
    payload.update({"readiness_tier": "outreach_ready", "outreach": outreach})
    return AppRecipe.model_validate(payload)


def _route(gmail: _RecordingGmail, recipe: AppRecipe | None = None) -> GatedRoute:
    return GatedRoute(
        recipe=recipe or _recipe(),
        request=_request(),
        gmail=cast(GmailWorker, gmail),
    )


def test_preparation_has_no_side_effect_and_exposes_only_reviewed_metadata() -> None:
    gmail = _RecordingGmail()

    route = _route(gmail)

    assert gmail.calls == []
    assert asdict(route.target) == {
        "app_slug": "close",
        "intended_recipient": VENDOR,
        "template_id": "gated-access-v1",
        "sending_policy": "controlled_sink_only",
    }
    assert not hasattr(route, "subject")
    assert not hasattr(route, "body")


def test_explicit_send_is_deterministic_and_uses_the_callers_effect_identity() -> None:
    first_gmail = _RecordingGmail()
    second_gmail = _RecordingGmail()
    effect_identity = "run-123:gated-outreach:v1"

    first = asyncio.run(_route(first_gmail).send_outreach(effect_identity=effect_identity))
    second = asyncio.run(_route(second_gmail).send_outreach(effect_identity="run-456:outreach"))

    assert first_gmail.calls[0].subject == second_gmail.calls[0].subject
    assert first_gmail.calls[0].body == second_gmail.calls[0].body
    assert first_gmail.calls[0].effect_identity == effect_identity
    assert first_gmail.calls[0].recipient == VENDOR
    assert REQUEST_OVERRIDE not in first_gmail.calls[0].body
    assert "vault://" not in first_gmail.calls[0].body
    assert (
        "sk-test-abcdefghijklmnopqrstuv"  # pragma: allowlist secret
        not in first_gmail.calls[0].body
    )
    assert "[REDACTED]" in first_gmail.calls[0].body
    assert asdict(first) == {
        "session_id": "session-safe",
        "thread_id": "thread-safe",
        "message_id": "message-safe",
        "intended_recipient": VENDOR,
        "actual_recipient": CONTROLLED_SINK,
    }
    assert asdict(second).keys() == asdict(first).keys()


def test_route_requires_gated_recipe_and_matching_request() -> None:
    gmail = _RecordingGmail()
    managed = get_app_recipe("salesforce")
    assert managed is not None

    with pytest.raises(GatedRoutePolicyError) as wrong_route:
        GatedRoute(
            recipe=managed,
            request=_request("Salesforce"),
            gmail=cast(GmailWorker, gmail),
        )
    with pytest.raises(GatedRoutePolicyError) as mismatch:
        GatedRoute(
            recipe=_recipe(),
            request=_request("Freshdesk"),
            gmail=cast(GmailWorker, gmail),
        )

    assert wrong_route.value.reason_code == "route_kind_not_gated"
    assert mismatch.value.reason_code == "request_recipe_mismatch"
    assert gmail.calls == []


def test_review_required_and_url_only_contacts_cannot_send_email() -> None:
    gmail = _RecordingGmail()
    unreviewed = get_app_recipe("plain")
    assert unreviewed is not None

    with pytest.raises(GatedRoutePolicyError) as review_required:
        GatedRoute(
            recipe=unreviewed,
            request=_request("Plain"),
            gmail=cast(GmailWorker, gmail),
        )
    with pytest.raises(GatedRoutePolicyError) as email_missing:
        _route(gmail, _recipe(contact_email=None, contact_url="https://vendor.example/contact"))

    assert review_required.value.reason_code == "outreach_contact_not_verified"
    assert email_missing.value.reason_code == "verified_contact_email_missing"
    assert gmail.calls == []


def test_non_controlled_policy_and_invalid_effect_identity_fail_before_send() -> None:
    gmail = _RecordingGmail()
    recipe = _recipe()
    assert recipe.outreach is not None
    unsafe_outreach = recipe.outreach.model_copy(update={"sending_policy": "live_vendor"})
    unsafe_recipe = recipe.model_copy(update={"outreach": unsafe_outreach})
    unsafe_template = recipe.outreach.model_copy(update={"template_id": "bad\ntemplate"})
    unsafe_template_recipe = recipe.model_copy(update={"outreach": unsafe_template})

    with pytest.raises(GatedRoutePolicyError) as unsafe_policy:
        _route(gmail, unsafe_recipe)
    with pytest.raises(GatedRoutePolicyError) as invalid_template:
        _route(gmail, unsafe_template_recipe)

    route = _route(gmail)
    with pytest.raises(GatedRoutePolicyError) as invalid_effect:
        asyncio.run(route.send_outreach(effect_identity="bad\neffect"))

    assert unsafe_policy.value.reason_code == "sending_policy_not_controlled_sink_only"
    assert invalid_template.value.reason_code == "outreach_template_id_invalid"
    assert invalid_effect.value.reason_code == "effect_identity_invalid"
    assert gmail.calls == []


def test_worker_receipt_is_validated_before_crossing_the_boundary() -> None:
    gmail = _RecordingGmail(session_id="unsafe\nsession")

    with pytest.raises(GatedRoutePolicyError) as raised:
        asyncio.run(_route(gmail).send_outreach(effect_identity="run-789:outreach"))

    assert raised.value.reason_code == "gmail_session_id_invalid"


class _Response:
    def __init__(self, data: dict[str, object]) -> None:
        self.error = None
        self.data = data


class _Session:
    session_id = "session-controlled"
    id = session_id

    def __init__(self, sends: list[dict[str, object]]) -> None:
        self._sends = sends

    def execute(self, slug: str, arguments: dict[str, object]) -> _Response:
        if slug == "GMAIL_GET_PROFILE":
            return _Response({"email": "operator@example.test"})
        if slug == "GMAIL_SEND_EMAIL":
            self._sends.append(dict(arguments))
            return _Response({"message_id": "message-controlled", "thread_id": "thread-controlled"})
        if slug == "GMAIL_REPLY_TO_THREAD":
            self._sends.append(dict(arguments))
            return _Response({"message_id": "reply-controlled", "thread_id": "thread-controlled"})
        raise AssertionError(f"unexpected Gmail tool: {slug}")


class _Sessions:
    def __init__(self, sends: list[dict[str, object]]) -> None:
        self._sends = sends

    def create(self, **kwargs: object) -> _Session:
        del kwargs
        return _Session(self._sends)


class _FakeComposio:
    def __init__(self, sends: list[dict[str, object]]) -> None:
        self.sessions = _Sessions(sends)


def _real_worker(
    tmp_path: Path,
    sends: list[dict[str, object]],
    *,
    override: str | None,
    allow_live: bool,
) -> GmailWorker:
    settings = Settings(
        composio_gmail_api_key=SecretStr("offline-test-key"),  # pragma: allowlist secret
        composio_gmail_connected_account_id="gmail-account-test",
        outreach_recipient_override=override,
        allow_live_vendor_email=allow_live,
    )
    return GmailWorker(
        settings=settings,
        effect_store=SQLiteEffectStore(tmp_path / "effects.db"),
        sdk_client=_FakeComposio(sends),
    )


def test_gmail_worker_remains_the_recipient_override_and_live_email_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        sys.modules,
        "composio",
        types.SimpleNamespace(SESSION_PRESET_DIRECT_TOOLS="direct_tools"),
    )
    controlled_sends: list[dict[str, object]] = []
    controlled = _real_worker(
        tmp_path / "controlled",
        controlled_sends,
        override=CONTROLLED_SINK,
        allow_live=True,
    )

    receipt = asyncio.run(
        GatedRoute(recipe=_recipe(), request=_request(), gmail=controlled).send_outreach(
            effect_identity="run-controlled:outreach"
        )
    )

    assert controlled_sends[0]["recipient_email"] == CONTROLLED_SINK
    assert receipt.intended_recipient == VENDOR
    assert receipt.actual_recipient == CONTROLLED_SINK

    blocked_sends: list[dict[str, object]] = []
    blocked = _real_worker(
        tmp_path / "blocked",
        blocked_sends,
        override=None,
        allow_live=False,
    )
    with pytest.raises(ConfigurationRequiredError) as raised:
        asyncio.run(
            GatedRoute(recipe=_recipe(), request=_request(), gmail=blocked).send_outreach(
                effect_identity="run-blocked:outreach"
            )
        )

    assert raised.value.reason_code == "controlled_recipient_required"
    assert blocked_sends == []


def test_completed_outreach_replay_is_restart_safe_and_payload_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        sys.modules,
        "composio",
        types.SimpleNamespace(SESSION_PRESET_DIRECT_TOOLS="direct_tools"),
    )
    first_sends: list[dict[str, object]] = []
    first_worker = _real_worker(
        tmp_path,
        first_sends,
        override=CONTROLLED_SINK,
        allow_live=False,
    )
    first = asyncio.run(
        first_worker.send_outreach(
            VENDOR,
            "Reviewed subject",
            "Reviewed body",
            "run-payload-bound:gated-outreach:v1",
        )
    )
    assert len(first_sends) == 1

    # A fresh worker can reconstruct the completed receipt without reconnecting
    # to Gmail, while the same logical key with a changed body fails closed.
    replay_sends: list[dict[str, object]] = []
    replay_worker = _real_worker(
        tmp_path,
        replay_sends,
        override=CONTROLLED_SINK,
        allow_live=False,
    )
    replay = asyncio.run(
        replay_worker.send_outreach(
            VENDOR,
            "Reviewed subject",
            "Reviewed body",
            "run-payload-bound:gated-outreach:v1",
        )
    )
    assert replay == first
    assert replay_sends == []

    with pytest.raises(ProviderOperationError) as mismatch:
        asyncio.run(
            replay_worker.send_outreach(
                VENDOR,
                "Reviewed subject",
                "Changed body",
                "run-payload-bound:gated-outreach:v1",
            )
        )
    assert mismatch.value.reason_code == "idempotency_payload_mismatch"
    assert replay_sends == []


def test_completed_reply_replay_is_restart_safe_and_payload_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        sys.modules,
        "composio",
        types.SimpleNamespace(SESSION_PRESET_DIRECT_TOOLS="direct_tools"),
    )
    first_calls: list[dict[str, object]] = []
    first_worker = _real_worker(
        tmp_path,
        first_calls,
        override=CONTROLLED_SINK,
        allow_live=False,
    )
    first = asyncio.run(
        first_worker.reply(
            "thread-controlled",
            "Reviewed follow-up",
            "run-payload-bound:follow-up:v1",
        )
    )
    assert len(first_calls) == 1

    replay_calls: list[dict[str, object]] = []
    replay_worker = _real_worker(
        tmp_path,
        replay_calls,
        override=CONTROLLED_SINK,
        allow_live=False,
    )
    replay = asyncio.run(
        replay_worker.reply(
            "thread-controlled",
            "Reviewed follow-up",
            "run-payload-bound:follow-up:v1",
        )
    )
    assert replay == first
    assert replay_calls == []

    with pytest.raises(ProviderOperationError) as mismatch:
        asyncio.run(
            replay_worker.reply(
                "thread-controlled",
                "Changed follow-up",
                "run-payload-bound:follow-up:v1",
            )
        )
    assert mismatch.value.reason_code == "idempotency_payload_mismatch"
    assert replay_calls == []
