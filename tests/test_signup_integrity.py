"""Release-blocking signup credential and Gmail preflight invariants."""

from __future__ import annotations

import asyncio
import sqlite3
import sys
import time
import types
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from pydantic import SecretStr

from api.app import create_app
from api.service import LocalRunService
from ops.browser.worker import BrowserObservation
from ops.core.config import Settings
from ops.core.models import CompanyProfile, OperationsRequest
from ops.core.secret_store import SignupCredentialStateError, SQLiteSecretStore
from ops.gmail.worker import GmailSignupPreflight, GmailWorker
from ops.recipes.app_recipes import get_app_recipe, recipe_to_operational_research
from ops.runs.projections import _public_run
from ops.runs.service import RunService as CoreRunService
from ops.workflow.canonical_runtime import CanonicalRuntime

_APP = "pipedrive"
_ACCOUNT = "acct_0123456789abcdef0123456789abcdef"
_RUN_A = "run_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
_RUN_B = "run_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


class _Response:
    error = None

    def __init__(self, data: object) -> None:
        self.data = data


class _Session:
    session_id = "gmail-preflight-session"

    def __init__(
        self,
        *,
        fetch_delay_seconds: float = 0.0,
        profile: object | None = None,
    ) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.fetch_delay_seconds = fetch_delay_seconds
        self.profile = {"emailAddress": "signup@example.test"} if profile is None else profile

    def execute(self, slug: str, arguments: dict[str, object]) -> _Response:
        self.calls.append((slug, dict(arguments)))
        if slug == "GMAIL_GET_PROFILE":
            return _Response(self.profile)
        if slug == "GMAIL_FETCH_EMAILS":
            if self.fetch_delay_seconds:
                time.sleep(self.fetch_delay_seconds)
            return _Response({"messages": []})
        raise AssertionError("unexpected Gmail tool")


class _Sessions:
    def __init__(self, session: _Session) -> None:
        self._session = session

    def create(self, **_: object) -> _Session:
        return self._session


class _Client:
    def __init__(self, session: _Session) -> None:
        self.sessions = _Sessions(session)


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "composio_gmail_api_key": SecretStr("test-key"),  # pragma: allowlist secret
        "composio_gmail_connected_account_id": "gmail-account-one",
        "gmail_signup_address": SecretStr("signup@example.test"),
        "gmail_retry_max_attempts": 1,
        "gmail_retry_base_delay_seconds": 0.0,
    }
    values.update(overrides)
    return Settings(**values)


def _store(tmp_path: Path) -> SQLiteSecretStore:
    return SQLiteSecretStore(
        tmp_path / "vault.db",
        Fernet.generate_key().decode("ascii"),
    )


@pytest.fixture(autouse=True)
def _composio_module(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(
        sys.modules,
        "composio",
        types.SimpleNamespace(SESSION_PRESET_DIRECT_TOOLS="direct_tools"),
    )


def test_signup_preflight_executes_real_fetch_with_no_match_query() -> None:
    session = _Session()
    worker = GmailWorker(settings=_settings(), sdk_client=_Client(session))

    result = asyncio.run(worker.preflight_signup_inbox(timeout_seconds=2.0))

    assert result.ready is True
    assert result.status == "ready"
    assert result.reason_code == "gmail_signup_inbox_ready"
    fetches = [arguments for slug, arguments in session.calls if slug == "GMAIL_FETCH_EMAILS"]
    assert len(fetches) == 1
    assert fetches[0]["max_results"] == 1
    query = str(fetches[0]["query"])
    assert query.startswith("in:anywhere rfc822msgid:<ops-signup-preflight-")
    assert query.endswith("@invalid.invalid>")
    assert not hasattr(result, "messages")


def test_signup_preflight_binds_configured_address_to_connected_profile() -> None:
    session = _Session(profile={"emailAddress": "other@example.test"})
    worker = GmailWorker(settings=_settings(), sdk_client=_Client(session))

    result = asyncio.run(worker.preflight_signup_inbox(timeout_seconds=2.0))

    assert result.ready is False
    assert result.status == "configuration_required"
    assert result.reason_code == "gmail_signup_mailbox_mismatch"
    assert result.provider_read_attempted is True
    assert [slug for slug, _arguments in session.calls] == ["GMAIL_GET_PROFILE"]
    assert "signup@example.test" not in repr(result)
    assert "other@example.test" not in repr(result)


def test_signup_preflight_rejects_profile_without_one_mailbox() -> None:
    session = _Session(profile={"messagesTotal": 42})
    worker = GmailWorker(settings=_settings(), sdk_client=_Client(session))

    result = asyncio.run(worker.preflight_signup_inbox(timeout_seconds=2.0))

    assert result.status == "unavailable"
    assert result.reason_code == "gmail_signup_profile_incompatible"
    assert result.provider_read_attempted is True
    assert [slug for slug, _arguments in session.calls] == ["GMAIL_GET_PROFILE"]


def test_signup_preflight_is_machine_safe_when_unconfigured() -> None:
    worker = GmailWorker(settings=Settings())
    result = asyncio.run(worker.preflight_signup_inbox(timeout_seconds=2.0))
    assert result.status == "configuration_required"
    assert result.provider_read_attempted is False
    assert result.reason_code == "composio_gmail_api_key_missing"


def test_signup_preflight_returns_at_its_caller_visible_deadline() -> None:
    session = _Session(fetch_delay_seconds=5.0)
    worker = GmailWorker(settings=_settings(), sdk_client=_Client(session))
    started = time.monotonic()
    result = asyncio.run(worker.preflight_signup_inbox(timeout_seconds=1.0))
    elapsed = time.monotonic() - started
    assert result.status == "timeout"
    assert result.reason_code == "gmail_signup_preflight_timeout"
    assert elapsed < 1.5


def test_api_signup_readiness_is_cached_and_health_stays_observational(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(gmail_signup_address=SecretStr("signup@example.test"))
    core = CoreRunService.from_paths(db_path=tmp_path / "ops.db", settings=settings)
    calls = 0

    def preflight(*, timeout_seconds: float) -> GmailSignupPreflight:
        nonlocal calls
        calls += 1
        assert timeout_seconds == settings.gmail_signup_preflight_timeout_seconds
        return GmailSignupPreflight(
            status="ready",
            reason_code="gmail_signup_inbox_ready",
            provider_read_attempted=True,
        )

    monkeypatch.setattr(core, "gmail_signup_preflight", preflight)
    service = LocalRunService(
        tmp_path / "ops.db",
        core_service=core,
        settings=settings,
    )
    with TestClient(create_app(service=service)) as client:
        health = client.get("/api/system/health")
        assert calls == 0
        first = client.get("/api/system/signup-readiness")
        second = client.get("/api/system/signup-readiness")

    assert health.status_code == 200
    assert first.status_code == 200
    assert second.status_code == 200
    gmail = first.json()
    assert gmail["status"] == "ready"
    assert gmail["reason_code"] == "gmail_signup_inbox_ready"
    assert gmail["checked_at"]
    assert gmail["expires_at"]
    assert calls == 1


def _signup_payload() -> dict[str, object]:
    return {
        "app_name": "Pipedrive",
        "account_mode": "create_account",
        "company": {
            "legal_name": "Example Company",
            "website": "https://example.test",
            "work_email_ref": "vault://company/work_email/test-operator",
            "use_case": "Evaluate documented integration access.",
            "callback_urls": ["https://example.test/oauth/callback"],
        },
        "requested_scope_policy": "maximum",
        "execution_mode": "execute_when_configured",
        "browser_provider": "playwright",
    }


def test_executable_signup_has_one_authoritative_preflight_and_replay_has_none(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(
        allow_live_browser=True,
        browser_provider="playwright",
        playwright_in_process_sandbox=True,
        gmail_signup_address=SecretStr("signup@example.test"),
        secret_vault_key=SecretStr(Fernet.generate_key().decode("ascii")),
    )
    core = CoreRunService.from_paths(db_path=tmp_path / "ops.db", settings=settings)
    calls = 0

    def preflight(*, timeout_seconds: float) -> GmailSignupPreflight:
        nonlocal calls
        calls += 1
        assert timeout_seconds == settings.gmail_signup_preflight_timeout_seconds
        return GmailSignupPreflight(
            status="ready" if calls == 1 else "unavailable",
            reason_code=(
                "gmail_signup_inbox_ready" if calls == 1 else "gmail_signup_preflight_failed"
            ),
            provider_read_attempted=True,
        )

    def avoid_browser_start(
        runtime: CanonicalRuntime,
        run_id: str,
        **_: object,
    ) -> dict[str, object]:
        record = runtime._context.storage.get_run(run_id)
        assert record is not None
        return _public_run(record)

    monkeypatch.setattr(core, "gmail_signup_preflight", preflight)
    monkeypatch.setattr(CanonicalRuntime, "_start_playwright", avoid_browser_start)
    service = LocalRunService(
        tmp_path / "ops.db",
        core_service=core,
        settings=settings,
    )
    idempotency_key = "idem_" + "a" * 32
    with TestClient(create_app(service=service)) as client:
        first = client.post(
            "/api/runs",
            json=_signup_payload(),
            headers={"Idempotency-Key": idempotency_key},
        )
        replayed = client.post(
            "/api/runs",
            json=_signup_payload(),
            headers={"Idempotency-Key": idempotency_key},
        )

    assert first.status_code == 201
    assert replayed.status_code == 201
    assert replayed.json() == first.json()
    assert calls == 1
    assert core.storage.count_runs() == 1


def test_failed_authoritative_signup_preflight_writes_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(
        allow_live_browser=True,
        browser_provider="playwright",
        playwright_in_process_sandbox=True,
        gmail_signup_address=SecretStr("signup@example.test"),
    )
    core = CoreRunService.from_paths(db_path=tmp_path / "ops.db", settings=settings)
    calls = 0

    def preflight(*, timeout_seconds: float) -> GmailSignupPreflight:
        nonlocal calls
        calls += 1
        assert timeout_seconds == settings.gmail_signup_preflight_timeout_seconds
        return GmailSignupPreflight(
            status="unavailable",
            reason_code="gmail_signup_preflight_failed",
            provider_read_attempted=True,
        )

    monkeypatch.setattr(core, "gmail_signup_preflight", preflight)
    service = LocalRunService(
        tmp_path / "ops.db",
        core_service=core,
        settings=settings,
    )
    with TestClient(create_app(service=service)) as client:
        response = client.post("/api/runs", json=_signup_payload())

    assert response.status_code == 409
    assert response.json()["reason_code"] == "gmail_signup_preflight_failed"
    assert calls == 1
    assert core.storage.count_runs() == 0


def test_signup_pair_is_staged_without_overwriting_reusable_login(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.put_account_login_pair(
        app_slug=_APP,
        account_ref=_ACCOUNT,
        email="known@example.test",
        password="known-password",  # pragma: allowlist secret
    )

    staged = store.stage_signup_login_pair(
        app_slug=_APP,
        account_ref=_ACCOUNT,
        run_id=_RUN_A,
        email="signup@example.test",
        password="generated-password",  # pragma: allowlist secret
    )

    assert staged == {
        "login_email": "signup@example.test",
        "login_password": "generated-password",  # pragma: allowlist secret
    }
    assert store.get_account_login_pair(app_slug=_APP, account_ref=_ACCOUNT) == {
        "login_email": "known@example.test",
        "login_password": "known-password",  # pragma: allowlist secret
    }


def test_account_pair_write_rolls_back_both_fields_on_failure(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.put_account_login_pair(
        app_slug=_APP,
        account_ref=_ACCOUNT,
        email="known@example.test",
        password="known-password",  # pragma: allowlist secret
    )
    with store._connect() as connection:
        connection.execute(
            """
            CREATE TRIGGER fail_password_insert
            BEFORE INSERT ON vault_entries
            WHEN NEW.kind = 'account_login_login_password'
            BEGIN
                SELECT RAISE(ABORT, 'synthetic pair failure');
            END
            """
        )

    with pytest.raises(sqlite3.IntegrityError):
        store.put_account_login_pair(
            app_slug=_APP,
            account_ref=_ACCOUNT,
            email="new@example.test",
            password="new-password",  # pragma: allowlist secret
        )
    assert store.get_account_login_pair(app_slug=_APP, account_ref=_ACCOUNT) == {
        "login_email": "known@example.test",
        "login_password": "known-password",  # pragma: allowlist secret
    }


def test_staging_is_idempotent_for_run_and_serialized_across_runs(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first = store.stage_signup_login_pair(
        app_slug=_APP,
        account_ref=_ACCOUNT,
        run_id=_RUN_A,
        email="signup@example.test",
        password="first-generated-password",  # pragma: allowlist secret
    )
    replay = store.stage_signup_login_pair(
        app_slug=_APP,
        account_ref=_ACCOUNT,
        run_id=_RUN_A,
        email="different@example.test",
        password="different-password",  # pragma: allowlist secret
    )
    assert replay == first

    with pytest.raises(SignupCredentialStateError) as raised:
        store.stage_signup_login_pair(
            app_slug=_APP,
            account_ref=_ACCOUNT,
            run_id=_RUN_B,
            email="signup@example.test",
            password="second-generated-password",  # pragma: allowlist secret
        )
    assert raised.value.reason_code == "signup_identity_in_progress"


def test_promotion_is_atomic_idempotent_and_blocks_duplicate_signup(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.stage_signup_login_pair(
        app_slug=_APP,
        account_ref=_ACCOUNT,
        run_id=_RUN_A,
        email="signup@example.test",
        password="generated-password",  # pragma: allowlist secret
    )

    assert store.get_account_login_pair(app_slug=_APP, account_ref=_ACCOUNT) == {}
    assert store.promote_staged_signup_login_pair(
        app_slug=_APP,
        account_ref=_ACCOUNT,
        run_id=_RUN_A,
    ) == ("login_email", "login_password")
    assert store.promote_staged_signup_login_pair(
        app_slug=_APP,
        account_ref=_ACCOUNT,
        run_id=_RUN_A,
    ) == ("login_email", "login_password")
    assert store.get_account_login_pair(app_slug=_APP, account_ref=_ACCOUNT) == {
        "login_email": "signup@example.test",
        "login_password": "generated-password",  # pragma: allowlist secret
    }

    with pytest.raises(SignupCredentialStateError) as raised:
        store.stage_signup_login_pair(
            app_slug=_APP,
            account_ref=_ACCOUNT,
            run_id=_RUN_B,
            email="signup@example.test",
            password="new-password",  # pragma: allowlist secret
        )
    assert raised.value.reason_code == "signup_identity_already_registered"


def test_email_challenge_outcome_carries_a_persistable_request_timestamp() -> None:
    runtime = CanonicalRuntime(object())  # type: ignore[arg-type]
    recipe = get_app_recipe(_APP)
    assert recipe is not None
    request = OperationsRequest(
        app_name="Pipedrive",
        company=CompanyProfile(
            legal_name="Example",
            website="https://example.test",
            work_email_ref="vault://company/work_email/operator",
            use_case="Connect the reviewed integration.",
        ),
        account_mode="create_account",
        browser_provider="playwright",
        dry_run=False,
    )
    outcome = runtime._resolve_browser_outcome(
        run_id=_RUN_A,
        observation=BrowserObservation(
            status="human_action_required",
            current_url="https://app.pipedrive.com/auth/signup",
            page_title="Verify email",
            human_action_type="email_otp",
            human_instruction="Enter the emailed code.",
            reason_code="email_otp_required",
        ),
        research=recipe_to_operational_research(recipe),
        request=request,
        recipe=recipe,
        context=object(),  # type: ignore[arg-type]
    )
    assert outcome.hitl is not None
    requested_at = outcome.hitl.get("verification_requested_at")
    assert isinstance(requested_at, str)
    assert requested_at.endswith("Z")
