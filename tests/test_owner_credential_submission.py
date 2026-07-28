"""Compact offline checks for canonical owner-submitted credentials."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from ops.browser_worker import BrowserObservation, BrowserSessionContext
from ops.config import Settings
from ops.models import CompanyProfile, OperationsRequest
from ops.run_errors import CredentialSubmissionError
from ops.run_service import RunService
from ops.secret_store import SQLiteSecretStore

RAW_TOKEN = "canonical-owner-token-DO-NOT-PERSIST"  # pragma: allowlist secret


class _EntryOnlyPlaywright:
    provider_name = "playwright"

    async def start(self, profile_id: str | None, **_kwargs: object) -> BrowserSessionContext:
        return BrowserSessionContext(
            profile_id=profile_id or "telegram-owner",
            session_id="playwright-telegram-1",
            live_view_available=True,
            allowed_domains=("web.telegram.org",),
            created_at="2026-07-28T00:00:00Z",
            inactivity_expires_at="2026-07-28T00:15:00Z",
            maximum_expires_at="2026-07-28T04:00:00Z",
        )

    async def navigate_onboarding(
        self,
        context: BrowserSessionContext,
        research: object,
        **_kwargs: object,
    ) -> BrowserObservation:
        del context, research
        return BrowserObservation(
            status="developer_console_ready",
            current_url="https://web.telegram.org/",
            page_title="Telegram",
            reason_code="reviewed_public_entry_reached",
        )

    async def stop(self, context: BrowserSessionContext) -> None:
        del context


def _company() -> CompanyProfile:
    return CompanyProfile(
        legal_name="Example Labs, Inc.",
        website="https://example.com",
        work_email_ref="vault://company/work_email/profile_1",
        use_case="Connect the authorized Telegram integration.",
    )


def _service(tmp_path: Path) -> tuple[RunService, SQLiteSecretStore]:
    store = SQLiteSecretStore(tmp_path / "private" / "vault.db", Fernet.generate_key())
    service = RunService.from_paths(
        db_path=tmp_path / "private" / "ops.db",
        settings=Settings(),
    )
    browser = _EntryOnlyPlaywright()
    service._browser_workers = {"playwright": browser}  # type: ignore[assignment]
    service._browser_worker = browser  # type: ignore[assignment]
    service._secret_store = store
    return service, store


def _entry_reached(service: RunService) -> str:
    run = service.create_run(
        OperationsRequest(
            app_name="Telegram",
            company=_company(),
            browser_provider="playwright",
        ),
        execution_mode="execute_when_configured",
    )
    for thread in service._browser_threads:
        thread.join(timeout=5)
    stored = service.storage.get_run(str(run["run_id"]))
    assert stored is not None
    assert stored["status"] == "browser_running"
    assert stored["phase"] == "entry_reached"
    return str(run["run_id"])


def test_owner_submission_vaults_reference_without_claiming_validation(tmp_path: Path) -> None:
    service, store = _service(tmp_path)
    run_id = _entry_reached(service)

    result = service.submit_owner_credentials(
        run_id,
        company=_company(),
        fields={"bot_token": SecretStr(RAW_TOKEN)},
    )

    assert result["status"] == "credentials_ready"
    assert result["phase"] == "credential_ready"
    assert result["reason_code"] == "owner_credentials_vaulted_unvalidated"
    bundle = service.get_output(run_id)
    assert bundle is not None
    reference = str(bundle["credential_refs"]["bot_token"])
    assert reference.startswith("vault://telegram/bot_token/")
    assert store.get(reference) == RAW_TOKEN


def test_owner_submission_never_persists_raw_value(tmp_path: Path) -> None:
    service, _store = _service(tmp_path)
    run_id = _entry_reached(service)
    service.submit_owner_credentials(
        run_id,
        company=_company(),
        fields={"bot_token": SecretStr(RAW_TOKEN)},
    )

    haystack = repr(service.storage.get_run(run_id)) + repr(service.get_timeline(run_id))
    assert RAW_TOKEN not in haystack
    assert RAW_TOKEN.encode() not in (tmp_path / "private" / "ops.db").read_bytes()


def test_owner_submission_requires_exact_recipe_fields(tmp_path: Path) -> None:
    service, _store = _service(tmp_path)
    run_id = _entry_reached(service)

    with pytest.raises(CredentialSubmissionError) as raised:
        service.submit_owner_credentials(
            run_id,
            company=_company(),
            fields={"api_key": SecretStr(RAW_TOKEN)},
        )
    assert raised.value.reason_code == "credential_fields_do_not_match_recipe"


def test_owner_submission_after_restart_uses_creation_time_field_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ops.app_recipes as recipe_module

    service, store = _service(tmp_path)
    run_id = _entry_reached(service)
    original = recipe_module.get_app_recipe("telegram")
    assert original is not None
    payload = original.model_dump(mode="python")
    payload["credential_fields"] = (
        {
            "name": "api_key",
            "label": "Changed API key",
            "kind": "api_key",
            "secret": True,
        },
    )
    changed = type(original).model_validate(payload)
    monkeypatch.setattr(recipe_module, "get_app_recipe", lambda _slug: changed)

    restarted = RunService.from_paths(
        db_path=tmp_path / "private" / "ops.db",
        settings=Settings(),
    )
    restarted._secret_store = store
    result = restarted.submit_owner_credentials(
        run_id,
        company=_company(),
        fields={"bot_token": SecretStr(RAW_TOKEN)},
    )

    assert result["status"] == "credentials_ready"
    bundle = restarted.get_output(run_id)
    assert bundle is not None
    assert set(bundle["credential_refs"]) == {"bot_token"}


def test_owner_submission_cannot_be_replayed(tmp_path: Path) -> None:
    service, _store = _service(tmp_path)
    run_id = _entry_reached(service)
    fields = {"bot_token": SecretStr(RAW_TOKEN)}
    service.submit_owner_credentials(run_id, company=_company(), fields=fields)

    with pytest.raises(CredentialSubmissionError) as raised:
        service.submit_owner_credentials(run_id, company=_company(), fields=fields)
    assert raised.value.reason_code == "run_not_awaiting_credentials"
