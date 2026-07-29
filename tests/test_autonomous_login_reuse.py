"""Autonomous sign-in: remembered credentials and machine-resolved HITL gates.

Every other login path in this system is one-time and run-scoped, which is why a
second run could never authenticate itself and always stopped at a human gate.
These tests pin the two behaviours that make a run autonomous:

* the owner's app credentials survive one run in the encrypted vault, addressable
  only by (app, field), and never leak into a response, event, or log; and
* a waiting run whose gate the agent CAN resolve is resumed automatically, while a
  gate that genuinely needs a person (CAPTCHA, passkey, billing) never is.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from ops.config import Settings
from ops.run_service import RunService
from ops.secret_store import (
    ACCOUNT_LOGIN_KIND_PREFIX,
    REUSABLE_LOGIN_FIELDS,
    AccountLoginStateError,
    SQLiteSecretStore,
)

_EMAIL = "owner@example.test"
_PASSWORD = "correct-horse-battery"  # pragma: allowlist secret
_ACCOUNT = "acct_0123456789abcdef0123456789abcdef"
_OTHER_ACCOUNT = "acct_fedcba9876543210fedcba9876543210"
_RUN = "run_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def _store(tmp_path: Path) -> SQLiteSecretStore:
    return SQLiteSecretStore(tmp_path / "vault.db", Fernet.generate_key().decode("ascii"))


def _service(tmp_path: Path, **overrides: Any) -> RunService:
    settings = Settings(**overrides)
    return RunService.from_paths(db_path=tmp_path / "ops.db", settings=settings)


# --- durable vault surface ----------------------------------------------------
def test_account_login_round_trips_and_is_namespaced(tmp_path: Path) -> None:
    store = _store(tmp_path)

    reference = store.put_account_login(
        app_slug="pipedrive",
        account_ref=_ACCOUNT,
        field="login_email",
        value=_EMAIL,
    )

    # A reusable sign-in secret must never share the namespace of a captured
    # integration credential, or one could be read through the other's path.
    assert reference.startswith(f"vault://pipedrive/{ACCOUNT_LOGIN_KIND_PREFIX}login_email/")
    assert (
        store.get_account_login(app_slug="pipedrive", account_ref=_ACCOUNT, field="login_email")
        == _EMAIL
    )


def test_account_login_replaces_rather_than_accumulates(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.put_account_login(
        app_slug="pipedrive",
        account_ref=_ACCOUNT,
        field="login_password",
        value="old-password",
    )
    store.put_account_login(
        app_slug="pipedrive",
        account_ref=_ACCOUNT,
        field="login_password",
        value=_PASSWORD,
    )

    # A rotated password must not be shadowed by a stale row.
    assert (
        store.get_account_login(app_slug="pipedrive", account_ref=_ACCOUNT, field="login_password")
        == _PASSWORD
    )


def test_missing_account_login_is_none_not_an_error(tmp_path: Path) -> None:
    store = _store(tmp_path)

    assert (
        store.get_account_login(app_slug="pipedrive", account_ref=_ACCOUNT, field="login_email")
        is None
    )


def test_only_reusable_login_fields_are_accepted(tmp_path: Path) -> None:
    store = _store(tmp_path)

    # An OTP or verification link is single-use by nature and must never become a
    # durable row, so the narrow field set is enforced at the vault boundary.
    assert REUSABLE_LOGIN_FIELDS == frozenset({"login_email", "login_password"})
    with pytest.raises(ValueError):
        store.put_account_login(
            app_slug="pipedrive",
            account_ref=_ACCOUNT,
            field="login_otp",
            value="123456",
        )
    with pytest.raises(ValueError):
        store.get_account_login(app_slug="pipedrive", account_ref=_ACCOUNT, field="api_token")


def test_delete_account_login_forgets_the_credential(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.put_account_login(
        app_slug="pipedrive",
        account_ref=_ACCOUNT,
        field="login_email",
        value=_EMAIL,
    )

    store.delete_account_login(app_slug="pipedrive", account_ref=_ACCOUNT, field="login_email")

    assert (
        store.get_account_login(app_slug="pipedrive", account_ref=_ACCOUNT, field="login_email")
        is None
    )


def test_account_logins_are_isolated_per_bound_account(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.put_account_login(
        app_slug="pipedrive",
        account_ref=_ACCOUNT,
        field="login_password",
        value=_PASSWORD,
    )
    store.put_account_login(
        app_slug="pipedrive",
        account_ref=_OTHER_ACCOUNT,
        field="login_password",
        value="different-password",
    )

    assert (
        store.get_account_login(app_slug="pipedrive", account_ref=_ACCOUNT, field="login_password")
        == _PASSWORD
    )
    assert (
        store.get_account_login(
            app_slug="pipedrive",
            account_ref=_OTHER_ACCOUNT,
            field="login_password",
        )
        == "different-password"
    )


def test_existing_login_stage_cannot_clobber_known_good_pair(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.put_account_login_pair(
        app_slug="pipedrive",
        account_ref=_ACCOUNT,
        email=_EMAIL,
        password=_PASSWORD,
    )

    staged = store.stage_existing_login_pair(
        app_slug="pipedrive",
        account_ref=_ACCOUNT,
        run_id=_RUN,
        email=_EMAIL,
        password="typed-wrong-password",  # pragma: allowlist secret
    )

    assert staged["login_password"] == "typed-wrong-password"  # pragma: allowlist secret
    assert store.get_account_login_pair(
        app_slug="pipedrive",
        account_ref=_ACCOUNT,
    ) == {"login_email": _EMAIL, "login_password": _PASSWORD}


def test_existing_login_stage_promotes_atomically_after_success(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.put_account_login_pair(
        app_slug="pipedrive",
        account_ref=_ACCOUNT,
        email=_EMAIL,
        password=_PASSWORD,
    )
    store.stage_existing_login_pair(
        app_slug="pipedrive",
        account_ref=_ACCOUNT,
        run_id=_RUN,
        email="rotated@example.test",
        password="rotated-password",  # pragma: allowlist secret
    )

    assert store.promote_staged_existing_login_pair(
        app_slug="pipedrive",
        account_ref=_ACCOUNT,
        run_id=_RUN,
    ) == ("login_email", "login_password")
    assert store.get_account_login_pair(
        app_slug="pipedrive",
        account_ref=_ACCOUNT,
    ) == {
        "login_email": "rotated@example.test",
        "login_password": "rotated-password",  # pragma: allowlist secret
    }


def test_unique_account_lookup_reuses_only_an_exact_selection(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.put_account_login_pair(
        app_slug="pipedrive",
        account_ref=_ACCOUNT,
        email=_EMAIL,
        password=_PASSWORD,
    )

    selected = store.get_unique_account_login_pair(app_slug="pipedrive")
    assert selected == (
        _ACCOUNT,
        {"login_email": _EMAIL, "login_password": _PASSWORD},
    )

    store.put_account_login_pair(
        app_slug="pipedrive",
        account_ref=_OTHER_ACCOUNT,
        email="other@example.test",
        password="other-password",  # pragma: allowlist secret
    )
    with pytest.raises(AccountLoginStateError) as raised:
        store.get_unique_account_login_pair(app_slug="pipedrive")
    assert raised.value.reason_code == "stored_login_account_ambiguous"


# --- RunService remember / reuse ---------------------------------------------
def test_owner_credentials_are_remembered_and_reused(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service._secret_store = _store(tmp_path)

    remembered = service._remember_reusable_login(
        app_slug="pipedrive",
        account_ref=_ACCOUNT,
        values={"login_email": SecretStr(_EMAIL), "login_password": SecretStr(_PASSWORD)},
    )
    assert remembered == ("login_email", "login_password")

    reused = service._reusable_login_values("pipedrive", _ACCOUNT)
    assert sorted(reused) == ["login_email", "login_password"]
    assert reused["login_email"].get_secret_value() == _EMAIL
    assert reused["login_password"].get_secret_value() == _PASSWORD


def test_a_partial_credential_pair_is_not_reused(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service._secret_store = _store(tmp_path)

    service._remember_reusable_login(
        app_slug="pipedrive",
        account_ref=_ACCOUNT,
        values={"login_email": SecretStr(_EMAIL)},
    )

    # An email with no password would type half a login and then stall, so an
    # incomplete set counts as nothing stored and the owner is asked once.
    assert service._reusable_login_values("pipedrive", _ACCOUNT) == {}


def test_reuse_can_be_disabled_by_policy(tmp_path: Path) -> None:
    service = _service(tmp_path, browser_login_credential_reuse=False)
    service._secret_store = _store(tmp_path)

    assert (
        service._remember_reusable_login(
            app_slug="pipedrive",
            account_ref=_ACCOUNT,
            values={"login_email": SecretStr(_EMAIL), "login_password": SecretStr(_PASSWORD)},
        )
        == ()
    )
    assert service._reusable_login_values("pipedrive", _ACCOUNT) == {}


def test_reuse_is_scoped_per_app(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service._secret_store = _store(tmp_path)
    service._remember_reusable_login(
        app_slug="pipedrive",
        account_ref=_ACCOUNT,
        values={"login_email": SecretStr(_EMAIL), "login_password": SecretStr(_PASSWORD)},
    )

    assert service._reusable_login_values("attio", _ACCOUNT) == {}


# --- autonomous advancement ---------------------------------------------------
class _Recorder:
    """Captures resume calls without touching the durable workflow."""

    def __init__(self) -> None:
        self.resumed: list[str] = []

    def __call__(self, run_id: str, *, signal: str = "completed", **_: Any) -> dict[str, Any]:
        self.resumed.append(run_id)
        return {"run_id": run_id, "status": "browser_running"}


def _waiting(service: RunService, run_id: str, action_type: str) -> None:
    service.storage.create_run(
        run_id=run_id,
        thread_id=f"thread_{run_id}",
        app_name="Pipedrive",
        app_slug="pipedrive",
        status="waiting_for_hitl",
        hitl_request={"type": action_type},
    )


def test_login_gate_is_not_resumed_from_remembered_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    service._secret_store = _store(tmp_path)
    service._remember_reusable_login(
        app_slug="pipedrive",
        account_ref=_ACCOUNT,
        values={"login_email": SecretStr(_EMAIL), "login_password": SecretStr(_PASSWORD)},
    )
    _waiting(service, "run_login", "login_required")
    recorder = _Recorder()
    monkeypatch.setattr(service, "resume_run", recorder)

    assert service.advance_autonomous_runs() == 0
    assert recorder.resumed == []


def test_login_gate_is_left_alone_without_stored_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    service._secret_store = _store(tmp_path)
    _waiting(service, "run_login", "login_required")
    recorder = _Recorder()
    monkeypatch.setattr(service, "resume_run", recorder)

    # Retrying with nothing to inject would just re-raise the same gate.
    assert service.advance_autonomous_runs() == 0
    assert recorder.resumed == []


@pytest.mark.parametrize(
    "action_type",
    ["captcha", "email_otp", "passkey", "security_key", "device_approval", "billing"],
)
def test_gates_needing_a_real_human_are_never_advanced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action_type: str
) -> None:
    service = _service(tmp_path)
    service._secret_store = _store(tmp_path)
    service._remember_reusable_login(
        app_slug="pipedrive",
        account_ref=_ACCOUNT,
        values={"login_email": SecretStr(_EMAIL), "login_password": SecretStr(_PASSWORD)},
    )
    _waiting(service, f"run_{action_type}", action_type)
    recorder = _Recorder()
    monkeypatch.setattr(service, "resume_run", recorder)

    assert service.advance_autonomous_runs() == 0
    assert recorder.resumed == []


def test_advancement_is_bounded_per_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(tmp_path, max_autonomous_advances=2)
    service._secret_store = _store(tmp_path)
    service._remember_reusable_login(
        app_slug="pipedrive",
        account_ref=_ACCOUNT,
        values={"login_email": SecretStr(_EMAIL), "login_password": SecretStr(_PASSWORD)},
    )
    _waiting(service, "run_login", "login_required")
    recorder = _Recorder()
    monkeypatch.setattr(service, "resume_run", recorder)

    for _ in range(5):
        service.advance_autonomous_runs()

    # Resume never recreates consumed login references, even with a non-zero
    # legacy advancement budget.
    assert recorder.resumed == []


def test_advancement_is_off_when_the_budget_is_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path, max_autonomous_advances=0)
    service._secret_store = _store(tmp_path)
    _waiting(service, "run_login", "login_required")
    recorder = _Recorder()
    monkeypatch.setattr(service, "resume_run", recorder)

    assert service.advance_autonomous_runs() == 0
    assert recorder.resumed == []


# --- reviewed trace no longer blocks its own autonomy -------------------------
def test_pipedrive_trace_has_no_blanket_human_checkpoint() -> None:
    """The reviewed Pipedrive path must be drivable end to end by the agent.

    Checkpoint 1 used to be ``requires_hitl``, so a run that had ALREADY signed in
    still returned human_action_required and the timeline alternated between
    hitl_resumed and browser_hitl_required forever. Login, CAPTCHA and structural
    gates are detected independently, before checkpoints, so that blanket stop was
    redundant as well as fatal to autonomy.
    """

    from ops.browser_api_trace_catalog import get_browser_api_trace

    trace = get_browser_api_trace("pipedrive")
    assert trace is not None
    assert [checkpoint.requires_hitl for checkpoint in trace.checkpoints] == [False, False, False]
    # A non-HITL checkpoint may only advance on proven evidence.
    for checkpoint in trace.checkpoints:
        assert checkpoint.completion.has_positive_condition()
    assert trace.success.has_positive_condition()
