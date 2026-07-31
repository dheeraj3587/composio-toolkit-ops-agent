"""Focused offline proofs for the reviewed-recipe canonical runtime.

The provider doubles in this module fail if they are called while the SQLite
unit-of-work is open.  No test opens Chromium, calls Composio, sends email, or
uses a research provider.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import threading
from collections import Counter
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from pydantic import SecretStr

from api.app import create_app
from api.models import ManagedConnectionResponse, RunSummary
from ops.browser.account_binding import derive_browser_account_ref
from ops.browser.worker import BrowserObservation, BrowserSessionContext
from ops.core.config import Settings
from ops.core.models import CompanyProfile, OperationsRequest
from ops.core.redaction import RedactingFilter
from ops.core.secret_store import SQLiteSecretStore
from ops.core.storage import OperationsStorage, OperationsUnitOfWork
from ops.gmail.models import GmailSendResult
from ops.onboarding.composition import (
    InferenceCandidateDecider,
    SettingsRunPlanner,
    build_onboarding_ports,
)
from ops.onboarding.driver import SQLitePhaseHistoryStore
from ops.onboarding.lease_store import SQLiteLeaseStore, SQLiteRunQueue
from ops.planner.adherence import RouteAdherenceMonitor
from ops.planner.store import SQLiteRunPlanStore
from ops.planner.validator import validate_plan
from ops.playwright.routing import select_initial_target
from ops.providers.composio_managed_auth import ManagedConnectionPoll, ManagedConnectionStart
from ops.providers.profile_store import SQLiteProviderProfileStore
from ops.recipes.app_recipes import (
    GATED_SLUGS,
    MANAGED_AUTH_SLUGS,
    PLAYWRIGHT_SLUGS,
    get_app_browser_trace,
    get_app_recipe,
    load_app_recipe_catalog,
    recipe_to_operational_research,
)
from ops.research.p1_adapter import P1OperationalAdapter
from ops.runs.errors import CredentialSubmissionError
from ops.runs.reconciliation import RunReconciliationService
from ops.workflow.canonical_runtime import CanonicalRuntime


class _TransactionTrackingStorage(OperationsStorage):
    """Expose only whether the test-owned unit-of-work boundary is active."""

    def __init__(self, db_path: Path) -> None:
        super().__init__(db_path)
        self._depth = 0
        self._depth_lock = threading.Lock()

    @property
    def transaction_open(self) -> bool:
        with self._depth_lock:
            return self._depth > 0

    @contextmanager
    def unit_of_work(self) -> Iterator[OperationsUnitOfWork]:
        with self._depth_lock:
            self._depth += 1
        try:
            with super().unit_of_work() as transaction:
                yield transaction
        finally:
            with self._depth_lock:
                self._depth -= 1


class _FakeManagedAuth:
    def __init__(self, storage: _TransactionTrackingStorage) -> None:
        self.storage = storage
        self.start_calls: list[tuple[str, str, str]] = []
        self.poll_calls: list[tuple[str, str | None]] = []
        self._effects: dict[str, str] = {}
        self._poll_index = 0

    def _assert_outside_transaction(self) -> None:
        assert self.storage.transaction_open is False

    async def start_connection(
        self,
        *,
        toolkit_slug: str,
        callback_url: str,
        effect_identity: str,
    ) -> ManagedConnectionStart:
        self._assert_outside_transaction()
        self.start_calls.append((toolkit_slug, callback_url, effect_identity))
        existing = self._effects.get(effect_identity)
        if existing is not None:
            return ManagedConnectionStart(
                connection_request_id=existing,
                redirect_url=None,
                replayed=True,
            )
        request_id = f"connection_{toolkit_slug}"
        self._effects[effect_identity] = request_id
        return ManagedConnectionStart(
            connection_request_id=request_id,
            redirect_url=f"https://connect.example.test/{request_id}",
            replayed=False,
        )

    async def poll_connection(
        self,
        connection_request_id: str,
        *,
        toolkit_slug: str | None = None,
    ) -> ManagedConnectionPoll:
        self._assert_outside_transaction()
        self.poll_calls.append((connection_request_id, toolkit_slug))
        self._poll_index += 1
        if self._poll_index == 1:
            return ManagedConnectionPoll(
                connection_request_id=connection_request_id,
                state="pending",
                provider_status="INITIATED",
                reason_code="managed_connection_pending",
            )
        return ManagedConnectionPoll(
            connection_request_id=connection_request_id,
            state="active",
            provider_status="ACTIVE",
            reason_code="managed_connection_active",
        )


class _FakePlaywright:
    provider_name = "playwright"
    requires_session_capability_scope = True
    requires_secret_broker_grants = False

    def __init__(
        self,
        storage: _TransactionTrackingStorage,
        *,
        start_failures: int = 0,
    ) -> None:
        self.storage = storage
        self.starts = 0
        self.started_context: BrowserSessionContext | None = None
        self.navigate_context: BrowserSessionContext | None = None
        self.resume_context: BrowserSessionContext | None = None
        self.navigate_research: Any = None
        self.navigate_recipe: Any = None
        self.resume_recipe: Any = None
        self.capture_recipe: Any = None
        self.sensitive_mapping: Mapping[str, str] | None = None
        self.saw_expected_login_secret = False
        self.capture_calls = 0
        self.capture_capability_scope: str | None = None
        self.capture_broker_grant: str | None = None
        self.navigate_secret_grants: Mapping[str, str] | None = None
        self.resume_secret_grants: Mapping[str, str] | None = None
        self.worker_rpc_lock_free: list[bool] = []
        self._runtime_context: Any = None
        self.released: list[str] = []
        self.start_failures = start_failures
        self.start_storage_state: list[bool] = []

    def _assert_outside_transaction(self) -> None:
        assert self.storage.transaction_open is False

    async def start(self, profile_id: str | None, **kwargs: object) -> BrowserSessionContext:
        del profile_id
        self._assert_outside_transaction()
        self.start_storage_state.append(bool(kwargs.get("use_storage_state", True)))
        self.starts += 1
        if self.starts <= self.start_failures:
            raise RuntimeError("synthetic browser start failure")
        session_number = self.starts
        context = BrowserSessionContext(
            profile_id="profile-pipedrive",
            session_id=f"playwright-session-{session_number}",
            live_view_available=True,
            allowed_domains=("app.pipedrive.com",),
            created_at="2026-07-28T00:00:00Z",
            inactivity_expires_at="2026-07-28T00:15:00Z",
            maximum_expires_at="2026-07-28T04:00:00Z",
            capability_scope=str(kwargs.get("secret_scope") or ""),
        )
        self.started_context = context
        return context

    def provider_session_id(self, session_id: str) -> str:
        assert session_id.startswith("playwright-session-")
        return session_id.replace("playwright-session", "browser-service-session")

    async def navigate_onboarding(
        self,
        context: BrowserSessionContext,
        research: object,
        *,
        recipe: object | None = None,
        sensitive_data: Mapping[str, str] | None = None,
        secret_grants: Mapping[str, str] | None = None,
        account_creation_requested: bool = False,
        signup_fields: Mapping[str, str] | None = None,
        setup_fields: Mapping[str, str] | None = None,
        credential_creation_policy: str = "reuse_only",
    ) -> BrowserObservation:
        del account_creation_requested, signup_fields, setup_fields, credential_creation_policy
        self._assert_outside_transaction()
        self.navigate_context = context
        self.navigate_research = research
        self.navigate_recipe = recipe
        self.sensitive_mapping = sensitive_data
        self.navigate_secret_grants = secret_grants
        self._record_rpc_lock_state(context.capability_scope)
        self.saw_expected_login_secret = bool(
            sensitive_data
            and sensitive_data.get("login_email") == "owner@example.test"
            and sensitive_data.get("login_password") == "raw-login-secret"
        )
        return BrowserObservation(
            status="human_action_required",
            current_url="https://app.pipedrive.com/auth/login",
            page_title="Pipedrive login",
            human_action_type="captcha",
            human_instruction="Complete the visible challenge.",
            reason_code="captcha_required",
        )

    async def resume_after_hitl(
        self,
        context: BrowserSessionContext,
        signal: str,
        research: object = None,
        *,
        recipe: object | None = None,
        sensitive_data: Mapping[str, str] | None = None,
        secret_grants: Mapping[str, str] | None = None,
        account_creation_requested: bool = False,
        signup_fields: Mapping[str, str] | None = None,
        setup_fields: Mapping[str, str] | None = None,
        credential_creation_policy: str = "reuse_only",
        provider_session_id: str | None = None,
    ) -> BrowserObservation:
        del (
            research,
            sensitive_data,
            account_creation_requested,
            signup_fields,
            setup_fields,
            credential_creation_policy,
        )
        self._assert_outside_transaction()
        assert signal == "captcha_completed"
        assert provider_session_id == "browser-service-session-1"
        self.resume_context = context
        self.resume_recipe = recipe
        self.resume_secret_grants = secret_grants
        self._record_rpc_lock_state(context.capability_scope)
        return BrowserObservation(
            status="credential_page_ready",
            current_url="https://app.pipedrive.com/settings/api",
            page_title="API",
        )

    async def auto_capture_credentials(
        self,
        session_id: str,
        app_slug: str,
        secret_store: object,
        *,
        recipe: object | None = None,
        capability_scope: str,
        broker_grant: str | None = None,
    ) -> None:
        del session_id, app_slug, secret_store
        self._assert_outside_transaction()
        self.capture_calls += 1
        self.capture_recipe = recipe
        self.capture_capability_scope = capability_scope
        self.capture_broker_grant = broker_grant
        self._record_rpc_lock_state(capability_scope)
        return None

    def _record_rpc_lock_state(self, run_id: str) -> None:
        if not self.requires_secret_broker_grants:
            return
        acquired: list[bool] = []

        def contender() -> None:
            lock = self._runtime_context._run_lock(run_id)
            got_lock = lock.acquire(timeout=0.5)
            acquired.append(got_lock)
            if got_lock:
                lock.release()

        thread = threading.Thread(target=contender)
        thread.start()
        thread.join(timeout=1)
        self.worker_rpc_lock_free.append(acquired == [True])


class _FakeGmail:
    def __init__(self) -> None:
        self.recipients: list[str] = []

    async def send_outreach(
        self,
        recipient: str,
        subject: str,
        body: str,
        idempotency_key: str,
    ) -> GmailSendResult:
        del subject, body, idempotency_key
        self.recipients.append(recipient)
        return GmailSendResult(
            session_id="controlled-session",
            thread_id="controlled-thread",
            message_id="controlled-message",
            intended_recipient=recipient,
            actual_recipient="controlled-sink@example.test",
        )


class _RuntimeContext:
    def __init__(
        self,
        tmp_path: Path,
        *,
        with_browser: bool = False,
        browser_start_failures: int = 0,
    ) -> None:
        self.storage = _TransactionTrackingStorage(tmp_path / "private" / "ops.db")
        self.p1_adapter = P1OperationalAdapter()
        vault_key = Fernet.generate_key().decode("ascii")
        self._settings = SimpleNamespace(
            managed_auth_callback_base_url="https://ops.example.test",
            browser_login_credential_reuse=True,
            secret_vault_key=SecretStr(vault_key),
        )
        self._browser_threads: list[threading.Thread] = []
        self._secret_store = SQLiteSecretStore(
            tmp_path / "private" / "vault.db",
            vault_key,
        )
        self._credential_validator = None
        self._managed_auth_provider = _FakeManagedAuth(self.storage)
        self._gmail_worker: Any = None
        self.browser = (
            _FakePlaywright(self.storage, start_failures=browser_start_failures)
            if with_browser
            else None
        )
        if self.browser is not None:
            self.browser._runtime_context = self
        self._locks: dict[str, threading.RLock] = {}
        self.remembered_login_fields: tuple[str, ...] = ()
        self.released_sessions: list[str] = []

    def _run_lock(self, run_id: str) -> threading.RLock:
        return self._locks.setdefault(run_id, threading.RLock())

    def _browser_worker_for(self, source: object) -> _FakePlaywright | None:
        provider = source if isinstance(source, str) else ""
        return self.browser if provider == "playwright" else None

    def _browser_login_payload(
        self,
        *,
        provider: str,
        app_slug: str,
        scope_id: str,
        values: Mapping[str, SecretStr],
    ) -> dict[str, str]:
        del provider
        if self.browser is not None and self.browser.requires_secret_broker_grants:
            return {
                name: self._secret_store.put_transient(
                    app_slug=app_slug,
                    kind=f"browser_login_{name}",
                    scope_id=scope_id,
                    value=secret.get_secret_value(),
                )
                for name, secret in values.items()
            }
        return {name: secret.get_secret_value() for name, secret in values.items()}

    def _remember_reusable_login(
        self,
        *,
        app_slug: str,
        account_ref: str,
        values: Mapping[str, SecretStr],
    ) -> tuple[str, ...]:
        pair = {
            field: values[field].get_secret_value()
            for field in ("login_email", "login_password")
            if field in values
        }
        if set(pair) != {"login_email", "login_password"}:
            return ()
        self._secret_store.put_account_login_pair(
            app_slug=app_slug,
            account_ref=account_ref,
            email=pair["login_email"],
            password=pair["login_password"],
        )
        self.remembered_login_fields = ("login_email", "login_password")
        return self.remembered_login_fields

    def _reusable_login_values(self, app_slug: str, account_ref: str) -> dict[str, SecretStr]:
        return {
            field: SecretStr(value)
            for field, value in self._secret_store.get_account_login_pair(
                app_slug=app_slug,
                account_ref=account_ref,
            ).items()
        }

    def _finalize_captured_credentials(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("the fake never returns captured credentials")

    def _session_context_for(self, run_id: str) -> BrowserSessionContext | None:
        record = self.storage.get_run(run_id)
        if (
            record is None
            or self.browser is None
            or self.browser.started_context is None
            or record.get("browser_session_id") != self.browser.started_context.session_id
        ):
            return None
        return self.browser.started_context

    def _release_browser_session(
        self,
        context: BrowserSessionContext | None,
        provider: str,
        *,
        reason: str,
    ) -> None:
        del provider, reason
        if context is not None:
            self.released_sessions.append(context.session_id)


def _company() -> CompanyProfile:
    return CompanyProfile(
        legal_name="Example Company",
        website="https://example.test",
        work_email_ref="vault://company/work_email/operator",
        use_case="Connect one reviewed integration.",
    )


def _request(app_name: str, *, browser_provider: str = "browser_use") -> OperationsRequest:
    return OperationsRequest(
        app_name=app_name,
        company=_company(),
        account_mode="existing_account",
        browser_provider=cast(Any, browser_provider),
        credential_creation_policy="reuse_only",
        dry_run=False,
    )


def _join_browser(context: _RuntimeContext) -> None:
    for thread in list(context._browser_threads):
        thread.join(timeout=3)
        assert thread.is_alive() is False


def _transient_secret_count(store: SQLiteSecretStore) -> int:
    with sqlite3.connect(store.db_path) as connection:
        row = connection.execute("SELECT COUNT(*) FROM vault_entries WHERE one_time = 1").fetchone()
    assert row is not None
    return int(row[0])


def test_exact_fifty_recipe_matrix_routes_to_canonical_plan_state(tmp_path: Path) -> None:
    catalog = load_app_recipe_catalog()
    counts = Counter(recipe.route_kind for recipe in catalog.apps)

    assert counts == {"managed_auth": 25, "playwright": 14, "gated": 11}
    assert (
        tuple(recipe.app_slug for recipe in catalog.apps if recipe.route_kind == "managed_auth")
        == MANAGED_AUTH_SLUGS
    )
    assert (
        tuple(recipe.app_slug for recipe in catalog.apps if recipe.route_kind == "playwright")
        == PLAYWRIGHT_SLUGS
    )
    assert (
        tuple(recipe.app_slug for recipe in catalog.apps if recipe.route_kind == "gated")
        == GATED_SLUGS
    )

    context = _RuntimeContext(tmp_path)
    runtime = CanonicalRuntime(cast(Any, context))
    for recipe in catalog.apps:
        provider = "playwright" if recipe.route_kind == "playwright" else "browser_use"
        run = runtime.create_run(
            _request(recipe.app_name, browser_provider=provider),
            idempotency_key=None,
            execution_mode="plan_only",
            browser_login=None,
        )
        assert run["state_engine"] == "canonical_v1"
        assert run["route_kind"] == recipe.route_kind
        assert run["readiness_tier"] == recipe.readiness_tier
        assert run["status"] == "route_selected"
        assert run["phase"] == "route_selected"
        assert run["external_actions"] is False


def test_execute_route_initial_states_are_truthful_and_provider_free(tmp_path: Path) -> None:
    context = _RuntimeContext(tmp_path)
    runtime = CanonicalRuntime(cast(Any, context))

    managed = runtime.create_run(
        _request("GitHub"),
        idempotency_key=None,
        execution_mode="execute_when_configured",
        browser_login=None,
    )
    gated = runtime.create_run(
        _request("Close"),
        idempotency_key=None,
        execution_mode="execute_when_configured",
        browser_login=None,
    )

    assert (managed["status"], managed["phase"], managed["route_kind"]) == (
        "connection_required",
        "connection_required",
        "managed_auth",
    )
    assert (gated["status"], gated["phase"], gated["route_kind"]) == (
        "route_selected",
        "outreach_review",
        "gated",
    )
    assert context._managed_auth_provider.start_calls == []


def test_managed_connect_replay_and_poll_are_idempotent_and_outside_uow(
    tmp_path: Path,
) -> None:
    context = _RuntimeContext(tmp_path)
    runtime = CanonicalRuntime(cast(Any, context))
    created = runtime.create_run(
        _request("GitHub"),
        idempotency_key=None,
        execution_mode="execute_when_configured",
        browser_login=None,
    )
    run_id = str(created["run_id"])

    first = runtime.connect_managed_run(run_id)
    replay = runtime.connect_managed_run(run_id)
    pending = runtime.poll_managed_connection(run_id)
    active = runtime.poll_managed_connection(run_id)

    assert first["connection_request_id"] == "connection_github"
    assert first["replayed"] is False
    assert first["redirect_url"] == "https://connect.example.test/connection_github"
    assert replay["connection_request_id"] == first["connection_request_id"]
    assert replay["replayed"] is True
    assert replay["redirect_url"] is None
    assert [call[2] for call in context._managed_auth_provider.start_calls] == [
        f"{run_id}:managed-connect:v1",
        f"{run_id}:managed-connect:v1",
    ]
    assert pending["state"] == "pending"
    assert pending["run"]["status"] == "connection_required"
    assert active["state"] == "active"
    assert active["run"]["status"] == "completed"
    assert active["run"]["phase"] == "completed"
    assert context._managed_auth_provider.poll_calls == [
        ("connection_github", "github"),
        ("connection_github", "github"),
    ]
    persisted = context.storage.get_run(run_id)
    assert persisted is not None
    assert persisted["connection_request_id"] == "connection_github"
    bundle = persisted["integrator_bundle"]
    assert isinstance(bundle, dict)
    assert bundle["readiness"] == "credentials_ready"
    assert bundle["provider_account_id"] == "connection_github"
    assert bundle["credential_refs"] == {}
    assert "connect.example.test" not in context.storage.db_path.read_text(
        encoding="utf-8", errors="ignore"
    )


def test_managed_connect_and_poll_reject_unsafe_callback_before_provider_call(
    tmp_path: Path,
) -> None:
    context = _RuntimeContext(tmp_path)
    runtime = CanonicalRuntime(cast(Any, context))
    created = runtime.create_run(
        _request("GitHub"),
        idempotency_key=None,
        execution_mode="execute_when_configured",
        browser_login=None,
    )
    run_id = str(created["run_id"])

    context._settings.managed_auth_callback_base_url = "http://127.0.0.1"
    with pytest.raises(CredentialSubmissionError) as connect_error:
        runtime.connect_managed_run(run_id)

    assert connect_error.value.reason_code == "managed_auth_callback_not_configured"
    assert context._managed_auth_provider.start_calls == []

    context._settings.managed_auth_callback_base_url = "https://ops.example.test"
    runtime.connect_managed_run(run_id)
    context._settings.managed_auth_callback_base_url = "https://ops.example.test/unreviewed-base"
    with pytest.raises(CredentialSubmissionError) as poll_error:
        runtime.poll_managed_connection(run_id)

    assert poll_error.value.reason_code == "managed_auth_callback_not_configured"
    assert context._managed_auth_provider.poll_calls == []


def test_managed_and_gated_operations_ignore_catalog_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Route, toolkit and reviewed recipient stay frozen at run creation."""

    import ops.recipes.app_recipes as recipe_module
    import ops.workflow.canonical_runtime as runtime_module

    context = _RuntimeContext(tmp_path)
    gmail = _FakeGmail()
    context._gmail_worker = gmail
    runtime = CanonicalRuntime(cast(Any, context))
    managed = runtime.create_run(
        _request("GitHub"),
        idempotency_key=None,
        execution_mode="execute_when_configured",
        browser_login=None,
    )
    gated = runtime.create_run(
        _request("Close"),
        idempotency_key=None,
        execution_mode="execute_when_configured",
        browser_login=None,
    )
    unrelated = get_app_recipe("salesforce")
    assert unrelated is not None
    monkeypatch.setattr(recipe_module, "get_app_recipe", lambda _slug: unrelated)
    monkeypatch.setattr(runtime_module, "get_app_recipe", lambda _slug: unrelated)

    runtime.connect_managed_run(str(managed["run_id"]))
    runtime.send_gated_outreach(str(gated["run_id"]))

    assert context._managed_auth_provider.start_calls[0][0] == "github"
    assert gmail.recipients == ["support@close.com"]


def test_plan_only_managed_run_cannot_start_or_poll_connection(tmp_path: Path) -> None:
    context = _RuntimeContext(tmp_path)
    runtime = CanonicalRuntime(cast(Any, context))
    created = runtime.create_run(
        _request("GitHub"),
        idempotency_key=None,
        execution_mode="plan_only",
        browser_login=None,
    )
    run_id = str(created["run_id"])

    with pytest.raises(CredentialSubmissionError) as connect_error:
        runtime.connect_managed_run(run_id)
    with pytest.raises(CredentialSubmissionError) as poll_error:
        runtime.poll_managed_connection(run_id)

    assert connect_error.value.reason_code == "plan_only_run_is_read_only"
    assert poll_error.value.reason_code == "plan_only_run_is_read_only"
    assert context._managed_auth_provider.start_calls == []
    assert context._managed_auth_provider.poll_calls == []


def test_pipedrive_target_order_is_login_then_reviewed_credential_surface() -> None:
    recipe = get_app_recipe("pipedrive")
    trace = get_app_browser_trace("pipedrive")
    assert recipe is not None and recipe.browser is not None and trace is not None
    research = recipe_to_operational_research(recipe)
    patterns = tuple(
        dict.fromkeys(
            (
                *recipe.browser.exact_hosts,
                *recipe.browser.identity_provider_hosts,
                *recipe.browser.static_resource_hosts,
            )
        )
    )

    assert (
        select_initial_target(
            research,
            trace,
            patterns,
            account_state="unknown",
        )
        == "https://app.pipedrive.com/auth/login"
    )
    assert (
        select_initial_target(
            research,
            trace,
            patterns,
            account_state="existing_account",
        )
        == "https://app.pipedrive.com/auth/login"
    )
    assert trace.start_url == "https://app.pipedrive.com/settings/api"
    assert (
        select_initial_target(
            research,
            trace,
            patterns,
            account_state="authenticated",
        )
        == trace.start_url
    )


def test_pipedrive_same_session_resume_and_raw_login_non_persistence(tmp_path: Path) -> None:
    context = _RuntimeContext(tmp_path, with_browser=True)
    runtime = CanonicalRuntime(cast(Any, context))
    login = {
        "login_email": SecretStr("owner@example.test"),
        "login_password": SecretStr("raw-login-secret"),
    }

    created = runtime.create_run(
        _request("Pipedrive", browser_provider="playwright"),
        idempotency_key=None,
        execution_mode="execute_when_configured",
        browser_login=login,
    )
    run_id = str(created["run_id"])
    _join_browser(context)
    waiting = context.storage.get_run(run_id)
    assert waiting is not None
    assert waiting["status"] == "waiting_for_hitl"
    assert waiting["phase"] == "challenge_pending"
    assert waiting["browser_session_id"] == "playwright-session-1"
    assert waiting["provider_session_id"] == "browser-service-session-1"
    assert context.browser is not None
    assert context.browser.saw_expected_login_secret is True
    assert context.browser.sensitive_mapping == {}
    assert context.browser.start_storage_state == [False]
    account_ref = str(waiting["browser_account_ref"])
    assert (
        context._secret_store.get_account_login_pair(
            app_slug="pipedrive",
            account_ref=account_ref,
        )
        == {}
    )

    resumed = runtime.resume_run(
        run_id,
        signal="captcha_completed",
        browser_login=None,
    )

    assert resumed["status"] == "browser_running"
    assert resumed["phase"] == "credential_ready"
    assert resumed["reason_code"] == "automatic_capture_failed_owner_submission_available"
    persisted = context.storage.get_run(run_id)
    assert persisted is not None
    assert persisted["browser_session_id"] == "playwright-session-1"
    assert context.browser.navigate_context is context.browser.started_context
    assert context.browser.resume_context is context.browser.started_context
    assert context.browser.navigate_research.login_url == "https://app.pipedrive.com/auth/login"
    assert context.browser.navigate_research.credential_management_url == (
        "https://app.pipedrive.com/settings/api"
    )
    capture_effect = context.storage.get_side_effect(
        run_id,
        f"{run_id}:credential-capture:v1",
    )
    assert capture_effect is not None
    assert capture_effect["provider"] == "playwright_vault"
    assert capture_effect["status"] == "completed"
    assert capture_effect["external_id"] == "no_credential_found"
    assert context.browser.capture_capability_scope == run_id
    assert context._secret_store.get_account_login_pair(
        app_slug="pipedrive",
        account_ref=account_ref,
    ) == {
        "login_email": "owner@example.test",
        "login_password": "raw-login-secret",  # pragma: allowlist secret
    }
    assert any(
        event["event_type"] == "existing_login_promoted"
        for event in context.storage.list_audit_events(run_id)
    )
    durable_text = context.storage.db_path.read_text(encoding="utf-8", errors="ignore")
    assert "raw-login-secret" not in durable_text
    assert "owner@example.test" not in durable_text
    assert "raw-login-secret" not in str(context.storage.list_audit_events(run_id))


def test_isolated_worker_receives_exact_grants_with_no_run_lock_held(
    tmp_path: Path,
) -> None:
    context = _RuntimeContext(tmp_path, with_browser=True)
    assert context.browser is not None
    context.browser.requires_secret_broker_grants = True
    runtime = CanonicalRuntime(cast(Any, context))

    created = runtime.create_run(
        _request("Pipedrive", browser_provider="playwright"),
        idempotency_key=None,
        execution_mode="execute_when_configured",
        browser_login={
            "login_email": SecretStr("owner@example.test"),
            "login_password": SecretStr("raw-login-secret"),
        },
    )
    run_id = str(created["run_id"])
    _join_browser(context)

    assert set(context.browser.navigate_secret_grants or {}) == {
        "login_email",
        "login_password",
    }
    runtime.resume_run(
        run_id,
        signal="captcha_completed",
        browser_login=None,
    )

    assert set(context.browser.resume_secret_grants or {}) == {
        "login_email",
        "login_password",
    }
    all_grants = (
        *(context.browser.navigate_secret_grants or {}).values(),
        *(context.browser.resume_secret_grants or {}).values(),
        context.browser.capture_broker_grant,
    )
    assert all(
        isinstance(grant, str) and grant.startswith("bsg_") and len(grant) == 47
        for grant in all_grants
    )
    # navigate, resume and automatic capture each execute after their short
    # reservation critical section has released the per-run lock.
    assert context.browser.worker_rpc_lock_free == [True, True, True]


def test_resume_grant_failure_discards_transients_before_worker_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _RuntimeContext(tmp_path, with_browser=True)
    runtime = CanonicalRuntime(cast(Any, context))
    created = runtime.create_run(
        _request("Pipedrive", browser_provider="playwright"),
        idempotency_key=None,
        execution_mode="execute_when_configured",
        browser_login=None,
    )
    run_id = str(created["run_id"])
    _join_browser(context)
    assert context.browser is not None
    context.browser.requires_secret_broker_grants = True
    durable_ref = context._secret_store.put(
        app_slug="pipedrive",
        kind="api_token",
        value="durable-api-token",
    )

    def fail_grant_reservation(**_kwargs: object) -> dict[str, str]:
        raise RuntimeError("synthetic resume grant failure")

    monkeypatch.setattr(runtime, "_reserve_consume_grants_locked", fail_grant_reservation)
    with pytest.raises(RuntimeError, match="synthetic resume grant failure"):
        runtime.resume_run(
            run_id,
            signal="captcha_completed",
            browser_login={
                "login_email": SecretStr("owner@example.test"),
                "login_password": SecretStr("raw-login-secret"),
            },
        )

    assert context.browser.resume_context is None
    assert _transient_secret_count(context._secret_store) == 0
    assert context._secret_store.get(durable_ref) == "durable-api-token"


def test_resume_failure_after_dispatch_does_not_delete_outcome_unknown_transients(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _RuntimeContext(tmp_path, with_browser=True)
    runtime = CanonicalRuntime(cast(Any, context))
    created = runtime.create_run(
        _request("Pipedrive", browser_provider="playwright"),
        idempotency_key=None,
        execution_mode="execute_when_configured",
        browser_login=None,
    )
    run_id = str(created["run_id"])
    _join_browser(context)
    assert context.browser is not None
    context.browser.requires_secret_broker_grants = True
    dispatched_references: dict[str, str] = {}

    async def fail_after_dispatch(
        _context: BrowserSessionContext,
        _signal: str,
        _research: object,
        **kwargs: object,
    ) -> BrowserObservation:
        sensitive_data = kwargs.get("sensitive_data")
        assert isinstance(sensitive_data, Mapping)
        dispatched_references.update(cast(Mapping[str, str], sensitive_data))
        raise RuntimeError("synthetic post-dispatch failure")

    monkeypatch.setattr(context.browser, "resume_after_hitl", fail_after_dispatch)
    failed = runtime.resume_run(
        run_id,
        signal="captcha_completed",
        browser_login={
            "login_email": SecretStr("owner@example.test"),
            "login_password": SecretStr("raw-login-secret"),
        },
    )

    assert failed["status"] == "failed"
    assert set(dispatched_references) == {"login_email", "login_password"}
    assert _transient_secret_count(context._secret_store) == 2
    for field_name, reference in dispatched_references.items():
        context._secret_store.consume_transient(
            reference,
            expected_app_slug="pipedrive",
            expected_kind=f"browser_login_{field_name}",
            expected_scope_id=run_id,
        )
    assert _transient_secret_count(context._secret_store) == 0


def test_rejected_existing_login_never_replaces_known_good_pair(tmp_path: Path) -> None:
    context = _RuntimeContext(tmp_path, with_browser=True)
    runtime = CanonicalRuntime(cast(Any, context))
    submitted = {
        "login_email": SecretStr("owner@example.test"),
        "login_password": SecretStr("typed-wrong-password"),
    }
    account_ref = derive_browser_account_ref(
        run_id="run_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        app_slug="pipedrive",
        work_email_ref=_company().work_email_ref,
        browser_login=submitted,
        binding_secret=context._settings.secret_vault_key,
    )
    context._secret_store.put_account_login_pair(
        app_slug="pipedrive",
        account_ref=account_ref,
        email="owner@example.test",
        password="known-good-password",  # pragma: allowlist secret
    )

    created = runtime.create_run(
        _request("Pipedrive", browser_provider="playwright"),
        idempotency_key=None,
        execution_mode="execute_when_configured",
        browser_login=submitted,
    )
    run_id = str(created["run_id"])
    _join_browser(context)
    assert context._secret_store.get_account_login_pair(
        app_slug="pipedrive",
        account_ref=account_ref,
    ) == {
        "login_email": "owner@example.test",
        "login_password": "known-good-password",  # pragma: allowlist secret
    }
    assert context.browser is not None and context.browser.started_context is not None
    recipe = get_app_recipe("pipedrive")
    assert recipe is not None

    failed = runtime._apply_browser_observation(
        run_id,
        observation=BrowserObservation(
            status="failed",
            current_url="https://app.pipedrive.com/auth/login",
            page_title="Pipedrive login",
            reason_code="authentication_failed",
        ),
        research=recipe_to_operational_research(recipe),
        request=_request("Pipedrive", browser_provider="playwright"),
        recipe=recipe,
        context=context.browser.started_context,
    )

    assert failed is not None and failed["status"] == "failed"
    assert context._secret_store.get_account_login_pair(
        app_slug="pipedrive",
        account_ref=account_ref,
    ) == {
        "login_email": "owner@example.test",
        "login_password": "known-good-password",  # pragma: allowlist secret
    }


def test_later_run_seeds_the_only_complete_reusable_account(tmp_path: Path) -> None:
    context = _RuntimeContext(tmp_path, with_browser=True)
    runtime = CanonicalRuntime(cast(Any, context))
    context._secret_store.put_account_login_pair(
        app_slug="pipedrive",
        account_ref="acct_0123456789abcdef0123456789abcdef",
        email="owner@example.test",
        password="raw-login-secret",  # pragma: allowlist secret
    )

    created = runtime.create_run(
        _request("Pipedrive", browser_provider="playwright"),
        idempotency_key=None,
        execution_mode="execute_when_configured",
        browser_login=None,
    )
    _join_browser(context)

    persisted = context.storage.get_run(str(created["run_id"]))
    assert persisted is not None
    assert persisted["browser_account_ref"] == "acct_0123456789abcdef0123456789abcdef"
    assert context.browser is not None
    assert context.browser.saw_expected_login_secret is True
    assert context.browser.start_storage_state == [True]


def test_ambiguous_reusable_accounts_fail_closed_before_browser_start(tmp_path: Path) -> None:
    context = _RuntimeContext(tmp_path, with_browser=True)
    runtime = CanonicalRuntime(cast(Any, context))
    for account_ref, email in (
        ("acct_0123456789abcdef0123456789abcdef", "one@example.test"),
        ("acct_fedcba9876543210fedcba9876543210", "two@example.test"),
    ):
        context._secret_store.put_account_login_pair(
            app_slug="pipedrive",
            account_ref=account_ref,
            email=email,
            password="known-password",  # pragma: allowlist secret
        )

    result = runtime.create_run(
        _request("Pipedrive", browser_provider="playwright"),
        idempotency_key=None,
        execution_mode="execute_when_configured",
        browser_login=None,
    )

    assert result["status"] == "configuration_required"
    assert result["phase"] == "login_account_selection"
    assert result["reason_code"] == "stored_login_account_ambiguous"
    assert context.browser is not None and context.browser.starts == 0


def test_idempotent_replay_continues_pristine_staged_browser_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _RuntimeContext(tmp_path, with_browser=True)
    runtime = CanonicalRuntime(cast(Any, context))
    request = _request("Pipedrive", browser_provider="playwright")
    login = {
        "login_email": SecretStr("owner@example.test"),
        "login_password": SecretStr("raw-login-secret"),
    }
    original_start = runtime._start_playwright

    def crash_before_dispatch(*_args: object, **_kwargs: object) -> dict[str, Any]:
        raise RuntimeError("simulated process exit before browser dispatch")

    monkeypatch.setattr(runtime, "_start_playwright", crash_before_dispatch)
    with pytest.raises(RuntimeError, match="simulated process exit"):
        runtime.create_run(
            request,
            idempotency_key="idem_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            execution_mode="execute_when_configured",
            browser_login=login,
        )
    persisted = context.storage.get_idempotent_run("idem_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    assert persisted is not None
    original_run = persisted[0]
    assert original_run["phase"] == "browser_pending"
    assert original_run["attempt"] == 0

    monkeypatch.setattr(runtime, "_start_playwright", original_start)
    replayed = runtime.create_run(
        request,
        idempotency_key="idem_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        execution_mode="execute_when_configured",
        browser_login=login,
    )
    _join_browser(context)

    assert replayed["run_id"] == original_run["run_id"]
    assert replayed["status"] == "browser_running"
    assert context.browser is not None
    assert context.browser.starts == 1
    assert context.browser.saw_expected_login_secret is True
    assert context.browser.start_storage_state == [False]


def test_idempotent_replay_never_duplicates_a_reserved_browser_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _RuntimeContext(tmp_path, with_browser=True)
    runtime = CanonicalRuntime(cast(Any, context))
    request = _request("Pipedrive", browser_provider="playwright")
    login = {
        "login_email": SecretStr("owner@example.test"),
        "login_password": SecretStr("raw-login-secret"),
    }
    assert context.browser is not None
    browser = context.browser
    browser.requires_secret_broker_grants = True
    original_start = browser.start

    async def crash_after_reservation(
        _profile_id: str | None,
        **_kwargs: object,
    ) -> BrowserSessionContext:
        browser.starts += 1
        raise KeyboardInterrupt

    monkeypatch.setattr(browser, "start", crash_after_reservation)
    with pytest.raises(KeyboardInterrupt):
        runtime.create_run(
            request,
            idempotency_key="idem_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            execution_mode="execute_when_configured",
            browser_login=login,
        )
    persisted = context.storage.get_idempotent_run("idem_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    assert persisted is not None
    assert persisted[0]["attempt"] == 1
    assert (
        context.storage.get_side_effect(
            str(persisted[0]["run_id"]),
            f"{persisted[0]['run_id']}:browser-start:v1",
        )
        is not None
    )
    assert _transient_secret_count(context._secret_store) == 0

    monkeypatch.setattr(browser, "start", original_start)
    replayed = runtime.create_run(
        request,
        idempotency_key="idem_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        execution_mode="execute_when_configured",
        browser_login=login,
    )

    assert replayed["run_id"] == persisted[0]["run_id"]
    assert replayed["status"] == "configuration_required"
    assert replayed["phase"] == "effect_reconciliation"
    assert replayed["reason_code"] == "browser_start_reconciliation_required"
    assert browser.starts == 1
    assert _transient_secret_count(context._secret_store) == 0


def test_browser_start_failure_discards_only_run_scoped_transient_login(
    tmp_path: Path,
) -> None:
    context = _RuntimeContext(tmp_path, with_browser=True, browser_start_failures=1)
    assert context.browser is not None
    context.browser.requires_secret_broker_grants = True
    durable_ref = context._secret_store.put(
        app_slug="pipedrive",
        kind="api_token",
        value="durable-api-token",
    )
    runtime = CanonicalRuntime(cast(Any, context))

    failed = runtime.create_run(
        _request("Pipedrive", browser_provider="playwright"),
        idempotency_key=None,
        execution_mode="execute_when_configured",
        browser_login={
            "login_email": SecretStr("owner@example.test"),
            "login_password": SecretStr("raw-login-secret"),
        },
    )

    assert failed["status"] == "failed"
    assert failed["phase"] == "browser_start_failed"
    assert _transient_secret_count(context._secret_store) == 0
    assert context._secret_store.get(durable_ref) == "durable-api-token"


def test_browser_session_is_released_and_transients_discarded_when_state_commit_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _RuntimeContext(tmp_path, with_browser=True)
    assert context.browser is not None
    context.browser.requires_secret_broker_grants = True
    runtime = CanonicalRuntime(cast(Any, context))
    request = _request("Pipedrive", browser_provider="playwright")
    created = runtime.create_run(
        request,
        idempotency_key=None,
        execution_mode="plan_only",
        browser_login=None,
    )
    recipe = get_app_recipe("pipedrive")
    assert recipe is not None
    original_unit_of_work = context.storage.unit_of_work
    unit_of_work_calls = 0

    @contextmanager
    def fail_second_unit_of_work() -> Iterator[OperationsUnitOfWork]:
        nonlocal unit_of_work_calls
        unit_of_work_calls += 1
        if unit_of_work_calls == 2:
            raise RuntimeError("synthetic browser state commit failure")
        with original_unit_of_work() as transaction:
            yield transaction

    monkeypatch.setattr(context.storage, "unit_of_work", fail_second_unit_of_work)
    with pytest.raises(RuntimeError, match="synthetic browser state commit failure"):
        runtime._start_playwright(
            str(created["run_id"]),
            request=request,
            research=recipe_to_operational_research(recipe),
            recipe=recipe,
            browser_login={
                "login_email": SecretStr("owner@example.test"),
                "login_password": SecretStr("raw-login-secret"),
            },
        )

    assert context.browser.started_context is not None
    assert context.released_sessions == [context.browser.started_context.session_id]
    assert _transient_secret_count(context._secret_store) == 0


def test_browser_thread_start_failure_releases_session_and_discards_transients(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _RuntimeContext(tmp_path, with_browser=True)
    assert context.browser is not None
    context.browser.requires_secret_broker_grants = True
    runtime = CanonicalRuntime(cast(Any, context))

    def fail_thread_start(_thread: threading.Thread) -> None:
        raise RuntimeError("synthetic thread start failure")

    monkeypatch.setattr(threading.Thread, "start", fail_thread_start)
    failed = runtime.create_run(
        _request("Pipedrive", browser_provider="playwright"),
        idempotency_key=None,
        execution_mode="execute_when_configured",
        browser_login={
            "login_email": SecretStr("owner@example.test"),
            "login_password": SecretStr("raw-login-secret"),
        },
    )

    assert failed["status"] == "failed"
    assert failed["phase"] == "browser_start_failed"
    assert failed["reason_code"] == "browser_dispatch_failed"
    assert context.browser.started_context is not None
    assert context.released_sessions == [context.browser.started_context.session_id]
    assert context._browser_threads == []
    assert _transient_secret_count(context._secret_store) == 0


def test_navigation_grant_failure_discards_transients_before_worker_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _RuntimeContext(tmp_path, with_browser=True)
    assert context.browser is not None
    context.browser.requires_secret_broker_grants = True
    runtime = CanonicalRuntime(cast(Any, context))

    def fail_grant_reservation(**_kwargs: object) -> dict[str, str]:
        raise RuntimeError("synthetic grant reservation failure")

    monkeypatch.setattr(runtime, "_reserve_consume_grants_locked", fail_grant_reservation)
    created = runtime.create_run(
        _request("Pipedrive", browser_provider="playwright"),
        idempotency_key=None,
        execution_mode="execute_when_configured",
        browser_login={
            "login_email": SecretStr("owner@example.test"),
            "login_password": SecretStr("raw-login-secret"),
        },
    )
    _join_browser(context)

    persisted = context.storage.get_run(str(created["run_id"]))
    assert persisted is not None
    assert persisted["status"] == "failed"
    assert context.browser.navigate_context is None
    assert _transient_secret_count(context._secret_store) == 0


def test_delayed_reconciliation_continues_pristine_browser_pending(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _RuntimeContext(tmp_path, with_browser=True)
    runtime = CanonicalRuntime(cast(Any, context))
    login = {
        "login_email": SecretStr("owner@example.test"),
        "login_password": SecretStr("raw-login-secret"),
    }
    original_start = runtime._start_playwright

    def crash_before_dispatch(*_args: object, **_kwargs: object) -> dict[str, Any]:
        raise RuntimeError("simulated process exit before browser dispatch")

    monkeypatch.setattr(runtime, "_start_playwright", crash_before_dispatch)
    with pytest.raises(RuntimeError, match="simulated process exit"):
        runtime.create_run(
            _request("Pipedrive", browser_provider="playwright"),
            idempotency_key=None,
            execution_mode="execute_when_configured",
            browser_login=login,
        )
    pending = next(
        record
        for record in context.storage.list_runs(limit=10, offset=0)
        if record["phase"] == "browser_pending"
    )
    monkeypatch.setattr(runtime, "_start_playwright", original_start)
    monkeypatch.setattr(
        context,
        "_continue_pristine_playwright_run",
        lambda record: runtime._continue_pristine_playwright_run(
            record,
            browser_login=None,
        ),
        raising=False,
    )

    RunReconciliationService(cast(Any, context)).reconcile_stranded_runs()
    _join_browser(context)

    recovered = context.storage.get_run(str(pending["run_id"]))
    assert recovered is not None
    assert recovered["status"] == "waiting_for_hitl"
    assert recovered["attempt"] == 1
    assert context.browser is not None
    assert context.browser.starts == 1
    assert context.browser.saw_expected_login_secret is True


def test_capture_effect_replay_requires_reconciliation_without_recapture(tmp_path: Path) -> None:
    context = _RuntimeContext(tmp_path, with_browser=True)
    runtime = CanonicalRuntime(cast(Any, context))
    created = runtime.create_run(
        _request("Pipedrive", browser_provider="playwright"),
        idempotency_key=None,
        execution_mode="execute_when_configured",
        browser_login=None,
    )
    run_id = str(created["run_id"])
    _join_browser(context)
    first = runtime.resume_run(
        run_id,
        signal="captcha_completed",
        browser_login=None,
    )
    assert first["phase"] == "credential_ready"
    assert context.browser is not None
    assert context.browser.capture_calls == 1
    assert context.browser.started_context is not None
    recipe = get_app_recipe("pipedrive")
    assert recipe is not None

    replay = runtime._apply_browser_observation(
        run_id,
        observation=BrowserObservation(
            status="credential_page_ready",
            current_url="https://app.pipedrive.com/settings/api",
            page_title="API",
        ),
        research=recipe_to_operational_research(recipe),
        request=_request("Pipedrive", browser_provider="playwright"),
        recipe=recipe,
        context=context.browser.started_context,
    )

    assert replay is not None
    assert replay["status"] == "configuration_required"
    assert replay["phase"] == "effect_reconciliation"
    assert replay["reason_code"] == "credential_capture_reconciliation_required"
    assert context.browser.capture_calls == 1


def test_failed_browser_start_retries_with_a_new_effect_and_no_login_reuse(
    tmp_path: Path,
) -> None:
    context = _RuntimeContext(
        tmp_path,
        with_browser=True,
        browser_start_failures=1,
    )
    runtime = CanonicalRuntime(cast(Any, context))

    failed = runtime.create_run(
        _request("Pipedrive", browser_provider="playwright"),
        idempotency_key=None,
        execution_mode="execute_when_configured",
        browser_login=None,
    )
    run_id = str(failed["run_id"])

    assert failed["status"] == "failed"
    assert failed["phase"] == "browser_start_failed"
    assert failed["attempt"] == 1

    retried = runtime.retry_browser_run(run_id)
    assert retried["status"] == "browser_running"
    assert retried["attempt"] == 2
    _join_browser(context)

    waiting = context.storage.get_run(run_id)
    assert waiting is not None
    assert waiting["status"] == "waiting_for_hitl"
    assert waiting["attempt"] == 2
    first = context.storage.get_side_effect(run_id, f"{run_id}:browser-start:v1")
    second = context.storage.get_side_effect(run_id, f"{run_id}:browser-start:v2")
    assert first is not None and first["status"] == "failed"
    assert second is not None and second["status"] == "completed"
    assert context.browser is not None
    assert context.browser.starts == 2
    assert context.browser.sensitive_mapping is None


def test_browser_retry_and_resume_after_restart_use_creation_time_selectors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ops.recipes.app_recipes as recipe_module
    import ops.workflow.canonical_runtime as runtime_module

    first_context = _RuntimeContext(tmp_path, with_browser=True, browser_start_failures=1)
    failed = CanonicalRuntime(cast(Any, first_context)).create_run(
        _request("Pipedrive", browser_provider="playwright"),
        idempotency_key=None,
        execution_mode="execute_when_configured",
        browser_login=None,
    )
    original = get_app_recipe("pipedrive")
    assert original is not None
    payload = original.model_dump(mode="python")
    changed_selector = "input[name='changed_token']"
    capture = dict(payload["capture"])
    capture["selectors"] = (changed_selector,)
    browser = dict(payload["browser"])
    browser["sensitive_selectors"] = ("input[type='password']", changed_selector)
    payload.update({"capture": capture, "browser": browser})
    changed = type(original).model_validate(payload)
    monkeypatch.setattr(recipe_module, "get_app_recipe", lambda _slug: changed)
    monkeypatch.setattr(runtime_module, "get_app_recipe", lambda _slug: changed)

    # A fresh runtime instance proves the policy comes from SQLite, not memory.
    restarted = _RuntimeContext(tmp_path, with_browser=True)
    runtime = CanonicalRuntime(cast(Any, restarted))
    run_id = str(failed["run_id"])
    runtime.retry_browser_run(run_id)
    _join_browser(restarted)
    assert restarted.browser is not None
    assert restarted.browser.navigate_recipe.capture.selectors == original.capture.selectors

    runtime.resume_run(run_id, signal="captcha_completed", browser_login=None)
    assert restarted.browser.resume_recipe.capture.selectors == original.capture.selectors
    assert restarted.browser.capture_recipe.capture.selectors == original.capture.selectors


def test_pre_snapshot_canonical_run_fails_closed_before_provider_call(tmp_path: Path) -> None:
    context = _RuntimeContext(tmp_path)
    runtime = CanonicalRuntime(cast(Any, context))
    context.storage.create_run(
        run_id="run_without_recipe_snapshot",
        thread_id="canonical-before-snapshot-migration",
        app_name="GitHub",
        app_slug="github",
        status="connection_required",
        access_route="self_serve",
        operational_research={},
        request=_request("GitHub").model_dump(mode="json"),
        execution_mode="operations",
        recipe_version="recovery-50@1.0",
        route_kind="managed_auth",
        readiness_tier="managed_auth_ready",
        phase="connection_required",
        state_engine="canonical_v1",
    )

    with pytest.raises(CredentialSubmissionError) as raised:
        runtime.connect_managed_run("run_without_recipe_snapshot")

    assert raised.value.reason_code == "immutable_recipe_snapshot_missing"
    assert context._managed_auth_provider.start_calls == []


def test_legacy_runs_are_read_only_for_resume_and_managed_connect(tmp_path: Path) -> None:
    context = _RuntimeContext(tmp_path)
    runtime = CanonicalRuntime(cast(Any, context))
    run_id = "run_00000000000000000000000000000000"
    context.storage.create_run(
        run_id=run_id,
        thread_id="legacy-thread",
        app_name="GitHub",
        app_slug="github",
        status="waiting_for_hitl",
        access_route="self_serve",
        state_engine="legacy",
        request=_request("GitHub").model_dump(mode="json"),
    )

    with pytest.raises(CredentialSubmissionError) as resume_error:
        runtime.resume_run(run_id, signal="completed", browser_login=None)
    with pytest.raises(CredentialSubmissionError) as connect_error:
        runtime.connect_managed_run(run_id)

    assert resume_error.value.reason_code == "legacy_run_is_read_only"
    assert connect_error.value.reason_code == "legacy_run_is_read_only"
    unchanged = context.storage.get_run(run_id)
    assert unchanged is not None
    assert unchanged["state_engine"] == "legacy"
    assert unchanged["status"] == "waiting_for_hitl"


class _ManagedEndpointService:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def startup(self) -> None:
        return None

    async def shutdown(self) -> None:
        return None

    @staticmethod
    def _run(status: str, phase: str) -> RunSummary:
        return RunSummary(
            run_id="run_00000000000000000000000000000000",
            thread_id="sqlite-test",
            app_name="GitHub",
            app_slug="github",
            status=cast(Any, status),
            access_route="self_serve",
            created_at="2026-07-28T00:00:00Z",
            updated_at="2026-07-28T00:00:00Z",
            execution_mode="execute_when_configured",
            browser_provider="browser_use",
            credential_creation_policy="reuse_only",
            recipe_version="recovery-50@1.0",
            route_kind="managed_auth",
            readiness_tier="managed_auth_ready",
            phase=phase,
            reason_code=(
                "managed_connection_active"
                if status == "completed"
                else "managed_connection_pending"
            ),
            state_engine="canonical_v1",
            external_actions=True,
        )

    async def connect_managed(self, run_id: str) -> ManagedConnectionResponse:
        self.calls.append(f"connect:{run_id}")
        return ManagedConnectionResponse(
            run=self._run("connection_required", "waiting_for_connection"),
            connection_request_id="connection_github",
            state="pending",
            redirect_url="https://connect.example.test/connection_github",
            replayed=False,
        )

    async def poll_managed_connection(self, run_id: str) -> ManagedConnectionResponse:
        self.calls.append(f"poll:{run_id}")
        return ManagedConnectionResponse(
            run=self._run("completed", "completed"),
            connection_request_id="connection_github",
            state="active",
            replayed=False,
        )


def test_managed_api_endpoints_are_owner_gated_typed_and_no_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    internal_token = "canonical-runtime-internal-token-" + ("i" * 32)
    monkeypatch.setenv("ALLOW_LOCAL_CREDENTIAL_SUBMISSION", "true")
    monkeypatch.setenv("OPS_INTERNAL_API_TOKEN", internal_token)
    service = _ManagedEndpointService()
    application = create_app(service=cast(Any, service))
    run_id = "run_00000000000000000000000000000000"
    headers = {"X-Ops-Internal-Token": internal_token}

    with TestClient(application, raise_server_exceptions=False) as client:
        connected = client.post(f"/api/runs/{run_id}/connect", headers=headers)
        polled = client.post(f"/api/runs/{run_id}/poll-connection", headers=headers)

    assert connected.status_code == 200
    assert connected.headers["cache-control"] == "no-store"
    assert connected.json()["state"] == "pending"
    assert connected.json()["redirect_url"] == ("https://connect.example.test/connection_github")
    assert polled.status_code == 200
    assert polled.headers["cache-control"] == "no-store"
    assert polled.json()["state"] == "active"
    assert "redirect_url" not in polled.json()
    assert service.calls == [f"connect:{run_id}", f"poll:{run_id}"]


class _UnusedSessions:
    """The browser seam the composition root does not own; never opened here."""

    async def session_for(self, *, run_id: str, phase: str, lease: object) -> object:
        raise AssertionError("composing the ports opens no browser session")


def test_composition_root_binds_every_onboarding_port(tmp_path: Path) -> None:
    """One happy path through the application boundary (design LL-2).

    A configured deployment composes the durable stores, the mailbox adapter, the
    validator, and the inference-backed decider, and hands the driver a fully wired
    ``OnboardingDeps``. No provider is called: binding an adapter is not using one.
    """

    settings = _settings(tmp_path)
    ports = build_onboarding_ports(settings, ledger_path=tmp_path / "ops.db")
    try:
        # The four durable ports, all against the one ledger this deployment owns.
        assert isinstance(ports.phases, SQLitePhaseHistoryStore)
        assert isinstance(ports.leases, SQLiteLeaseStore)
        assert isinstance(ports.queue, SQLiteRunQueue)
        assert isinstance(ports.profiles, SQLiteProviderProfileStore)
        assert ports.profiles.owner == settings.browser_service_owner
        # Planning is one composed graph: the store is shared by admission and
        # adherence, and the validator is the catalog validator rather than an
        # inference fallback.
        assert isinstance(ports.plans, SQLiteRunPlanStore)
        assert isinstance(ports.planner, SettingsRunPlanner)
        assert ports.plan_validator is validate_plan
        assert isinstance(ports.adherence, RouteAdherenceMonitor)
        # The adapters that need configuration, bound because it is present.
        assert ports.verification is not None and ports.verification.kind == "gmail"
        assert ports.validator is not None
        assert ports.decider is not None
        assert ports.vault is not None
        # Research is the one port with no implementation to bind in this tree, and
        # it says so rather than pretending (Requirement 2.7 is a run outcome; this
        # is a configuration one).
        assert ports.unavailable == {"research": "research_adapters_unavailable"}
        # The budgets and lease timings come from settings, not from literals.
        assert ports.captcha_budget.max_pauses == settings.onboarding_captcha_pause_budget
        assert ports.budget.max_actions == settings.onboarding_loop_max_actions
        assert ports.timings.ttl_seconds == settings.onboarding_lease_ttl_seconds

        deps = ports.deps_for(
            run_id="run_" + "a" * 32,
            sessions=cast(Any, _UnusedSessions()),
        )
        # The phase store is bound as all three of its ports, so the boundary, the
        # pause, and the reservation view are one consistent set of rows.
        assert deps.phases is ports.phases
        assert deps.pauses is ports.phases
        assert deps.effects is ports.phases
        assert deps.outcomes is ports.outcomes
        assert deps.plans is ports.plans
        assert deps.planner is ports.planner
        assert deps.plan_validator is ports.plan_validator
        # An explicitly unwired plan store disables adherence instead of letting
        # the monitor infer an expectation from transient state.
        assert replace(ports, plans=None).adherence is None
        # The decider is the composed chain, rebound to this run's attempt sink so
        # each inference attempt is recorded against the run that made it (R4.3).
        assert isinstance(deps.decider, InferenceCandidateDecider)
        assert deps.verification is ports.verification
        assert deps.vault is ports.vault
        # Requirement 19.4: the same filter the API and CLI startup boundaries
        # install is in place for a process that composed these ports directly.
        assert any(isinstance(item, RedactingFilter) for item in logging.getLogger().filters)
    finally:
        asyncio.run(ports.aclose())


def _settings(tmp_path: Path) -> Settings:
    """A deployment with a vault, a model key, and no network access configured."""

    return Settings(
        ops_db_path=tmp_path / "ops.db",
        secret_vault_db_path=tmp_path / "secret_vault.db",
        secret_vault_key=SecretStr(Fernet.generate_key().decode()),
        groq_api_key=SecretStr("gsk_" + "a" * 40),
    )
