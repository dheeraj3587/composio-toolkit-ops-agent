"""Two apify runs on the vault-first login route, walked end to end.

Run 1 (app + credentials) supplies the reusable login pair at creation, and the
walk signs in through the vault-probed login route, reaches the credential
surface, and captures the onboarding API key into the vault — with zero operator
prompts and no browser ever started in this process.

Run 2 (new run id, no credentials supplied) reuses the stored pair through the
production reuse path, binds the SAME account reference, and walks the same
login route with zero admission prompts.

What is real: ``build_onboarding_ports`` composes every port, and the run
ledger, the profile store, the phase history, the vault, and the effect ledger
are real SQLite files under ``tmp_path``. ``MountedOnboardingRuntime.advance``
drives the production phase handlers (``_effectful_handlers``, including the
``route_selected_login`` handler), the real ``_ResearchHandler`` /
``build_profile`` pipeline, the real planner and plan validator, and the real
action loop. The phase boundaries, the effect reservations, the admission
decision, and the outcome row are all written by the production code that owns
them.

What is fake, and only ever behind an LL-2 ``Protocol``: the provider site (the
loop's session port, the login submitter surface, and the credential surface,
one object because the run walks one site), the evidence fetcher
(``ProfileEvidenceFetcher`` — profile research has no fetcher bound in this
deployment), the inference backend (``CandidateDecider``), and the credential
probe (``CredentialValidatorPort``). Nothing reaches the network, which the
autouse fixture below enforces rather than assumes.

The browser itself is never started: the run's session is bound by
``_bind_browser_session`` from the fake factory, and ``_NeverStartedPlaywright``
raises if any in-process browser worker is touched.
"""

from __future__ import annotations

import asyncio
import re
import socket
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from ops.browser.candidates import ActionCandidate
from ops.browser.decider import SnapshotElement
from ops.browser.worker import BrowserObservation
from ops.core.config import Settings
from ops.core.models import CompanyProfile, OperationsRequest
from ops.core.secret_store import SQLiteSecretStore
from ops.credentials.validator import CredentialValidationResult
from ops.onboarding.action_loop import LoopObservation
from ops.onboarding.lease import Lease
from ops.onboarding.phase import OnboardingPhase
from ops.onboarding.runtime import MountedOnboardingRuntime
from ops.playwright.page_inspection import PageInspection
from ops.research.operational_research import EvidenceDocument
from ops.runs.service import RunService

APP_SLUG = "apify"
APP_NAME = "Apify"
OWNER = "ops-owner"
WORKER = "worker-apify-e2e"

# The fake provider's own surfaces. Every one of them is on the single
# registrable domain the evidence corroborates, so the allow-list the profile
# derives admits them all.
SIGN_IN_URL = "https://console.apify.com/sign-in"
SIGN_UP_URL = "https://console.apify.com/sign-up"
SURFACE_URL = "https://console.apify.com/settings/integrations"
CONSOLE_URL = "https://console.apify.com"

LOGIN_EMAIL = "ops.login+apify@gmail.com"
LOGIN_PASSWORD = "Apify-" + "p" * 20  # pragma: allowlist secret
CREDENTIAL_VALUE = "apify_api_" + "a" * 30  # pragma: allowlist secret
CREDENTIAL_KIND = "api_key"
APP_ID = "app-apify-e2e-1"

# Literal, corroborated route claims, present in EVERY document the fake
# fetcher returns, so ``_literal_route_claims`` derives the same three required
# fields from six distinct excerpts.
_CORROBORATION = (
    "Apify is the platform for web scraping and AI agents. Sign in to the Apify "
    f"Console at {SIGN_IN_URL} with your apify.com account, or create a new one "
    f"at {SIGN_UP_URL}."
)

TERMINAL_STATUSES = frozenset({"completed", "failed", "blocked", "cancelled"})


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """The walk runs entirely on fakes; a socket would be a wiring bug."""

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("the onboarding login walk must not reach the network")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)


# --- the fake provider site --------------------------------------------------


def _page(
    *,
    status: str,
    url: str,
    title: str,
    controls: tuple[str, ...] = (),
    developer_app_id: str | None = None,
    credential_labels: tuple[str, ...] = (),
) -> LoopObservation:
    """One page as the browser would report it, plus the controls it renders."""

    return LoopObservation(
        observation=BrowserObservation(
            status=cast(Any, status),
            current_url=url,
            page_title=title,
            developer_app_id=developer_app_id,
            credential_field_labels=credential_labels,
        ),
        raw_elements=tuple(
            {"role": "button", "name": name, "visible": True, "enabled": True} for name in controls
        ),
    )


@dataclass
class _ApifySite:
    """The provider, behind every port that touches a page or a form.

    One object rather than three fakes, because a run walks one site on one
    session: the login form, the developer console, and the credential surface
    are the same provider at three points in the walk. The state moves forward
    only when the system does something to the page.
    """

    vault: SQLiteSecretStore
    session_id: str = "session-apify-e2e-1"
    state: str = "fresh"
    acted: list[str] = field(default_factory=list)
    logins: int = 0
    fills: list[tuple[str, str]] = field(default_factory=list)

    # --- the loop's session port -------------------------------------------

    async def observe(self) -> LoopObservation:
        if self.state == "submitted":
            # The post-login landing page: still navigating, so the loop's first
            # decision is the one goto the phase goal allows.
            return _page(status="navigating", url=CONSOLE_URL, title="Apify Console")
        if self.state == "console":
            return _page(
                status="developer_console_ready",
                url=SURFACE_URL,
                title="API & Integrations",
                controls=("Create app",),
            )
        if self.state == "app_created":
            # The real settings/integrations page renders BOTH the developer-apps
            # section and the personal API token, so the walk never leaves this
            # page: the developer-app postcondition reads the id, and the capture
            # boundary reads the token, from the same observation.
            return _page(
                status="credential_page_ready",
                url=SURFACE_URL,
                title="API & Integrations",
                developer_app_id=APP_ID,
                credential_labels=("API token",),
            )
        if self.state == "credential_surface":
            return _page(
                status="credential_page_ready",
                url=SURFACE_URL,
                title="API & Integrations",
                credential_labels=("API token",),
            )
        raise AssertionError(f"site is not on a page this walk expects (state={self.state})")

    async def act(self, candidate: ActionCandidate) -> None:
        self.acted.append(candidate.semantic_target)
        if candidate.action == "goto":
            if self.state == "submitted":
                self.state = "console"
            elif self.state == "app_created":
                self.state = "credential_surface"
            elif self.state == "console":
                pass  # re-navigating the surface the run is already on
            else:
                raise AssertionError(f"site cannot goto from {self.state}")
        elif candidate.action == "click":
            if self.state == "console":
                self.state = "app_created"
            else:
                raise AssertionError(f"site cannot click from {self.state}")
        else:
            raise AssertionError(f"site cannot act {candidate.action}")

    # --- the login submitter surface ---------------------------------------

    async def navigate_to(self, url: str) -> None:
        assert url == SIGN_IN_URL
        assert self.state == "fresh"
        self.state = "login_page"

    async def inspect(self) -> PageInspection:
        if self.state in ("login_page", "login_filled"):
            return PageInspection(
                url=SIGN_IN_URL,
                title="Sign in to Apify",
                visible_text="Sign in to Apify",
                elements=(
                    SnapshotElement(index=0, role="textbox", name="Email", element_type="email"),
                    SnapshotElement(
                        index=1,
                        role="textbox",
                        name="Password",
                        element_type="password",
                        secretish=True,
                    ),
                    SnapshotElement(index=2, role="button", name="Continue"),
                ),
                locators=(),
                fingerprint="signin-page",
            )
        if self.state == "submitted":
            return PageInspection(
                url=CONSOLE_URL,
                title="Apify Console",
                visible_text="API & Integrations",
                elements=(),
                locators=(),
                fingerprint="console-post-login",
            )
        if self.state in ("app_created", "credential_surface"):
            return PageInspection(
                url=SURFACE_URL,
                title="API & Integrations",
                visible_text="API token",
                elements=(
                    SnapshotElement(
                        index=0,
                        role="textbox",
                        name="API token",
                        element_type="text",
                        has_value=True,
                        secretish=True,
                    ),
                ),
                locators=(),
                fingerprint="credential-surface",
            )
        raise AssertionError(f"site is not on the login page (state={self.state})")

    async def fill_from_grant(
        self, *, kinds: Sequence[str], reference: str, kind: str, grant: str
    ) -> None:
        # The browser is handed references and grants; no value crosses here.
        assert reference.startswith("vault://apify/")
        assert grant
        self.fills.append((reference, grant))
        self.state = "login_filled"

    async def click_index(self, *, element_index: int, inspection: PageInspection) -> None:
        assert element_index == 2
        assert self.state == "login_filled"
        self.logins += 1
        self.state = "submitted"

    # --- the credential surface ---------------------------------------------

    async def arm_credential_surface(self) -> bool:
        return self.state in ("app_created", "credential_surface")

    async def read_pattern_matched(
        self,
        *,
        element_indexes: Sequence[int],
        inspection: PageInspection,
        value_pattern: str,
    ) -> tuple[str, ...]:
        # The browser is asked for matching values only; the value never crosses
        # the run boundary. The value is pattern-checked by the capture boundary
        # again before it is stored, so a page that returns garbage is refused.
        assert self.state in ("app_created", "credential_surface")
        assert inspection.fingerprint == "credential-surface"
        assert list(element_indexes) == [0]
        assert re.fullmatch(value_pattern, CREDENTIAL_VALUE) is not None
        return (CREDENTIAL_VALUE,)


@dataclass
class _Sessions:
    """Hands the driver the one session a run is driven on."""

    site: _ApifySite
    opened: list[OnboardingPhase] = field(default_factory=list)

    async def session_for(self, *, run_id: str, phase: OnboardingPhase, lease: Lease) -> _ApifySite:
        del run_id, lease
        self.opened.append(phase)
        return self.site


# --- the fake inference backend, credential probe, and fetcher ---------------


class _Decider:
    """Picks the first id the schema offers, as a constrained backend would."""

    async def choose(self, prompt: str, *, schema: Mapping[str, object]) -> Mapping[str, object]:
        del prompt
        properties = schema["properties"]
        assert isinstance(properties, Mapping)
        candidate_id = properties["candidate_id"]
        assert isinstance(candidate_id, Mapping)
        ids = candidate_id["enum"]
        assert isinstance(ids, Sequence)
        return {"decision": "select_candidate", "candidate_id": ids[0], "reason": "next step"}


@dataclass
class _Validator:
    """The provider's read-only probe: it answers for a reference, never a value."""

    probed: list[str] = field(default_factory=list)

    async def validate(self, *, reference: str, policy: object) -> CredentialValidationResult:
        self.probed.append(reference)
        return CredentialValidationResult(
            status="valid",
            endpoint="https://api.apify.com/v2/users/me",
            http_status=200,
            checked_at="2025-01-01T00:00:00Z",
            reason_code="credential_valid",
        )


class _FakeFetcher:
    """Returns one corroborating document for every URL it was asked for."""

    async def fetch_many(self, urls: Sequence[str]) -> tuple[EvidenceDocument, ...]:
        return tuple(
            EvidenceDocument(
                source_url=url,
                title="Apify documentation",
                relevant_text=f"{_CORROBORATION} See {url} for the current details.",
            )
            for url in urls
        )


class _NeverStartedPlaywright:
    """Any call proves a session was opened before research ran."""

    provider_name = "playwright"

    async def start(self, profile_id: str | None, **_kwargs: object) -> object:
        raise AssertionError("an apify login-route run must not start an in-process browser")

    async def stop(self, context: object) -> None:
        del context


# --- the assembled system ----------------------------------------------------


@dataclass
class _Composed:
    settings: Settings
    service: RunService
    runtime: MountedOnboardingRuntime
    sites: dict[str, _ApifySite]


def _company() -> CompanyProfile:
    return CompanyProfile(
        legal_name="Example Labs, Inc.",
        website="https://example.com",
        work_email_ref="vault://company/work_email/profile_1",
        use_case="Connect the authorized integration.",
    )


@pytest.fixture
def composed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[_Composed]:
    db_path = tmp_path / "private" / "ops.db"
    settings = Settings(
        ops_db_path=db_path,
        secret_vault_db_path=tmp_path / "private" / "secret_vault.db",
        secret_vault_key=SecretStr(Fernet.generate_key().decode()),
        provider_effects_db_path=tmp_path / "private" / "provider_effects.db",
        browser_service_owner=OWNER,
    )
    service = RunService.from_paths(db_path=db_path, settings=settings)
    # The production path builds the vault in ``startup()`` before any run can
    # be created; the login pair is persisted at creation time and the mounted
    # probe reads it back through this same database file. The offline fixture
    # reproduces exactly that wiring instead of running the full startup.
    service._secret_store = SQLiteSecretStore(  # type: ignore[assignment]
        settings.secret_vault_db_path,
        settings.secret_vault_key.get_secret_value(),
    )
    browser = _NeverStartedPlaywright()
    service._browser_workers = {"playwright": browser}  # type: ignore[assignment]
    service._browser_worker = browser  # type: ignore[assignment]

    runtime = MountedOnboardingRuntime(settings, ledger_path=str(db_path))
    # The two outbound seams replaced on the composed value rather than around
    # it: the credential probe would otherwise reach the provider, and the
    # action-loop decider has no inference backend wired in this deployment.
    runtime._ports = replace(
        runtime._ports,
        decider=cast(Any, _Decider()),
        validator=cast(Any, _Validator()),
    )
    sites: dict[str, _ApifySite] = {}

    def fake_sessions(run_id: str, app_slug: str, **_kwargs: object) -> Any:
        assert app_slug == APP_SLUG
        site = sites.setdefault(
            run_id,
            _ApifySite(
                vault=cast(Any, runtime._ports.vault),
                session_id=f"session-apify-e2e-{len(sites) + 1}",
            ),
        )
        return _Sessions(site)

    monkeypatch.setattr(runtime, "_loop_sessions", fake_sessions)
    monkeypatch.setattr(
        runtime,
        "_evidence_fetcher",
        lambda client, policy, static_urls: cast(Any, _FakeFetcher()),
    )
    try:
        yield _Composed(settings=settings, service=service, runtime=runtime, sites=sites)
    finally:
        asyncio.run(runtime.aclose())


def _login_request() -> OperationsRequest:
    return OperationsRequest(
        app_name=APP_NAME,
        company=_company(),
        account_mode="existing_account",
        onboarding=True,
        browser_provider="playwright",
        credential_surface_url=SURFACE_URL,
    )


def _create_run(
    composed: _Composed,
    *,
    with_credentials: bool,
) -> tuple[str, _ApifySite]:
    service, runtime, sites = composed.service, composed.runtime, composed.sites
    result = service.create_run(
        _login_request(),
        execution_mode="execute_when_configured",
        browser_login=(
            {
                "login_email": SecretStr(LOGIN_EMAIL),
                "login_password": SecretStr(LOGIN_PASSWORD),
            }
            if with_credentials
            else None
        ),
    )
    run_id = str(result["run_id"])
    for thread in service._browser_threads:
        thread.join(timeout=5)
    site = _drive_to_terminal(runtime, service, sites, run_id)
    return run_id, site


def _drive_to_terminal(
    runtime: MountedOnboardingRuntime,
    service: RunService,
    sites: dict[str, _ApifySite],
    run_id: str,
) -> _ApifySite:
    """Advance one run exactly like the API's drain sweep, to a terminal status."""

    for _ in range(80):
        record = service.storage.get_run(run_id)
        assert record is not None
        status = str(record["status"])
        if status in TERMINAL_STATUSES:
            assert run_id in sites, "the walk never opened a session for the run"
            return sites[run_id]
        asyncio.run(runtime.advance(run_id))
    raise AssertionError(
        f"run {run_id} never reached a terminal status; history="
        f"{[(b.from_phase, b.to_phase, b.reason_code) for b in runtime.ports.phases.history(run_id=run_id)]}"
        f"; record={ {k: service.storage.get_run(run_id)[k] for k in ('status', 'phase', 'reason_code')} if service.storage.get_run(run_id) else None }"
        f"; reservations={[(r['operation_key'], r['disposition'], r['receipt']) for r in runtime.ports.ledger.list_effect_reservations(run_id=run_id)]}"
    )


def _walk_asserts(
    composed: _Composed,
    *,
    run_id: str,
    site: _ApifySite,
    expected_account_ref: str,
) -> None:
    """The properties both runs must share: one login, one capture, zero prompts."""

    runtime, service = composed.runtime, composed.service
    record = service.storage.get_run(run_id)
    assert record is not None
    assert str(record["status"]) == "completed"
    assert str(record["browser_account_ref"]) == expected_account_ref
    assert str(record["browser_session_id"]) == site.session_id

    decision = runtime.ports.ledger.read_admission_decision(run_id)
    assert decision is not None
    assert decision.route == "login"
    assert decision.decided_by == "system"
    assert decision.reason_code == "credentials_present"

    outcome = runtime.ports.ledger.read_autonomy_outcome(run_id)
    assert outcome is not None
    assert str(outcome["terminal_phase"]) == "completed"
    assert str(outcome["verdict"]) == "fully_autonomous"
    assert int(outcome["admission_prompts"]) == 0
    assert int(outcome["other_operator_prompts"]) == 0
    assert int(outcome["captcha_prompts"]) == 0

    # Exactly one login submission, every fill a reference, one captured key.
    assert site.logins == 1
    assert len(site.fills) == 2
    for reference, _grant in site.fills:
        assert reference.startswith("vault://apify/")
    captured_refs = [
        f"vault://apify/onboarding_api_key/{record['receipt']['reference_id']}"
        for record in runtime.ports.ledger.list_effect_reservations(run_id=run_id)
        if record["receipt"] is not None and "reference_id" in record["receipt"]
    ]
    assert len(captured_refs) == 1
    captured = captured_refs[0]
    assert captured.startswith("vault://apify/onboarding_api_key/")
    assert runtime.ports.vault is not None
    assert runtime.ports.vault.get(captured) == CREDENTIAL_VALUE

    # The phase machine never asked anyone anything.
    history = runtime.ports.phases.history(run_id=run_id)
    assert all(boundary.to_phase != "awaiting_admission" for boundary in history)


def test_run_one_logs_in_from_the_vault_pair_and_captures_the_api_key(
    composed: _Composed,
) -> None:
    """App + credentials: sign in on the vault-probed route, zero prompts."""

    run_id, site = _create_run(composed, with_credentials=True)
    record = composed.service.storage.get_run(run_id)
    assert record is not None
    account_ref = str(record["browser_account_ref"])

    _walk_asserts(composed, run_id=run_id, site=site, expected_account_ref=account_ref)

    # The pair this run supplied became the vault's stored pair for the app.
    selected = composed.runtime.ports.vault.get_unique_account_login_pair(app_slug=APP_SLUG)
    assert selected is not None
    selected_account_ref, pair = selected
    assert selected_account_ref == account_ref
    assert pair["login_email"] == LOGIN_EMAIL
    assert pair["login_password"] == LOGIN_PASSWORD


def test_run_two_reuses_the_stored_pair_without_an_admission_prompt(
    composed: _Composed,
) -> None:
    """New run id, same account ref: the pair comes back from the vault."""

    first_run_id, first_site = _create_run(composed, with_credentials=True)
    first_record = composed.service.storage.get_run(first_run_id)
    assert first_record is not None
    account_ref = str(first_record["browser_account_ref"])

    second_run_id, second_site = _create_run(composed, with_credentials=False)

    _walk_asserts(
        composed,
        run_id=second_run_id,
        site=second_site,
        expected_account_ref=account_ref,
    )

    # The returning run reused the SAME stored pair; nothing new was written.
    selected = composed.runtime.ports.vault.get_unique_account_login_pair(app_slug=APP_SLUG)
    assert selected is not None
    selected_account_ref, pair = selected
    assert selected_account_ref == account_ref
    assert pair["login_email"] == LOGIN_EMAIL
    assert pair["login_password"] == LOGIN_PASSWORD

    # Neither run ever asked an operator anything.
    for run_id in (first_run_id, second_run_id):
        history = composed.runtime.ports.phases.history(run_id=run_id)
        assert all(boundary.to_phase != "awaiting_admission" for boundary in history)
        outcome = composed.runtime.ports.ledger.read_autonomy_outcome(run_id)
        assert outcome is not None
        assert int(outcome["admission_prompts"]) == 0
        assert int(outcome["other_operator_prompts"]) == 0
