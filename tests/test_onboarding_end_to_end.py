"""One signup run, walked end to end through the assembled onboarding ports.

This is the walkthrough of task 25.4, and it is deliberately not a matrix. It
exists to show that the pieces the rest of this feature builds in isolation run
as one system: the composition root binds the ports, the driver walks the phase
machine, and the run comes out the other end holding a credential the validator
proved and one durable autonomy outcome.

What is real: ``build_onboarding_ports`` composes every port, and the run ledger,
the profile store, the vault, and the effect ledger are real SQLite files under
``tmp_path``. The phase boundaries, the effect reservations, the vault rows, and
the outcome row are all written by the production code that owns them.

What is fake, and only ever behind an LL-2 ``Protocol``: the provider site (the
loop's session port, the signup submitter, the verification session, and the
credential surface, all one object because the run walks one site), the research
adapters (``ProfileDiscovery`` / ``ProfileEvidenceFetcher`` / ``ProfileExtractor``
— the two the deployment binds to ``None`` by design are supplied here), the
inference backend (``CandidateDecider``), the mailbox
(``VerificationProvider``), and the credential probe
(``CredentialValidatorPort``). Nothing reaches the network, which the autouse
fixture below enforces rather than assumes.

The run takes two worker turns, because that is what the sequence actually is
(design "Sequence Diagrams" 1): the first turn researches the provider, finds no
stored credentials, and stops at ``awaiting_admission``; the operator's decision
is then recorded durably (Requirement 3.5); the second turn walks signup,
verification, the developer application, and the credential lifecycle through to
``completed``.

The phases with no production handler in this tree — research, the vault probe,
admission, the route, and the credential lifecycle — are registered here through
``OnboardingPorts.deps_for(handlers=...)``, which is the seam they exist for.
Each one calls the production component that owns the decision and returns an
inert ``PhaseStep``; the driver remains the only committer.
"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from ops.browser import signup as signup_phase
from ops.browser.candidates import ActionCandidate
from ops.browser.signup import (
    SignupIdentity,
    SignupPhaseHandler,
    SignupSecretFill,
    SignupSubmission,
)
from ops.browser.worker import BrowserObservation
from ops.core.config import Settings
from ops.core.effect_ledger import SQLiteEffectStore
from ops.core.secret_store import EmailMessageIngestionReservation, SQLiteSecretStore
from ops.core.storage import OperationsStorage
from ops.credentials.validator import CredentialValidationResult
from ops.email.verification import VerificationCandidate
from ops.email.verification_provider import VerificationQuery
from ops.onboarding.action_loop import LoopObservation
from ops.onboarding.admission import admit_from_vault, decide_from_operator
from ops.onboarding.composition import (
    OnboardingPorts,
    ProfileResearchPorts,
    SettingsRunPlanner,
    build_onboarding_ports,
)
from ops.onboarding.credentials import (
    CredentialLifecycleDeps,
    CredentialStep,
    capture_store_validate_publish,
)
from ops.onboarding.driver import (
    DEVELOPER_APP_RECEIPT_KEY,
    DeveloperAppPhaseHandler,
    DeveloperAppRequest,
    OnboardingDeps,
    PhaseStep,
    VerificationContext,
    developer_app_name,
    drive_run,
    phase_correlation_id,
)
from ops.onboarding.effects import create_dev_app_key, plan_effect
from ops.onboarding.lease import Lease, deadline_after
from ops.onboarding.phase import OnboardingPhase
from ops.providers.profile import ProfileField, ProviderProfile
from ops.providers.profile_builder import ProfileClaim, build_profile, discovery_adapter
from ops.providers.profile_store import ProviderProfileStore
from ops.recipes.app_recipes import SignupPolicy
from ops.research.operational_research import EvidenceDocument

# The run and its bindings. Both identifiers are the opaque forms the vault's own
# grammar admits, because this walk stores credentials in the real vault.
RUN_ID = "run_" + "ab" * 16
ACCOUNT_REF = "acct_" + "cd" * 16
SESSION_ID = "session-e2e-1"
OWNER = "ops-owner"
WORKER = "worker-e2e"

PROVIDER_NAME = "Provider"
APP_SLUG = "provider"
CREDENTIAL_KIND = "api_key"

# The fake provider's own surfaces. Every one of them is on the single
# registrable domain the research evidence corroborates, so the allow-list the
# profile derives admits them all.
DOCS_URL = "https://developers.provider.com/docs"
GUIDE_URL = "https://developers.provider.com/guide"
SIGNUP_URL = "https://provider.com/signup"
LOGIN_URL = "https://app.provider.com/login"
PORTAL_URL = "https://developers.provider.com/apps"
DEV_APP_URL = "https://developers.provider.com/apps/new"
API_KEY_URL = "https://app.provider.com/settings/api"  # pragma: allowlist secret
WELCOME_URL = "https://app.provider.com/welcome"
APP_CREATED_URL = "https://developers.provider.com/apps/app-e2e-1"
VALIDATION_ENDPOINT = "https://api.provider.com/v1/me"
VERIFY_LINK = "https://app.provider.com/verify-email?token=e2e"

MAILBOX = "ops.signup+provider@gmail.com"
MESSAGE_ID = "msg-e2e-1"
APP_ID = "app-e2e-1"
CREDENTIAL_VALUE = "pk_live_" + "e" * 24  # pragma: allowlist secret


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """The walkthrough runs entirely on fakes; a socket would be a wiring bug."""

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("the onboarding walkthrough must not reach the network")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)


def _now_ms() -> int:
    return int(datetime.now(UTC).timestamp() * 1000)


def _page(
    *,
    status: str,
    url: str,
    title: str,
    reason_code: str | None = None,
    developer_app_id: str | None = None,
    controls: tuple[str, ...] = (),
) -> LoopObservation:
    """One page as the browser would report it, plus the controls it renders."""

    return LoopObservation(
        observation=BrowserObservation(
            status=cast(Any, status),
            current_url=url,
            page_title=title,
            reason_code=reason_code,
            developer_app_id=developer_app_id,
        ),
        raw_elements=tuple(
            {"role": "button", "name": name, "visible": True, "enabled": True} for name in controls
        ),
    )


# --- the fake provider site --------------------------------------------------


@dataclass
class _ProviderSite:
    """The provider, behind every port that touches a page or a form.

    One object rather than four fakes, because a run walks one site on one
    session: the signup form, the verification page, the developer console, and
    the credential surface are the same provider at four points in the walk. The
    state moves forward only when the system does something to the page.
    """

    vault: SQLiteSecretStore
    session_id: str = SESSION_ID
    state: str = "anonymous"
    acted: list[str] = field(default_factory=list)
    armed_before_capture: bool = False
    captured: list[str] = field(default_factory=list)

    # --- the loop's session port --------------------------------------------

    async def observe(self) -> LoopObservation:
        if self.state == "app_created":
            return _page(
                status="developer_console_ready",
                url=APP_CREATED_URL,
                title="Application created",
                developer_app_id=APP_ID,
            )
        if self.state == "console":
            return _page(
                status="developer_console_ready",
                url=PORTAL_URL,
                title="Developer applications",
                controls=("Create app",),
            )
        # Signed up and verified: the provider's post-verification landing page,
        # which is where the ``authenticated`` phase starts from.
        return _page(
            status="navigating",
            url=WELCOME_URL,
            title="Welcome",
            reason_code="verification_email_found",
            controls=("Developer settings",),
        )

    async def act(self, candidate: ActionCandidate) -> None:
        self.acted.append(candidate.semantic_target)
        if self.state == "verified":
            self.state = "console"
        elif self.state == "console":
            self.state = "app_created"

    # --- the signup submitter -----------------------------------------------

    async def submit_signup(
        self,
        *,
        run_id: str,
        session_id: str,
        fills: Sequence[SignupSecretFill],
        fields: Mapping[str, str],
    ) -> SignupSubmission:
        # The browser is handed references and grants; no value crosses here.
        assert all(fill.reference and fill.grant for fill in fills)
        self.state = "signed_up"
        return SignupSubmission(status="submitted", receipt={"provider_account": "acct-e2e"})

    # --- the verification session -------------------------------------------

    async def navigate_verification_link(self, link: SecretStr) -> None:
        assert link.get_secret_value().startswith("https://app.provider.com/")
        self.state = "verified"

    async def inject_one_time_code(self, *, reference: str, kind: str, grant: str) -> None:
        raise AssertionError("this provider verifies by link, not by code")

    # --- the credential surface ---------------------------------------------

    async def arm_credential_surface(self) -> bool:
        self.armed_before_capture = not self.captured
        return True

    async def capture_credential(self, *, grant: str, kind: str) -> str:
        # What the broker does on the far side of this port: the value is written
        # to the vault inside the browser process and only a reference comes back.
        reference = self.vault.put(app_slug=APP_SLUG, kind=kind, value=CREDENTIAL_VALUE)
        self.captured.append(reference)
        return reference


@dataclass
class _Sessions:
    """Hands the driver the one session this run is driven on."""

    site: _ProviderSite
    opened: list[OnboardingPhase] = field(default_factory=list)

    async def session_for(
        self, *, run_id: str, phase: OnboardingPhase, lease: Lease
    ) -> _ProviderSite:
        self.opened.append(phase)
        return self.site


# --- the fake research adapters ----------------------------------------------


@dataclass
class _Discovery:
    """A named discovery adapter that proposes evidence URLs and nothing more."""

    name: str = "fake-search"

    async def discover(self, *, app_name: str) -> tuple[str, ...]:
        return (DOCS_URL, GUIDE_URL)


@dataclass
class _Fetcher:
    """Returns the prepared excerpt for each URL it was asked for."""

    documents: Mapping[str, str]

    async def fetch_many(self, urls: Sequence[str]) -> tuple[EvidenceDocument, ...]:
        return tuple(
            EvidenceDocument(source_url=url, title="Provider docs", relevant_text=text)
            for url in urls
            if (text := self.documents.get(url)) is not None
        )


@dataclass
class _Extractor:
    """Emits the claims each document supports, cited to that document."""

    claims: Mapping[str, Mapping[str, str]]

    async def extract(
        self, *, app_name: str, documents: tuple[EvidenceDocument, ...]
    ) -> tuple[ProfileClaim, ...]:
        return tuple(
            ProfileClaim(
                field=cast(ProfileField, name),
                value=value,
                source_url=document.source_url,
                confidence=0.9,
            )
            for document in documents
            for name, value in self.claims.get(document.source_url, {}).items()
        )


def _research_ports() -> ProfileResearchPorts:
    """The three research ports, with corroborated evidence for one provider."""

    shared = f"Provider developer documentation. provider.com {SIGNUP_URL} {LOGIN_URL}"
    documents = {
        DOCS_URL: f"{shared} {DOCS_URL} {PORTAL_URL} {DEV_APP_URL} {API_KEY_URL}",
        GUIDE_URL: f"{shared} getting started",
    }
    required = {
        "registrable_domain": "provider.com",
        "signup_url": SIGNUP_URL,
        "login_url": LOGIN_URL,
    }
    return ProfileResearchPorts(
        discovery=(discovery_adapter(_Discovery()),),
        fetcher=cast(Any, _Fetcher(documents)),
        extractor=cast(
            Any,
            _Extractor(
                {
                    DOCS_URL: {
                        **required,
                        "developer_docs_url": DOCS_URL,
                        "developer_portal_url": PORTAL_URL,
                        "developer_app_flow": DEV_APP_URL,
                        "api_key_flow": API_KEY_URL,
                    },
                    GUIDE_URL: dict(required),
                }
            ),
        ),
    )


# --- the fake inference backend, mailbox, validator, and publisher ------------


class _Decider:
    """Picks the first id the schema offers, as a constrained backend would."""

    async def choose(self, prompt: str, *, schema: Mapping[str, object]) -> Mapping[str, object]:
        properties = schema["properties"]
        assert isinstance(properties, Mapping)
        candidate_id = properties["candidate_id"]
        assert isinstance(candidate_id, Mapping)
        ids = candidate_id["enum"]
        assert isinstance(ids, Sequence)
        return {"decision": "select_candidate", "candidate_id": ids[0], "reason": "next step"}


@dataclass
class _Mailbox:
    """The run's mailbox: one bound, authenticated, fresh verification message."""

    journal: list[str] = field(default_factory=list)
    name: str = "fake_mailbox"
    kind: str = "vendor_api"

    def is_configured(self) -> bool:
        return True

    async def search(self, query: VerificationQuery) -> tuple[VerificationCandidate, ...]:
        # The query the driver asked with is bound to this run's own alias.
        assert query.expected_recipient == MAILBOX
        self.journal.append("search")
        return (
            VerificationCandidate(
                message_id=MESSAGE_ID,
                sender="no-reply@provider.com",
                recipients=(MAILBOX,),
                received_at=str(_now_ms()),
                subject="Verify your email",
                body=f"Confirm your address: {VERIFY_LINK}",
                authentication_results=(
                    "mx.google.com; dkim=pass header.i=@provider.com; "
                    "dmarc=pass header.from=provider.com",
                ),
            ),
        )

    async def claim(self, *, message_id: str, run_id: str) -> EmailMessageIngestionReservation:
        self.journal.append("claim")
        return EmailMessageIngestionReservation(status="acquired", claim_token="claim-e2e-1")

    async def release(self, *, message_id: str, run_id: str, claim_token: str) -> None:
        self.journal.append("release")

    async def settle(self, *, message_id: str, run_id: str, claim_token: str) -> None:
        self.journal.append("settle")


@dataclass
class _Validator:
    """The provider's read-only probe: it answers for a reference, never a value."""

    probed: list[str] = field(default_factory=list)

    async def validate(self, *, reference: str, policy: object) -> CredentialValidationResult:
        self.probed.append(reference)
        return CredentialValidationResult(
            status="valid",
            endpoint=VALIDATION_ENDPOINT,
            http_status=200,
            checked_at="2025-01-01T00:00:00Z",
            reason_code="credential_valid",
        )


@dataclass
class _Publisher:
    """Where a proven credential becomes published provider configuration."""

    published: list[tuple[str, str, str]] = field(default_factory=list)

    def publish_provider_configuration(
        self,
        *,
        run_id: str,
        reference: str,
        kind: str,
        result: CredentialValidationResult,
        completed_at: str,
    ) -> None:
        self.published.append((reference, result.status, completed_at))


@dataclass
class _SignupBinding:
    """The run's durable signup bindings: mailbox alias, account, session."""

    def signup_identity(self, *, run_id: str) -> SignupIdentity:
        return SignupIdentity(
            account_ref=ACCOUNT_REF, session_id=SESSION_ID, signup_address=MAILBOX
        )


@dataclass
class _DeveloperAppBinding:
    """What the run wants out of the developer-application phase."""

    def developer_app_request(self, *, run_id: str) -> DeveloperAppRequest:
        return DeveloperAppRequest(owner_id=OWNER, credential_kind=CREDENTIAL_KIND)


@dataclass
class _VerificationBinding:
    """Which mailbox the run verifies with, and on which still-alive session."""

    site: _ProviderSite

    def verification_context(
        self, *, run_id: str, challenge_issued_at_ms: int
    ) -> VerificationContext:
        return VerificationContext(
            mailbox_address=MAILBOX,
            session_id=self.site.session_id,
            challenge_issued_at_ms=challenge_issued_at_ms,
        )

    async def verification_session(self, *, run_id: str, lease: Lease) -> _ProviderSite:
        return self.site


# --- the phases no production handler owns yet -------------------------------


@dataclass
class _WalkHandlers:
    """The handlers this walk supplies for the phases no production one owns.

    Each one calls the production component that owns it — the profile builder,
    the admission service, the credential lifecycle — and returns an inert
    ``PhaseStep``. None of them writes a phase boundary; the driver does that.
    """

    research: ProfileResearchPorts
    ledger: OperationsStorage
    vault: SQLiteSecretStore
    credentials: CredentialLifecycleDeps
    site: _ProviderSite
    earned: CredentialStep | None = None

    async def research_provider(
        self,
        *,
        run_id: str,
        phase: OnboardingPhase,
        profile: ProviderProfile | None,
        lease: Lease,
        deps: OnboardingDeps,
    ) -> PhaseStep:
        fetcher = self.research.fetcher
        extractor = self.research.extractor
        assert fetcher is not None and extractor is not None
        built = await build_profile(
            run_id=run_id,
            provider_name=PROVIDER_NAME,
            app_slug=APP_SLUG,
            adapters=self.research.discovery,
            fetcher=fetcher,
            extractor=extractor,
            store=cast(ProviderProfileStore, deps.profiles),
        )
        assert isinstance(built, ProviderProfile)
        return PhaseStep.advance(
            "vault_check", "profile_corroborated", profile_digest=built.profile_digest
        )

    async def probe_vault(
        self,
        *,
        run_id: str,
        phase: OnboardingPhase,
        profile: ProviderProfile | None,
        lease: Lease,
        deps: OnboardingDeps,
    ) -> PhaseStep:
        assert profile is not None
        outcome = admit_from_vault(
            self.vault,
            run_id=run_id,
            profile_digest=profile.profile_digest,
            app_slug=profile.app_slug,
            app_name=profile.provider_name,
            account_ref=ACCOUNT_REF,
            owner_id=OWNER,
        )
        return PhaseStep.advance(outcome.phase, outcome.reason_code)

    async def await_admission(
        self,
        *,
        run_id: str,
        phase: OnboardingPhase,
        profile: ProviderProfile | None,
        lease: Lease,
        deps: OnboardingDeps,
    ) -> PhaseStep:
        decision = self.ledger.read_admission_decision(run_id)
        if decision is None or decision.route != "signup":
            # Nobody has answered yet, so the run comes back rather than
            # advancing on a decision that does not exist (Requirement 3.5).
            return PhaseStep.defer(deadline_after(300), "signup_authorization_required")
        return PhaseStep.advance("route_selected_signup", decision.reason_code)

    async def enter_signup(
        self,
        *,
        run_id: str,
        phase: OnboardingPhase,
        profile: ProviderProfile | None,
        lease: Lease,
        deps: OnboardingDeps,
    ) -> PhaseStep:
        return PhaseStep.advance("signup", "operator_approved_signup")

    async def generate_credential(
        self,
        *,
        run_id: str,
        phase: OnboardingPhase,
        profile: ProviderProfile | None,
        lease: Lease,
        deps: OnboardingDeps,
    ) -> PhaseStep:
        assert profile is not None
        # The developer application id comes from the reservation the previous
        # phase completed, which is the receipt Requirement 9.6 recorded it as.
        plan = plan_effect(
            self.credentials.effects,
            operation_key=create_dev_app_key(
                run_id, profile, developer_app_name(owner_id=OWNER, run_id=run_id)
            ),
            action="create_dev_app",
        )
        assert plan.disposition == "skip" and plan.receipt is not None
        earned = await capture_store_validate_publish(
            run_id=run_id,
            profile=profile,
            developer_app_id=plan.receipt[DEVELOPER_APP_RECEIPT_KEY],
            kind=CREDENTIAL_KIND,
            session=self.site,
            deps=self.credentials,
            attempt=0,
            correlation_id=phase_correlation_id(run_id=run_id, phase=phase, attempt=0),
        )
        # The lifecycle committed ``vault_storage`` and ``credential_validation``
        # itself (Requirement 10.7), so the step it returns is anchored at the
        # phase the run durably stands in — ``credential_validation`` — and the
        # driver commits the boundary it names from there, exactly as the
        # production ``CredentialPhaseHandler`` maps it.
        return PhaseStep(
            kind=earned.kind,
            reason_code=earned.reason_code,
            next_phase=earned.next_phase,
            not_before=earned.not_before,
        )


# --- the assembled system ----------------------------------------------------


@dataclass
class _Walkthrough:
    ports: OnboardingPorts
    deps: OnboardingDeps
    site: _ProviderSite
    publisher: _Publisher
    validator: _Validator


@pytest.fixture
def walkthrough(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[_Walkthrough]:
    # The fake provider has no catalog entry, so the reviewed signup policy the
    # catalog would return for it is supplied here: signup is admitted only where
    # a policy exists (Requirement 7.1).
    monkeypatch.setattr(
        signup_phase,
        "declared_signup_policy",
        lambda app_slug: SignupPolicy(
            flow="email_first",
            entry_path_prefixes=("/signup",),
            entry_submit_labels=("Create account",),
            entry_submit_implies_legal_acceptance=False,
        ),
    )
    db_path = tmp_path / "private" / "ops.db"
    settings = Settings(
        ops_db_path=db_path,
        secret_vault_db_path=tmp_path / "private" / "secret_vault.db",
        secret_vault_key=SecretStr(Fernet.generate_key().decode()),
        provider_effects_db_path=tmp_path / "private" / "provider_effects.db",
        groq_api_key=SecretStr("gsk_" + "a" * 40),
        browser_service_owner=OWNER,
    )
    composed = build_onboarding_ports(settings, ledger_path=db_path)
    composed.ledger.create_run(
        run_id=RUN_ID,
        thread_id=f"thread-{RUN_ID}",
        app_name=PROVIDER_NAME,
        app_slug=APP_SLUG,
    )
    mailbox = _Mailbox()
    validator = _Validator()
    # The five outbound seams, replaced on the composed value rather than around
    # it: research is the pair this deployment binds to ``None`` by design, and
    # the other four would otherwise reach a provider.
    #
    # ``planner`` is the fifth and was long invisible here: before the route
    # authority widened to committed profiles, ``plan_admission`` resolved this
    # fake provider's slug against the catalog, found nothing, and refused before
    # the planner was ever consulted. The profile path now reaches it, so the
    # chain it holds has to be closed like any other outbound seam. ``None``
    # means "plan with no model": the deterministic profile route is a
    # first-class outcome (``plan_provider_unconfigured``), which is exactly what
    # an offline deployment gets.
    ports = replace(
        composed,
        research=_research_ports(),
        decider=cast(Any, _Decider()),
        verification=cast(Any, mailbox),
        validator=cast(Any, validator),
        planner=SettingsRunPlanner(settings, inference=None),
    )
    assert ports.vault is not None
    site = _ProviderSite(vault=ports.vault)
    effects = SQLiteEffectStore(settings.provider_effects_db_path)
    publisher = _Publisher()
    handlers = _WalkHandlers(
        research=ports.research,
        ledger=ports.ledger,
        vault=ports.vault,
        credentials=CredentialLifecycleDeps(
            journal=ports.phases,
            effects=effects,
            vault=ports.vault,
            validator=cast(Any, ports.validator),
            publisher=publisher,
            research_endpoint=VALIDATION_ENDPOINT,
        ),
        site=site,
    )
    deps = ports.deps_for(
        run_id=RUN_ID,
        sessions=cast(Any, _Sessions(site)),
        handlers={
            "research": handlers.research_provider,
            "vault_check": handlers.probe_vault,
            "awaiting_admission": handlers.await_admission,
            "route_selected_signup": handlers.enter_signup,
            "signup": SignupPhaseHandler(
                vault=ports.vault,
                effects=effects,
                binding=_SignupBinding(),
                submitter=site,
            ),
            "developer_app": DeveloperAppPhaseHandler(
                effects=effects, binding=_DeveloperAppBinding()
            ),
            "credential_generation": handlers.generate_credential,
        },
        verification_binding=cast(Any, _VerificationBinding(site)),
    )
    try:
        yield _Walkthrough(
            ports=ports,
            deps=deps,
            site=site,
            publisher=publisher,
            validator=validator,
        )
    finally:
        asyncio.run(ports.aclose())


def test_one_signup_run_reaches_a_validated_credential(walkthrough: _Walkthrough) -> None:
    """The whole pipeline, once: research to a proven credential (task 25.4)."""

    ports, deps = walkthrough.ports, walkthrough.deps

    # Turn one: research the provider, find no stored credentials, and stop for
    # the one decision a person owns.
    first = asyncio.run(drive_run(run_id=RUN_ID, worker_id=WORKER, deps=deps))
    assert first is not None and first.terminal_phase == "awaiting_admission"
    assert ports.ledger.read_autonomy_outcome(RUN_ID) is None

    # The operator authorizes account creation, recorded durably before signup is
    # entered (Requirement 3.5), exactly as the API records it.
    profile = ports.profiles.get_for_run(run_id=RUN_ID)
    assert profile is not None
    ports.ledger.record_admission_decision(
        decide_from_operator(
            "create_account",
            run_id=RUN_ID,
            profile_digest=profile.profile_digest,
            actor_owner_id=OWNER,
        )
    )

    # Turn two: signup, autonomous email verification, the developer
    # application, and the credential lifecycle, through to a terminal phase.
    outcome = asyncio.run(drive_run(run_id=RUN_ID, worker_id=WORKER, deps=deps))

    assert outcome is not None
    assert outcome.terminal_phase == "completed"
    # The credential the run came out with was proven by the validator against a
    # vault reference, and published only after that (Requirements 10.12, 10.14).
    assert walkthrough.validator.probed == walkthrough.site.captured
    assert [status for _, status, _ in walkthrough.publisher.published] == ["valid"]
    reference, _, completed_at = walkthrough.publisher.published[0]
    assert reference.startswith(f"vault://{APP_SLUG}/onboarding_{CREDENTIAL_KIND}/")
    assert completed_at > "2025-01-01T00:00:00Z"

    # Exactly one autonomy outcome for the run, written at the terminal phase
    # (Requirement 20.4), and no operator prompt beyond admission (11.15).
    record = ports.ledger.read_autonomy_outcome(RUN_ID)
    assert record is not None
    assert record["terminal_phase"] == "completed"
    assert record["captcha_prompts"] == 0 and record["other_operator_prompts"] == 0
    assert len(ports.ledger.list_autonomy_outcomes()) == 1
