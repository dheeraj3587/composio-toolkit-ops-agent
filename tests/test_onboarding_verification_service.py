"""One happy-path check of the autonomous verification service (LL-3.4).

Exercises the path that matters: a run-bound query reaches the mailbox through the
``VerificationProvider`` port, the bound message's link is navigated on the run's
own session, the claim is settled exactly once, and the phase advances into
``authenticated`` with ``verification_email_found`` (Requirements 7.4, 7.14, 7.21,
7.23, 7.30).
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime

from pydantic import SecretStr

from ops.browser.worker import BrowserObservation
from ops.core.secret_store import EmailMessageIngestionReservation
from ops.email.verification import VerificationCandidate
from ops.email.verification_provider import VerificationQuery
from ops.onboarding.action_loop import LoopObservation
from ops.onboarding.driver import (
    VerificationBudget,
    VerificationContext,
    await_verification,
    verification_backoff_seconds,
)
from ops.providers.profile import FieldEvidence, FlowSpec, ProviderProfile, compute_profile_digest

DIGEST = "a" * 64
RUN_ID = "run-verify-1"
SESSION_ID = "session-1"
MAILBOX = "ops.signup+provider@gmail.com"
MESSAGE_ID = "msg-1"
VERIFY_LINK = "https://app.provider.com/verify-email?token=abc"


def _profile() -> ProviderProfile:
    profile = ProviderProfile(
        run_id=RUN_ID,
        provider_name="Provider",
        app_slug="provider",
        registrable_domain="provider.com",
        auxiliary_hosts=(),
        developer_portal_url="https://developers.provider.com/",
        signup_url="https://provider.com/signup",
        login_url="https://app.provider.com/login",
        developer_docs_url="https://developers.provider.com/docs",
        developer_app_flow=FlowSpec(
            kind="developer_app",
            supported=True,
            entry_url="https://developers.provider.com/apps/new",
        ),
        oauth_flow=FlowSpec(kind="oauth", supported=False, entry_url=None),
        api_key_flow=FlowSpec(
            kind="api_key", supported=True, entry_url="https://app.provider.com/settings/api"
        ),
        pat_flow=FlowSpec(kind="pat", supported=False, entry_url=None),
        approval_requirement="none",
        billing_requirement="none",
        evidence=(
            FieldEvidence(
                field="signup_url",
                value="https://provider.com/signup",
                source_url="https://provider.com/docs",
                source_digest=DIGEST,
                adapters=("fake-discovery",),
                corroborations=2,
                confidence=0.9,
                extracted_at="2025-01-01T00:00:00Z",
            ),
        ),
        confidence=0.9,
        adapters_engaged=("fake-discovery",),
        built_at="2025-01-01T00:00:00Z",
    )
    return replace(profile, profile_digest=compute_profile_digest(profile))


@dataclass
class _Provider:
    """A mailbox holding one bound, authenticated, fresh verification message."""

    candidate: VerificationCandidate
    journal: list[str] = field(default_factory=list)
    name: str = "fake_mailbox"
    kind: str = "vendor_api"

    def is_configured(self) -> bool:
        return True

    async def search(self, query: VerificationQuery) -> tuple[VerificationCandidate, ...]:
        # Requirement 7.4: the query the service asked with is bound to this run.
        assert query.expected_recipient == MAILBOX
        self.journal.append("search")
        return (self.candidate,)

    async def claim(self, *, message_id: str, run_id: str) -> EmailMessageIngestionReservation:
        self.journal.append(f"claim:{message_id}")
        return EmailMessageIngestionReservation(status="acquired", claim_token="claim-1")

    async def release(self, *, message_id: str, run_id: str, claim_token: str) -> None:
        self.journal.append("release")

    async def settle(self, *, message_id: str, run_id: str, claim_token: str) -> None:
        self.journal.append("settle")


@dataclass
class _Session:
    """The still-alive signup session, journalling what it was asked to do."""

    journal: list[str] = field(default_factory=list)
    navigated_host: str = ""

    @property
    def session_id(self) -> str:
        return SESSION_ID

    async def navigate_verification_link(self, link: SecretStr) -> None:
        self.journal.append("navigate")
        self.navigated_host = link.get_secret_value().split("/")[2]

    async def inject_one_time_code(self, *, reference: str, kind: str, grant: str) -> None:
        self.journal.append("inject")

    async def observe(self) -> LoopObservation:
        return LoopObservation(
            observation=BrowserObservation(
                status="developer_console_ready",
                current_url="https://app.provider.com/welcome",
                page_title="Welcome",
                reason_code="verification_email_found",
            )
        )


@dataclass
class _Vault:
    """Only reached by the code path; present so the service is fully wired."""

    values: dict[str, str] = field(default_factory=dict)

    def put_transient(
        self, *, app_slug: str, kind: str, scope_id: str, value: str, ttl_seconds: int = 600
    ) -> str:
        reference = f"vault://{app_slug}/{kind}/ref-{len(self.values)}"
        self.values[reference] = value
        return reference

    def reserve_browser_secret_grant(self, **kwargs: object) -> str:
        return "bsg_" + "a" * 43


async def test_a_bound_message_is_navigated_once_and_settles_into_authenticated() -> None:
    now = datetime.now(UTC)
    now_ms = int(now.timestamp() * 1000)
    provider = _Provider(
        candidate=VerificationCandidate(
            message_id=MESSAGE_ID,
            sender="no-reply@provider.com",
            recipients=(MAILBOX,),
            received_at=str(now_ms - 30_000),
            subject="Verify your email",
            body=f"Confirm your address: {VERIFY_LINK}",
            authentication_results=(
                "mx.google.com; dkim=pass header.i=@provider.com; "
                "dmarc=pass header.from=provider.com",
            ),
        )
    )
    session = _Session()

    step = await await_verification(
        run_id=RUN_ID,
        profile=_profile(),
        provider=provider,
        session=session,
        vault=_Vault(),
        context=VerificationContext(
            mailbox_address=MAILBOX,
            session_id=SESSION_ID,
            challenge_issued_at_ms=now_ms - 60_000,
        ),
        attempt=0,
        budget=VerificationBudget(),
        clock=lambda: now,
    )

    assert step.kind == "advance"
    assert step.next_phase == "authenticated"
    assert step.reason_code == "verification_email_found"
    # Claimed once, settled once, never released (Requirements 7.16, 7.21).
    assert provider.journal == ["search", f"claim:{MESSAGE_ID}", "settle"]
    # The link was opened on the run's own session, inside the allow-list, and no
    # code injection and no second login submission happened (7.14, 7.30).
    assert session.journal == ["navigate"]
    assert session.navigated_host == "app.provider.com"
    # The ladder a later attempt would wait on is bounded and jittered (7.25).
    assert verification_backoff_seconds(budget=VerificationBudget(), attempt=4, jitter=1.0) == 30.0
