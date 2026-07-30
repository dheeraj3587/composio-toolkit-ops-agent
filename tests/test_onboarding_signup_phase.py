"""Happy-path check on the signup phase's ordering (Requirement 6).

The one thing worth a test here is the order of events, because every other
property of this phase depends on it: the credentials must be in the vault and
addressed by one reference each *before* the operation key is reserved, and the
key must be reserved before the form is submitted. A crash anywhere in that
sequence then leaves either no account, or an account whose credentials the run
still holds — never a real provider account nobody can log into.

The second test is the same ordering read from the other end: a replay finds the
reservation completed and submits nothing, which is what keeps one run from
creating two accounts.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Literal, cast

from ops.browser.signup import (
    SIGNUP_LOGIN_FIELDS,
    SignupIdentity,
    SignupPhaseHandler,
    SignupSecretFill,
    SignupSubmission,
)
from ops.core.effect_ledger import SQLiteEffectStore
from ops.onboarding.driver import OnboardingDeps
from ops.onboarding.lease import Lease
from ops.providers.profile import FieldEvidence, FlowSpec, ProviderProfile, compute_profile_digest

DIGEST = "a" * 64
RUN_ID = "run-signup-1"
ACCOUNT_REF = "mailbox-1"
SESSION_ID = "session-1"
SIGNUP_ADDRESS = "ops+provider@example.com"


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
            kind="api_key",
            supported=True,
            entry_url="https://app.provider.com/settings/api",
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
class _Vault:
    """In-memory stand-in for the signup vault, journalling what it was asked.

    It behaves like the real store in the ways this test depends on: a staged
    pair is owned by one run and replayed rather than regenerated, and a
    transient value is addressed by a reference the caller cannot read back.
    """

    journal: list[str]
    staged: dict[str, str] = field(default_factory=dict)
    values: dict[str, str] = field(default_factory=dict)
    promoted: bool = False

    def stage_signup_login_pair(
        self, *, app_slug: str, account_ref: str, run_id: str, email: str, password: str
    ) -> dict[str, str]:
        self.journal.append("stage")
        if not self.staged:
            self.staged = {"login_email": email, "login_password": password}
        return dict(self.staged)

    def get_staged_signup_login_pair(
        self, *, app_slug: str, account_ref: str, run_id: str
    ) -> dict[str, str]:
        return dict(self.staged)

    def promote_staged_signup_login_pair(
        self, *, app_slug: str, account_ref: str, run_id: str
    ) -> tuple[str, ...]:
        self.journal.append("promote")
        self.promoted = True
        return SIGNUP_LOGIN_FIELDS

    def put_transient(
        self, *, app_slug: str, kind: str, scope_id: str, value: str, ttl_seconds: int = 600
    ) -> str:
        self.journal.append(f"reference:{kind}")
        reference = f"vault://{app_slug}/{kind}/ref-{len(self.values)}"
        self.values[reference] = value
        return reference

    def reserve_browser_secret_grant(
        self,
        *,
        operation_key: str,
        run_id: str,
        session_id: str,
        app_slug: str,
        kind: str,
        action: Literal["consume", "capture"],
        reference: str | None = None,
        ttl_seconds: int = 900,
    ) -> str:
        assert reference in self.values, "a grant must name a stored reference"
        self.journal.append(f"grant:{kind}")
        return f"bsg_{kind}"


@dataclass
class _Binding:
    def signup_identity(self, *, run_id: str) -> SignupIdentity:
        return SignupIdentity(
            account_ref=ACCOUNT_REF, session_id=SESSION_ID, signup_address=SIGNUP_ADDRESS
        )


@dataclass
class _Effects:
    """The real effect ledger, with the two verbs this phase uses journalled."""

    store: SQLiteEffectStore
    journal: list[str]

    def reserve(self, *, provider: str, action: str, idempotency_key: str) -> object:
        self.journal.append("reserve")
        return self.store.reserve(provider=provider, action=action, idempotency_key=idempotency_key)

    def complete(
        self, *, provider: str, action: str, idempotency_key: str, receipt: Mapping[str, str]
    ) -> None:
        self.journal.append("complete")
        self.store.complete(
            provider=provider, action=action, idempotency_key=idempotency_key, receipt=receipt
        )

    def reconcile_completed(
        self, *, provider: str, action: str, idempotency_key: str, receipt: Mapping[str, str]
    ) -> None:  # pragma: no cover - unused on the happy path
        self.store.reconcile_completed(
            provider=provider, action=action, idempotency_key=idempotency_key, receipt=receipt
        )

    def mark_outcome_unknown(
        self, *, provider: str, action: str, idempotency_key: str
    ) -> None:  # pragma: no cover - unused on the happy path
        self.store.mark_outcome_unknown(
            provider=provider, action=action, idempotency_key=idempotency_key
        )

    def mark_failed(
        self, *, provider: str, action: str, idempotency_key: str
    ) -> None:  # pragma: no cover - unused on the happy path
        self.store.mark_failed(provider=provider, action=action, idempotency_key=idempotency_key)


@dataclass
class _Submitter:
    journal: list[str]
    seen: list[SignupSecretFill] = field(default_factory=list)

    async def submit_signup(
        self,
        *,
        run_id: str,
        session_id: str,
        fills: Sequence[SignupSecretFill],
        fields: Mapping[str, str],
    ) -> SignupSubmission:
        self.journal.append("submit")
        self.seen.extend(fills)
        return SignupSubmission(status="submitted", receipt={"provider_account": "acct-1"})


def _handler(tmp_path: Path) -> tuple[SignupPhaseHandler, list[str], _Vault, _Submitter]:
    journal: list[str] = []
    vault = _Vault(journal=journal)
    submitter = _Submitter(journal=journal)
    handler = SignupPhaseHandler(
        vault=vault,
        effects=cast(
            "SQLiteEffectStore",
            _Effects(store=SQLiteEffectStore(tmp_path / "effects.db"), journal=journal),
        ),
        binding=_Binding(),
        submitter=submitter,
    )
    return handler, journal, vault, submitter


def _lease() -> Lease:
    return Lease(
        run_id=RUN_ID,
        worker_id="worker-1",
        fencing_token=1,
        deadline="2099-01-01T00:00:00.000000Z",
    )


async def test_credentials_are_stored_and_reserved_before_the_form_is_submitted(
    tmp_path: Path,
) -> None:
    handler, journal, vault, submitter = _handler(tmp_path)

    step = await handler(
        run_id=RUN_ID,
        phase="signup",
        profile=_profile(),
        lease=_lease(),
        deps=cast("OnboardingDeps", None),
    )

    # The ordering Requirement 6 is about, read straight off the journal: the
    # pair is staged, each field gets one reference and one grant, the submission
    # is reserved, and only then is the form submitted.
    assert journal == [
        "stage",
        "reference:browser_login_login_email",
        "grant:browser_login_login_email",
        "reference:browser_login_login_password",
        "grant:browser_login_login_password",
        "reserve",
        "submit",
        "complete",
        "promote",
    ]
    # The browser was handed references and grants, never values.
    assert [fill.field for fill in submitter.seen] == list(SIGNUP_LOGIN_FIELDS)
    assert all(fill.reference in vault.values and fill.grant for fill in submitter.seen)
    # The generated password is durable before anything was submitted.
    assert set(vault.staged) == set(SIGNUP_LOGIN_FIELDS)
    assert vault.staged["login_email"] == SIGNUP_ADDRESS
    # The driver, not the handler, commits: the phase only asks for the boundary
    # that must be durable before the first verification search runs.
    assert (step.kind, step.next_phase, step.reason_code) == (
        "advance",
        "email_verification",
        "signup_submitted",
    )


async def test_a_replayed_signup_phase_submits_nothing_a_second_time(tmp_path: Path) -> None:
    handler, journal, _vault, submitter = _handler(tmp_path)
    profile = _profile()

    first = await handler(
        run_id=RUN_ID,
        phase="signup",
        profile=profile,
        lease=_lease(),
        deps=cast("OnboardingDeps", None),
    )
    journal.clear()
    second = await handler(
        run_id=RUN_ID,
        phase="signup",
        profile=profile,
        lease=_lease(),
        deps=cast("OnboardingDeps", None),
    )

    assert first == second
    # Same key, ledger says completed, so the disposition is skip: no second
    # submission and no second account.
    assert "submit" not in journal
    assert len(submitter.seen) == len(SIGNUP_LOGIN_FIELDS)
