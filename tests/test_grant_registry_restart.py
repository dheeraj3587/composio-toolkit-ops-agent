"""Re-reservation across a process restart, and the execute/reconcile split.

WHY THIS FILE IS THE IMPORTANT ONE FOR THE GRANT REGISTRY. The registry is
in-process, so the obvious worry is that a restart loses an entry a resumed run
needs. The design claim is that it cannot: ``put_transient`` mints a RANDOM
identifier, the reference is part of the grant's HMAC material, so a resumed run
re-stages, gets a fresh reference and therefore a fresh grant, recorded on the way
through. These tests pin that claim rather than trusting it.

They also pin the branch that actually matters for safety. "Resume mid-signup" is
not one behaviour — it splits on what the effect ledger says about the prior attempt:

* ``execute``   (no prior row, or a provably ``failed`` one) — re-stage and re-submit.
  This is correct retry.
* ``reconcile`` (a ``pending`` or ``outcome_unknown`` row) — the prior attempt MAY
  have reached the provider, so the handler must pause and must NOT submit again.

Asserting only the first would let a regression that turns the second into a silent
double-submit pass, which is the expensive failure: the ledger cannot un-create a
duplicate account at the provider.
"""

from __future__ import annotations

import asyncio
import tempfile
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet

from ops.browser.signup import SignupIdentity, SignupPhaseHandler, SignupSubmission
from ops.core.effect_ledger import SQLiteEffectStore
from ops.core.secret_store import BrowserSecretGrantError, SQLiteSecretStore
from ops.onboarding.admission import AdmissionDecision
from ops.onboarding.grant_registry import GrantBinding, RunGrantRegistry
from ops.onboarding.grant_vault import InProcessGrantConsumer, RecordingSecretVault
from ops.providers.profile import FlowSpec, ProviderProfile, compute_profile_digest

RUN = "run_" + "0" * 32
SESSION = "bs_" + "0" * 32
ACCOUNT = "acct_" + "a" * 32
APP = "resend"


def _store(tmp: Path, key: str) -> SQLiteSecretStore:
    return SQLiteSecretStore(tmp / "vault.db", key)


def _profile() -> ProviderProfile:
    """A committed profile with a signup URL, which is what the key is derived from."""

    profile = ProviderProfile(
        run_id=RUN,
        provider_name="Resend",
        app_slug=APP,
        registrable_domain="resend.com",
        auxiliary_hosts=(),
        developer_portal_url="https://resend.com/api-keys",
        signup_url="https://resend.com/signup",
        login_url="https://resend.com/login",
        developer_docs_url=None,
        developer_app_flow=FlowSpec(kind="developer_app", supported=False, entry_url=None),
        oauth_flow=FlowSpec(kind="oauth", supported=False, entry_url=None),
        api_key_flow=FlowSpec(
            kind="api_key",
            supported=True,
            entry_url="https://resend.com/api-keys",
            produces=("api_key",),
        ),
        pat_flow=FlowSpec(kind="pat", supported=False, entry_url=None),
        approval_requirement="none",
        billing_requirement="none",
        evidence=(),
        confidence=0.9,
        adapters_engaged=("fake-discovery",),
        built_at="2026-01-01T00:00:01Z",
    )
    return replace(profile, profile_digest=compute_profile_digest(profile))


# --- the registry's own contract ---------------------------------------------


def test_a_grant_absent_from_the_registry_is_refused() -> None:
    """The empty-registry refusal: no key is guessed or reconstructed."""

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        key = Fernet.generate_key().decode()
        store = _store(tmp, key)
        registry = RunGrantRegistry()
        consumer = InProcessGrantConsumer(store=store, registry=registry)
        reference = store.put_transient(
            app_slug=APP, kind="browser_login_login_email", scope_id=RUN, value="a@b.c"
        )
        with pytest.raises(BrowserSecretGrantError):
            consumer.consume(
                reference=reference,
                kind="browser_login_login_email",
                grant="bsg_" + "a" * 43,
            )
        # The row is still there: a refusal consumed nothing.
        recording = RecordingSecretVault(store=store, registry=registry)
        grant = recording.reserve_browser_secret_grant(
            operation_key=f"{RUN}:signup-submit:abc:v1:consume:login_email",
            run_id=RUN,
            session_id=SESSION,
            app_slug=APP,
            kind="browser_login_login_email",
            action="consume",
            reference=reference,
        )
        assert (
            consumer.consume(reference=reference, kind="browser_login_login_email", grant=grant)
            == "a@b.c"
        )


def test_a_grant_cannot_redeem_a_reference_it_was_not_reserved_for() -> None:
    """Possession of one grant must not read a different secret.

    NOTE ON WHAT THIS DOES AND DOES NOT PROVE. Deleting the consumer's own
    reference/kind agreement check does NOT make this test fail, and that is correct
    rather than a gap: the VAULT refuses a mismatched pair by itself (confirmed by
    calling ``consume_transient_with_grant`` directly with grant-for-A and
    reference-B, which raises). So this pins the END-TO-END property — one grant
    cannot read another secret — and is deliberately indifferent to which of the two
    layers refuses. See :class:`InProcessGrantConsumer` on why its check is
    defence-in-depth.
    """

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        store = _store(tmp, Fernet.generate_key().decode())
        registry = RunGrantRegistry()
        recording = RecordingSecretVault(store=store, registry=registry)
        consumer = InProcessGrantConsumer(store=store, registry=registry)
        first = store.put_transient(
            app_slug=APP, kind="browser_login_login_email", scope_id=RUN, value="first@b.c"
        )
        second = store.put_transient(
            app_slug=APP, kind="browser_login_login_email", scope_id=RUN, value="second@b.c"
        )
        grant = recording.reserve_browser_secret_grant(
            operation_key=f"{RUN}:signup-submit:abc:v1:consume:login_email",
            run_id=RUN,
            session_id=SESSION,
            app_slug=APP,
            kind="browser_login_login_email",
            action="consume",
            reference=first,
        )
        with pytest.raises(BrowserSecretGrantError):
            consumer.consume(reference=second, kind="browser_login_login_email", grant=grant)


def test_one_grant_one_use_is_still_the_vaults_guarantee() -> None:
    """The registry keeps no used-set; the vault's row deletion is the enforcement."""

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        store = _store(tmp, Fernet.generate_key().decode())
        registry = RunGrantRegistry()
        recording = RecordingSecretVault(store=store, registry=registry)
        consumer = InProcessGrantConsumer(store=store, registry=registry)
        reference = store.put_transient(
            app_slug=APP, kind="browser_login_login_email", scope_id=RUN, value="a@b.c"
        )
        grant = recording.reserve_browser_secret_grant(
            operation_key=f"{RUN}:signup-submit:abc:v1:consume:login_email",
            run_id=RUN,
            session_id=SESSION,
            app_slug=APP,
            kind="browser_login_login_email",
            action="consume",
            reference=reference,
        )
        assert (
            consumer.consume(reference=reference, kind="browser_login_login_email", grant=grant)
            == "a@b.c"
        )
        # The entry is deliberately still in the registry; the VAULT refuses.
        assert registry.binding_for(grant) is not None
        with pytest.raises(BrowserSecretGrantError):
            consumer.consume(reference=reference, kind="browser_login_login_email", grant=grant)


# --- the restart claim -------------------------------------------------------


def test_a_restart_yields_a_fresh_reference_and_grant_and_keeps_the_identity() -> None:
    """The core restart claim, asserted rather than assumed.

    A new registry (the restart) plus a re-staged secret must produce a working
    grant, and the STAGED PAIR — the account identity — must be unchanged.
    """

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        key = Fernet.generate_key().decode()

        # --- process 1: stage the pair and reserve a grant -------------------
        first_store = _store(tmp, key)
        pair = first_store.stage_signup_login_pair(
            app_slug=APP,
            account_ref=ACCOUNT,
            run_id=RUN,
            email="alias@example.com",
            password="Pw1234567890123456789",
        )
        first_registry = RunGrantRegistry()
        first_recording = RecordingSecretVault(store=first_store, registry=first_registry)
        first_reference = first_recording.put_transient(
            app_slug=APP,
            kind="browser_login_login_email",
            scope_id=RUN,
            value=pair["login_email"],
        )
        first_grant = first_recording.reserve_browser_secret_grant(
            operation_key=f"{RUN}:signup-submit:abc:v1:consume:login_email",
            run_id=RUN,
            session_id=SESSION,
            app_slug=APP,
            kind="browser_login_login_email",
            action="consume",
            reference=first_reference,
        )

        # --- process 2: a brand-new store AND an empty registry -------------
        second_store = _store(tmp, key)
        second_registry = RunGrantRegistry()
        second_recording = RecordingSecretVault(store=second_store, registry=second_registry)
        second_consumer = InProcessGrantConsumer(store=second_store, registry=second_registry)

        # The old grant is unknown to the new registry, exactly as expected.
        assert second_registry.binding_for(first_grant) is None

        # The IDENTITY survives: this is what must not be regenerated.
        resumed = second_store.get_staged_signup_login_pair(
            app_slug=APP, account_ref=ACCOUNT, run_id=RUN
        )
        assert resumed["login_email"] == pair["login_email"]
        assert resumed["login_password"] == pair["login_password"]

        # Re-staging mints a FRESH reference, hence a FRESH grant, recorded here.
        second_reference = second_recording.put_transient(
            app_slug=APP,
            kind="browser_login_login_email",
            scope_id=RUN,
            value=resumed["login_email"],
        )
        assert second_reference != first_reference, "the transient identifier is random"
        second_grant = second_recording.reserve_browser_secret_grant(
            operation_key=f"{RUN}:signup-submit:abc:v1:consume:login_email",
            run_id=RUN,
            session_id=SESSION,
            app_slug=APP,
            kind="browser_login_login_email",
            action="consume",
            reference=second_reference,
        )
        assert second_grant != first_grant, "a new reference yields a new grant"

        # And it redeems cleanly — no missing-entry refusal after the restart.
        assert (
            second_consumer.consume(
                reference=second_reference,
                kind="browser_login_login_email",
                grant=second_grant,
            )
            == pair["login_email"]
        )


# --- the execute / reconcile split ------------------------------------------


@dataclass
class _Binding:
    def signup_identity(self, *, run_id: str) -> SignupIdentity:
        del run_id
        return SignupIdentity(
            account_ref=ACCOUNT, session_id=SESSION, signup_address="alias@example.com"
        )


@dataclass
class _Submitter:
    """Records whether the provider was contacted, and with what."""

    status: str = "failed"
    calls: list[tuple[str, ...]] = field(default_factory=list)
    consumer: Any = None

    async def submit_signup(
        self, *, run_id: str, session_id: str, fills: Any, fields: Any
    ) -> SignupSubmission:
        del run_id, session_id, fields
        resolved: list[str] = []
        for fill in fills:
            # Exactly what the real submitter does: redeem each grant through the
            # in-process consumer. A registry miss would raise here.
            resolved.append(
                self.consumer.consume(reference=fill.reference, kind=fill.kind, grant=fill.grant)
            )
        self.calls.append(tuple(resolved))
        return SignupSubmission(status=self.status, receipt={"reason": "test"})


@dataclass
class _Admissions:
    """An operator-decided signup admission for this exact profile digest."""

    profile_digest: str

    def read_admission_decision(self, run_id: str) -> AdmissionDecision:
        return AdmissionDecision(
            run_id=run_id,
            profile_digest=self.profile_digest,
            route="signup",
            reason_code="operator_approved_signup",
            decided_by="operator",
            actor_owner_id="ops-owner",
            decided_at="2026-01-01T00:00:00Z",
        )


@dataclass
class _Phases:
    """The one phase read the handler's postcondition path makes."""

    def current_phase(self, *, run_id: str) -> tuple[str, int] | None:
        del run_id
        return ("signup", 0)


def _handler(
    tmp: Path, store: SQLiteSecretStore, effects: SQLiteEffectStore, profile: ProviderProfile
) -> tuple[SignupPhaseHandler, _Submitter, RunGrantRegistry]:
    """A handler wired exactly as ``_effectful_handlers`` wires it: recording vault."""

    registry = RunGrantRegistry()
    recording = RecordingSecretVault(store=store, registry=registry)
    consumer = InProcessGrantConsumer(store=store, registry=registry)
    submitter = _Submitter(consumer=consumer)
    handler = SignupPhaseHandler(
        vault=recording,
        effects=effects,
        binding=_Binding(),
        submitter=submitter,
        admissions=_Admissions(profile_digest=profile.profile_digest),
    )
    return handler, submitter, registry


def _drive(handler: SignupPhaseHandler, profile: ProviderProfile) -> Any:
    return asyncio.run(
        handler(
            run_id=RUN,
            phase="signup",
            profile=profile,
            lease=None,  # type: ignore[arg-type]
            deps=None,  # type: ignore[arg-type]
        )
    )


def test_a_failed_attempt_re_reserves_and_re_submits_after_a_restart() -> None:
    """EXECUTE branch: a provably-failed prior attempt is retried cleanly.

    This is the re-reservation path. The second walk uses a BRAND-NEW registry (the
    restart), so if the consumer needed a surviving entry it would raise here rather
    than resolve the staged email.
    """

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        key = Fernet.generate_key().decode()
        profile = _profile()
        effects = SQLiteEffectStore(tmp / "effects.db")

        # --- walk 1: the submit provably fails, so the key is marked failed ---
        first_store = _store(tmp, key)
        first, first_submitter, _ = _handler(tmp, first_store, effects, profile)
        first_submitter.status = "failed"
        step_one = _drive(first, profile)
        assert step_one.kind == "pause"
        assert step_one.reason_code == "postcondition_failed"
        assert len(first_submitter.calls) == 1, "the first walk reached the provider path"
        first_email = first_submitter.calls[0][0]

        # --- walk 2: a restart. New store, new handler, EMPTY registry. --------
        second_store = _store(tmp, key)
        second, second_submitter, second_registry = _handler(tmp, second_store, effects, profile)
        assert second_registry.binding_for("bsg_" + "a" * 43) is None
        second_submitter.status = "submitted"
        step_two = _drive(second, profile)

        # The retry re-staged, re-reserved, and redeemed its FRESH grant.
        assert len(second_submitter.calls) == 1, "the retry submitted exactly once"
        assert second_submitter.calls[0][0] == first_email, (
            "the identity is stable across the restart — same staged email"
        )
        assert step_two.kind == "advance"
        assert step_two.next_phase == "email_verification"


def test_an_ambiguous_prior_attempt_pauses_and_never_re_submits() -> None:
    """RECONCILE branch: the expensive failure this guards against.

    A prior attempt whose outcome is unknown MAY have created an account, so the
    handler must pause without contacting the provider again. The ledger cannot
    un-create a duplicate account, which is why this asserts on CALLS MADE.
    """

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        key = Fernet.generate_key().decode()
        profile = _profile()
        effects = SQLiteEffectStore(tmp / "effects.db")

        # --- walk 1: the outcome is unknown (not a provable failure) ----------
        first_store = _store(tmp, key)
        first, first_submitter, _ = _handler(tmp, first_store, effects, profile)
        first_submitter.status = "outcome_unknown"
        step_one = _drive(first, profile)
        assert step_one.kind == "pause"
        assert step_one.reason_code == "outcome_unknown"
        assert len(first_submitter.calls) == 1

        # --- walk 2: a restart. The ledger must refuse a second submission. ---
        second_store = _store(tmp, key)
        second, second_submitter, _ = _handler(tmp, second_store, effects, profile)
        second_submitter.status = "submitted"
        step_two = _drive(second, profile)

        assert second_submitter.calls == [], (
            "THE POINT: an ambiguous prior attempt must not reach the provider again"
        )
        assert step_two.kind == "pause"


def test_the_registry_miss_refusal_is_this_classes_own_and_reaches_no_vault() -> None:
    """The one refusal that IS load-bearing here, pinned so a regression shows.

    Unlike the reference-agreement check, this one has no vault backstop: with the
    grant absent there is no recorded operation key, so there is nothing to pass as
    ``expected_operation_key`` at all. A regression that guessed a key, or passed an
    empty one, would turn a wiring fault into an attempted vault read — so the
    assertion is that the store is NEVER TOUCHED.
    """

    @dataclass
    class _ExplodingStore:
        touched: int = 0

        def consume_transient_with_grant(self, *args: Any, **kwargs: Any) -> str:
            self.touched += 1
            raise AssertionError("an unknown grant must not reach the vault")

    store = _ExplodingStore()
    consumer = InProcessGrantConsumer(store=store, registry=RunGrantRegistry())
    with pytest.raises(BrowserSecretGrantError):
        consumer.consume(
            reference="vault://resend/browser_login_login_email/abcdefghij",
            kind="browser_login_login_email",
            grant="bsg_" + "a" * 43,
        )
    assert store.touched == 0


def test_a_capture_grant_cannot_be_redeemed_as_a_consume() -> None:
    """A capture grant authorizes a WRITE; redeeming it as a read is a category error."""

    @dataclass
    class _ExplodingStore:
        touched: int = 0

        def consume_transient_with_grant(self, *args: Any, **kwargs: Any) -> str:
            self.touched += 1
            raise AssertionError("a capture grant must not reach the consume verb")

    registry = RunGrantRegistry()
    registry.record(
        "bsg_" + "b" * 43,
        GrantBinding(
            operation_key=f"{RUN}:generate-credential:abc:v1:capture:browser_capture_api_key",
            run_id=RUN,
            session_id=SESSION,
            app_slug=APP,
            kind="browser_capture_api_key",
            action="capture",
            reference=None,
        ),
    )
    store = _ExplodingStore()
    consumer = InProcessGrantConsumer(store=store, registry=registry)
    with pytest.raises(BrowserSecretGrantError):
        consumer.consume(
            reference="vault://resend/browser_capture_api_key/abcdefghij",
            kind="browser_capture_api_key",
            grant="bsg_" + "b" * 43,
        )
    assert store.touched == 0
