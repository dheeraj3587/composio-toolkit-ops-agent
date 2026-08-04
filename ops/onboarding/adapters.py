"""Production adapters for the onboarding phases that were protocol-only.

Every port here existed as a ``Protocol`` with no implementation anywhere in
``ops/``, which is why the second half of the walk — signup submission, developer
application, credential capture — had never executed. The reviewed handlers
(``SignupPhaseHandler``, ``DeveloperAppPhaseHandler``,
``capture_store_validate_publish``) were already written and already guarded by the
effect ledger; they simply had nothing to call.

Two properties hold across the whole module, because they are what the reviewed
handlers assume:

**No adapter here ever sees a credential value.** Secrets travel as
``(reference, kind, grant)`` and are redeemed inside the browser seam
(``PlaywrightLoopSession.fill_from_grant``) or by the broker's capture verb, which
writes to the vault before it answers. ``SignupSubmitter.submit_signup`` returns a
status and a non-secret receipt, never a value (Requirement 6.6), and
``CredentialSurfaceSession.capture_credential`` returns a ``vault://`` reference.

**No adapter commits a phase or reserves an effect.** The driver is the only
committer and the handlers own their operation keys, so a duplicate submission is
prevented by the ledger rather than by anything written here. That is the entire
point of driving signup through ``SignupPhaseHandler`` instead of the action loop:
one run, one account.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, cast

from ops.browser.login import (
    LoginGrant,
    LoginObservation,
    LoginRouteContext,
)
from ops.browser.signup import (
    SignupIdentity,
    SignupSecretFill,
    SignupSubmission,
)

# The worker's page-text gate classifier, reused so the login route and the
# action loop cannot drift apart on what page text means a human action. Its
# ``provider_verification`` catch-all is read here as "no recognised challenge",
# which the caller turns into an unknown outcome rather than a gate.
from ops.browser.worker import _classify_human_action
from ops.core.effect_ledger import EffectStore
from ops.credentials.capture_boundary import (
    CaptureRefused,
    CaptureVault,
    capture_validated_credential,
)
from ops.credentials.capture_specs import CredentialCaptureSpec
from ops.onboarding.action_loop import phase_postcondition_satisfied
from ops.onboarding.admission import AdmissionDecision
from ops.onboarding.capture_specs import CaptureContractUnavailable
from ops.onboarding.credentials import (
    CREDENTIAL_EFFECT,
    ONBOARDING_VAULT_KIND_PREFIX,
    ONBOARDING_VAULT_KINDS,
    CredentialLifecycleDeps,
    capture_store_validate_publish,
)
from ops.onboarding.driver import (
    DEVELOPER_APP_RECEIPT_KEY,
    DeveloperAppRequest,
    OnboardingDeps,
    PhaseStep,
    phase_correlation_id,
)
from ops.onboarding.effects import DEFAULT_CREDENTIAL_KIND, generate_credential_key
from ops.onboarding.lease import Lease
from ops.onboarding.phase import OnboardingPhase, OnboardingReasonCode
from ops.playwright.loop_session import PlaywrightLoopSession
from ops.playwright.page_inspection import PageInspection
from ops.providers.profile import ProviderProfile

# The three phases one credential handler covers, because
# ``capture_store_validate_publish`` commits the latter two itself through
# ``STORAGE_BOUNDARIES`` — see :class:`CredentialPhaseHandler`.
CREDENTIAL_PHASES: frozenset[OnboardingPhase] = frozenset(
    {"credential_generation", "vault_storage", "credential_validation"}
)

# The credential kind an off-catalog onboarding run asks for. A plain API key is
# the only kind every self-serve provider in the researched set actually mints from
# a page; OAuth client pairs and PATs exist but are declared per provider, so
# asking for one the profile never declared would pause ``flow_unsupported``
# immediately. ``developer_app_flows`` looks the flow up BY KIND, so this is the
# value that has to agree with what ``_with_operator_credential_surface`` declared.
#
# The canonical home is ``ops.onboarding.effects`` (the driver derives its
# boundary operation key from the same constant); this re-export keeps the
# adapter's historical import site working.

# Element types the signup email and password fields are chosen from. Ordered:
# a dedicated ``email`` input wins over a generic ``text`` one.
_EMAIL_FIELD_TYPES: tuple[str, ...] = ("email", "text")
_PASSWORD_FIELD_TYPES: tuple[str, ...] = ("password",)

_FIELD_TYPES: dict[str, tuple[str, ...]] = {
    "login_email": _EMAIL_FIELD_TYPES,
    "login_password": _PASSWORD_FIELD_TYPES,
}

# Accessible names a signup submit control carries. Matched case-folded against the
# whole name, and only among visible enabled buttons, so a link that merely mentions
# one of these words is not a submit target.
_SUBMIT_LABELS: tuple[str, ...] = (
    "create account",
    "sign up",
    "signup",
    "get started",
    "register",
    "continue",
)

# Page text that positively identifies an existing-account refusal. Deliberately
# narrow: a phrase that only MIGHT mean this belongs in ``outcome_unknown``, because
# reporting ``duplicate_account`` routes the run to login and closes the effect.
_DUPLICATE_ACCOUNT_MARKERS: tuple[str, ...] = (
    "already exists",
    "already registered",
    "already have an account with",
    "email is taken",
    "already taken",
    "account already",
)

# Page text that positively identifies a submission the provider accepted. Also
# narrow, for the same reason in the other direction.
_SUBMITTED_MARKERS: tuple[str, ...] = (
    "check your email",
    "verify your email",
    "verification email",
    "confirm your email",
    "we sent",
    "almost there",
)


def _first_submit_index(inspection: PageInspection) -> int | None:
    """The index of the one visible, enabled submit control, or ``None``.

    Chosen from the bounded inspection by accessible name, never by a selector
    string. ``None`` means there is nothing to click, which the caller reports as
    ``failed`` — provably nothing was sent.
    """

    for element in inspection.elements:
        if not (element.visible and element.enabled):
            continue
        if element.role != "button" and element.element_type not in {"submit", "button"}:
            continue
        name = (element.name or "").strip().casefold()
        if any(label in name for label in _SUBMIT_LABELS):
            return element.index
    return None


def _url_changed(before: PageInspection, after: PageInspection) -> bool:
    """Whether the page navigated, ignoring a trailing-slash-only difference."""

    return before.url.rstrip("/") != after.url.rstrip("/")


class RunLedgerReader(Protocol):
    """The one read the bindings need from the run ledger."""

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        """The run's durable row, or ``None``."""


class LoginDecisionReader(Protocol):
    """The one read the login context needs from the admission service."""

    def read_admission_decision(self, run_id: str) -> AdmissionDecision | None:
        """The run's recorded admission decision, or ``None`` if it has none."""


@dataclass(slots=True)
class LedgerSignupBinding:
    """``SignupRunBinding``: the run's durable account, session and address.

    All three are read from durable rows rather than derived, because the operation
    key the effect ledger guards the submission with is derived from them. A binding
    that answered differently on a retry would produce a different key and defeat
    the single-submit guarantee.
    """

    ledger: RunLedgerReader
    vault: Any
    signup_address: str

    def signup_identity(self, *, run_id: str) -> SignupIdentity:
        record = self.ledger.get_run(run_id)
        if record is None:
            raise LookupError("the run has no ledger row")
        account_ref = str(record.get("browser_account_ref") or "")
        session_id = str(record.get("browser_session_id") or "")
        if not account_ref or not session_id:
            # Both are written before the browser phases are reachable, so their
            # absence is a wiring fault rather than a run outcome.
            raise LookupError("the run has no bound account or browser session")
        # The staged pair is authoritative for the address when it exists: it is the
        # alias this run actually signed up with, and the verification search must
        # bind to the same one. The configured address is the fallback for the first
        # attempt, before anything has been staged.
        staged = self.vault.get_staged_signup_login_pair(
            app_slug=str(record.get("app_slug") or ""),
            account_ref=account_ref,
            run_id=run_id,
        )
        return SignupIdentity(
            account_ref=account_ref,
            session_id=session_id,
            signup_address=str(staged.get("login_email") or self.signup_address),
        )


@dataclass(slots=True)
class LedgerMailboxBinder:
    """``SignupMailboxBinder``: records the alias this run verifies on.

    A no-op write today, and deliberately so rather than absent. The recipient is
    already recoverable from the staged signup pair, which is keyed by exactly
    ``(app_slug, account_ref, run_id)`` and is what
    ``_RunVerificationBinding.verification_context`` reads. Writing a second copy
    would create two facts that could disagree, and the one that matters — the
    address the mailbox search binds to — must be the alias signup submitted.

    The call is retained so the handler's contract is satisfied and so a deployment
    that later needs a distinct recipient store has one place to put it.
    """

    def bind_verification_recipient(self, *, run_id: str, session_id: str, address: str) -> None:
        del run_id, session_id, address


@dataclass(slots=True)
class LedgerLoginContextStore:
    """``LoginRouteContextStore``: the run's durable login context.

    Every field is read from durable rows rather than derived, for the same
    reason ``LedgerSignupBinding`` states: the operation keys the effect ledger
    guards the login with are derived from them, and a context store that
    answered differently on a retry would produce different keys and defeat the
    single-grant guarantee. ``effect_identity`` in particular is the run row's
    durable column — the broker recomposes ``consume`` operation keys from the
    same value — which is written at creation for the login route
    (``CanonicalRuntime.create_run``).
    """

    ledger: RunLedgerReader
    decisions: LoginDecisionReader

    def login_context(self, *, run_id: str) -> LoginRouteContext | None:
        record = self.ledger.get_run(run_id)
        if record is None:
            return None
        app_slug = str(record.get("app_slug") or "")
        account_ref = str(record.get("browser_account_ref") or "")
        session_id = str(record.get("browser_session_id") or "")
        effect_identity = str(record.get("effect_identity") or "")
        if not (app_slug and account_ref and session_id and effect_identity):
            # A run missing any of these never completed a mounted login probe:
            # account and effect identity are written at creation, and the
            # session is bound before the walk reaches the login phase. The
            # absence is a wiring fault rather than a run outcome, so the
            # handler reports it as PhaseNotDrivable rather than guessing.
            return None
        decision = self.decisions.read_admission_decision(run_id)
        if decision is None or decision.route != "login":
            return None
        return LoginRouteContext(
            decision=decision,
            session_id=session_id,
            app_slug=app_slug,
            account_ref=account_ref,
            effect_identity=effect_identity,
        )


@dataclass(slots=True)
class SessionSignupSubmitter:
    """``SignupSubmitter`` over the run's own bound browser session.

    ``submit_signup`` fills each staged field through the grant path and submits
    once. No credential value crosses this class in either direction: each fill is
    ``(reference, kind, grant)`` and the value is redeemed inside the browser seam.

    The submission is NOT idempotent here and does not try to be — the handler
    reserves ``signup_submit`` through the effect ledger before calling, so a second
    arrival is refused before it reaches this code.
    """

    session: PlaywrightLoopSession

    async def observe_signup(self) -> PageInspection:
        """A fresh, bounded inspection of the page the submission landed on."""

        return await self.session.inspect()

    async def submit_signup(
        self,
        *,
        run_id: str,
        session_id: str,
        fills: Any,
        fields: Any,
    ) -> SignupSubmission:
        del run_id, fields
        if session_id != self.session.session_id:
            # The handler derived its operation key from the run's bound session;
            # submitting on a different one would attribute the account to the wrong
            # session. Nothing was submitted, so this is retryable.
            return SignupSubmission(status="failed", receipt={"reason": "session_mismatch"})
        for fill in cast("tuple[SignupSecretFill, ...]", tuple(fills)):
            types = _FIELD_TYPES.get(fill.field)
            if types is None:
                return SignupSubmission(status="failed", receipt={"reason": "unknown_fill_field"})
            try:
                await self.session.fill_from_grant(
                    kinds=types,
                    reference=fill.reference,
                    kind=fill.kind,
                    grant=fill.grant,
                )
            except Exception:
                # A fill that did not happen means nothing was submitted. Reported as
                # ``failed`` (retryable with a FRESH reservation and fresh grants)
                # rather than ``outcome_unknown``, which would authorize nothing.
                return SignupSubmission(status="failed", receipt={"reason": "signup_fill_failed"})
        return await self._submit_and_classify()

    async def _submit_and_classify(self) -> SignupSubmission:
        """Submit the form once and classify what the provider did with it.

        THE CLASSIFICATION IS THE SAFETY PROPERTY HERE, not the submission.
        ``ops.browser.signup`` states the rule: ``failed`` means the attempt
        provably did not reach the provider, which is the only failure that may be
        retried; anything ambiguous is ``outcome_unknown`` and authorizes nothing
        further. So:

        * ``failed`` — ONLY when the submit provably never left this process: the
          control is absent from the page, or clicking it raised before navigation.
          Nothing reached the provider, so a retry cannot create a second account.
        * ``outcome_unknown`` — everything else that is not a positively recognised
          outcome. A click that landed but whose result could not be read, a
          navigation timeout, an unexpected destination. A stuck run is cheap; a
          duplicate account is expensive and the ledger cannot undo it.
        * ``submitted`` / ``duplicate_account`` — only on positive recognition.

        The asymmetry is deliberate: the cost of over-reporting ``outcome_unknown``
        is an operator looking at a paused run, and the cost of under-reporting it is
        a second real account at the provider.
        """

        before = await self.session.inspect()
        index = _first_submit_index(before)
        if index is None:
            # Provably nothing was sent: there was no control to click.
            return SignupSubmission(status="failed", receipt={"reason": "signup_submit_not_found"})
        try:
            await self.session.click_index(element_index=index, inspection=before)
        except Exception:
            # The click did not execute. The executor re-validates the page before
            # acting, so a raise here means the action was refused rather than
            # partially performed — nothing reached the provider.
            return SignupSubmission(status="failed", receipt={"reason": "signup_submit_refused"})
        # From this point the submission MAY have reached the provider, so no
        # branch below may report ``failed``.
        try:
            after = await self.session.inspect()
        except Exception:
            return SignupSubmission(
                status="outcome_unknown", receipt={"reason": "signup_result_unreadable"}
            )
        text = after.visible_text.casefold()
        if any(marker in text for marker in _DUPLICATE_ACCOUNT_MARKERS):
            # Positively recognised: the provider says this identity already exists.
            # The handler routes this to login rather than retrying signup.
            return SignupSubmission(
                status="duplicate_account", receipt={"reason": "provider_reported_existing"}
            )
        if _url_changed(before, after) or any(marker in text for marker in _SUBMITTED_MARKERS):
            return SignupSubmission(status="submitted", receipt={"signup_landing": "observed"})
        # The page did not move and said nothing recognisable. It may or may not have
        # registered the account; refuse to guess.
        return SignupSubmission(
            status="outcome_unknown", receipt={"reason": "signup_result_unrecognised"}
        )


# Page text that positively identifies a rejected login. Narrow, so a phrase
# that only MIGHT mean this stays in the unknown outcome instead of pausing the
# run with a diagnosis it cannot support.
_LOGIN_REJECTED_MARKERS: tuple[str, ...] = (
    "incorrect password",
    "wrong password",
    "invalid password",
    "invalid email",
    "incorrect email",
    "couldn't find your account",
    "no account found with",
    "enter a valid email",
    "email or password",
)


@dataclass(slots=True)
class SessionLoginSubmitter:
    """``LoginRouteWorker`` over the run's own bound browser session.

    ``submit_login`` fills each login field through the grant path and submits
    once. No credential value crosses this class in either direction: each fill
    is ``(reference, kind, grant)`` and the value is redeemed inside the browser
    seam (``PlaywrightLoopSession.fill_from_grant``).

    The submission is NOT idempotent here and does not try to be — the handler
    mints deterministic grants per attempt (``login_grants``), so a retry either
    reuses an unspent grant or reserves a fresh one before calling; nothing in
    this class can create a second attempt on its own.
    """

    session: PlaywrightLoopSession

    async def submit_login(
        self,
        *,
        run_id: str,
        session_id: str,
        account_ref: str,
        grants: Sequence[LoginGrant],
    ) -> LoginObservation:
        del run_id, account_ref
        if session_id != self.session.session_id:
            # The handler derived its operation keys from the run's bound session;
            # submitting on a different one would attribute the login to the wrong
            # session. Nothing was submitted, so this is retryable.
            return LoginObservation(accepted=False, reason_code="postcondition_failed")
        for grant in grants:
            types = _FIELD_TYPES.get(grant.field)
            if types is None:
                return LoginObservation(accepted=False, reason_code="postcondition_failed")
            try:
                await self.session.fill_from_grant(
                    kinds=types,
                    reference=grant.reference,
                    kind=grant.kind,
                    grant=grant.grant,
                )
            except Exception:
                # A fill that did not happen means nothing was submitted. Reported
                # as a plain failure (retryable with a FRESH reservation) rather
                # than a gate or an acceptance.
                return LoginObservation(accepted=False, reason_code="postcondition_failed")
        return await self._submit_and_classify()

    async def _submit_and_classify(self) -> LoginObservation:
        """Submit the form once and classify what the provider did with it.

        THE CLASSIFICATION IS THE SAFETY PROPERTY HERE, not the submission:
        ``accepted`` is reported ONLY on a positive recognition — the page
        navigated after the submit and said nothing that rejects the identity.
        Anything ambiguous stays unaccepted and pauses, because advancing
        ``route_selected_login`` wrong would walk the developer-application and
        credential phases on an account that is not signed in.

        * CAPTCHA and other typed challenges name the gate, so the handler's
          gate path (or the seam) owns the pause.
        * A positively recognised rejection pauses as
          ``credential_invalid_retryable`` — the stored pair was refused, so
          re-driving with the same values cannot succeed.
        * Anything else is ``postcondition_failed``: nothing provable happened,
          and a stuck run is cheap while a misattributed login is not.
        """

        before = await self.session.inspect()
        index = _first_submit_index(before)
        if index is None:
            # Provably nothing was sent: there was no control to click.
            return LoginObservation(accepted=False, reason_code="postcondition_failed")
        try:
            await self.session.click_index(element_index=index, inspection=before)
        except Exception:
            # The click did not execute. The executor re-validates the page before
            # acting, so a raise here means the action was refused rather than
            # partially performed — nothing reached the provider.
            return LoginObservation(accepted=False, reason_code="postcondition_failed")
        # From this point the submission MAY have reached the provider, so no
        # branch below may report an acceptance on page text alone.
        try:
            after = await self.session.inspect()
        except Exception:
            return LoginObservation(accepted=False, reason_code="postcondition_failed")
        text = after.visible_text.casefold()
        if any(marker in text for marker in _LOGIN_REJECTED_MARKERS):
            # Positively recognised: the provider refused this identity.
            return LoginObservation(accepted=False, reason_code="credential_invalid_retryable")
        if _url_changed(before, after):
            return LoginObservation(accepted=True)
        gate_type = _classify_human_action(text)
        if gate_type != "provider_verification":
            reason: OnboardingReasonCode = (
                "captcha_detected" if gate_type == "captcha" else "candidate_risk_requires_human"
            )
            return LoginObservation(accepted=False, gate_type=gate_type, reason_code=reason)
        # The page did not move and said nothing recognisable. Refuse to guess.
        return LoginObservation(accepted=False, reason_code="postcondition_failed")


@dataclass(slots=True)
class RunDeveloperAppBinding:
    """``DeveloperAppBinding``: the run's owner and the credential it is after.

    Both are durable run facts, not page-derived ones, because
    ``developer_app_name`` digests over the owner and the run to derive the
    operation key that guards application creation. A binding that answered
    differently per attempt would ask the provider for a second application.
    """

    owner_id: str
    credential_kind: str = DEFAULT_CREDENTIAL_KIND

    def developer_app_request(self, *, run_id: str) -> DeveloperAppRequest:
        del run_id
        return DeveloperAppRequest(
            owner_id=self.owner_id,
            credential_kind=cast("Any", self.credential_kind),
        )


@dataclass(slots=True)
class SessionCredentialSurface:
    """``CredentialSurfaceSession``: broad read, strict re-validation.

    NO SELECTORS ARE INVENTED HERE, and that is the whole design rather than a
    limitation. On the off-catalog path the capture contract comes from
    ``ops.onboarding.capture_specs.profile_capture_contract``, which returns
    ``selectors=()`` deliberately:

        "A brand-new provider has no reviewed page, and inventing selectors from
        research or from live DOM text would put the untrusted page inside its own
        admission check ... the absence is the design, not an omission to be filled
        in later."

    That same docstring names the two mechanisms that replace selectors, and this
    class sits between them:

    1. **Proof of place.** ``arm_credential_surface`` returns ``True`` only when the
       action loop's own ``credential_visible`` postcondition holds for the current
       page — status ``credential_page_ready`` AND non-empty
       ``credential_field_labels``. Both come from the classifier, not from this
       class, and ``credential_page_ready`` additionally requires the URL to equal
       the plan's committed credential surface. So "we are on the credential page" is
       established before any grant is issued.
    2. **Proof of shape.** Every candidate read is offered to
       ``capture_validated_credential``, which re-applies the checked-in
       ``credential_value_pattern`` anchored end to end and writes nothing on a
       mismatch. Correctness comes from THAT, not from having picked the right node.

    The read may therefore be broad — every ``secretish`` element the inspection
    reports, index-addressed, no selector strings — because a wrong read is refused
    rather than stored.

    **Ambiguity pauses rather than guesses.** If more than one distinct candidate
    passes the pattern, this refuses: storing the wrong one fails later at validation,
    where it is far harder to diagnose than a paused run.

    KNOWN LIMIT, AND IT FAILS CLOSED. The inspection collects INTERACTIVE elements
    only (``ops.browser.snapshot.INTERACTIVE_SELECTOR``), so a key rendered into a
    readonly ``<input>`` is readable and a key rendered into a ``<code>`` block is not
    in ``inspection.elements`` at all. Such a run pauses ``outcome_unknown`` with
    nothing stored. The page's ``visible_text`` is NOT a fallback: it has already been
    through ``sanitize_page_text``, which redacts exactly the token shapes being
    looked for, so reading it would find nothing. Widening the selector would change
    the element set the model sees on EVERY page, which is a much larger blast radius
    than this phase, so the narrow read stays and the gap is recorded in
    RUN_BLOCKERS.md.

    **What this does NOT do:** it does not revoke outstanding live-view grants. The
    port's docstring says arming does; nothing in the codebase revokes anything. The
    gap is recorded in RUN_BLOCKERS.md rather than papered over here, because a
    comment asserting a fact the code does not deliver is worse than a documented gap.
    Local runs are loopback-only; the production RPC path is where it matters.
    """

    session: PlaywrightLoopSession
    store: CaptureVault
    # ``resolve_capture_contract`` bound to this run's core — the SAME authority
    # order the RPC broker uses, deliberately not a second one.
    spec_for: Callable[[str], CredentialCaptureSpec]
    run_id: str
    app_slug: str
    operation_key: str
    # A plain attribute rather than a property because ``CredentialSurfaceSession``
    # declares it settable. Mirrored from the bound session in ``__post_init__`` so
    # the two cannot name different sessions.
    session_id: str = ""
    # Set by ``arm_credential_surface`` so the capture reads the page that was
    # actually proven, not one observed later.
    _armed: PageInspection | None = None

    def __post_init__(self) -> None:
        self.session_id = self.session.session_id

    async def arm_credential_surface(self) -> bool:
        """Prove this page IS the run's credential surface, before any grant exists.

        Mechanism 1 of the two named above. ``False`` means the surface must not be
        read at all, which the caller turns into a pause BEFORE it reserves the
        capture effect or mints a grant — so a refusal here leaves nothing half-done.

        It does NOT install the pixel mask, despite what "arm" suggests: the mask is
        installed once per session before the FIRST vendor navigation
        (``ops.playwright.worker`` refuses to proceed when
        ``install_live_pixel_mask`` fails), so by the time this runs it is already
        active and installing it here would be a second, later, weaker guarantee.
        """

        observation = await self.session.observe()
        if not phase_postcondition_satisfied("credential_visible", observation.observation):
            return False
        # The inspection behind that observation is what the read is addressed
        # against, so the proof and the read describe the same page.
        self._armed = await self.session.inspect()
        return True

    async def capture_credential(self, *, grant: str, kind: str) -> str:
        """Read candidate values and store the one that matches the contract.

        ``kind`` is the vault row kind the value is stored under (the
        ``onboarding_*`` namespace on this path). The contract is resolved under
        the credential kind that namespace mechanically derives from, and the
        pattern is matched against the contract's OWN field kind: a reviewed
        recipe names its captured field after the page control (``api_token``),
        which is not the credential-kind vocabulary the operator requested under,
        while the profile path names them identically — so both resolve through
        the same code and neither is guessed from page text.

        POST: returns the ``vault://`` reference of a row the vault already wrote.
              No value is returned to the caller, logged, or retained.
        """

        inspection = self._armed
        if inspection is None:
            # Arming is the caller's precondition; reading without it would skip
            # mechanism 1 entirely.
            raise CaptureRefused
        credential_kind = kind
        if credential_kind.startswith(ONBOARDING_VAULT_KIND_PREFIX):
            # The vault namespace is a mechanical derivation of the credential
            # kind (``ONBOARDING_VAULT_KINDS``), so the reverse is mechanical too.
            credential_kind = credential_kind[len(ONBOARDING_VAULT_KIND_PREFIX) :]
        try:
            spec = self.spec_for(credential_kind)
        except CaptureContractUnavailable:
            # No contract means no pattern, and a read with no pattern is exactly the
            # selector-invention this design refuses.
            raise CaptureRefused from None
        field = spec.field(credential_kind)
        if field is None and len(spec.capture_fields) == 1:
            # ONE reviewed field is the app's token field by construction: the
            # recipe was reviewed for automatic capture of exactly that field, so
            # its pattern is the exact contract for the minted value, still
            # anchored below by ``capture_validated_credential``.
            field = spec.capture_fields[0]
        if field is None:
            raise CaptureRefused
        indexes = [
            element.index
            for element in inspection.elements
            # ``secretish`` is the INSPECTION layer's classification, not this
            # class's guess at what looks like a credential.
            if element.secretish and element.visible
        ]
        if not indexes:
            raise CaptureRefused
        candidates = await self.session.read_pattern_matched(
            element_indexes=indexes,
            inspection=inspection,
            value_pattern=field.value_pattern,
        )
        if len(candidates) != 1:
            # Zero: nothing on the page matched the contract. More than one: the page
            # rendered several values that could each be the credential, and picking
            # would be a guess that fails later at validation.
            raise CaptureRefused
        # Mechanism 2. The value is passed straight through and never bound here.
        return capture_validated_credential(
            store=self.store,
            spec=spec,
            grant=grant,
            app_slug=self.app_slug,
            kind=kind,
            field_kind=field.field_kind,
            scope_id=self.run_id,
            session_id=self.session.session_id,
            value=candidates[0],
            operation_key=self.operation_key,
        )


@dataclass(slots=True)
class CredentialPhaseHandler:
    """``credential_generation``, ``vault_storage`` and ``credential_validation``.

    ONE handler for all three phases, which is a property of the lifecycle rather
    than a shortcut: ``capture_store_validate_publish`` commits ``vault_storage`` and
    ``credential_validation`` ITSELF, through ``STORAGE_BOUNDARIES``, because
    Requirement 10.7 orders them relative to a capture only it witnessed. Registering
    three handlers would mean two of them raced the boundaries the first already
    committed.

    Like ``SignupPhaseHandler`` and ``DeveloperAppPhaseHandler``, this exists because
    the phase reserves a provider-visible effect: the action loop alone would walk the
    credential page without ever reserving ``generate_credential``, and a retry would
    mint a second key.

    ``developer_app_id`` is recovered from the completed ``create_dev_app`` receipt
    through the READ-ONLY reservation reader. Deliberately not ``plan_effect``: that
    reserves as a side effect, so calling it here would insert a pending
    ``create_dev_app`` row and permanently refuse the real application creation.
    """

    journal: Any
    effects: EffectStore
    vault: Any
    validator: Any
    publisher: Any
    reservations: Callable[..., Any]
    spec_for: Callable[[str], CredentialCaptureSpec]
    research_endpoint: str | None = None
    credential_kind: str = DEFAULT_CREDENTIAL_KIND

    async def __call__(
        self,
        *,
        run_id: str,
        phase: OnboardingPhase,
        profile: ProviderProfile | None,
        lease: Lease,
        deps: OnboardingDeps,
    ) -> PhaseStep:
        if phase not in CREDENTIAL_PHASES:
            raise ValueError("the credential handler drives the credential phases only")
        if profile is None:
            # The capture contract is a projection of the profile, so there is no
            # contract to capture against without one.
            return PhaseStep.pause("capture_spec_unavailable")
        developer_app_id = self._developer_app_id(run_id)
        if developer_app_id is None:
            # Reached only if the phase machine let the run past ``developer_app``
            # without a completed receipt, which is a wiring fault rather than a run
            # outcome — but pausing beats minting a credential for an application
            # this run cannot name.
            return PhaseStep.pause("outcome_unknown")
        current = deps.phases.current_phase(run_id=run_id)
        attempt = current[1] if current is not None else 0
        lifecycle_deps = CredentialLifecycleDeps(
            journal=self.journal,
            effects=self.effects,
            vault=self.vault,
            validator=self.validator,
            publisher=self.publisher,
            research_endpoint=self.research_endpoint,
        )
        session = await self._surface(
            run_id=run_id,
            profile=profile,
            developer_app_id=developer_app_id,
            deps=deps,
            phase=phase,
            lease=lease,
        )
        step = await capture_store_validate_publish(
            run_id=run_id,
            profile=profile,
            developer_app_id=developer_app_id,
            kind=self.credential_kind,
            session=session,
            deps=lifecycle_deps,
            attempt=attempt,
            correlation_id=phase_correlation_id(run_id=run_id, phase=phase, attempt=attempt),
        )
        # ``CredentialStep`` and ``PhaseStep`` are field-for-field parallel by
        # design — ``ops.onboarding.credentials`` says so where it declares
        # ``CredentialStepKind`` — so this is a translation, not a re-decision.
        return PhaseStep(
            kind=step.kind,
            reason_code=step.reason_code,
            next_phase=step.next_phase,
            not_before=step.not_before,
        )

    async def _surface(
        self,
        *,
        run_id: str,
        profile: ProviderProfile,
        developer_app_id: str,
        deps: OnboardingDeps,
        phase: OnboardingPhase,
        lease: Lease,
    ) -> SessionCredentialSurface:
        """The credential surface, bound to the key the grant will be reserved under.

        The operation key is derived from the SAME inputs
        ``capture_store_validate_publish`` derives its own from — including
        ``current_generation``, which reads without advancing — so the grant the
        lifecycle reserves and the key this surface presents are the same string. A
        mismatch is refused by the vault's grant-binding check rather than trusted,
        so a drift here fails closed rather than writing to the wrong row.
        """

        generation = self.journal.current_generation(run_id=run_id, effect=CREDENTIAL_EFFECT)
        vault_kind = ONBOARDING_VAULT_KINDS[cast("Any", self.credential_kind)]
        operation_key = generate_credential_key(
            run_id,
            developer_app_id,
            cast("Any", self.credential_kind),
            generation,
        )
        session = await deps.sessions.session_for(run_id=run_id, phase=phase, lease=lease)
        return SessionCredentialSurface(
            session=cast("PlaywrightLoopSession", session),
            store=cast("CaptureVault", self.vault),
            spec_for=self.spec_for,
            run_id=run_id,
            app_slug=profile.app_slug,
            operation_key=f"{operation_key}:capture:{vault_kind}",
        )

    def _developer_app_id(self, run_id: str) -> str | None:
        """The application id the completed ``create_dev_app`` effect recorded."""

        for record in self.reservations(run_id=run_id):
            if record.effect != "create_dev_app" or record.disposition != "skip":
                continue
            recorded = (record.receipt or {}).get(DEVELOPER_APP_RECEIPT_KEY)
            if recorded:
                return str(recorded)
        return None


@dataclass(slots=True)
class LedgerConfigurationPublisher:
    """``ProviderConfigurationPublisher``: a proven credential becomes config.

    Publishes only the ``vault://`` reference and the validation outcome — never a
    value — so the published configuration carries no credential material.
    """

    ledger: Any

    def publish_provider_configuration(
        self,
        *,
        run_id: str,
        reference: str,
        kind: Any,
        result: Any,
        completed_at: str,
    ) -> None:
        self.ledger.append_audit_event(
            run_id=run_id,
            event_type="provider_configuration_published",
            payload={
                "credential_kind": str(kind),
                "credential_reference": reference,
                "validation_status": str(getattr(result, "status", "")),
                "validation_endpoint": str(getattr(result, "endpoint", "")),
                "completed_at": completed_at,
            },
        )


__all__ = [
    "DEFAULT_CREDENTIAL_KIND",
    "LedgerConfigurationPublisher",
    "LedgerMailboxBinder",
    "LedgerSignupBinding",
    "RunDeveloperAppBinding",
    "SessionCredentialSurface",
    "SessionSignupSubmitter",
]
