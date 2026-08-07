"""The terminal-step adapters: the ports a real run reaches and finds empty.

Every protocol implemented here already existed, was already a required (or
driver-consulted) field of a dependency object, and had **zero** implementations
anywhere in the tree. That is a very specific kind of gap: a run does not fail
these ports at composition time, it fails them at the last step of a phase it has
already spent provider-visible effects reaching. ``ProviderConfigurationPublisher``
is the worst of them — it is a non-optional field of
:class:`~ops.onboarding.credentials.CredentialLifecycleDeps`, so the only way a
deployment could construct that object at all was with a test double.

**Why one module rather than five.** Each adapter here is the same shape: a port
declared next to its call site, bound to durable state that already exists
(the run ledger, the effect ledger, the vault). None of them owns a policy, and
none of them may be reached from the driver — the composition root binds them and
hands them across. Keeping them together is what makes it checkable at a glance
that no adapter here reads a value, prompts a human, or decides anything.

**The two rules every adapter below keeps.**

*References, never values.* Three of these ports sit next to a vault verb that
returns plaintext, and every one of them is deliberately built over the
reference-returning verb instead — see :class:`VaultLoginReferenceBinder`, where
the reasoning is written out, because that is the port where the wrong choice
looks most convenient.

*No new pause a human must clear.* An adapter that cannot answer returns the
empty/absent answer its port already documents (``()``, ``None``) so the driver
takes the path it already has for "this deployment cannot do that". Nothing here
invents an escalation; the one genuinely irreversible action in this module —
creating provider configuration at Composio — is made exactly once by the effect
ledger the managed-auth boundary already owns, not by a second scheme here.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, cast, get_args

from ops.browser.signup import SignupIdentity, SignupMailboxBinder, SignupRunBinding
from ops.core.secret_store import REUSABLE_LOGIN_FIELDS, SecretStoreError, parse_vault_reference
from ops.credentials.validator import CredentialValidationResult
from ops.onboarding.credentials import ProviderConfigurationPublisher
from ops.onboarding.driver import (
    CREDENTIAL_FLOW_KINDS,
    DeveloperAppBinding,
    DeveloperAppRequest,
    LoginReferenceBinder,
    LoopSessionFactory,
    VerificationBinding,
    VerificationContext,
    VerificationSession,
)
from ops.onboarding.handlers import ResearchTarget, RunAccountBinding, RunProviderBinding
from ops.onboarding.lease import Lease
from ops.onboarding.phase import OnboardingPhase
from ops.providers.composio_managed_auth import (
    ManagedConnectionStart,
    validate_managed_auth_callback_base_url,
)
from ops.providers.profile import CredentialKind
from ops.recipes.app_recipes import RouteKind

LOGGER = logging.getLogger("composio_ops.onboarding_publishers")

# The routes a run row may legally name, derived from the type rather than
# restated, so this stays correct when a route is added. See ``_route_kind``.
_ROUTE_KINDS: frozenset[str] = frozenset(get_args(RouteKind))

# The audit event a published configuration writes, and the one the mailbox
# binder writes. Named constants because both are also *read back* below: the
# verification binding recovers the run's mailbox alias from the second one, so a
# renamed string on one side and not the other would silently un-bind a run's
# verification rather than fail.
CONFIGURATION_PUBLISHED_EVENT = "provider_configuration_published"
VERIFICATION_RECIPIENT_EVENT = "verification_recipient_bound"

# The event the enqueue path writes when a caller opts a run into the autonomous
# driver, and the only durable home the operator's research hint has. Read back
# by :class:`LedgerRunProviderBinding`, so the same renaming hazard applies as
# above: a changed string on one side alone silently drops the hint.
ONBOARDING_REQUEST_EVENT = "onboarding_requested"

# The phase the verification session is obtained for. Stated once so the session
# the binding hands back is attributable to the phase that asked for it.
VERIFICATION_PHASE: OnboardingPhase = "email_verification"


# --- provider configuration (LL-3.5's terminal step) -------------------------


class ManagedConnectionStarter(Protocol):
    """The one managed-auth verb publication needs, as a port.

    Structurally satisfied by
    :class:`~ops.providers.composio_managed_auth.ComposioManagedAuthProvider`. It
    is declared as a port rather than imported as a class so a test can publish
    against a fake and this module never has to reach for the SDK — no live
    Composio call is made anywhere below this line.
    """

    async def start_connection(
        self, *, toolkit_slug: str, callback_url: str, effect_identity: str
    ) -> ManagedConnectionStart:
        """Resolve or create the toolkit's managed auth config, then link once."""


class PublishedConfigurationLedger(Protocol):
    """Where the run records that its configuration is published.

    Two verbs off :class:`~ops.core.storage.OperationsStorage`, both of which
    already redact what they write. There is no read verb: publication is a write,
    and an adapter that could read the run row could be tempted into deciding
    something from it.
    """

    def update_run(self, run_id: str, **changes: object) -> dict[str, Any]:
        """Update the declared mutable run columns."""

    def append_audit_event(
        self, *, run_id: str, event_type: str, payload: Mapping[str, object] | None = None
    ) -> int:
        """Append one redacted audit row to the run's timeline."""


@dataclass(frozen=True, slots=True)
class ComposioProviderConfigurationPublisher:
    """Publish one proven credential as Composio provider configuration.

    **Why this wraps ``start_connection`` rather than calling the SDK.**
    ``ops.providers.composio_managed_auth`` already owns the reserve → act →
    complete walk over the effect ledger for exactly the two calls publication
    needs: ``auth_configs.create`` (resolve-or-create the toolkit's managed auth
    config) and ``connected_accounts.link`` (create the connection). That walk is
    the codebase's only idempotency scheme for provider-visible Composio effects,
    including the reconcile-by-alias recovery for an ambiguous link and the
    adopt-the-ACTIVE-account recovery for a duplicate. Re-deriving any of it here
    would be a second scheme over the same two irreversible calls, which is how a
    run ends up with two connections for one app.

    **The effect identity is per-run and nothing else.** A retry of the terminal
    step — a worker that crashed between the Composio call and the ledger write,
    a re-driven ``credential_validation`` — presents the same identity, so the
    managed-auth boundary replays its receipt instead of linking again. It
    deliberately does not include the credential reference: a run that superseded
    an invalid credential and published the next one must still hold exactly one
    connection, and keying on the reference would give the second generation a
    fresh identity and therefore a second link.

    **Nothing here holds a value, and nothing here persists the redirect.**
    ``reference`` is parsed for its app slug and then written as text; the
    credential itself never enters this process. ``ManagedConnectionStart``
    refuses to be serialized at all, and this adapter reads only its
    ``connection_request_id`` and ``replayed`` flag — the one-time redirect is left
    where the managed-auth boundary put it, which is nowhere durable.
    """

    connections: ManagedConnectionStarter
    ledger: PublishedConfigurationLedger
    # The public HTTPS origin the connection's callback is built on, validated at
    # construction by the managed-auth boundary's own checker rather than by a
    # second copy of the rules: a placeholder or loopback origin is a deployment
    # mistake, and it should fail where the deployment is composed and not at the
    # last step of a run that has already spent its effects.
    callback_base_url: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "callback_base_url",
            validate_managed_auth_callback_base_url(self.callback_base_url),
        )

    def publish_provider_configuration(
        self,
        *,
        run_id: str,
        reference: str,
        kind: CredentialKind,
        result: CredentialValidationResult,
        completed_at: str,
    ) -> None:
        """Publish configuration for one validated reference (Requirement 10.12).

        PRE:  the caller established ``result.status == "valid"`` and a
              ``completed_at`` strictly after ``result.checked_at``. Both are
              re-checked here, not because the caller is untrusted but because
              this is the last inch before an irreversible provider call and the
              check costs nothing.
        POST: the toolkit's managed auth config exists, exactly one connection is
              linked for this run, and the run's timeline names the reference —
              never a value and never the redirect.

        **This method is synchronous and blocks, on purpose.** The port is
        declared ``def`` (its two existing test doubles are synchronous), and the
        installed Composio 0.18 SDK is synchronous too. ``asyncio.run`` here is
        safe and correct *because* the single call site awaits this through
        ``asyncio.to_thread`` — so the driver's event loop is free while the
        provider call is in flight, which is the same guarantee
        ``composio_managed_auth`` gets from wrapping each SDK call in a thread.
        Calling this directly from a coroutine would raise rather than deadlock,
        which is the failure mode worth having.
        """

        if result.status != "valid":
            raise ValueError("provider configuration is published only for a valid credential")
        if completed_at <= result.checked_at:
            raise ValueError("a completion timestamp must strictly follow its validation")
        # The app slug comes from the reference the vault itself minted, so the
        # toolkit this configuration is published for is a durable fact of the run
        # rather than anything a page or a research pass could influence.
        parts = parse_vault_reference(reference)

        started = asyncio.run(
            self.connections.start_connection(
                toolkit_slug=parts.app_slug,
                callback_url=f"{self.callback_base_url}/runs/{run_id}",
                effect_identity=publication_effect_identity(run_id),
            )
        )

        # The Composio effect is durable before this line, so a failure below is
        # replayable: the same identity returns the same connection rather than
        # linking a second one.
        self.ledger.update_run(run_id, connection_request_id=started.connection_request_id)
        self.ledger.append_audit_event(
            run_id=run_id,
            event_type=CONFIGURATION_PUBLISHED_EVENT,
            payload={
                # ``kind`` and not ``credential_kind``. The ledger redacts every
                # payload it writes, and ``ops/core/redaction.py``'s
                # ``credentials?`` alternative matches any key with a
                # ``credential`` segment — so ``credential_kind`` reaches the
                # timeline as ``[REDACTED]`` and this event loses the one fact it
                # exists to record. The sibling ``credential_reference`` survives
                # only because a ``vault://`` value is on the redactor's allow
                # list, which is exactly why it keeps its longer name.
                "kind": kind,
                "credential_reference": reference,
                "connection_request_id": started.connection_request_id,
                "validated_at": result.checked_at,
                "completed_at": completed_at,
                "replayed": started.replayed,
            },
        )
        LOGGER.info(
            "onboarding run %s published %s configuration for %s",
            run_id,
            kind,
            parts.app_slug,
        )


def publication_effect_identity(run_id: str) -> str:
    """The effect identity one run's publication reserves, derived and stable.

    A free function so the identity is derivable by anything that has to reason
    about the reservation — a reconciliation pass, an operator answering "did this
    run link a connection" — without constructing a publisher.
    """

    return f"{run_id}:onboarding-publish:v1"


# --- login references after a duplicate-account re-route (Requirement 6.8) ---


class SignupLoginReferenceVault(Protocol):
    """The two vault verbs the login re-route needs, and no others.

    Structurally satisfied by :class:`~ops.core.secret_store.SQLiteSecretStore`.
    Both verbs below are the reference-shaped ones; the value-shaped siblings that
    sit beside them in the same class are deliberately absent from this port, so
    an implementation of this binder cannot resolve a login even by mistake.
    """

    def promote_staged_signup_login_pair(
        self, *, app_slug: str, account_ref: str, run_id: str
    ) -> tuple[str, ...]:
        """Promote this run's staged signup pair into reusable account scope."""

    def account_login_references(self, *, app_slug: str, account_ref: str) -> dict[str, str]:
        """``{login field: vault://app/kind/id}`` for whatever is stored."""


class RunBindingLedger(Protocol):
    """The one read the run-scoped bindings need: the run's own durable row.

    Read-only by construction. Every fact these adapters supply — the app slug,
    the account binding, the browser session — is a column the run was created
    with, so none of them is inferred, and an adapter that could write the row
    could change the identity it is supposed to be reporting.
    """

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        """The run's record, or ``None`` when the run does not exist."""

    def list_audit_events(self, run_id: str) -> list[dict[str, Any]]:
        """The run's redacted timeline, oldest first."""


@dataclass(frozen=True, slots=True)
class VaultLoginReferenceBinder:
    """Bind a re-routed run's stored signup pair as its login REFERENCES.

    **Why the reference form is the only safe one here, in full.** There is a
    ready-made verb one layer up — ``ops.runs.login_secrets`` exposes a
    ``staged_signup_login_values`` that returns ``{field: SecretStr(value)}`` —
    and it is *not* a drop-in for this port even though the field names line up.
    The login route consumes what this binder returns through the browser secret
    broker: a reference plus a one-shot grant is redeemed *inside* the browser
    process, so the plaintext exists only in the page's own address space and
    never in this one (Requirements 6.3, 6.5, 6.6). Returning values instead would
    move real sign-in credentials through the driver, through whatever logs a step
    boundary writes, and into a ``PhaseStep`` the ledger records — a layer whose
    entire contract is that it holds references and nothing else (Requirement
    19.8). The two forms are one call apart and one security posture apart, which
    is exactly why the port's return type is a pair of strings and the vault verb
    this adapter is built on selects ``kind, id`` and never ``ciphertext``: the
    absence of a value is structural, not a discipline anyone has to keep.

    **Promotion is what creates the references, and it is idempotent.** Before a
    signup submits, the generated pair lives encrypted in ``staged_signup_logins``
    — a staging table with no vault row and therefore no reference. Promotion
    moves it into the reusable account scope, which is where
    ``account_login_references`` can see it. The already-promoted account is read
    first, so a re-driven re-route (a crash, a second worker) rebinds the same
    references and promotes nothing; the driver relies on that, because it calls
    this on every pass through the re-routed phase.
    """

    vault: SignupLoginReferenceVault
    ledger: RunBindingLedger

    def adopt_signup_references_for_login(
        self, *, run_id: str, profile_digest: str
    ) -> tuple[tuple[str, str], ...]:
        """Bind the run's stored signup references as its login references.

        POST: returns complete ``(login field, vault reference)`` pairs, sorted by
              field so two workers produce byte-identical bindings, or ``()`` when
              this run has nothing to sign in with. ``()`` is the honest answer
              rather than an exception: the driver already treats an empty binding
              as a wiring/storage defect and refuses the re-route with a named
              cause, and raising a vault error through it would replace that named
              cause with a stack trace.

        ``profile_digest`` is not a selector. The login identity belongs to the
        run's app and account binding, both of which are durable run columns; the
        digest names the provider profile the phase is being driven under, and
        choosing a credential by it would let a re-researched profile point the
        re-route at a different account's row.
        """

        record = self.ledger.get_run(run_id)
        if record is None:
            LOGGER.warning("onboarding run %s has no ledger row to adopt logins for", run_id)
            return ()
        app_slug = str(record.get("app_slug") or "")
        account_ref = str(record.get("browser_account_ref") or "")
        if not app_slug or not account_ref:
            # A run with no account binding never staged a signup pair under one,
            # so there is nothing to adopt and nothing to promote.
            return ()

        references = self.vault.account_login_references(app_slug=app_slug, account_ref=account_ref)
        if not self._is_complete(references):
            try:
                self.vault.promote_staged_signup_login_pair(
                    app_slug=app_slug, account_ref=account_ref, run_id=run_id
                )
            except (SecretStoreError, ValueError) as exc:
                # ``signup_login_stage_missing`` is the ordinary shape of this:
                # the run reached the re-route without ever staging a pair. The
                # reason code is logged and the empty binding is returned, which
                # is the same outcome with a cause an operator can read.
                #
                # ``ValueError`` is caught alongside it deliberately.
                # ``promote_staged_signup_login_pair`` validates the identifier
                # SHAPES itself and raises a bare ``ValueError`` for a run id or
                # account ref that is not the opaque ``(acct|run)_<32 hex>`` form,
                # while its reference-reading sibling answers ``{}`` for the same
                # input. Without this arm, a run row carrying a legacy or
                # hand-made identifier would sail past the "nothing stored" check
                # and then crash the re-route out of the driver instead of
                # refusing it with a named cause — a hard stop where the port
                # already documents an empty binding.
                LOGGER.warning(
                    "onboarding run %s could not promote its signup login (%s)",
                    run_id,
                    getattr(exc, "reason_code", "signup_login_promotion_failed"),
                )
                return ()
            references = self.vault.account_login_references(
                app_slug=app_slug, account_ref=account_ref
            )

        if not self._is_complete(references):
            # A partial pair cannot sign in, and reporting it as though it could
            # would send the login route at a form it can only half fill.
            return ()
        return tuple(sorted(references.items()))

    @staticmethod
    def _is_complete(references: Mapping[str, str]) -> bool:
        """Whether every reusable login field has a reference."""

        return set(references) == set(REUSABLE_LOGIN_FIELDS)


# --- the run-scoped bindings the phases read (design LL-2) -------------------


def _route_kind(record: Mapping[str, object]) -> RouteKind | None:
    """The run's reviewed route, or ``None`` when the row cannot name a known one.

    The column is plain ``TEXT`` (``ops.core.storage``), so it is a string that
    *usually* holds a route and carries no guarantee. It is checked against the
    live ``RouteKind`` members rather than cast, for two reasons. A row written by
    an older or newer deployment can hold a value this build has no field set for,
    and ``_REQUIRED_FIELDS_BY_ROUTE`` would then silently miss and relax nothing —
    the same answer, but reached by accident instead of on purpose. And deriving
    the membership set from ``get_args`` rather than restating it means a route
    added later (the planned ``managed_key``) is admitted here the moment it is
    added to the type, with no second list to remember.

    Returning ``None`` for an unrecognised value is the conservative direction:
    :class:`~ops.onboarding.handlers.ResearchTarget` documents ``None`` as the
    strictest, self-serve field set, so an unreadable route makes research harder
    to satisfy, never easier.
    """

    value = record.get("route_kind")
    if not isinstance(value, str) or value not in _ROUTE_KINDS:
        return None
    return cast("RouteKind", value)


@dataclass(frozen=True, slots=True)
class LedgerRunProviderBinding:
    """Which provider a run is for, read from the row the run was created with.

    Research's INPUT, and therefore deliberately not read from the provider
    profile — that is research's output, and deriving the target from it would
    make the phase a no-op that corroborates whatever it already concluded.

    ``app_name`` and ``app_slug`` are columns the canonical creation path writes
    from the reviewed recipe, so two workers picking the same run up research the
    same provider. The hint URL is the one field that is not a column: it is an
    operator's optional pointer, recorded onto the run's own timeline by the
    enqueue path (:data:`ONBOARDING_REQUEST_EVENT`) rather than into the request
    record, because the request record is what the idempotency fingerprint is
    computed over and a new field on it would turn every stored fingerprint into
    a false replay conflict.
    """

    ledger: RunBindingLedger

    def research_target(self, *, run_id: str) -> ResearchTarget:
        """The provider this run was created to onboard."""

        record = self.ledger.get_run(run_id)
        if record is None:
            raise ValueError("the run has no ledger row to derive a research target from")
        provider_name = str(record.get("app_name") or "")
        app_slug = str(record.get("app_slug") or "")
        if not provider_name or not app_slug:
            # Raised rather than degraded: research driven with no provider would
            # corroborate an arbitrary domain and commit it as this run's profile,
            # which every later phase's host confinement is derived from.
            raise ValueError("the run's ledger row names no provider to research")
        return ResearchTarget(
            provider_name=provider_name,
            app_slug=app_slug,
            hint_url=self._hint(run_id),
            route_kind=_route_kind(record),
        )

    def _hint(self, run_id: str) -> str | None:
        """The most recently recorded operator hint URL, or ``None``.

        Only an ``https://`` value is returned. The API already refuses anything
        else at the boundary; re-checking here is one line and keeps a
        hand-written or migrated timeline row from handing the research fetcher a
        scheme it has no policy for.
        """

        found: str | None = None
        try:
            events = self.ledger.list_audit_events(run_id)
        except Exception:
            # A timeline that cannot be read costs the hint, never the phase:
            # ``hint_url`` is one more candidate for research to corroborate and
            # never an admitted claim.
            LOGGER.warning("onboarding run %s could not be read for a research hint", run_id)
            return None
        for event in events:
            if event.get("event_type") != ONBOARDING_REQUEST_EVENT:
                continue
            payload = event.get("payload")
            if not isinstance(payload, Mapping):
                continue
            hint = payload.get("hint_url")
            if isinstance(hint, str) and hint.startswith("https://"):
                found = hint
        return found


@dataclass(frozen=True, slots=True)
class LedgerRunAccountBinding:
    """The opaque account scope a run's credentials are stored under.

    One column, read and never derived. ``browser_account_ref`` is minted at run
    creation from the run id, the app slug, and the work-email reference
    (``ops.workflow.canonical_runtime`` via ``derive_browser_account_ref``), and
    the vault probe, the signup staging rows and the login re-route all key on it
    — so a binding that recomputed it instead of reading it would ask the vault
    about an account this run does not own. That reads as "no credentials", which
    routes a run that could have signed in straight to the one operator prompt
    this system has.

    An absent value is returned as ``""`` rather than raised. That is the honest
    shape: a run created against a non-Playwright recipe never gets an account
    binding, the probe finds nothing stored under it, and the run takes the
    admission route it would have taken anyway.
    """

    ledger: RunBindingLedger

    def account_ref(self, *, run_id: str) -> str:
        """The account binding this run's credentials are stored under."""

        record = self.ledger.get_run(run_id) or {}
        return str(record.get("browser_account_ref") or "")


@dataclass(frozen=True, slots=True)
class LedgerDeveloperAppBinding:
    """The developer-application request, read from the run's durable facts.

    Both fields of a :class:`~ops.onboarding.driver.DeveloperAppRequest` have to
    be derivable by *any* worker that picks the run up, because the requested
    application name — and therefore the operation key that makes the creation
    happen once — is a pure function of them. So neither may come from a page.

    ``owner_id`` is deployment configuration (the capability owner this
    installation acts as), and the credential kind is the run's own recorded
    request when it has one, falling back to the deployment's reviewed default.
    The fallback is a *policy* rather than a guess: it is a checked-in credential
    kind supplied at composition time, and an unrecognised recorded kind is
    ignored in its favour rather than passed through, because a kind outside
    ``CREDENTIAL_FLOW_KINDS`` would select no flow at all.
    """

    ledger: RunBindingLedger
    owner_id: str
    default_credential_kind: CredentialKind = "api_key"

    def __post_init__(self) -> None:
        if self.default_credential_kind not in CREDENTIAL_FLOW_KINDS:
            raise ValueError("the default credential kind must select a declared flow")

    def developer_app_request(self, *, run_id: str) -> DeveloperAppRequest:
        """The run's durable developer-application request."""

        record = self.ledger.get_run(run_id) or {}
        request = record.get("request")
        recorded = request.get("credential_kind") if isinstance(request, Mapping) else None
        kind = (
            cast(CredentialKind, recorded)
            if isinstance(recorded, str) and recorded in CREDENTIAL_FLOW_KINDS
            else self.default_credential_kind
        )
        # ``DeveloperAppRequest`` re-validates both fields; a run row that cannot
        # produce a valid request raises here rather than reaching the provider
        # with a name derived from something malformed.
        return DeveloperAppRequest(owner_id=self.owner_id, credential_kind=kind)


@dataclass(frozen=True, slots=True)
class LedgerSignupRunBinding:
    """The account binding, session, and signup address one signup runs under.

    ``account_ref`` and ``session_id`` are run columns — the same account binding
    the admission probe already decided against, and the session the run is being
    driven on — so the signup operation key and the vault rows agree with what the
    run was admitted for. ``signup_address`` is deployment configuration (the
    mailbox this installation signs up with) and is the one field that is not a
    run column: a run does not get to invent the address its verification will be
    searched on.
    """

    ledger: RunBindingLedger
    signup_address: str

    def signup_identity(self, *, run_id: str) -> SignupIdentity:
        """The account binding, browser session, and signup address for this run.

        Raises rather than returning a partial identity: every field is a
        precondition of an effect-bearing phase, and a signup submitted under a
        missing account binding would create a real vendor account nobody can
        attribute.
        """

        record = self.ledger.get_run(run_id)
        if record is None:
            raise ValueError("the run has no ledger row to derive a signup identity from")
        return SignupIdentity(
            account_ref=str(record.get("browser_account_ref") or ""),
            session_id=str(record.get("browser_session_id") or ""),
            signup_address=self.signup_address,
        )


@dataclass(frozen=True, slots=True)
class LedgerSignupMailboxBinder:
    """Record the canonical mailbox alias one run verifies on (Req. 7.3, 7.4).

    One write, onto the run's own timeline. The alias is not a secret — it is the
    plus-tagged address the signup was submitted under — but it *is* the single
    fact that stops one run consuming another run's verification message, so it is
    written where it is durable and attributable rather than held in a worker.

    The write is an append, so a re-driven signup records the binding again rather
    than failing; :class:`LedgerVerificationBinding` reads the most recent one,
    which is the same answer.
    """

    ledger: PublishedConfigurationLedger

    def bind_verification_recipient(self, *, run_id: str, session_id: str, address: str) -> None:
        """Record the canonical mailbox alias this run verifies on."""

        self.ledger.append_audit_event(
            run_id=run_id,
            event_type=VERIFICATION_RECIPIENT_EVENT,
            payload={"session_id": session_id, "address": address},
        )


@dataclass(frozen=True, slots=True)
class LedgerVerificationBinding:
    """Where the driver learns which mailbox and which session a run verifies on.

    The context is rebuilt from the binding the signup phase recorded, which is
    what makes verification continue on the account signup actually created rather
    than on whatever address configuration currently names: a deployment that
    rotates its signup alias must not retarget a run that is mid-flight.

    The session is obtained from the same factory the driver drives every other
    phase through, so verification continues on the run's live session and submits
    no second login (Requirement 7.30). The cast is the seam between two narrow
    views of one session object, exactly as the credential handlers do it — this
    adapter cannot widen what the verification phase may call.
    """

    ledger: RunBindingLedger
    sessions: LoopSessionFactory

    def verification_context(
        self, *, run_id: str, challenge_issued_at_ms: int
    ) -> VerificationContext:
        """The run's mailbox alias, bound session, and freshness floor.

        Raises when the run has no recorded recipient. That is deliberate and it
        is not a new human gate: a verification search with no bound alias is the
        one search that could read another run's mail, so there is no degraded
        answer to return. The driver's caller already treats a raised binding as
        the phase failing rather than as an operator prompt.
        """

        binding = self._latest_recipient(run_id)
        if binding is None:
            raise ValueError("the run has no recorded verification recipient")
        address, bound_session = binding
        record = self.ledger.get_run(run_id) or {}
        # The session recorded with the binding wins over the run column: it is
        # the session that actually submitted the signup, and the column may have
        # since been re-pointed by a reattach.
        session_id = bound_session or str(record.get("browser_session_id") or "")
        # ``consumed_message_ids`` is left at its default, and that is not an
        # omission. It is a within-call skip list: the mailbox provider rebuilds
        # it as it walks its own selection rounds, and the durable guarantee that
        # a message is consumed once is the per-message CLAIM, not this tuple.
        # Reconstructing a cross-attempt list from the timeline would duplicate
        # the claim as a weaker second scheme, and a stale entry in it would hide
        # the only message a re-driven verification can still use.
        return VerificationContext(
            mailbox_address=address,
            session_id=session_id,
            challenge_issued_at_ms=challenge_issued_at_ms,
        )

    async def verification_session(self, *, run_id: str, lease: Lease) -> VerificationSession:
        """The still-alive session the signup submission was made on."""

        session = await self.sessions.session_for(
            run_id=run_id, phase=VERIFICATION_PHASE, lease=lease
        )
        return cast(VerificationSession, session)

    def _latest_recipient(self, run_id: str) -> tuple[str, str] | None:
        """The most recent recorded ``(address, session id)``, or ``None``."""

        found: tuple[str, str] | None = None
        for event in self.ledger.list_audit_events(run_id):
            if event.get("event_type") != VERIFICATION_RECIPIENT_EVENT:
                continue
            payload = event.get("payload")
            if not isinstance(payload, Mapping):
                continue
            address = payload.get("address")
            if not isinstance(address, str) or not address:
                continue
            session_id = payload.get("session_id")
            found = (address, session_id if isinstance(session_id, str) else "")
        return found


# --- typecheck-only conformance ----------------------------------------------
#
# Each adapter is checked against the port it claims here, in the module that owns
# the adapter, so a protocol that changes shape fails next to the implementation
# instead of at the composition root that merely names it.


def _publisher_conformance(
    publisher: ComposioProviderConfigurationPublisher,
) -> ProviderConfigurationPublisher:
    return publisher


def _login_binder_conformance(binder: VaultLoginReferenceBinder) -> LoginReferenceBinder:
    return binder


def _developer_app_conformance(binding: LedgerDeveloperAppBinding) -> DeveloperAppBinding:
    return binding


def _verification_conformance(binding: LedgerVerificationBinding) -> VerificationBinding:
    return binding


def _signup_binding_conformance(binding: LedgerSignupRunBinding) -> SignupRunBinding:
    return binding


def _signup_mailbox_conformance(binder: LedgerSignupMailboxBinder) -> SignupMailboxBinder:
    return binder


def _provider_binding_conformance(binding: LedgerRunProviderBinding) -> RunProviderBinding:
    return binding


def _account_binding_conformance(binding: LedgerRunAccountBinding) -> RunAccountBinding:
    return binding


__all__ = [
    "CONFIGURATION_PUBLISHED_EVENT",
    "ONBOARDING_REQUEST_EVENT",
    "VERIFICATION_RECIPIENT_EVENT",
    "ComposioProviderConfigurationPublisher",
    "LedgerDeveloperAppBinding",
    "LedgerRunAccountBinding",
    "LedgerRunProviderBinding",
    "LedgerSignupMailboxBinder",
    "LedgerSignupRunBinding",
    "LedgerVerificationBinding",
    "ManagedConnectionStarter",
    "PublishedConfigurationLedger",
    "RunBindingLedger",
    "SignupLoginReferenceVault",
    "VaultLoginReferenceBinder",
    "publication_effect_identity",
]
