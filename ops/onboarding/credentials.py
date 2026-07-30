"""Credential kinds, their vault kinds, and their checked-in value contracts.

An onboarding run drives a provider the repo has never reviewed, so nearly
everything the run knows about that provider comes from research. The one thing
that must never come from research is what a valid credential *looks like*.
Research may say **where** a credential is minted — that is the profile's
``FlowSpec.entry_url`` — but the accepted value shape is checked in here, in
code, keyed by credential kind and by nothing else (Requirement 10.5).

**Why the key is the credential kind and never the app slug.** The value pattern
is the broker's defence against a compromised browser worker persisting
arbitrary material under a credential's name. A pattern that arrived alongside
the value, or one selected by an app slug that the same worker also supplies,
defends against nothing: whoever controls the value controls the check. Keying
on ``CredentialKind`` — the closed ``Literal`` in ``ops.providers.profile`` —
means the contract for an ``api_key`` is one contract for every provider,
forever, and onboarding a new provider cannot widen it. There is deliberately no
app slug anywhere in either mapping.

**Two mappings, two different disciplines.** ``ONBOARDING_VAULT_KINDS`` is
*derived* from the credential-kind vocabulary, because a vault kind is a
mechanical namespace decision and a new credential kind should not be able to
land without one. ``CREDENTIAL_VALUE_PATTERNS`` is written out explicitly and
checked for totality at import, because a value contract is a security review,
not a naming convention: a credential kind added without a reviewed pattern
fails this module's import rather than silently inheriting a permissive one.

**No new vault kinds.** Sign-in credentials minted during signup keep using the
durable kinds the vault already defines (``ACCOUNT_LOGIN_KIND_PREFIX`` over
``REUSABLE_LOGIN_FIELDS``, staged and promoted by ``ops.core.secret_store``), and the
one-shot fills keep using the four ``browser_login_*`` kinds the broker already
allows. Those are restated here as the onboarding vocabulary — in one place next
to the captured-credential kinds — not redefined; ``tests`` pins each against
the module that owns it, so a rename there fails there and here together. The
full kind table is design LL-5.3.

**The validation policy is the same discipline one boundary later** (design
LL-2.3, Requirements 10.8–10.11). Proving a stored credential works means one
read-only authenticated probe, and the two halves of that probe come from
different authorities for the same reason the capture contract's halves do:
*where* to probe may be research-derived, but it is admitted only when the
endpoint is a reviewed ``NetworkEndpointPolicy`` entry or resolves to the
profile's single registrable domain; *how* to authenticate comes from the
checked-in ``VALIDATION_AUTH_SCHEMES`` table keyed by credential kind, never
from page text. When neither half can be established the builder returns
``None``, which is a pause with reason code ``capture_spec_unavailable`` and the
reference left unpublished — never an implicit pass (Requirement 10.11).

Nothing in this module holds credential material. It names kinds and shapes, so
the only thing that ever crosses into a projection or an API response is a
reference (Requirement 19.8). The validator adapter below keeps that true at the
probe boundary too: it accepts a ``vault://`` reference, hands it to the existing
:class:`~ops.credentials.validator.CredentialValidator` (which resolves the value
in-process and discards it), and so the value is absent from the result, from log
records, and from every exception message this module can raise
(Requirement 10.10).

**The lifecycle itself is the last section** (design LL-3.5, Requirement 10):
:func:`capture_store_validate_publish` walks one credential from the provider's
page to published provider configuration, and the ordering it enforces is
``generate -> capture(store) -> validate -> publish``. Three properties of that
walk are worth stating up front, because they are why the code is shaped the way
it is:

*Storage is not a step a caller can forget.* The value crosses into the vault
inside the broker's capture verb, so the reference this module receives already
implies a durable row (Requirement 10.3, Property 9). There is no branch here in
which a captured value exists and a reference does not.

*Publication is gated on a recorded ``valid``.* The publish call sits behind one
equality test against the validator's status, and the completion timestamp it
records is derived to be strictly after the validation timestamp
(Requirements 10.12, 10.13, 10.14). Every other status leaves the reference
unpublished.

*The ladder terminates, and the only generation advance in the codebase lives on
one branch of it.* ``unavailable`` / ``failed`` retries up to the validation
attempt budget and then pauses; ``invalid`` supersedes up to the generation
budget and then pauses. The supersede branch is the sole caller of
``PhaseHistoryStore.next_generation`` (Requirement 13.12), which is what makes a
Retry Current Step derive the operation key it already reserved and be refused a
second mint. Superseding and marking unusable are status moves on the existing
``secrets`` rows, never deletes, so an audit can still answer "which credential
did we abandon" (design LL-5.3).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, Literal, Protocol, Self, TypeGuard, get_args
from urllib.parse import urlsplit

import httpx

from ops.browser.host_policy import registrable_domain as resolve_registrable_domain
from ops.core.effect_ledger import EffectStore
from ops.core.network_endpoint_policy import NetworkEndpointError, normalize_endpoint
from ops.core.network_endpoint_policy import validation_endpoint as reviewed_validation_endpoint
from ops.core.secret_store import (
    ACCOUNT_LOGIN_KIND_PREFIX,
    REUSABLE_LOGIN_FIELDS,
    SecretStore,
    parse_vault_reference,
)
from ops.credentials.validator import (
    CredentialValidationPolicy,
    CredentialValidationResult,
    CredentialValidator,
    PolicyBoundCredentialValidator,
    ValidationAuthScheme,
)
from ops.onboarding.effects import (
    OnboardingEffect,
    complete_effect,
    generate_credential_key,
    mark_effect_outcome_unknown,
    plan_effect,
)
from ops.onboarding.phase import (
    ONBOARDING_REASON_CODES,
    OnboardingPhase,
    OnboardingReasonCode,
    is_legal_phase_transition,
)
from ops.providers.profile import CredentialKind, ProviderProfile

if TYPE_CHECKING:  # pragma: no cover - imported for typing only
    # Typing-only so this module stays out of the settings import chain;
    # ``CredentialBudgets.from_settings`` needs attribute access alone.
    from ops.core.config import Settings

LOGGER = logging.getLogger("composio_ops.onboarding_credentials")

# Derived from the ``Literal`` rather than re-typed, the way
# ``ops.providers.profile`` derives its own vocabularies, so this module's notion
# of "every credential kind" cannot drift from the type the profile declares.
CREDENTIAL_KINDS: Final[tuple[CredentialKind, ...]] = get_args(CredentialKind)

# Captured integration credentials live in their own kind namespace, distinct
# from the sign-in namespace (``account_login_``) and from the one-shot transient
# namespace (``browser_login_``), so a durable credential can never be read
# through a path built for a different purpose.
ONBOARDING_VAULT_KIND_PREFIX: Final = "onboarding_"

# The kind column values of design LL-5.3, derived so the mapping is total by
# construction. Values are pinned to the reviewed table by test, so deriving
# them is a totality guarantee and not a licence to rename a stored kind.
ONBOARDING_VAULT_KINDS: Final[Mapping[CredentialKind, str]] = MappingProxyType(
    {kind: f"{ONBOARDING_VAULT_KIND_PREFIX}{kind}" for kind in CREDENTIAL_KINDS}
)

# The durable sign-in kinds, reused rather than re-invented: exactly
# ``account_login_login_email`` and ``account_login_login_password``, keyed by
# the login field the deterministic login state machine fills.
SIGNUP_LOGIN_VAULT_KINDS: Final[Mapping[str, str]] = MappingProxyType(
    {field: f"{ACCOUNT_LOGIN_KIND_PREFIX}{field}" for field in sorted(REUSABLE_LOGIN_FIELDS)}
)

# The one-shot fills. These four kinds already exist at the broker boundary and
# at the browser-service client boundary; onboarding adds none.
TRANSIENT_LOGIN_KIND_PREFIX: Final = "browser_login_"
TRANSIENT_LOGIN_FIELDS: Final[tuple[str, ...]] = (
    "login_email",
    "login_password",
    "login_otp",
    "login_verification_url",
)
TRANSIENT_LOGIN_VAULT_KINDS: Final[frozenset[str]] = frozenset(
    f"{TRANSIENT_LOGIN_KIND_PREFIX}{field}" for field in TRANSIENT_LOGIN_FIELDS
)

# Value contracts, keyed by credential kind. Checked in, reviewed, and total over
# ``CredentialKind``.
#
# WHY THESE ARE ANCHORED SOURCE STRINGS. The pattern has to survive two
# different consumers. ``api.browser_secret_broker`` applies it with
# ``re.fullmatch`` and ``ops.playwright.worker`` compiles it and applies
# ``Pattern.fullmatch``, so both already require a whole-value match — but a
# third consumer reaching for ``re.search`` or ``re.match`` would silently
# weaken the contract into "contains something credential-shaped", which a page
# full of prose can satisfy. Writing ``\A``/``\Z`` into the pattern itself makes
# the whole-value requirement a property of the contract instead of a property
# of each call site; ``_require_anchored`` below enforces it at import.
#
# The exported mapping stays ``str`` rather than ``re.Pattern`` because a
# ``CredentialCaptureSpec.value_pattern`` is a string field that crosses into
# recipe-shaped structures and is compared for equality with reviewed recipe
# patterns. The compiled forms are kept privately alongside so this module's own
# matcher never recompiles per capture, which is where the ``re.Pattern`` value
# actually pays off.
CREDENTIAL_VALUE_PATTERNS: Final[Mapping[CredentialKind, str]] = MappingProxyType(
    {
        # Public identifier: never secret, but still bounded, because an
        # unbounded "identifier" is an injection surface for published config.
        "oauth_client_id": r"\A[A-Za-z0-9_.~-]{8,256}\Z",
        "oauth_client_secret": r"\A[A-Za-z0-9_.~+/=-]{16,512}\Z",
        # The api_key / PAT / pair classes admit base64url and padded base64
        # because providers mint all three shapes; the 4096 ceiling is the
        # largest value that is still plausibly a single credential rather than
        # a page of text the worker scraped by mistake.
        "api_key": r"\A[A-Za-z0-9_.~+/=-]{16,4096}\Z",
        "personal_access_token": r"\A[A-Za-z0-9_.~+/=-]{16,4096}\Z",
        "client_credentials_pair": r"\A[A-Za-z0-9_.~+/=-]{16,4096}\Z",
    }
)

_ANCHOR_PREFIX: Final = "\\A"
_ANCHOR_SUFFIX: Final = "\\Z"

# The kind grammar shared by the vault reference parser
# (``ops.core.secret_store.parse_vault_reference``) and the broker request models. A
# kind that failed it would be unwritable, so it is checked here rather than
# discovered when a capture fails.
_VAULT_KIND = re.compile(r"[a-z0-9][a-z0-9_-]{0,99}")


def _require_total(mapping: Mapping[CredentialKind, object], *, name: str) -> None:
    """Refuse a credential-kind mapping that is not total, at import time.

    A missing kind is the dangerous direction: a lookup miss on a capture path
    either raises deep inside the broker or, worse, tempts a caller into a
    permissive default. A surplus key means the mapping and the ``Literal`` have
    diverged, which makes "keyed by credential kind" untrue.
    """

    missing = tuple(kind for kind in CREDENTIAL_KINDS if kind not in mapping)
    surplus = tuple(sorted(str(key) for key in mapping if key not in CREDENTIAL_KINDS))
    if missing or surplus:
        raise RuntimeError(
            f"{name} is not total over CredentialKind: missing={missing} surplus={surplus}"
        )


def _require_anchored(patterns: Mapping[CredentialKind, str]) -> None:
    """Refuse an unanchored or uncompilable value contract, at import time."""

    for kind, pattern in patterns.items():
        if not pattern.startswith(_ANCHOR_PREFIX) or not pattern.endswith(_ANCHOR_SUFFIX):
            raise RuntimeError(f"credential value pattern for {kind} is not whole-value anchored")
        try:
            re.compile(pattern)
        except re.error as exc:  # pragma: no cover - a malformed literal fails the import
            raise RuntimeError(f"credential value pattern for {kind} is invalid") from exc


def _require_writable_kinds(kinds: frozenset[str]) -> None:
    """Refuse a vault kind the reference grammar could not address."""

    for kind in sorted(kinds):
        if _VAULT_KIND.fullmatch(kind) is None:
            raise RuntimeError(f"vault kind {kind!r} is outside the vault reference grammar")


_require_total(ONBOARDING_VAULT_KINDS, name="ONBOARDING_VAULT_KINDS")
_require_total(CREDENTIAL_VALUE_PATTERNS, name="CREDENTIAL_VALUE_PATTERNS")
_require_anchored(CREDENTIAL_VALUE_PATTERNS)
_require_writable_kinds(
    frozenset(ONBOARDING_VAULT_KINDS.values())
    | frozenset(SIGNUP_LOGIN_VAULT_KINDS.values())
    | TRANSIENT_LOGIN_VAULT_KINDS
)

_COMPILED_VALUE_PATTERNS: Final[Mapping[CredentialKind, re.Pattern[str]]] = MappingProxyType(
    {kind: re.compile(pattern) for kind, pattern in CREDENTIAL_VALUE_PATTERNS.items()}
)


def is_credential_kind(value: str) -> TypeGuard[CredentialKind]:
    """Whether ``value`` is a member of the checked-in credential vocabulary.

    The narrowing guard for the boundaries where a kind arrives as an
    unvalidated string — the broker request payload above all — so a lookup is
    never attempted with a kind the vocabulary does not contain.
    """

    return value in CREDENTIAL_KINDS


def onboarding_vault_kind(kind: str) -> str:
    """The durable vault kind for a captured credential of ``kind``.

    PRE:  ``kind`` is a member of ``CredentialKind``.
    POST: returns the LL-5.3 vault kind, or raises ``ValueError``. Never falls
          back to a default kind, because a mis-kinded credential row is a
          credential readable through the wrong path.
    """

    if not is_credential_kind(kind):
        raise ValueError("credential kind is outside the checked-in vocabulary")
    return ONBOARDING_VAULT_KINDS[kind]


def credential_value_pattern(kind: str) -> str:
    """The checked-in, whole-value-anchored contract for ``kind``.

    This is the accessor a capture contract uses for its ``value_pattern``
    (task 11.2). It takes only a credential kind, so there is no argument
    through which research output or page text could influence the result.
    """

    if not is_credential_kind(kind):
        raise ValueError("credential kind is outside the checked-in vocabulary")
    return CREDENTIAL_VALUE_PATTERNS[kind]


def credential_value_matches(kind: str, value: str) -> bool:
    """Whether ``value`` satisfies the checked-in contract for ``kind``.

    Fail-closed in both directions: an unknown kind raises rather than returning
    ``True``, and a value that does not match the whole pattern returns ``False``
    rather than being trimmed or retried against a looser form. The value is
    excluded from the return value and from every exception message, so a
    rejected credential cannot reach a log through this function.
    """

    if not is_credential_kind(kind):
        raise ValueError("credential kind is outside the checked-in vocabulary")
    return _COMPILED_VALUE_PATTERNS[kind].fullmatch(value) is not None


# --- the profile-derived validation policy (LL-2.3) -------------------------

# How a credential of each kind authenticates a read-only probe. Checked in,
# keyed by credential kind, total over ``CredentialKind``, and deliberately
# partial in its *values*: ``None`` means "no probe shape is derivable for this
# kind", which is a pause rather than a permissive default.
#
# WHY ONLY ``bearer`` IS EVER DERIVED. ``ValidationAuthScheme`` has three
# members, and the other two need a fact that no kind-keyed, checked-in source
# can supply for a provider nobody has reviewed:
#
# * ``api_key_header`` needs the provider's own header name (``x-api-token``,
#   ``Klaviyo-API-Key``, ...). That name lives in a reviewed per-app policy or on
#   the provider's docs page; reading it from research or page text would put the
#   untrusted page inside its own auth decision.
# * ``basic_auth`` needs a *second* vault reference for the username half, and
#   the validator port takes exactly one reference, so the scheme is not
#   expressible on this path at all.
#
# The kinds mapped to ``None`` are unprovable for a different reason each:
# ``oauth_client_id`` is a public identifier and a probe carrying it proves
# nothing; ``oauth_client_secret`` and ``client_credentials_pair`` are proven
# only by a token exchange, which is a write-shaped request against a token
# endpoint rather than the read-only probe Requirement 10.8 mandates.
VALIDATION_AUTH_SCHEMES: Final[Mapping[CredentialKind, ValidationAuthScheme | None]] = (
    MappingProxyType(
        {
            "oauth_client_id": None,
            "oauth_client_secret": None,
            "api_key": "bearer",  # pragma: allowlist secret
            "personal_access_token": "bearer",
            "client_credentials_pair": None,
        }
    )
)

_require_total(VALIDATION_AUTH_SCHEMES, name="VALIDATION_AUTH_SCHEMES")


class CredentialValidatorPort(Protocol):
    """Read-only authenticated probe proving a stored credential works (LL-2.3).

    PRE:  ``parse_vault_reference(reference)`` succeeds; ``policy`` came from
          :func:`profile_validation_policy` or from a reviewed per-app policy, so
          every endpoint is inside the run's profile domain or the reviewed
          ``NetworkEndpointPolicy``.
    POST: ``result.status`` is one of ``valid``, ``invalid``, ``unavailable``,
          ``failed``; the response body is never persisted or returned beyond a
          bounded ``account_identifier``; the credential VALUE never appears in
          the result, in a log record, or in an exception message.
    """

    async def validate(
        self,
        *,
        reference: str,
        policy: CredentialValidationPolicy,
    ) -> CredentialValidationResult: ...


def profile_validation_policy(
    profile: ProviderProfile,
    *,
    kind: str,
    research_endpoint: str | None = None,
) -> CredentialValidationPolicy | None:
    """Build a validation policy from the profile, or ``None`` if unprovable.

    PRE:  ``profile`` is committed (its URLs already resolve to
          ``registrable_domain`` by construction) and ``kind`` is untrusted
          input, checked here against the closed vocabulary.
    POST: every ``allowed_endpoints`` host is either a reviewed
          ``NetworkEndpointPolicy`` entry for the profile's app slug or resolves
          to ``profile.registrable_domain``; ``auth_scheme`` is chosen from
          ``VALIDATION_AUTH_SCHEMES`` by credential kind, not by page text
          (Requirements 10.8, 10.9). ``None`` means validation is unavailable,
          which the caller turns into a pause with ``capture_spec_unavailable``
          and an unpublished reference — never an implicit pass
          (Requirement 10.11, Property 8). No credential material is read, so
          neither the result nor any raised message can carry a value
          (Requirement 10.10).

    ``research_endpoint`` is the one research-derived input, and it is admitted
    only when its host resolves to the profile's own registrable domain. It is
    optional and keyword-only so the documented ``(profile, kind=...)`` call form
    stays exact: a run whose provider has a reviewed endpoint needs nothing else,
    and a run with neither a reviewed entry nor a corroborated endpoint is
    unprovable, which is a pause.

    A reviewed entry wins over the research endpoint when both exist. A reviewed
    policy is a different, stronger authority — that is how ``api.hubapi.com``
    can validate ``hubspot`` at all, since it is off the vendor's registrable
    domain — so a research string never overrides it.
    """

    if not is_credential_kind(kind):
        # Fail closed on an unknown kind rather than probing with a default
        # scheme. The same posture as ``credential_value_pattern``, except this
        # path reports "unprovable" instead of raising, because the caller's
        # contract for an unbuildable policy is a pause.
        return None
    scheme = VALIDATION_AUTH_SCHEMES[kind]
    if scheme != "bearer":
        # ``None`` (kind not provable by a read-only probe) and the two schemes
        # that need a per-provider header name or a second reference all land
        # here. See ``VALIDATION_AUTH_SCHEMES``.
        return None

    endpoint = _admitted_validation_endpoint(profile, research_endpoint=research_endpoint)
    if endpoint is None:
        return None
    try:
        return CredentialValidationPolicy(
            app_slug=profile.app_slug,
            allowed_endpoints=(endpoint,),
            auth_scheme=scheme,
            # The credential kind is the field name on this path, exactly as it
            # is for the profile-derived capture contract: there is no reviewed
            # per-app field name to map onto.
            credential_field=kind,
            # Bearer probes carry the value in ``Authorization``; the policy
            # enforces that pairing itself.
            header_name="Authorization",
            # No checked-in body shape exists for an unreviewed provider, so no
            # account identifier is extracted. The probe's HTTP status is the
            # whole proof.
            account_identifier_paths=(),
        )
    except ValueError:
        # The policy's own construction checks are the last gate. A candidate
        # that fails them is unprovable, not an error to propagate: the caller
        # pauses either way, and returning ``None`` keeps that one code path.
        return None


def _admitted_validation_endpoint(
    profile: ProviderProfile,
    *,
    research_endpoint: str | None,
) -> str | None:
    """The one endpoint a probe may call, or ``None`` when none is admissible.

    Two sources, in precedence order (Requirement 10.8): the reviewed
    ``NetworkEndpointPolicy`` entry whose purpose is ``credential_validation``,
    then a research-supplied endpoint confined to the profile's registrable
    domain. Domain resolution is delegated to
    ``ops.browser.host_policy.registrable_domain`` — the same authority the
    profile itself was validated against — so this module cannot disagree with
    the reviewed browser boundary about what a vendor owns.
    """

    reviewed = reviewed_validation_endpoint(profile.app_slug)
    if reviewed is not None:
        return reviewed
    if research_endpoint is None:
        return None
    try:
        candidate = normalize_endpoint(research_endpoint)
    except NetworkEndpointError:
        # A malformed, non-HTTPS, or query-bearing candidate is unprovable.
        return None
    host = urlsplit(candidate).hostname or ""
    if resolve_registrable_domain(host) != profile.registrable_domain:
        return None
    return candidate


class ProfileBoundCredentialValidator:
    """Satisfy :class:`CredentialValidatorPort` with the existing validator stack.

    The onboarding port is reference-shaped (one ``vault://`` reference plus the
    policy that governs it) while :class:`PolicyBoundCredentialValidator` is
    app-shaped (a slug plus a field-keyed reference map), because it predates
    onboarding and serves the reviewed-recipe path. This adapter is that
    translation and nothing more: no HTTP, no vault access, and no second
    validation implementation to drift from the reviewed one.
    """

    def __init__(self, *, validator: PolicyBoundCredentialValidator) -> None:
        self._validator = validator

    async def validate(
        self,
        *,
        reference: str,
        policy: CredentialValidationPolicy,
    ) -> CredentialValidationResult:
        """Probe ``policy``'s single endpoint with the credential at ``reference``.

        The reference's own app segment must match the policy's app slug, so a
        reference minted for one provider can never be probed against another
        provider's endpoint. The value stays inside
        :class:`~ops.credentials.validator.CredentialValidator`; this method never
        holds it, and the ``ValueError`` from a malformed reference names the
        grammar rather than any material.
        """

        parts = parse_vault_reference(reference)
        if parts.app_slug != policy.app_slug:
            raise PermissionError("validation reference app does not match the policy")
        return await self._validator.validate(
            app_slug=policy.app_slug,
            credential_refs={policy.credential_field: reference},
            policy=policy,
        )


def build_profile_bound_validator(
    *,
    secret_store: SecretStore,
    http_client: httpx.AsyncClient,
) -> ProfileBoundCredentialValidator:
    """Compose the port from the existing validator, with no per-app endpoints.

    The endpoint map of :class:`PolicyBoundCredentialValidator` stays empty on
    purpose: on the onboarding path the endpoint always arrives on the policy
    built by :func:`profile_validation_policy`, so there is no app-slug-keyed
    fallback that could probe an endpoint the profile never authorized.
    """

    return ProfileBoundCredentialValidator(
        validator=PolicyBoundCredentialValidator(
            validator=CredentialValidator(secret_store=secret_store, http_client=http_client),
            endpoints={},
        )
    )


# --- the credential lifecycle (LL-3.5) --------------------------------------


def _utc_moment() -> datetime:
    """The default clock. Named so it can be a dataclass field default."""

    return datetime.now(UTC)


# The provider-visible effect this lifecycle reserves, and the durable counter
# name its operation key reads. One effect, so the key derivation and the
# generation counter cannot be pointed at different names by accident.
CREDENTIAL_EFFECT: Final[OnboardingEffect] = "generate_credential"

# How long the capture grant stays redeemable: one reviewed walk to the credential
# surface and back, and no longer. The vault's own bound is 30..3600 seconds.
CAPTURE_GRANT_TTL_SECONDS: Final = 900

# How long a validation retry waits before the run becomes ready again. A probe
# that answered ``unavailable`` or ``failed`` is usually answering for a provider
# that is briefly unreachable, so the delay is short and fixed rather than
# exponential: the attempt budget, not the backoff curve, is what terminates this
# ladder (Requirements 10.15, 10.16).
VALIDATION_RETRY_DELAY_SECONDS: Final = 30

# The non-secret identifiers a completed capture records. Both are identifiers by
# construction — the ledger refuses a receipt whose values look secret-shaped —
# and the reference is recomposed from them plus the run's own durable facts
# rather than stored whole, so nothing that reads like a credential path is
# written into the ledger.
#
# The reference key is deliberately not spelled ``credential_reference_id``: the
# ledger sanitizes receipts through ``ops.core.redaction``, whose key grammar treats a
# ``credential``-prefixed key as secret-bearing and refuses the write. Naming it
# for what it holds — a vault row identifier — keeps the receipt writable and
# keeps the redaction boundary strict, which is the right way round.
CAPTURE_RECEIPT_REFERENCE_ID: Final = "reference_id"
CAPTURE_RECEIPT_DEVELOPER_APP_ID: Final = "developer_app_id"

# The reason code every boundary of the store-then-validate pair carries. One
# code for both, because the pair is one fact — "the credential is durable" —
# recorded at two phases (Requirement 10.7).
CREDENTIAL_STORED: Final[OnboardingReasonCode] = "credential_stored"

# The phase walk this module commits and the walk it asks the driver to commit.
# Written as data and checked at import for the same reason the driver checks its
# own successor table: a transition this module intends must be one the phase
# machine admits, or a live run against a real provider is where the refusal
# would surface.
CREDENTIAL_PHASE_WALK: Final[tuple[tuple[OnboardingPhase, OnboardingPhase], ...]] = (
    ("credential_generation", "vault_storage"),
    ("vault_storage", "credential_validation"),
    ("credential_validation", "completed"),
    ("credential_validation", "credential_generation"),
)

assert all(is_legal_phase_transition(source, target) for source, target in CREDENTIAL_PHASE_WALK), (
    "every credential lifecycle transition must be a legal phase transition"
)

# The two boundaries this module commits itself, in the order Requirement 10.7
# fixes. The rest of the walk is requested through a :class:`CredentialStep` and
# committed by the driver, which is the only component that may commit one.
STORAGE_BOUNDARIES: Final[tuple[tuple[OnboardingPhase, OnboardingPhase], ...]] = (
    CREDENTIAL_PHASE_WALK[:2]
)

# What this lifecycle asks the driver to do about the phase it just drove. The
# member names and the field names below match
# :class:`ops.onboarding.driver.PhaseStep` exactly, so the driver — which already
# imports this module — maps a step field-for-field and no third vocabulary
# exists. The type is declared here rather than imported because the driver
# depends on this module for the transient login kinds, and a runtime import back
# into the driver would be a cycle.
CredentialStepKind = Literal["advance", "yield", "pause"]


@dataclass(frozen=True, slots=True)
class CredentialStep:
    """One credential phase's request for a transition. Carries no authority.

    Inert by construction: a step names a target phase and a reason code, and only
    the driver turns either into a durable boundary (Requirement 12.9). The two
    boundaries the lifecycle *does* commit — ``vault_storage`` and
    ``credential_validation`` — are committed through the phase journal because
    Requirement 10.7 orders them relative to the capture that already happened,
    which is a fact only this function holds.
    """

    kind: CredentialStepKind
    reason_code: OnboardingReasonCode
    next_phase: OnboardingPhase | None = None
    not_before: str | None = None

    def __post_init__(self) -> None:
        if self.reason_code not in ONBOARDING_REASON_CODES:
            raise ValueError("a credential step carries an onboarding reason code")
        if self.kind == "advance":
            if self.next_phase is None:
                raise ValueError("an advancing step names the phase it advances into")
            if self.not_before is not None:
                raise ValueError("an advancing step does not carry a deferral time")
        elif self.kind == "yield":
            if self.not_before is None:
                raise ValueError("a yielding step names the time it becomes ready again")
            if self.next_phase is not None:
                raise ValueError("a yielding step commits no transition")
        elif self.next_phase is not None or self.not_before is not None:
            raise ValueError("a pausing step names neither a target phase nor a deferral time")

    @classmethod
    def advance(cls, next_phase: OnboardingPhase, reason_code: OnboardingReasonCode) -> Self:
        """Ask for a boundary into ``next_phase``."""

        return cls(kind="advance", reason_code=reason_code, next_phase=next_phase)

    @classmethod
    def retry_validation(cls, not_before: str, reason_code: OnboardingReasonCode) -> Self:
        """Ask to be re-queued at ``not_before`` with the phase left where it is.

        The retry half of Requirement 10.15: the run comes back at
        ``credential_validation`` and probes the same stored reference again, so no
        credential is minted and nothing is published in the meantime.
        """

        return cls(kind="yield", reason_code=reason_code, not_before=not_before)

    @classmethod
    def pause(cls, reason_code: OnboardingReasonCode) -> Self:
        """Ask for a boundary into ``paused`` carrying ``reason_code``."""

        return cls(kind="pause", reason_code=reason_code)


@dataclass(frozen=True, slots=True)
class CredentialBudgets:
    """The two budgets that give the retry → supersede → pause ladder an end.

    Defaults and bounds mirror ``ops.core.config.Settings`` exactly, so a deployment
    that never wires settings gets the reviewed numbers and a deployment that does
    cannot widen them past what the settings model admits.
    """

    validation_attempts: int = 3
    generations: int = 2

    def __post_init__(self) -> None:
        if not 1 <= self.validation_attempts <= 10:
            raise ValueError("the validation attempt budget is bounded 1..10")
        if not 1 <= self.generations <= 5:
            raise ValueError("the credential generation budget is bounded 1..5")

    @classmethod
    def from_settings(cls, settings: Settings) -> CredentialBudgets:
        """The budgets a deployment configured (task 3.1's two fields)."""

        return cls(
            validation_attempts=settings.credential_validation_attempt_budget,
            generations=settings.credential_generation_budget,
        )


class CredentialPhaseJournal(Protocol):
    """The durable phase and counter operations this lifecycle needs.

    Structurally satisfied by
    :class:`ops.onboarding.driver.SQLitePhaseHistoryStore`, and deliberately
    narrower than that store's own port: there is no history read and no
    reservation verb here, so this module can neither resume a run nor reserve an
    effect outside the one plan it makes below.
    """

    def commit_phase(
        self,
        *,
        run_id: str,
        from_phase: OnboardingPhase | None,
        to_phase: OnboardingPhase,
        reason_code: OnboardingReasonCode,
        profile_digest: str,
        attempt: int,
        correlation_id: str,
    ) -> bool:
        """Durably record one phase boundary. ``False`` means it was a replay."""

    def current_generation(self, *, run_id: str, effect: str) -> int:
        """The effect's generation counter, without advancing it."""

    def next_generation(self, *, run_id: str, effect: str) -> int:
        """Advance the effect's generation counter by exactly one and return it."""

    def next_validation_attempt(self, *, run_id: str) -> int:
        """Count this validation attempt and return the new count."""


class CredentialCaptureVault(Protocol):
    """The vault operations one credential lifecycle needs, and no others.

    Structurally satisfied by :class:`ops.core.secret_store.SQLiteSecretStore`. There
    is deliberately no read verb: this module reserves a grant, receives a
    reference, and retires a row. It cannot resolve a value, so no branch below
    can leak one.
    """

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
        """Reserve one exact broker operation and return its opaque grant."""

    def mark_credential_superseded(self, reference: str) -> str:
        """Retire a credential the run is replacing. A status move, never a delete."""

    def mark_credential_unusable(self, reference: str) -> str:
        """Retire a credential the run will not replace. Also never a delete."""


class CredentialSurfaceSession(Protocol):
    """The browser seam: arm the session, then capture through the broker.

    ``capture_credential`` returns a reference because the value's only path out
    of the page is the broker's capture verb, which writes to the vault before it
    answers (Requirement 10.4). Nothing on this port can return a value.
    """

    session_id: str

    async def arm_credential_surface(self) -> bool:
        """Arm screenshot masking and revoke outstanding live grants.

        POST: on ``True`` the session's document-start pixel mask is installed and
              every live-view grant issued before now has been revoked, so the
              credential surface cannot render into a screenshot or an outstanding
              interactive session (Requirements 10.1, 10.2). ``False`` means the
              surface must not be rendered at all.
        """

    async def capture_credential(self, *, grant: str, kind: str) -> str:
        """Read the rendered credential inside the browser and store it.

        PRE:  masking is armed, ``grant`` names this exact capture, and ``kind`` is
              the durable onboarding vault kind for the credential.
        POST: returns the ``vault://`` reference of a row the broker already wrote
              (Requirement 10.3). The value is never returned to this process.
        """


class ProviderConfigurationPublisher(Protocol):
    """Where a proven credential becomes published provider configuration."""

    def publish_provider_configuration(
        self,
        *,
        run_id: str,
        reference: str,
        kind: CredentialKind,
        result: CredentialValidationResult,
        completed_at: str,
    ) -> None:
        """Publish configuration for one validated reference.

        PRE:  ``result.status == "valid"`` and ``result.checked_at`` strictly
              precedes ``completed_at`` (Requirements 10.13, 10.14). Both are the
              caller's guarantee, and both are established immediately above the
              single call site.
        POST: the published configuration names the reference and never a value.
        """


@dataclass(frozen=True, slots=True)
class CredentialLifecycleDeps:
    """Everything :func:`capture_store_validate_publish` needs, injected.

    Every field is a port, so this module knows nothing about SQLite, HTTP, or a
    browser. ``research_endpoint`` is the one research-derived input and it is
    admitted only when it resolves to the profile's own registrable domain — see
    :func:`profile_validation_policy`.
    """

    journal: CredentialPhaseJournal
    effects: EffectStore
    vault: CredentialCaptureVault
    validator: CredentialValidatorPort
    publisher: ProviderConfigurationPublisher
    budgets: CredentialBudgets = field(default_factory=CredentialBudgets)
    research_endpoint: str | None = None
    grant_ttl_seconds: int = CAPTURE_GRANT_TTL_SECONDS
    retry_delay_seconds: int = VALIDATION_RETRY_DELAY_SECONDS
    # Injectable for the same reason the driver's clock is: a test moves time
    # instead of sleeping through a retry delay.
    clock: Callable[[], datetime] = _utc_moment


async def capture_store_validate_publish(
    *,
    run_id: str,
    profile: ProviderProfile,
    developer_app_id: str,
    kind: str,
    session: CredentialSurfaceSession,
    deps: CredentialLifecycleDeps,
    attempt: int,
    correlation_id: str,
) -> CredentialStep:
    """Mint one credential, store it, prove it works, then publish config.

    PRE:
      P1. the run's phase is ``credential_generation`` and durably committed, so
          the effect reserved below is never the first durable fact about the
          phase that owns it.
      P2. ``developer_app_id`` came from a completed ``create_dev_app``
          reservation.
      P3. ``attempt`` and ``correlation_id`` are the driver's — it owns the phase
          attempt counter and derives the correlation id — so the boundaries
          committed here are attributable the same way every other boundary is
          (Requirement 12.12).

    POST:
      Q1. if the provider minted a credential, a vault reference for it exists:
          the broker writes the value to the vault before it returns one
          (Requirement 10.3, Property 9).
      Q2. no credential value is held, logged, returned, or published; only
          ``vault://`` references cross any boundary here (Requirement 10.4).
      Q3. ``completed`` is requested only behind a recorded ``valid`` whose
          ``checked_at`` strictly precedes the recorded completion timestamp
          (Requirements 10.12, 10.13, 10.14).
      Q4. a superseded or terminally invalid credential is retired by a row-status
          move on the existing ``secrets`` table and is never published and never
          deleted (Requirements 10.17, 10.19, design LL-5.3).
      Q5. exactly one ``generate_credential`` effect per
          ``(developer_app_id, kind, generation)``; a retry reuses the same key
          and is refused a second mint (Requirement 13.12, Property 1).

    The masking and grant revocation of Requirements 10.1 and 10.2 happen before
    anything that can render the credential surface — earlier than design LL-3.5
    sketches them, because arming ahead of the grant reservation is strictly
    stronger and costs nothing.
    """

    if not is_credential_kind(kind):
        # The kind arrives as ordinary untrusted input on this path too, and an
        # unknown kind has neither a vault namespace nor a value contract.
        return CredentialStep.pause("capture_spec_unavailable")
    vault_kind = ONBOARDING_VAULT_KINDS[kind]

    # Requirement 10.11 read as a precondition rather than a late check: a
    # credential this run could never prove is a credential it must not mint, so
    # the unprovable case pauses before any provider-visible effect exists.
    policy = profile_validation_policy(profile, kind=kind, research_endpoint=deps.research_endpoint)
    if policy is None:
        return CredentialStep.pause("capture_spec_unavailable")

    generation = deps.journal.current_generation(run_id=run_id, effect=CREDENTIAL_EFFECT)
    reference = await _stored_reference(
        run_id=run_id,
        profile=profile,
        developer_app_id=developer_app_id,
        kind=kind,
        vault_kind=vault_kind,
        generation=generation,
        session=session,
        deps=deps,
    )
    if isinstance(reference, CredentialStep):
        return reference

    # Requirement 10.7: the credential is durable, and both phases that say so are
    # committed in order before validation is attempted.
    _commit_storage_boundaries(
        run_id=run_id,
        profile=profile,
        deps=deps,
        attempt=attempt,
        correlation_id=correlation_id,
    )

    attempts_used = deps.journal.next_validation_attempt(run_id=run_id)
    result = await deps.validator.validate(reference=reference, policy=policy)

    if result.status == "valid":
        completed_at = _completion_moment(result.checked_at, clock=deps.clock)
        deps.publisher.publish_provider_configuration(
            run_id=run_id,
            reference=reference,
            kind=kind,
            result=result,
            completed_at=completed_at,
        )
        return CredentialStep.advance("completed", "credential_valid")

    if result.status in {"unavailable", "failed"}:
        # The probe did not answer for the credential, so the credential is not
        # the thing on trial: the same reference is probed again, and the reference
        # stays active and unpublished either way (Requirements 10.15, 10.16).
        if attempts_used < deps.budgets.validation_attempts:
            return CredentialStep.retry_validation(
                _deferred_moment(deps), "credential_invalid_retryable"
            )
        return CredentialStep.pause("credential_invalid_terminal")

    # ``invalid`` is the provider's definitive answer about this credential, so
    # the generation ladder owns it. ``generation`` counts from zero, so the mints
    # this run has made is one more than it.
    if generation + 1 < deps.budgets.generations:
        deps.vault.mark_credential_superseded(reference)
        # THE ONLY CALL TO ``next_generation`` IN THE CODEBASE (Requirement
        # 13.12). A Retry Current Step reads ``current_generation`` instead,
        # derives the key already reserved, and is told to skip — which is exactly
        # why a retry cannot mint a second credential.
        advanced = deps.journal.next_generation(run_id=run_id, effect=CREDENTIAL_EFFECT)
        LOGGER.info(
            "run %s superseded its credential; generation %s -> %s",
            run_id,
            generation,
            advanced,
        )
        return CredentialStep.advance("credential_generation", "credential_superseded")

    deps.vault.mark_credential_unusable(reference)
    return CredentialStep.pause("credential_invalid_terminal")


async def _stored_reference(
    *,
    run_id: str,
    profile: ProviderProfile,
    developer_app_id: str,
    kind: CredentialKind,
    vault_kind: str,
    generation: int,
    session: CredentialSurfaceSession,
    deps: CredentialLifecycleDeps,
) -> str | CredentialStep:
    """The reference of this generation's stored credential, or a step instead.

    Reserving before minting is what makes a second worker adopt rather than mint
    (Requirement 13.1). Three dispositions, three answers: ``skip`` recomposes the
    reference the completed reservation recorded, ``execute`` arms the session and
    captures, and anything else means a prior attempt may already have minted —
    which authorizes no second mint.
    """

    operation_key = generate_credential_key(run_id, developer_app_id, kind, generation)
    plan = plan_effect(deps.effects, operation_key=operation_key, action=CREDENTIAL_EFFECT)

    if plan.disposition == "skip":
        adopted = _recomposed_reference(
            plan.receipt, app_slug=profile.app_slug, vault_kind=vault_kind
        )
        if adopted is None:
            # A completed mint whose receipt cannot name its row is not a mint
            # this run may adopt, and minting again could create a second
            # credential at the provider.
            LOGGER.warning(
                "run %s has a completed credential effect with no usable receipt", run_id
            )
            return CredentialStep.pause("outcome_unknown")
        return adopted
    if plan.disposition != "execute":
        return CredentialStep.pause(plan.reason_code)

    # Requirements 10.1 and 10.2, before anything can render the credential
    # surface. A session that cannot prove both is a session this phase must not
    # drive: the value would be rendered into pixels an outstanding grant can see.
    if not await session.arm_credential_surface():
        LOGGER.warning("run %s could not arm its credential surface; nothing was captured", run_id)
        return CredentialStep.pause("postcondition_failed")

    grant = deps.vault.reserve_browser_secret_grant(
        # The exact operation key the broker recomposes from the run's durable
        # effect identity, so a grant minted for one capture cannot redeem another.
        operation_key=f"{operation_key}:capture:{vault_kind}",
        run_id=run_id,
        session_id=session.session_id,
        app_slug=profile.app_slug,
        kind=vault_kind,
        action="capture",
        ttl_seconds=deps.grant_ttl_seconds,
    )
    try:
        captured = await session.capture_credential(grant=grant, kind=vault_kind)
    except Exception:
        # The credential may already exist at the provider, so this is ambiguous
        # rather than a provable failure: it authorizes no second mint and the
        # count for this key stays where it is (Requirements 13.9, 13.10). The
        # exception is not re-raised or logged with its message, because a broker
        # or transport error string is not a place a value may appear.
        mark_effect_outcome_unknown(deps.effects, plan)
        LOGGER.warning("run %s could not complete its credential capture", run_id)
        return CredentialStep.pause("outcome_unknown")

    if not _reference_matches(captured, app_slug=profile.app_slug, vault_kind=vault_kind):
        # A reference outside this run's app and kind namespace would publish, or
        # retire, a row that belongs to something else.
        mark_effect_outcome_unknown(deps.effects, plan)
        return CredentialStep.pause("outcome_unknown")

    complete_effect(
        deps.effects,
        plan,
        receipt={
            CAPTURE_RECEIPT_REFERENCE_ID: parse_vault_reference(captured).identifier,
            CAPTURE_RECEIPT_DEVELOPER_APP_ID: developer_app_id,
        },
    )
    return captured


def _commit_storage_boundaries(
    *,
    run_id: str,
    profile: ProviderProfile,
    deps: CredentialLifecycleDeps,
    attempt: int,
    correlation_id: str,
) -> None:
    """Commit ``vault_storage`` then ``credential_validation``, in that order.

    Requirement 10.7 is an ordering claim, so the two commits are sequential and
    unconditional: a ``False`` return means the boundary was already durable,
    which is the same precondition for validation that a fresh commit establishes.
    """

    for source, target in STORAGE_BOUNDARIES:
        deps.journal.commit_phase(
            run_id=run_id,
            from_phase=source,
            to_phase=target,
            reason_code=CREDENTIAL_STORED,
            profile_digest=profile.profile_digest,
            attempt=attempt,
            correlation_id=correlation_id,
        )


def _recomposed_reference(
    receipt: Mapping[str, str] | None,
    *,
    app_slug: str,
    vault_kind: str,
) -> str | None:
    """Rebuild a reference from a completed reservation's receipt.

    The receipt stores the row identifier rather than the whole reference, so the
    app slug and the vault kind come from this run's own durable facts. A receipt
    cannot therefore redirect an adoption at a row in another app's namespace.
    """

    identifier = (receipt or {}).get(CAPTURE_RECEIPT_REFERENCE_ID, "")
    if not identifier:
        return None
    candidate = f"vault://{app_slug}/{vault_kind}/{identifier}"
    return (
        candidate
        if _reference_matches(candidate, app_slug=app_slug, vault_kind=vault_kind)
        else None
    )


def _reference_matches(reference: str, *, app_slug: str, vault_kind: str) -> bool:
    """Whether ``reference`` is a well-formed reference in this run's namespace."""

    try:
        parts = parse_vault_reference(reference)
    except ValueError:
        return False
    return parts.app_slug == app_slug and parts.kind == vault_kind


def _completion_moment(validated_at: str, *, clock: Callable[[], datetime]) -> str:
    """A completion timestamp that strictly follows the validation timestamp.

    Requirement 10.13 is an ordering invariant, so it is established by
    construction rather than asserted and hoped for. The validator stamps
    ``checked_at`` from its own process; a worker whose clock lags that process —
    or matches it to the microsecond — would otherwise record a completion that
    does not follow its own proof. When the clock is already ahead it is used
    unchanged, which is the ordinary case.
    """

    now = clock().astimezone(UTC)
    validated = _parse_moment(validated_at)
    if validated is not None and now <= validated:
        now = validated + timedelta(milliseconds=1)
    return _moment(now)


def _deferred_moment(deps: CredentialLifecycleDeps) -> str:
    """When a retrying run becomes ready again."""

    return _moment(deps.clock().astimezone(UTC) + timedelta(seconds=deps.retry_delay_seconds))


def _parse_moment(value: str) -> datetime | None:
    """One recorded timestamp as an aware instant, or ``None`` if unreadable."""

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _moment(value: datetime) -> str:
    """One aware instant as the timestamp text the durable rows carry."""

    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _port_conformance(validator: ProfileBoundCredentialValidator) -> CredentialValidatorPort:
    """Typecheck-only proof that the adapter satisfies the port."""

    return validator


__all__ = [
    "CAPTURE_GRANT_TTL_SECONDS",
    "CAPTURE_RECEIPT_DEVELOPER_APP_ID",
    "CAPTURE_RECEIPT_REFERENCE_ID",
    "CREDENTIAL_EFFECT",
    "CREDENTIAL_KINDS",
    "CREDENTIAL_PHASE_WALK",
    "CREDENTIAL_STORED",
    "CREDENTIAL_VALUE_PATTERNS",
    "ONBOARDING_VAULT_KINDS",
    "ONBOARDING_VAULT_KIND_PREFIX",
    "SIGNUP_LOGIN_VAULT_KINDS",
    "STORAGE_BOUNDARIES",
    "TRANSIENT_LOGIN_FIELDS",
    "TRANSIENT_LOGIN_KIND_PREFIX",
    "TRANSIENT_LOGIN_VAULT_KINDS",
    "VALIDATION_AUTH_SCHEMES",
    "VALIDATION_RETRY_DELAY_SECONDS",
    "CredentialBudgets",
    "CredentialCaptureVault",
    "CredentialLifecycleDeps",
    "CredentialPhaseJournal",
    "CredentialStep",
    "CredentialStepKind",
    "CredentialSurfaceSession",
    "CredentialValidatorPort",
    "ProfileBoundCredentialValidator",
    "ProviderConfigurationPublisher",
    "build_profile_bound_validator",
    "capture_store_validate_publish",
    "credential_value_matches",
    "credential_value_pattern",
    "is_credential_kind",
    "onboarding_vault_kind",
    "profile_validation_policy",
]
