"""Vault-first admission: who is allowed to create an account, and on what evidence.

An onboarding run reaches this module once its provider profile is committed and
before any browser session exists. It answers one question — *sign in, or create
an account?* — and the answer is load-bearing in two directions.

**The login route is fully autonomous, and it earns that by evidence.** If the
vault already holds sign-in credentials bound to this app slug and this account
binding, the run signs in and emits zero operator prompts (Requirements 3.2,
3.3). The evidence is read as *references*, never values: :func:`probe_login_refs`
asks its port for ``vault://app/kind/id`` strings and nothing else, so no
plaintext enters the deciding process at all. That is a structural property of
the port's shape rather than a rule the caller has to remember — there is no
method here that could return a secret.

**The signup route is never autonomous.** Creating an account has legal and
billing consequences, so it takes a human. Two mechanisms enforce that and they
are deliberately redundant. :class:`AdmissionDecision` refuses at construction to
represent a signup that a system decided (Requirement 3.6), the admission table's
``CHECK (route <> 'signup' OR decided_by = 'operator')`` refuses to store one
(task 10.2), and ``ops.access.gate_policy`` keeps ``signup_authorization`` permanently
human-only (Requirement 3.7). Any one of the three failing leaves the other two
standing.

Field names line up with two neighbours on purpose
--------------------------------------------------
``route``, ``decided_by``, and ``profile_digest`` are named to match the columns
of ``onboarding_admission_decisions`` and the ``admission_*`` fields of
``ops.access.gate_policy.ProfileGateAuthority``, so a recorded decision projects onto
the gate authority by copying three values rather than by translating them. A
translation layer between those two is exactly where an authorization could quietly
change meaning.

``credential_refs`` is references, and the email is one of them
--------------------------------------------------------------
The pairs in ``credential_refs`` are ``(login field, vault reference)``. The login
*email* is itself a reference — not an address — because an email address is
credential material on a signup path: it identifies the account the agent is about
to authenticate as. :meth:`AdmissionDecision.__post_init__` parses every reference
through ``ops.core.secret_store.parse_vault_reference``, so a value smuggled into this
tuple is a construction error and never reaches the durable row, the API response,
or a log line (Requirement 19.8).

Scope: this module decides and represents. Persisting the decision is the admission
table's job (task 10.2), committing ``awaiting_admission`` is the phase driver's
(task 14.1), and delivering the prompt is the API's (task 22.2).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, Literal, Protocol

from ops.core.models import HitlRequest
from ops.core.secret_store import parse_vault_reference
from ops.onboarding.credentials import SIGNUP_LOGIN_VAULT_KINDS
from ops.onboarding.phase import OnboardingPhase, OnboardingReasonCode

AdmissionRoute = Literal["login", "signup", "cancelled"]

# What an operator may submit. Two inputs, because admission is a yes/no business
# decision: anything richer would be a second place to encode routing policy.
AdmissionInput = Literal["create_account", "cancel"]

AdmissionDecider = Literal["system", "operator"]

# The gate type of the one prompt this module ever emits. Never inferred from a
# page — ``ops.browser.worker.HumanActionType`` carries the same note next to the
# member — and emitted only here, only after a probe finds nothing.
ADMISSION_GATE: Final = "signup_authorization"

# Requirement 3.4 is a count, so it is written as one: a probe that finds nothing
# yields exactly this many prompts, and every other path yields zero.
ADMISSION_PROMPT_LIMIT: Final = 1

# The login fields a run needs in order to authenticate. Taken from the signup
# credential vocabulary rather than restated, so the probe requires exactly the
# fields signup writes — ``login_email`` and ``login_password``, stored under the
# ``account_login_*`` kinds that mapping names — and cannot drift from them.
REQUIRED_LOGIN_FIELDS: Final[frozenset[str]] = frozenset(SIGNUP_LOGIN_VAULT_KINDS)

# A profile digest is a sha256 content address, checked here for the same reason
# ``ops.access.gate_policy`` checks it: an empty or placeholder digest would let an
# uncommitted profile stand in for the committed one this decision is attributed
# to.
_PROFILE_DIGEST: Final = re.compile(r"[0-9a-f]{64}")

_MAX_IDENTIFIER_LENGTH: Final = 200

_PROMPT_MESSAGE: Final = (
    "No login credentials exist for this provider. Create a new account on the "
    "provider's own site, or cancel this run?"
)
_PROMPT_COMPLETION_SIGNAL: Final = (
    "An admission decision recorded for this run: create_account to authorize "
    "account creation, or cancel to end the run."
)


def _utc_now() -> str:
    """The repo's timestamp convention: ISO-8601, UTC, aware."""

    return datetime.now(UTC).isoformat()


def _identifier(value: str, *, field: str) -> str:
    """Accept a bounded single-line identifier, mirroring the lease store's check."""

    if not value or len(value) > _MAX_IDENTIFIER_LENGTH:
        raise ValueError(f"{field} is invalid")
    if any(character.isspace() or not character.isprintable() for character in value):
        raise ValueError(f"{field} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class AdmissionDecision:
    """The durable record that authorizes (or refuses) account creation.

    Constructing one is the authorization check, not a step before it. The two
    refusals in :meth:`__post_init__` are the reason a reviewer does not have to
    audit every caller: a signup this system decided for itself, and a login route
    with no credentials to log in with, are both unrepresentable.
    """

    run_id: str
    profile_digest: str
    route: AdmissionRoute
    reason_code: OnboardingReasonCode
    decided_by: AdmissionDecider
    actor_owner_id: str
    decided_at: str
    # ``(login field, vault://app/kind/id)`` pairs. References only — see the
    # module docstring on why the email is one of them.
    credential_refs: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if self.route == "signup" and self.decided_by != "operator":
            # Property 7, as a construction error rather than a review convention:
            # no autonomous path can self-approve account creation.
            raise ValueError("signup route requires an operator decision")
        if self.route == "login" and not self.credential_refs:
            raise ValueError("login route requires credential references")
        _identifier(self.run_id, field="run id")
        _identifier(self.actor_owner_id, field="actor owner id")
        if _PROFILE_DIGEST.fullmatch(self.profile_digest) is None:
            raise ValueError("a decision must name a committed profile digest")
        if not self.decided_at:
            raise ValueError("a decision must carry its timestamp")
        seen: set[str] = set()
        for field, reference in self.credential_refs:
            _identifier(field, field="credential field")
            if field in seen:
                raise ValueError("credential references must name distinct fields")
            seen.add(field)
            # Raises for anything that is not an exact reference, which is what
            # keeps a credential *value* out of this tuple and out of every row,
            # response, and log line built from it.
            parse_vault_reference(reference)


@dataclass(frozen=True, slots=True)
class VaultProbeResult:
    """What the vault holds for one run's app slug and account binding.

    ``credential_refs`` is empty whenever ``credentials_present`` is false, so a
    caller cannot accidentally route to login on a partial pair.
    """

    credentials_present: bool
    reason_code: OnboardingReasonCode  # credentials_present | credentials_missing
    credential_refs: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class AdmissionOutcome:
    """The route the probe implies, and everything the driver needs to act on it.

    ``decision`` is present on the login route — the system decided it, so it is
    recordable immediately — and absent while a run awaits an operator, because
    there is nothing to record until a person answers. ``prompts`` carries exactly
    one entry in that second case and none in the first (Requirements 3.3, 3.4).
    """

    phase: OnboardingPhase  # route_selected_login | awaiting_admission
    reason_code: OnboardingReasonCode
    probe: VaultProbeResult
    decision: AdmissionDecision | None = None
    prompts: tuple[HitlRequest, ...] = ()


class CredentialReferenceProbe(Protocol):
    """Reference-only presence lookup over the vault.

    Deliberately the narrowest port in this feature: one method, returning
    references. ``ops.core.secret_store.SQLiteSecretStore`` satisfies it structurally,
    and its implementation selects no ciphertext column at all, so "the admission
    path cannot resolve a value" holds by the shape of this port rather than by
    the caller's restraint.
    """

    def account_login_references(self, *, app_slug: str, account_ref: str) -> Mapping[str, str]:
        """Stored reusable login references for one app slug and account binding.

        PRE:  ``app_slug`` and ``account_ref`` name the run's provider and its
              account binding.
        POST: ``{login field: vault://app/kind/id}`` for whichever reusable login
              fields are stored, possibly empty and possibly partial. No value is
              resolved, decrypted, or returned. An unknown app slug or binding
              reads as empty rather than raising: "nothing stored" is the normal
              first-run condition.
        """


def probe_login_refs(
    probe: CredentialReferenceProbe,
    *,
    app_slug: str,
    account_ref: str,
) -> VaultProbeResult:
    """Probe the vault for a usable login, reading references only.

    A *complete* pair is required. A run holding an email reference and no password
    reference cannot sign in, so a partial pair reads as absent and routes to
    admission — the fail-closed direction, since the alternative is an autonomous
    login attempt that is guaranteed to stall at a credential prompt.
    """

    references = dict(probe.account_login_references(app_slug=app_slug, account_ref=account_ref))
    present = {field: reference for field, reference in references.items() if reference}
    if not REQUIRED_LOGIN_FIELDS.issubset(present):
        return VaultProbeResult(credentials_present=False, reason_code="credentials_missing")
    refs = tuple((field, present[field]) for field in sorted(REQUIRED_LOGIN_FIELDS))
    return VaultProbeResult(
        credentials_present=True,
        reason_code="credentials_present",
        credential_refs=refs,
    )


def admission_prompt(app_name: str) -> HitlRequest:
    """The one operator prompt this module emits, for a run with no credentials.

    ``live_view_available`` is false because admission is decided before any
    browser session exists — there is no page to watch, and claiming otherwise
    would send an operator looking for a live view that cannot be granted.
    """

    return HitlRequest(
        type=ADMISSION_GATE,
        app_name=app_name,
        message=_PROMPT_MESSAGE,
        expected_completion_signal=_PROMPT_COMPLETION_SIGNAL,
        live_view_available=False,
    )


def admit_from_vault(
    probe: CredentialReferenceProbe,
    *,
    run_id: str,
    profile_digest: str,
    app_slug: str,
    app_name: str,
    account_ref: str,
    owner_id: str,
    decided_at: str | None = None,
) -> AdmissionOutcome:
    """Decide the run's route from the vault alone (Requirements 3.1 - 3.4).

    PRE:  the run's provider profile is committed and ``profile_digest`` is its
          content address; no browser session exists yet.
    POST: references present ⟹ phase ``route_selected_login``, a ``system``
          decision with reason ``credentials_present``, and zero prompts.
          References absent ⟹ phase ``awaiting_admission``, reason
          ``signup_authorization_required``, no decision yet, and exactly one
          ``signup_authorization`` prompt. Either way no value is read, nothing is
          persisted, and no side effect is reserved — this function decides and
          returns.
    """

    result = probe_login_refs(probe, app_slug=app_slug, account_ref=account_ref)
    if not result.credentials_present:
        return AdmissionOutcome(
            phase="awaiting_admission",
            reason_code="signup_authorization_required",
            probe=result,
            decision=None,
            prompts=(admission_prompt(app_name),),
        )
    decision = AdmissionDecision(
        run_id=run_id,
        profile_digest=profile_digest,
        route="login",
        reason_code="credentials_present",
        decided_by="system",
        actor_owner_id=owner_id,
        decided_at=decided_at or _utc_now(),
        credential_refs=result.credential_refs,
    )
    return AdmissionOutcome(
        phase="route_selected_login",
        reason_code="credentials_present",
        probe=result,
        decision=decision,
        prompts=(),
    )


def decide_from_operator(
    admission_input: AdmissionInput,
    *,
    run_id: str,
    profile_digest: str,
    actor_owner_id: str,
    decided_at: str | None = None,
) -> AdmissionDecision:
    """Turn one operator answer into the durable decision (Requirements 3.5, 3.8).

    ``decided_by`` is fixed to ``"operator"`` here rather than accepted as an
    argument: this is the only function that produces a signup route, and the only
    caller is the API handler acting on a person's submission, so there is no
    parameter through which a system caller could claim to be one.
    """

    if admission_input == "create_account":
        route: AdmissionRoute = "signup"
        reason_code: OnboardingReasonCode = "operator_approved_signup"
    else:
        route = "cancelled"
        reason_code = "operator_cancelled"
    return AdmissionDecision(
        run_id=run_id,
        profile_digest=profile_digest,
        route=route,
        reason_code=reason_code,
        decided_by="operator",
        actor_owner_id=actor_owner_id,
        decided_at=decided_at or _utc_now(),
    )


__all__ = [
    "ADMISSION_GATE",
    "ADMISSION_PROMPT_LIMIT",
    "REQUIRED_LOGIN_FIELDS",
    "AdmissionDecider",
    "AdmissionDecision",
    "AdmissionInput",
    "AdmissionOutcome",
    "AdmissionRoute",
    "CredentialReferenceProbe",
    "VaultProbeResult",
    "admission_prompt",
    "admit_from_vault",
    "decide_from_operator",
    "probe_login_refs",
]
