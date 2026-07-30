"""Operation-key derivation and retry disposition for provider-visible effects.

Three actions in an onboarding run are visible to the provider and therefore
unrepeatable: submitting the signup form, creating the developer application, and
minting a credential. Each is reserved under an ``operation_key`` in the existing
effect ledger (:mod:`ops.core.effect_ledger`) before it runs, and this module owns the
derivation of those keys plus the mapping from what the ledger already knows to
what the driver must do next.

The derivation is a pure function of durable facts, and that is the whole point.
    A key must be **stable** across a retry, a lease expiry, a worker restart, and
    a concurrent claim, and **distinct** across intentionally separate effects
    (Requirements 13.3, 13.4). So the attempt number, the worker id, the browser
    session id, timestamps, and random values appear in no key. Two workers racing
    on the same phase of the same run derive byte-identical keys and collide on
    one ledger row; one of them executes and the other is told the effect already
    happened.

    The contrast with the pre-existing ``browser-start`` keys
    (``f"{run_id}:browser-start:v{attempt}"``) is deliberate rather than an
    inconsistency: starting a browser session is not provider-visible, so a
    second session is wasteful and not harmful. A provider-visible mutation is
    never attempt-numbered.

The generation counter is the one deliberate escape hatch.
    ``generate_credential_key`` reads a durable counter that
    ``PhaseHistoryStore.next_generation`` advances *only* on the credential
    supersede path (Requirement 13.12). A retry reads
    ``current_generation`` instead, derives the same key, finds the row
    ``completed``, and skips — so it cannot mint a second credential. A supersede
    advances the counter, which makes a genuinely different effect with a
    genuinely different key.

URL canonicalization is part of key identity, not cosmetics.
    Without :func:`_canonical`, ``https://x.com/signup`` and
    ``https://X.com/signup?ref=a`` would derive two keys for one account, which
    means two accounts. Requirement 13.5 fixes the folding: lower-case host, no
    query, no fragment, no userinfo, no default port, and no trailing slash on a
    non-root path.

``EFFECT_KEY_VERSION`` is code-level, never per-run.
    Bumping it is a deliberate migration that declares "past reservations no
    longer describe this effect" for every run at once (Requirement 13.14). It
    must never be bumped to move a stuck run past a reservation it does not like.

Scope: this module derives keys and classifies ledger rows. The
``onboarding_effect_reservations`` table and the transactional
reserve-inside-the-phase-commit path are task 8.2 and are not sketched here.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal, get_args
from urllib.parse import urlsplit, urlunsplit

from ops.core.effect_ledger import EffectReservation, EffectStore
from ops.onboarding.phase import OnboardingReasonCode
from ops.providers.profile import CredentialKind, ProviderProfile

# The version every run's keys carry. A code-level constant shared by all runs, so
# that changing it is a migration rather than a per-run workaround.
EFFECT_KEY_VERSION: Final = 1

# The ledger's ``provider`` argument for every onboarding effect. One value, so
# that ``SQLiteEffectStore._key`` namespaces onboarding reservations away from the
# Gmail and managed-auth reservations that share the same table.
EFFECT_PROVIDER: Final = "provider_onboarding"

# The three provider-visible effects, matching the ledger's ``action`` argument
# and the ``effect`` CHECK on ``onboarding_effect_reservations``.
OnboardingEffect = Literal["signup_submit", "create_dev_app", "generate_credential"]

# The ledger's durable row statuses (``external_effects.status``). Distinct from
# the three-valued ``EffectStatus`` that ``reserve()`` returns: the row keeps
# ``pending`` and ``outcome_unknown`` apart, while ``reserve()`` collapses both to
# ``reconcile_required`` because the disposition is the same either way.
EffectRowStatus = Literal["pending", "completed", "outcome_unknown", "failed"]

# What the driver does about one key. ``pause_outcome_unknown`` is never returned
# by this module: it is the *result* of a reconciliation that stayed ambiguous
# (Requirement 13.9), which only the driver's read-only probe can determine. It is
# named here because the reservation table's CHECK and the driver's recovery plan
# share this vocabulary.
EffectDisposition = Literal["execute", "skip", "reconcile", "pause_outcome_unknown"]

ONBOARDING_EFFECTS: Final[tuple[OnboardingEffect, ...]] = get_args(OnboardingEffect)

# The disposition vocabulary as data, so ``onboarding_effect_reservations``
# generates its CHECK from the same source the code decides against and the table
# cannot drift from the type.
ONBOARDING_EFFECT_DISPOSITIONS: Final[tuple[EffectDisposition, ...]] = get_args(EffectDisposition)

# The reason code that names each effect. The design's timeline table uses the
# same code for an effect that is starting and one that finished
# (``onboarding_signup_started`` carries ``signup_submitted``), because the code
# names *which* effect the row is about while ``disposition`` says what is being
# done about it.
_EFFECT_REASON_CODES: Final[dict[OnboardingEffect, OnboardingReasonCode]] = {
    "signup_submit": "signup_submitted",
    "create_dev_app": "developer_app_created",
    "generate_credential": "credential_generated",
}

# A reservation that a prior attempt opened and never closed. ``pending`` and
# ``outcome_unknown`` share this code deliberately: in both cases this worker does
# not know whether the provider saw the submission, and "reconcile before you
# resend" is the only safe reading of either (Requirement 13.7).
_RECONCILE_REASON_CODE: Final[OnboardingReasonCode] = "outcome_unknown"

_DEFAULT_PORTS: Final[dict[str, int]] = {"http": 80, "https": 443}

# The ledger refuses an idempotency key longer than 500 characters; the parts that
# feed a key are bounded well below that so the composed key cannot reach it.
MAX_KEY_PART_LENGTH: Final = 200

# Truncated on purpose: 16 hex characters (64 bits) over a NUL-delimited part list
# is far past the collision budget of one run's three effects, and it keeps the
# composed key short enough to read in a log line.
SCOPE_DIGEST_LENGTH: Final = 16


@dataclass(frozen=True, slots=True)
class EffectPlan:
    """What the driver must do about one operation key, and why.

    ``receipt`` is populated only for ``skip``, where it carries the non-secret
    identifiers the completed effect recorded (a developer application id, a vault
    reference id) so the driver can adopt them instead of repeating the effect
    (Requirement 13.6).
    """

    operation_key: str
    provider: str
    action: OnboardingEffect
    disposition: EffectDisposition
    receipt: dict[str, str] | None
    reason_code: OnboardingReasonCode


def _scope_digest(*parts: str) -> str:
    """Stable 16-hex digest over a canonical, NUL-delimited part list.

    NUL is the delimiter because it cannot occur in any part this module accepts,
    so ``("ab", "c")`` and ``("a", "bc")`` cannot digest alike — a concatenation
    without a delimiter would make two different effects share one key.
    """

    for part in parts:
        if not part or "\x00" in part or len(part) > MAX_KEY_PART_LENGTH:
            raise ValueError("operation key parts must be bounded, non-empty, NUL-free strings")
    joined = "\x00".join(parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:SCOPE_DIGEST_LENGTH]


def _canonical(url: str) -> str:
    """Fold a URL to the form that participates in an operation key.

    POST: scheme and host are lower case; userinfo, query, and fragment are gone;
          a default port for the scheme is gone; a non-root path carries no
          trailing slash while the root path keeps its single slash.

    An empty path folds to ``"/"`` so ``https://x.com`` and ``https://x.com/``
    are one key rather than two. The host is read through ``urlsplit().hostname``,
    which already drops userinfo and folds case; an IPv6 literal is re-bracketed
    because ``hostname`` strips the brackets that make the port unambiguous.
    """

    parsed = urlsplit(url.strip())
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").rstrip(".")
    if not scheme or not host:
        raise ValueError("an operation key url must be absolute and carry a host")
    if ":" in host:
        host = f"[{host}]"
    port = parsed.port
    netloc = host if port is None or port == _DEFAULT_PORTS.get(scheme) else f"{host}:{port}"
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/") or "/"
    return urlunsplit((scheme, netloc, path, "", ""))


def signup_submit_key(run_id: str, profile: ProviderProfile, account_ref: str) -> str:
    """Key for the one signup form submission.

    Pure in its durable inputs: the run id, the profile's content address, the
    canonicalized signup URL, and the durable mailbox identity. No attempt number,
    worker id, session id, timestamp, or random value participates, so a retry, a
    second worker, and a run resumed from a CAPTCHA pause all derive the identical
    key and only one signup can be submitted (Requirements 13.3, 13.4).
    """

    if profile.signup_url is None:
        raise ValueError("a signup submission requires a profile signup url")
    scope = _scope_digest(
        profile.profile_digest,
        _canonical(profile.signup_url),
        _identifier(account_ref, field="account reference"),
    )
    return f"{_identifier(run_id, field='run id')}:signup-submit:{scope}:v{EFFECT_KEY_VERSION}"


def create_dev_app_key(run_id: str, profile: ProviderProfile, requested_name: str) -> str:
    """Key for creating one developer application.

    ``requested_name`` is the application name the run asks for, derived
    deterministically from owner and run identity and never from a clock
    (Requirement 9.4), so two workers driving the same phase request the same
    application and collide on one key. Pure in its durable inputs: no attempt
    number, worker id, session id, timestamp, or random value participates.
    """

    flow = profile.developer_app_flow
    if flow.entry_url is None:
        raise ValueError("a developer application requires a flow entry url")
    scope = _scope_digest(
        profile.profile_digest,
        flow.kind,
        _canonical(flow.entry_url),
        _identifier(requested_name, field="requested application name"),
    )
    return f"{_identifier(run_id, field='run id')}:create-dev-app:{scope}:v{EFFECT_KEY_VERSION}"


def generate_credential_key(
    run_id: str, developer_app_id: str, kind: CredentialKind, generation: int
) -> str:
    """Key for minting one credential of one kind for one developer application.

    ``generation`` is the only escape hatch, and it is durable rather than
    incidental: ``PhaseHistoryStore.next_generation`` advances it exclusively on
    the supersede path, so a retry reads the current generation, derives this same
    key, and is refused a second mint. Pure in its durable inputs otherwise: no
    attempt number, worker id, session id, timestamp, or random value
    participates.
    """

    if generation < 0:
        raise ValueError("a credential generation counter cannot be negative")
    scope = _scope_digest(
        _identifier(developer_app_id, field="developer application id"),
        kind,
        str(generation),
    )
    run = _identifier(run_id, field="run id")
    return f"{run}:generate-credential:{scope}:v{EFFECT_KEY_VERSION}"


def plan_for_row_status(
    *,
    operation_key: str,
    action: OnboardingEffect,
    row_status: EffectRowStatus | None,
    receipt: Mapping[str, str] | None = None,
) -> EffectPlan:
    """Map one durable ledger row onto the disposition it authorizes.

    PRE:  ``row_status`` is the ledger's stored status, or ``None`` when no row
          exists for the key. A ``completed`` row carries its receipt; no other
          status does.
    POST: ``execute`` only for an absent row or a provably ``failed`` one
          (Requirement 13.11); ``skip`` carries the recorded receipt
          (Requirement 13.6); ``pending`` and ``outcome_unknown`` both demand
          reconciliation before anything is resent (Requirements 13.7, 13.10).

    Pure: the same row status always yields the same plan, which is what lets the
    driver, the recovery planner, and the retry path agree without coordinating.
    """

    if row_status == "completed":
        if not receipt:
            raise ValueError("a completed effect must carry its receipt")
        return _plan(operation_key, action, "skip", dict(receipt))
    if receipt:
        raise ValueError("only a completed effect carries a receipt")
    if row_status in {"pending", "outcome_unknown"}:
        return _plan(operation_key, action, "reconcile", None)
    if row_status is None or row_status == "failed":
        return _plan(operation_key, action, "execute", None)
    raise ValueError(f"unknown effect row status: {row_status!r}")


def plan_effect(
    store: EffectStore,
    *,
    operation_key: str,
    action: OnboardingEffect,
) -> EffectPlan:
    """Present one key to the effect ledger and return the resulting plan.

    This is the only place the ``(provider, action)`` pair is composed, so the
    onboarding keys reach the existing ledger under exactly the stable pairs
    design LL-4.2 names and no parallel ledger is created.

    ``reserve()`` returns three values where the row has four: ``pending`` and
    ``outcome_unknown`` both arrive as ``reconcile_required``. That collapse is
    lossless for this decision — both mean "a prior attempt may have reached the
    provider", both map to ``reconcile``, and both carry
    :data:`_RECONCILE_REASON_CODE`.
    """

    reservation = store.reserve(
        provider=EFFECT_PROVIDER,
        action=_effect_action(action),
        idempotency_key=operation_key,
    )
    return plan_for_reservation(operation_key=operation_key, action=action, reservation=reservation)


def plan_for_reservation(
    *,
    operation_key: str,
    action: OnboardingEffect,
    reservation: EffectReservation,
) -> EffectPlan:
    """Map a ledger reservation result onto a disposition. Pure."""

    if reservation.status == "completed":
        if not reservation.receipt:
            raise ValueError("a completed effect must carry its receipt")
        return _plan(operation_key, action, "skip", dict(reservation.receipt))
    if reservation.status == "reconcile_required":
        return _plan(operation_key, action, "reconcile", None)
    return _plan(operation_key, action, "execute", None)


def complete_effect(store: EffectStore, plan: EffectPlan, *, receipt: Mapping[str, str]) -> None:
    """Record that the planned effect happened, with its non-secret receipt.

    The ledger rejects a receipt whose values are unbounded or secret-shaped, so
    the caller passes identifiers (developer application id, vault reference id)
    and never material.
    """

    store.complete(
        provider=EFFECT_PROVIDER,
        action=_effect_action(plan.action),
        idempotency_key=plan.operation_key,
        receipt=receipt,
    )


def reconcile_completed_effect(
    store: EffectStore, plan: EffectPlan, *, receipt: Mapping[str, str]
) -> None:
    """Record an effect a read-only provider probe proved already happened."""

    store.reconcile_completed(
        provider=EFFECT_PROVIDER,
        action=_effect_action(plan.action),
        idempotency_key=plan.operation_key,
        receipt=receipt,
    )


def mark_effect_outcome_unknown(store: EffectStore, plan: EffectPlan) -> None:
    """Mark an effect whose reconciliation stayed ambiguous.

    The row keeps the provider submission count for this key unchanged
    (Requirement 13.10): nothing here authorizes a second submission, and the
    driver pauses with reason code ``outcome_unknown``.
    """

    store.mark_outcome_unknown(
        provider=EFFECT_PROVIDER,
        action=_effect_action(plan.action),
        idempotency_key=plan.operation_key,
    )


def mark_effect_failed(store: EffectStore, plan: EffectPlan) -> None:
    """Mark an effect that provably did not reach the provider, so it may re-run."""

    store.mark_failed(
        provider=EFFECT_PROVIDER,
        action=_effect_action(plan.action),
        idempotency_key=plan.operation_key,
    )


def _plan(
    operation_key: str,
    action: OnboardingEffect,
    disposition: EffectDisposition,
    receipt: dict[str, str] | None,
) -> EffectPlan:
    return EffectPlan(
        operation_key=operation_key,
        provider=EFFECT_PROVIDER,
        action=action,
        disposition=disposition,
        receipt=receipt,
        reason_code=(
            _RECONCILE_REASON_CODE
            if disposition == "reconcile"
            else _EFFECT_REASON_CODES[_effect_action(action)]
        ),
    )


def _effect_action(action: str) -> OnboardingEffect:
    """Refuse an action outside the three provider-visible effects."""

    if action not in ONBOARDING_EFFECTS:
        raise ValueError(f"unknown onboarding effect: {action!r}")
    # ``action`` is narrowed by the membership test above, so no cast is needed and
    # the closed vocabulary stays the single source of truth.
    return action


def _identifier(value: str, *, field: str) -> str:
    """Bound an identifier that feeds a key, so the composed key stays bounded."""

    stripped = value.strip()
    if not stripped or len(stripped) > MAX_KEY_PART_LENGTH:
        raise ValueError(f"operation key {field} must be a bounded, non-empty identifier")
    return stripped


__all__ = [
    "EFFECT_KEY_VERSION",
    "EFFECT_PROVIDER",
    "MAX_KEY_PART_LENGTH",
    "ONBOARDING_EFFECTS",
    "ONBOARDING_EFFECT_DISPOSITIONS",
    "SCOPE_DIGEST_LENGTH",
    "EffectDisposition",
    "EffectPlan",
    "EffectRowStatus",
    "OnboardingEffect",
    "complete_effect",
    "create_dev_app_key",
    "generate_credential_key",
    "mark_effect_failed",
    "mark_effect_outcome_unknown",
    "plan_effect",
    "plan_for_reservation",
    "plan_for_row_status",
    "reconcile_completed_effect",
    "signup_submit_key",
]
