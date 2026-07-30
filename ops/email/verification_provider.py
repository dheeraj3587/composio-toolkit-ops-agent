"""The mailbox boundary autonomous email verification is resolved through.

Email verification is the phase most onboarding systems hand back to a human. It
stays autonomous here, which means the system reads a mailbox and types what it
finds into a live provider page. That makes the mailbox an *untrusted input
channel* and it makes "which mailbox" a deployment decision rather than a
hard-coded integration. This module owns both halves of that boundary: the
:class:`VerificationQuery` value a caller may ask with, and the
:class:`VerificationProvider` ``Protocol`` an adapter satisfies structurally.

The port exists so the verification service never names a mail vendor.
    Requirement 7.1 resolves verification *through the port*; Requirement 7.2
    makes Gmail-via-Composio merely one implementation of it. A second mailbox
    (IMAP, a vendor API) is therefore a new class satisfying this protocol plus a
    registration in ``Settings`` — not an edit to the phase driver. The service in
    LL-3.4 sees ``name``, ``kind``, and five methods.

What this module deliberately does not restate.
    Every decision about *whether a message is the one this run is waiting for*
    already lives in ``ops.email.verification``: recipient binding
    (``bind_recipient``), sender authentication
    (``sender_authentication_method``), freshness parsing
    (``parse_received_at_ms``), candidate selection (``select_verification``),
    and link-host confinement (``is_safe_verification_link``). The query carries
    the *bounds* those functions are applied with, and the candidate type crossing
    the port is ``ops.email.verification.VerificationCandidate`` itself rather
    than a parallel shape. A second candidate type would be a second place for a
    binding rule to be forgotten.

The query is secret-free by construction.
    Nothing on :class:`VerificationQuery` is a credential, a one-time code, or a
    link — it is a recipient address, a sender domain set, a freshness window, and
    an allow-list. The secret only exists on the way *back*, inside a
    ``VerificationCandidate`` (documented trusted-process-only) or a
    ``ResolvedVerification.secret``. That asymmetry is why a query may be logged
    and a candidate may not.

Exactly-once consumption is the vault's guarantee, not an adapter's.
    A one-time code is single-use, and two workers observing the same inbox must
    not both spend it. So ``claim`` / ``release`` / ``settle`` are on the port,
    but the uniqueness they promise is expected to be delegated:
    ``GmailVerificationProvider.claim`` (task 16.2) calls
    ``SQLiteSecretStore.begin_gmail_message_ingestion``, whose ``UNIQUE``
    constraint is what makes "exactly one caller across all processes" true. An
    adapter that reimplements the arbitration in Python would be reintroducing the
    race the vault already closed.

Emptiness is a value, not an exception.
    ``search`` returning ``()`` is the normal case for most attempts — the
    provider's mail has simply not arrived yet, and the service answers that with
    a jittered deferral (Requirement 7.25), not with an error. Only a
    *misconfigured* adapter raises, and a caller checks :meth:`is_configured`
    first precisely so it can pause with ``verification_unresolved`` and zero
    consumed messages (Requirement 7.3) instead of catching an exception.

Scope: this module is the vocabulary and the port. The Gmail adapter (task 16.2)
and the verification service that drives the claim/settle ladder (task 16.3) are
separate.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Literal, Protocol, runtime_checkable

from ops.email.verification import (
    MAX_VERIFICATION_AGE_SECONDS,
    VerificationCandidate,
    VerificationPurpose,
    canonical_address,
)

if TYPE_CHECKING:  # pragma: no cover - imported for typing only
    # Typing-only so this vocabulary module stays free of the vault's import
    # chain; only an adapter needs the store itself.
    from ops.core.secret_store import EmailMessageIngestionReservation

# Requirement 7.5: one inbox query asks for at most 10 candidates. The bound is
# not performance tuning — a wider page is a wider set of attacker-supplied
# messages the selector has to reject, and the message this run is waiting for is
# always among the newest few.
MAX_VERIFICATION_CANDIDATES: Final = 10

# The mailbox families an adapter may declare. Closed on purpose: `kind` reaches
# sanitized projections and structured logs, so it has to be a vocabulary rather
# than free text.
VerificationProviderKind = Literal["gmail", "imap", "vendor_api"]


@dataclass(frozen=True, slots=True)
class VerificationQuery:
    """A run-bound, freshness-bounded inbox query. Carries no secret.

    Run-binding is :attr:`expected_recipient`: the mailbox alias this run signed
    up with, plus-tag included. It is the single fact preventing one run from
    consuming another run's verification, which is why it is required rather than
    optional and why an unparsable address is refused at construction instead of
    being passed to a mail API that would happily return somebody else's mail.

    Freshness is expressed as a floor *and* a window. :attr:`not_before_ms` is the
    absolute floor (the run's own start, or the moment the challenge was issued);
    :attr:`max_age_seconds` is the rolling window measured against each message's
    provider receive timestamp. Both are needed: a window alone would admit a
    message that predates this run, and a floor alone would admit an arbitrarily
    old message from a long-running run.
    """

    expected_recipient: str
    # Sender domains worth asking for: the profile's registrable domain plus any
    # auxiliary hosts it declared. A coarse server-side hint only — the reviewed
    # sender check is `select_verification`'s, against the parsed From address.
    sender_domains: tuple[str, ...]
    purpose: VerificationPurpose
    # Epoch milliseconds. Freshness floor; no message received before it qualifies.
    not_before_ms: int
    max_age_seconds: int
    # Allow-list patterns from the run's profile. A magic link is only openable
    # when its host is inside this set (Requirement 7.14), so the bound travels
    # with the query rather than being re-derived at the navigation site.
    allowed_link_hosts: tuple[str, ...]
    limit: int = MAX_VERIFICATION_CANDIDATES

    def __post_init__(self) -> None:
        if canonical_address(self.expected_recipient) is None:
            raise ValueError("expected_recipient is not a single valid mailbox address")
        if not 0 < self.max_age_seconds <= MAX_VERIFICATION_AGE_SECONDS:
            raise ValueError(
                f"max_age_seconds must be in 1..{MAX_VERIFICATION_AGE_SECONDS} seconds"
            )
        if self.not_before_ms <= 0:
            raise ValueError("not_before_ms must be a positive epoch-millisecond instant")
        if not 0 < self.limit <= MAX_VERIFICATION_CANDIDATES:
            raise ValueError(f"limit must be in 1..{MAX_VERIFICATION_CANDIDATES}")

    def freshness_floor_ms(self, *, now_ms: int) -> int:
        """The earliest receive time a candidate may carry, in epoch milliseconds.

        The stricter of the two bounds wins, so an adapter and the selector agree
        on one number instead of each applying half of the window.
        """

        return max(self.not_before_ms, now_ms - self.max_age_seconds * 1000)


@runtime_checkable
class VerificationProvider(Protocol):
    """A mailbox the system may read to complete provider email verification.

    Implementations MUST NOT return a candidate whose recipient does not bind to
    ``query.expected_recipient`` under
    ``ops.email.verification.bind_recipient``; recipient binding is the only
    thing preventing one run from consuming another run's verification.
    Implementations MUST NOT log, persist, or return message bodies except inside
    ``VerificationCandidate``, which is documented trusted-process-only.
    """

    name: str
    kind: VerificationProviderKind

    def is_configured(self) -> bool:
        """True when the adapter can run without raising ``ConfigurationRequiredError``.

        Checked before any search so a missing mailbox pauses the run with
        ``verification_unresolved`` and zero consumed messages (Requirement 7.3)
        rather than surfacing as a failure mid-phase.
        """

    async def search(self, query: VerificationQuery) -> tuple[VerificationCandidate, ...]:
        """Return newest-first candidate messages, or ``()`` when none match.

        PRE:  ``is_configured()`` is True.
        POST: at most ``query.limit`` candidates; each has a receive time at or
              after ``query.not_before_ms`` and at least one recipient binding to
              ``query.expected_recipient``. ``()`` is a normal result, not an
              error.
        """

    async def claim(self, *, message_id: str, run_id: str) -> EmailMessageIngestionReservation:
        """Reserve exactly-once consumption of one message.

        PRE:  ``message_id`` came from this adapter's ``search()``.
        POST: exactly one caller across all processes receives ``"acquired"`` with
              a claim token; concurrent callers receive ``"busy"``; a caller
              arriving after settlement receives ``"completed"``. The uniqueness
              guarantee is expected to be delegated to the vault
              (``begin_gmail_message_ingestion``), not implemented in the adapter.
        """

    async def release(self, *, message_id: str, run_id: str, claim_token: str) -> None:
        """Release an acquired-but-unused claim so a later attempt can retry.

        Called when the provider did not accept the verification, or when the
        message carried a link outside the run's allow-list. Releasing rather than
        settling is what keeps a still-valid code usable by the next attempt.
        """

    async def settle(self, *, message_id: str, run_id: str, claim_token: str) -> None:
        """Mark the claim consumed; the message can never be claimed again.

        Called only after the provider accepted the verification, and before the
        service returns, so a retry cannot spend the same one-time secret twice.
        """


__all__ = [
    "MAX_VERIFICATION_CANDIDATES",
    "VerificationProvider",
    "VerificationProviderKind",
    "VerificationQuery",
]
