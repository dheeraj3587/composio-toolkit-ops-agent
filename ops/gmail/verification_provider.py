"""Gmail-over-Composio as one implementation of the verification port.

This is the adapter half of the mailbox boundary: :class:`GmailVerificationProvider`
satisfies ``ops.email.verification_provider.VerificationProvider`` structurally, and it is
the only adapter :func:`default_verification_provider` wires. The verification
service resolves mail through the port and therefore never names Gmail; a second
mailbox (IMAP, a vendor API) is a new class satisfying the same protocol plus a
change to that one factory.

What this module reuses rather than restates
-------------------------------------------
Every decision about *whether a message is the one this run is waiting for* already
lives in ``ops.email.verification``, and it stays there:

* ``gmail_freshness_query`` builds the coarse server-side pre-filter. Gmail cannot
  express an hour-scale bound (``m`` is months, and there is no hour unit), so the
  real freshness bound is applied here against each message's own receive
  timestamp via ``parse_received_at_ms``.
* ``bind_recipient`` (over ``parse_addresses`` / ``canonical_address``) decides
  recipient binding. Only ``exact`` and ``canonical`` candidates cross the port,
  which is the port's stated post-condition and the single fact preventing one run
  from consuming another run's verification.
* ``sender_authentication_method`` and ``is_safe_verification_link`` are applied by
  ``select_verification`` in the verification service, not duplicated here. This
  adapter's obligation is to *keep them decidable*: the candidate projection it
  returns carries the ``Authentication-Results`` / ARC headers and the untouched
  subject and body, so aligned DMARC/DKIM/SPF evidence and link-host confinement
  are still checkable downstream — and a message rejected for weak sender
  authentication is rejected *with its reason code recorded* by the service instead
  of vanishing silently inside the adapter.

The Composio call itself is the existing one. ``GmailWorker`` owns the pinned tool
allow-list, the scoped tool-router session, the bounded retry/reconnect ladder, and
the untrusted-payload projection; this adapter adds no HTTP client and no second
place where a Gmail payload is parsed.

Exactly-once is the vault's guarantee, not this adapter's
--------------------------------------------------------
``claim`` / ``release`` / ``settle`` delegate to
``SQLiteSecretStore.begin_gmail_message_ingestion`` and its completion and release
verbs. The ``UNIQUE`` reservation row inside a single SQLite transaction is what
makes "exactly one caller across all processes" true (Requirements 7.16, 7.17,
7.22). Arbitrating in Python here would reintroduce the race the vault closed.

The reservation key is deliberately derived from the connected Gmail account and
the immutable message id alone: the adapter passes the message id in the thread
slot as well, so two workers compute the same key from the same message without
having to agree on any thread state they happened to observe at search time.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from ops.core.config import Settings
from ops.core.secret_store import (
    EmailMessageIngestionReservation,
    GmailMessageIngestionStateError,
    SQLiteSecretStore,
)
from ops.email.verification import (
    VerificationCandidate,
    bind_recipient,
    canonical_address,
    gmail_freshness_query,
    parse_addresses,
    parse_received_at_ms,
)
from ops.email.verification_provider import (
    VerificationProvider,
    VerificationProviderKind,
    VerificationQuery,
)
from ops.gmail.worker import GmailWorker
from ops.providers.errors import ConfigurationRequiredError

# Vault app slug the verification reservations are booked under. Distinct from any
# provider slug so a verification claim can never be read through, or confused
# with, a captured integration credential.
VERIFICATION_APP_SLUG = "email-verification"

# A verification code is short-lived, so a crashed worker's claim should become
# reclaimable quickly — but only by the run that took it, which is the vault's
# rule, not this adapter's.
CLAIM_LEASE_SECONDS = 300

_CAPABILITY = "Composio Gmail verification"


class GmailVerificationProvider:
    """``VerificationProvider`` over the existing Gmail-via-Composio integration.

    Reuses, rather than reimplements, ``ops.email.verification``: the freshness
    query, recipient binding, sender authentication, candidate selection, and
    link-host confinement all remain that module's decisions (see the module
    docstring for which half runs where).
    """

    name = "gmail_composio"
    kind: VerificationProviderKind = "gmail"

    def __init__(
        self,
        *,
        settings: Settings,
        store: SQLiteSecretStore,
        worker: GmailWorker | None = None,
    ) -> None:
        self._settings = settings
        self._store = store
        # An injected worker is how a test drives this adapter against a fake
        # Composio client; production passes none and gets the configured one.
        self._worker = worker if worker is not None else GmailWorker(settings=settings)

    def is_configured(self) -> bool:
        """True when a Composio key and a connected Gmail account are both present.

        A caller checks this before searching so a missing mailbox pauses the run
        with ``verification_unresolved`` and zero consumed messages (Requirement
        7.3) instead of surfacing as a mid-phase failure.
        """

        account_id = self._settings.composio_gmail_connected_account_id
        return (
            self._settings.composio_gmail_api_key is not None
            and isinstance(account_id, str)
            and bool(account_id)
        )

    async def search(self, query: VerificationQuery) -> tuple[VerificationCandidate, ...]:
        """Read the mailbox once and return newest-first bound candidates.

        The server-side query is only a coarse pre-filter; the freshness floor and
        the recipient binding are enforced here, so an unparsable timestamp or a
        message delivered to a different alias never crosses the port. ``()`` is a
        normal result — the provider's mail has simply not arrived yet.
        """

        self._require_configuration()
        expected = canonical_address(query.expected_recipient)
        if expected is None:  # pragma: no cover - VerificationQuery already refused it
            return ()
        now = datetime.now(UTC)
        candidates = await self._worker.fetch_verification_candidates(
            query=self._inbox_query(query, now=now),
            max_results=query.limit,
        )
        floor_ms = query.freshness_floor_ms(now_ms=int(now.timestamp() * 1000))
        bound: list[tuple[int, VerificationCandidate]] = []
        for candidate in candidates:
            received_at_ms = parse_received_at_ms(candidate.received_at)
            if received_at_ms is None or received_at_ms < floor_ms:
                continue
            if bind_recipient(expected, parse_addresses(candidate.recipients)) not in {
                "exact",
                "canonical",
            }:
                continue
            bound.append((received_at_ms, candidate))
        # Newest first, ties broken on the immutable message id so two identical
        # reads cannot select a different one-time secret.
        bound.sort(key=lambda entry: (-entry[0], str(entry[1].message_id or "")))
        return tuple(candidate for _received_at_ms, candidate in bound[: query.limit])

    async def claim(self, *, message_id: str, run_id: str) -> EmailMessageIngestionReservation:
        """Reserve exactly-once consumption of one message through the vault."""

        self._require_configuration()
        return await asyncio.to_thread(
            self._store.begin_gmail_message_ingestion,
            connected_account_id=self._connected_account_id(),
            thread_id=message_id,
            message_id=message_id,
            owner_run_id=run_id,
            app_slug=VERIFICATION_APP_SLUG,
            credentials=(),
            lease_seconds=CLAIM_LEASE_SECONDS,
        )

    async def release(self, *, message_id: str, run_id: str, claim_token: str) -> None:
        """Expire an acquired-but-unused claim so a later attempt can retry.

        A claim that has already lapsed or been settled reports no change, which is
        not an error: the point of releasing is only that a still-valid code stays
        usable by the next attempt.
        """

        self._require_configuration()
        await asyncio.to_thread(
            self._store.release_gmail_message_ingestion,
            connected_account_id=self._connected_account_id(),
            thread_id=message_id,
            message_id=message_id,
            owner_run_id=run_id,
            claim_token=claim_token,
        )

    async def settle(self, *, message_id: str, run_id: str, claim_token: str) -> None:
        """Mark the claim consumed so the message can never be claimed again.

        A refused settlement (wrong run, wrong token, no reservation) fails loudly
        with a value-free reason code rather than letting the caller believe a
        one-time secret was retired when it was not.
        """

        self._require_configuration()
        settled = await asyncio.to_thread(
            self._store.complete_gmail_message_ingestion,
            connected_account_id=self._connected_account_id(),
            thread_id=message_id,
            message_id=message_id,
            owner_run_id=run_id,
            claim_token=claim_token,
        )
        if not settled:
            raise GmailMessageIngestionStateError("verification_claim_settlement_failed")

    def _inbox_query(self, query: VerificationQuery, *, now: datetime) -> str:
        """Build the coarse Gmail pre-filter for this run-bound query.

        The sender clause is a hint only, and only when the profile named exactly
        one plain domain: a wildcard pattern or several domains would either be
        invalid Gmail grammar or narrow the read past a legitimate sending
        subdomain. The reviewed-sender decision belongs to
        ``select_verification``, not to a server-side filter the mail provider may
        interpret loosely.
        """

        sender_hint: str | None = None
        if len(query.sender_domains) == 1 and "*" not in query.sender_domains[0]:
            sender_hint = query.sender_domains[0]
        try:
            return gmail_freshness_query(
                now=now,
                max_age_seconds=query.max_age_seconds,
                recipient=query.expected_recipient,
                sender_domain=sender_hint,
            )
        except ValueError:
            # An unusable sender domain costs a wider read, never a wrong one.
            return gmail_freshness_query(
                now=now,
                max_age_seconds=query.max_age_seconds,
                recipient=query.expected_recipient,
            )

    def _connected_account_id(self) -> str:
        account_id = self._settings.composio_gmail_connected_account_id
        if not isinstance(account_id, str) or not account_id:
            raise ConfigurationRequiredError(
                phase=4,
                capability=_CAPABILITY,
                reason_code="gmail_connected_account_missing",
            )
        return account_id

    def _require_configuration(self) -> None:
        if self._settings.composio_gmail_api_key is None:
            raise ConfigurationRequiredError(
                phase=4,
                capability=_CAPABILITY,
                reason_code="composio_gmail_api_key_missing",
            )
        self._connected_account_id()


def default_verification_provider(
    *,
    settings: Settings,
    store: SQLiteSecretStore,
) -> VerificationProvider:
    """The single mailbox adapter wired by default.

    Declared as the port rather than the concrete class on purpose: this function
    is the one place in the system that knows the default mailbox is Gmail, and the
    verification service that consumes it does not.
    """

    return GmailVerificationProvider(settings=settings, store=store)


__all__ = [
    "CLAIM_LEASE_SECONDS",
    "VERIFICATION_APP_SLUG",
    "GmailVerificationProvider",
    "default_verification_provider",
]
