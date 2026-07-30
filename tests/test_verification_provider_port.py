"""One happy-path check that the verification port is satisfiable as written.

The port's value is that an adapter satisfies it structurally, so the check that
matters is a small in-memory mailbox implementing the five methods and being
accepted as a ``VerificationProvider`` — the same shape the Gmail adapter (task
16.2) and the verification service (task 16.3) will meet.
"""

from __future__ import annotations

from ops.core.secret_store import EmailMessageIngestionReservation
from ops.email.verification import VerificationCandidate
from ops.email.verification_provider import VerificationProvider, VerificationQuery

NOW_MS = 1_716_000_000_000


class InMemoryVerificationProvider:
    """A mailbox holding one message, claimable exactly once."""

    name = "in_memory"
    kind = "vendor_api"

    def __init__(self, message: VerificationCandidate) -> None:
        self._message = message
        self._claimed = False

    def is_configured(self) -> bool:
        return True

    async def search(self, query: VerificationQuery) -> tuple[VerificationCandidate, ...]:
        return (self._message,)[: query.limit]

    async def claim(self, *, message_id: str, run_id: str) -> EmailMessageIngestionReservation:
        if self._claimed:
            return EmailMessageIngestionReservation(status="completed")
        self._claimed = True
        return EmailMessageIngestionReservation(status="acquired", claim_token="token-1")

    async def release(self, *, message_id: str, run_id: str, claim_token: str) -> None:
        self._claimed = False

    async def settle(self, *, message_id: str, run_id: str, claim_token: str) -> None:
        self._claimed = True


async def test_an_adapter_satisfies_the_port_and_answers_a_run_bound_query() -> None:
    message = VerificationCandidate(
        message_id="msg-1",
        sender="no-reply@provider.example",
        recipients=("ops+run001@gmail.com",),
        received_at=NOW_MS,
        subject="Verify your email",
        body="Your verification code is 123456",
    )
    provider: VerificationProvider = InMemoryVerificationProvider(message)
    query = VerificationQuery(
        expected_recipient="ops+run001@gmail.com",
        sender_domains=("provider.example",),
        purpose="signup_confirmation",
        not_before_ms=NOW_MS - 60_000,
        max_age_seconds=600,
        allowed_link_hosts=("provider.example", "*.provider.example"),
    )

    assert isinstance(provider, VerificationProvider)
    assert query.limit == 10
    assert query.freshness_floor_ms(now_ms=NOW_MS) == NOW_MS - 60_000
    assert provider.is_configured() is True
    assert await provider.search(query) == (message,)

    first = await provider.claim(message_id="msg-1", run_id="run-001")
    assert (first.status, first.claim_token) == ("acquired", "token-1")

    await provider.settle(message_id="msg-1", run_id="run-001", claim_token="token-1")
    assert (await provider.claim(message_id="msg-1", run_id="run-001")).status == "completed"
