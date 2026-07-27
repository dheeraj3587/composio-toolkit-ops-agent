"""Exception types raised across the run-service boundary.

These live in a leaf module because they are part of the contract rather than the
implementation: the HTTP layer maps them to status codes and reason codes, so they
must be importable without pulling in the service, the workflow, or any provider
adapter.

Each type deliberately carries a reason code or identifier instead of a message
built from caller input. A malformed idempotency key or a rejected credential
submission must never be echoed back, because the offending value can itself be
credential-shaped.
"""

from __future__ import annotations


class InvalidIdempotencyKeyError(ValueError):
    """Raised without echoing a malformed or credential-shaped key."""


class IdempotencyConflictError(ValueError):
    """Raised when a key is reused for a different canonical request."""


class RunConflictError(RuntimeError):
    """Raised when a competing command mutates the same run concurrently."""

    def __init__(self, run_id: str, action: str) -> None:
        self.run_id = run_id
        self.action = action
        super().__init__("a competing command is already modifying this run")


class CredentialSubmissionError(RuntimeError):
    """Owner credential submission rejected; no partial vault write is kept."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__("owner credential submission was rejected")


__all__ = [
    "CredentialSubmissionError",
    "IdempotencyConflictError",
    "InvalidIdempotencyKeyError",
    "RunConflictError",
]
