"""Replay-key validation and canonical request fingerprinting.

An idempotency key identifies a *replay*; a fingerprint identifies the *request*
that key was first used for. Comparing the two is what lets the service tell a
genuine retry (same key, same canonical request) from a conflicting reuse of a key
for different content, so both halves belong together in one module.

Fingerprints are computed over a sorted, separator-normalized JSON dump so the same
logical request always hashes identically regardless of field order or whitespace.
The legacy shapes are kept deliberately: older clients and stored rows were
fingerprinted before ``browser_provider`` and ``credential_creation_policy``
existed, and dropping them would turn an existing replay into a false conflict.
"""

from __future__ import annotations

import hashlib
import json
import re

from ops.models import OperationsRequest
from ops.redaction import redact_text
from ops.run_errors import InvalidIdempotencyKeyError

IDEMPOTENCY_KEY_PATTERN = re.compile(r"^idem_[0-9a-f]{32}$")


def validate_idempotency_key(value: str | None) -> str | None:
    """Validate a short opaque replay key without accepting secret material."""

    if value is None:
        return None
    if IDEMPOTENCY_KEY_PATTERN.fullmatch(value) is None or redact_text(value) != value:
        raise InvalidIdempotencyKeyError("idempotency key is invalid")
    return value


def _request_fingerprint(request: OperationsRequest, execution_mode: str) -> str:
    canonical = json.dumps(
        {"execution_mode": execution_mode, "request": request.model_dump(mode="json")},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _legacy_request_fingerprints(request: OperationsRequest, execution_mode: str) -> set[str]:
    """Accepted historical fingerprint shapes for compatibility replays."""

    if request.credential_creation_policy != "reuse_only":
        return set()
    fingerprints: set[str] = set()
    excluded_sets = [{"credential_creation_policy"}]
    if request.browser_provider == "browser_use":
        excluded_sets.append({"browser_provider", "credential_creation_policy"})
    for excluded in excluded_sets:
        legacy_request = request.model_dump(mode="json", exclude=excluded)
        canonical = json.dumps(
            {"execution_mode": execution_mode, "request": legacy_request},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        fingerprints.add(hashlib.sha256(canonical).hexdigest())
    return fingerprints


def _legacy_request_fingerprint(request: OperationsRequest, execution_mode: str) -> str:
    """Return the oldest Browser Use fingerprint shape kept for test/client compatibility."""

    legacy_request = request.model_dump(
        mode="json", exclude={"browser_provider", "credential_creation_policy"}
    )
    canonical = json.dumps(
        {"execution_mode": execution_mode, "request": legacy_request},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


__all__ = [
    "IDEMPOTENCY_KEY_PATTERN",
    "validate_idempotency_key",
]
