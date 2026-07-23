"""Read-only credential-validation boundary for Phase 6."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ops.graph import PhaseUnavailableError

ValidationStatus = Literal["valid", "invalid", "unavailable", "failed"]


@dataclass(frozen=True, slots=True)
class CredentialValidationResult:
    """Sanitized validation metadata; private response bodies are never represented."""

    status: ValidationStatus
    endpoint: str
    http_status: int | None
    checked_at: str


class CredentialValidator:
    async def validate(
        self,
        *,
        app_slug: str,
        credential_refs: dict[str, str],
        read_only_endpoint: str,
    ) -> CredentialValidationResult:
        del app_slug, credential_refs, read_only_endpoint
        raise PhaseUnavailableError(phase=6, capability="credential validation")
