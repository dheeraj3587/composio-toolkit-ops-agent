"""Sanitized capability errors shared by optional provider boundaries."""

from __future__ import annotations


class PhaseUnavailableError(RuntimeError):
    """A capability cannot run; the message never includes provider payloads."""

    def __init__(
        self, *, phase: int, capability: str, reason_code: str = "phase_unavailable"
    ) -> None:
        self.phase = phase
        self.capability = capability
        self.reason_code = reason_code
        super().__init__(
            f"{capability} is unavailable in the current runtime; "
            f"Phase {phase} capability status is {reason_code}."
        )


class ConfigurationRequiredError(PhaseUnavailableError):
    """Required opt-in or provider identifiers are absent."""

    def __init__(self, *, phase: int, capability: str, reason_code: str) -> None:
        super().__init__(phase=phase, capability=capability, reason_code=reason_code)


class ProviderContractError(PhaseUnavailableError):
    """The installed SDK cannot satisfy a mandatory safety invariant."""

    def __init__(self, *, phase: int, capability: str, reason_code: str) -> None:
        super().__init__(phase=phase, capability=capability, reason_code=reason_code)


class ProviderOperationError(RuntimeError):
    """A sanitized provider failure with a stable, non-payload reason code."""

    def __init__(self, *, capability: str, reason_code: str) -> None:
        self.capability = capability
        self.reason_code = reason_code
        super().__init__(f"{capability} failed with status {reason_code}")
