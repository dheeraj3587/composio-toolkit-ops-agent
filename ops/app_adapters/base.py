"""Secret-free interface for later deterministic provider adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class CredentialFieldSelector:
    """Identifies where deterministic code will read a named secret field."""

    kind: str
    selector: str


class AppAdapter(Protocol):
    """Non-secret provider metadata required by a future Playwright adapter."""

    @property
    def app_slug(self) -> str: ...

    @property
    def allowed_domains(self) -> tuple[str, ...]: ...

    @property
    def credential_field_selectors(self) -> tuple[CredentialFieldSelector, ...]: ...

    def developer_app_name(self) -> str: ...
