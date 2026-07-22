"""Playwright credential-capture boundary.

No Playwright import is permitted here until Phase 6. Future implementations must keep raw values
inside this method and return only exact vault references.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ops.graph import PhaseUnavailableError

if TYPE_CHECKING:
    from ops.secret_store import SecretStore


class CredentialCapture:
    def __init__(self, secret_store: SecretStore | None = None) -> None:
        self._secret_store = secret_store

    async def capture_and_store(
        self,
        cdp_url: str,
        app_slug: str,
        field_selectors: dict[str, str],
    ) -> dict[str, str]:
        del cdp_url, app_slug, field_selectors
        raise PhaseUnavailableError(phase=6, capability="Playwright credential capture")
