"""Authenticated, narrowly scoped client for the API-owned credential vault."""

from __future__ import annotations

import re
from typing import Any

import httpx
from pydantic import SecretStr

from browser_service.auth import OWNER_HEADER
from ops.browser_session_capability import CAPABILITY_HEADER
from ops.models import validate_vault_reference
from ops.provider_errors import ProviderOperationError

BROKER_TOKEN_HEADER = "X-Browser-Secret-Broker-Token"
_KIND = re.compile(r"^[a-z0-9][a-z0-9_-]{0,99}$")


class BrowserSecretBrokerClient:
    """Synchronous client used only at the short secret handoff boundaries.

    Playwright's existing ``SecretStore.put`` port is synchronous. Keeping this
    adapter synchronous avoids touching the reviewed capture state machine; the
    network call is a small private API/SQLite operation with a strict timeout.
    """

    def __init__(
        self,
        *,
        base_url: str,
        token: SecretStr,
        timeout_seconds: float,
        client: httpx.Client | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._owns_client = client is None
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(timeout_seconds, connect=min(timeout_seconds, 5.0)),
            follow_redirects=False,
        )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def _post(
        self,
        path: str,
        body: dict[str, str],
        *,
        owner: str,
        capability: str,
        retry_transport: bool = False,
    ) -> dict[str, Any]:
        response: httpx.Response | None = None
        attempts = 2 if retry_transport else 1
        for attempt in range(attempts):
            try:
                response = self._client.post(
                    f"{self._base_url}{path}",
                    headers={
                        BROKER_TOKEN_HEADER: self._token.get_secret_value(),
                        OWNER_HEADER: owner,
                        CAPABILITY_HEADER: capability,
                    },
                    json=body,
                )
                break
            except httpx.RequestError:
                if attempt + 1 >= attempts:
                    raise ProviderOperationError(
                        capability="browser secret broker",
                        reason_code="browser_secret_broker_unreachable",
                    ) from None
        if response is None:  # pragma: no cover - loop invariant
            raise ProviderOperationError(
                capability="browser secret broker",
                reason_code="browser_secret_broker_unreachable",
            )
        if response.status_code >= 400:
            reason = "browser_secret_broker_failed"
            try:
                payload = response.json()
                if isinstance(payload, dict) and payload.get("error") in {
                    "browser_secret_broker_unavailable",
                    "browser_secret_unavailable",
                    "browser_capture_not_authorized",
                }:
                    reason = str(payload["error"])
            except (TypeError, ValueError):
                pass
            raise ProviderOperationError(
                capability="browser secret broker",
                reason_code=reason,
            )
        try:
            payload = response.json()
        except ValueError:
            raise ProviderOperationError(
                capability="browser secret broker",
                reason_code="browser_secret_broker_invalid_response",
            ) from None
        if not isinstance(payload, dict):
            raise ProviderOperationError(
                capability="browser secret broker",
                reason_code="browser_secret_broker_invalid_response",
            )
        return payload

    def consume(
        self,
        *,
        grant: str,
        reference: str,
        app_slug: str,
        kind: str,
        scope_id: str,
        session_id: str,
        owner: str,
        capability: str,
    ) -> str:
        payload = self._post(
            "/internal/browser-secret-broker/consume",
            {
                "grant": grant,
                "reference": reference,
                "app_slug": app_slug,
                "kind": kind,
                "scope_id": scope_id,
                "session_id": session_id,
            },
            owner=owner,
            capability=capability,
        )
        if (
            set(payload) != {"value"}
            or not isinstance(payload["value"], str)
            or not payload["value"]
        ):
            raise ProviderOperationError(
                capability="browser secret broker",
                reason_code="browser_secret_broker_invalid_response",
            )
        return payload["value"]

    def capture(
        self,
        *,
        grant: str,
        app_slug: str,
        kind: str,
        scope_id: str,
        session_id: str,
        owner: str,
        capability: str,
        value: str,
    ) -> str:
        payload = self._post(
            "/internal/browser-secret-broker/capture",
            {
                "grant": grant,
                "app_slug": app_slug,
                "kind": kind,
                "scope_id": scope_id,
                "session_id": session_id,
                "value": value,
            },
            owner=owner,
            capability=capability,
            # Capture is idempotent under this exact durable grant. A response may
            # be lost after the vault transaction commits, so one transport retry
            # is safe and returns the original reference.
            retry_transport=True,
        )
        if set(payload) != {"reference"} or not isinstance(payload["reference"], str):
            raise ProviderOperationError(
                capability="browser secret broker",
                reason_code="browser_secret_broker_invalid_response",
            )
        return validate_vault_reference(payload["reference"])


class BrokerCaptureStore:
    """Write-only ``SecretStore`` adapter bound to one browser session scope."""

    def __init__(
        self,
        *,
        broker: BrowserSecretBrokerClient,
        grant: str,
        app_slug: str,
        scope_id: str,
        session_id: str,
        owner: str,
        capability: str,
    ) -> None:
        self._broker = broker
        self._grant = grant
        self._app_slug = app_slug
        self._scope_id = scope_id
        self._session_id = session_id
        self._owner = owner
        self._capability = capability

    def put(self, *, app_slug: str, kind: str, value: str) -> str:
        if app_slug != self._app_slug or _KIND.fullmatch(kind) is None:
            raise ProviderOperationError(
                capability="browser secret broker",
                reason_code="browser_capture_not_authorized",
            )
        return self._broker.capture(
            grant=self._grant,
            app_slug=self._app_slug,
            kind=kind,
            scope_id=self._scope_id,
            session_id=self._session_id,
            owner=self._owner,
            capability=self._capability,
            value=value,
        )


__all__ = [
    "BROKER_TOKEN_HEADER",
    "BrokerCaptureStore",
    "BrowserSecretBrokerClient",
]
