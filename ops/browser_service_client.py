"""API-side RPC client for the isolated browser service.

Implements the same provider surface as ``PlaywrightBrowserWorker`` so
``RunService`` can swap the in-process harness for the out-of-process service
without any graph/workflow change. The important behavioral difference:

``supports_restart_reattach = True`` — Chromium lives in the browser service, so
an API restart no longer kills a session. Reattachment is only claimed after
QUERYING the service: a persisted session id is never trusted on its own
(``reconcile_session`` returns ``session_lost`` when the service has no such
session).

The shared token travels in a header, never a query string, and is never logged
or returned. Credential VALUES never cross this boundary — only ``vault://``
references, which the service resolves internally.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

import httpx
from pydantic import SecretStr

from ops.browser_worker import BrowserObservation, BrowserSessionContext
from ops.models import validate_vault_reference
from ops.policies import (
    validate_account_policy,
    validate_credential_policy,
    validate_developer_app_policy,
)
from ops.provider_errors import ConfigurationRequiredError, ProviderOperationError
from ops.secret_store import parse_vault_reference

LOGGER = logging.getLogger("composio_ops.browser_service_client")

TOKEN_HEADER = "X-Browser-Service-Token"
OWNER_HEADER = "X-Browser-Session-Owner"

ReconcileOutcome = Literal["resumable", "session_lost", "unreachable"]

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_MAX_SCREENSHOT_BYTES = 8 * 1024 * 1024

# Health states mirrored from the service (no Browser Use wording here).
ProviderHealthState = Literal[
    "disabled",
    "not_configured",
    "configured_not_verified",
    "ready",
    "degraded",
    "capacity_exhausted",
    "unreachable",
    "version_mismatch",
]

# The RPC contract version this client speaks; a mismatch is reported, not guessed.
SUPPORTED_SERVICE_MAJOR = 1


@dataclass(frozen=True, slots=True)
class BrowserServiceHealth:
    """Sanitized provider health for the Playwright path."""

    state: ProviderHealthState
    reason_code: str
    version: str = ""
    chromium_installed: bool = False
    context_launch_ok: bool = False
    capacity_total: int = 0
    capacity_in_use: int = 0
    janitor_running: bool = False


class BrowserServiceClient:
    """Provider-shaped RPC client for the out-of-process browser service."""

    provider_name = "playwright"
    # HITL uses either the screenshot endpoint or a short-lived interactive grant;
    # neither is a durable hosted URL, so this stays False.
    supports_live_url = False
    supports_screenshot = True
    # Chromium is in its OWN process now: an API restart cannot kill it, and
    # reattachment is verified against the service before being claimed.
    supports_restart_reattach = True

    def __init__(
        self,
        *,
        base_url: str,
        token: SecretStr | str,
        owner: str,
        timeout_seconds: float = 150.0,
        client: httpx.AsyncClient | None = None,
        sync_client: httpx.Client | None = None,
    ) -> None:
        if not base_url:
            raise ConfigurationRequiredError(
                phase=3, capability="browser service", reason_code="browser_service_url_missing"
            )
        self._base_url = base_url.rstrip("/")
        self._token = token if isinstance(token, SecretStr) else SecretStr(token)
        self._owner = owner
        self._timeout = timeout_seconds
        self._client = client
        self._sync_client = sync_client
        # Sanitized per-session bookkeeping (never a URL with a query string).
        self._sessions: dict[str, str] = {}

    # --- transport ------------------------------------------------------------
    def _headers(self) -> dict[str, str]:
        # Token in a HEADER, never a query string (those land in access logs).
        return {
            TOKEN_HEADER: self._token.get_secret_value(),
            OWNER_HEADER: self._owner,
            "Content-Type": "application/json",
        }

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Mapping[str, object] | None = None,
        timeout: float | None = None,
    ) -> httpx.Response:
        url = f"{self._base_url}{path}"
        client = self._client
        owns_client = client is None
        if client is None:
            client = httpx.AsyncClient(
                timeout=httpx.Timeout(timeout or self._timeout, connect=10.0),
                follow_redirects=False,
            )
        try:
            return await client.request(
                method,
                url,
                json=json_body,
                headers=self._headers(),
                timeout=timeout or self._timeout,
            )
        finally:
            if owns_client:
                await client.aclose()

    @staticmethod
    def _reason(response: httpx.Response) -> str:
        """Extract the service's sanitized reason code (never its body text)."""

        try:
            payload = response.json()
        except ValueError:
            return f"http_{response.status_code}"
        if isinstance(payload, dict):
            detail = payload.get("detail") or payload.get("reason_code")
            if isinstance(detail, str) and detail and len(detail) <= 100:
                return detail
        return f"http_{response.status_code}"

    # --- provider surface -----------------------------------------------------
    async def start(
        self,
        profile_id: str | None,
        *,
        app_slug: str = "",
        account_ref: str | None = None,
        secret_scope: str | None = None,
        use_storage_state: bool = False,
        live_view_mode: str = "screenshot",
    ) -> BrowserSessionContext:
        body: dict[str, object] = {
            "app_slug": app_slug or "unknown",
            "profile_id": profile_id,
            "account_ref": account_ref,
            "secret_scope": secret_scope or "",
            "live_view_mode": live_view_mode,
            "use_storage_state": use_storage_state,
        }
        try:
            response = await self._request("POST", "/internal/browser/sessions", json_body=body)
        except httpx.RequestError:
            raise ProviderOperationError(
                capability="browser service", reason_code="browser_service_unreachable"
            ) from None
        if response.status_code >= 400:
            raise ProviderOperationError(
                capability="browser service", reason_code=self._reason(response)
            )
        payload = response.json()
        session_id = str(payload.get("session_id") or "")
        if not session_id:
            raise ProviderOperationError(
                capability="browser service", reason_code="session_id_missing"
            )
        self._sessions[session_id] = str(payload.get("app_slug") or "")
        now = datetime.now(UTC)
        return BrowserSessionContext(
            profile_id=profile_id or session_id,
            session_id=session_id,
            live_view_available=bool(payload.get("live_view_available", True)),
            allowed_domains=(),
            created_at=str(payload.get("created_at") or now.isoformat()),
            inactivity_expires_at=str(payload.get("maximum_expires_at") or now.isoformat()),
            maximum_expires_at=str(payload.get("maximum_expires_at") or now.isoformat()),
        )

    async def navigate_onboarding(
        self,
        context: BrowserSessionContext,
        research: Any,
        *,
        sensitive_data: Mapping[str, str] | None = None,
        account_policy: str | None = None,
        developer_app_policy: str | None = None,
        credential_policy: str | None = None,
        account_creation_requested: bool | None = None,
        credential_creation_policy: str | None = None,
    ) -> BrowserObservation:
        resolved_account = validate_account_policy(
            account_policy
            or ("create_if_missing" if account_creation_requested else "reuse_existing")
        )
        resolved_credential = validate_credential_policy(
            credential_policy
            or ("create_if_missing" if credential_creation_policy == "create_if_missing" else None)
        )
        return await self._drive(
            context,
            research,
            path="navigate",
            credential_refs=sensitive_data,
            signal=None,
            account_policy=resolved_account,
            developer_app_policy=validate_developer_app_policy(developer_app_policy),
            credential_policy=resolved_credential,
        )

    async def resume_after_hitl(
        self,
        context: BrowserSessionContext,
        signal: str,
        research: Any = None,
        *,
        sensitive_data: Mapping[str, str] | None = None,
        account_policy: str | None = None,
        developer_app_policy: str | None = None,
        credential_policy: str | None = None,
        credential_creation_policy: str | None = None,
        provider_session_id: str | None = None,
    ) -> BrowserObservation:
        del provider_session_id  # the service session id IS the provider id here
        resolved_credential = validate_credential_policy(
            credential_policy
            or ("create_if_missing" if credential_creation_policy == "create_if_missing" else None)
        )
        return await self._drive(
            context,
            research,
            path="resume",
            credential_refs=sensitive_data,
            signal=signal,
            account_policy=validate_account_policy(account_policy),
            developer_app_policy=validate_developer_app_policy(developer_app_policy),
            credential_policy=resolved_credential,
        )

    async def _drive(
        self,
        context: BrowserSessionContext,
        research: Any,
        *,
        path: str,
        credential_refs: Mapping[str, str] | None,
        signal: str | None,
        account_policy: str = "reuse_existing",
        developer_app_policy: str = "reuse_existing",
        credential_policy: str = "reuse_existing",
    ) -> BrowserObservation:
        refs = _vault_references_only(credential_refs)
        body: dict[str, object] = {
            "credential_refs": refs,
            "account_policy": account_policy,
            "developer_app_policy": developer_app_policy,
            "credential_policy": credential_policy,
        }
        if research is not None:
            body["research"] = (
                research.model_dump(mode="json") if hasattr(research, "model_dump") else research
            )
        elif path == "navigate":
            raise ProviderOperationError(
                capability="browser service", reason_code="verified_research_required"
            )
        if signal is not None:
            body["signal"] = signal
        try:
            response = await self._request(
                "POST", f"/internal/browser/sessions/{context.session_id}/{path}", json_body=body
            )
        except httpx.RequestError:
            raise ProviderOperationError(
                capability="browser service", reason_code="browser_service_unreachable"
            ) from None
        if response.status_code >= 400:
            raise ProviderOperationError(
                capability="browser service", reason_code=self._reason(response)
            )
        payload = response.json()
        return BrowserObservation(
            status=payload.get("status", "failed"),
            current_url=payload.get("current_url", "https://unknown.invalid/"),
            page_title=payload.get("page_title") or "Browser step",
            developer_app_id=payload.get("developer_app_id"),
            human_action_type=payload.get("human_action_type"),
            human_instruction=payload.get("human_instruction"),
            credential_field_labels=tuple(payload.get("credential_field_labels") or ()),
            non_secret_notes=tuple(payload.get("non_secret_notes") or ()),
            reason_code=payload.get("reason_code"),
        )

    async def auto_capture_credentials(
        self,
        handle: str,
        app_slug: str,
        secret_store: object | None = None,
    ) -> dict[str, str] | None:
        """Ask the service to capture into its vault; accept references only."""

        del secret_store  # the service owns the shared vault boundary
        known_slug = self._sessions.get(handle)
        if known_slug and known_slug != app_slug:
            raise ProviderOperationError(
                capability="browser service credential capture",
                reason_code="capture_app_mismatch",
            )
        try:
            response = await self._request(
                "POST",
                f"/internal/browser/sessions/{handle}/capture-credentials",
                json_body={},
            )
        except httpx.RequestError:
            raise ProviderOperationError(
                capability="browser service", reason_code="browser_service_unreachable"
            ) from None
        if response.status_code >= 400:
            raise ProviderOperationError(
                capability="browser service credential capture",
                reason_code=self._reason(response),
            )
        try:
            payload = response.json()
            if not isinstance(payload, dict) or set(payload) != {"credential_refs"}:
                raise ValueError("invalid response shape")
            raw_refs = payload["credential_refs"]
            if not isinstance(raw_refs, dict):
                raise ValueError("invalid reference mapping")
            refs: dict[str, str] = {}
            for kind, reference in raw_refs.items():
                if (
                    not isinstance(kind, str)
                    or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,99}", kind) is None
                ):
                    raise ValueError("invalid credential kind")
                if not isinstance(reference, str):
                    raise ValueError("invalid credential reference")
                validated = validate_vault_reference(reference)
                parts = parse_vault_reference(validated)
                if parts.app_slug != app_slug or parts.kind != kind:
                    raise ValueError("credential reference binding mismatch")
                refs[kind] = validated
        except (ValueError, TypeError, KeyError):
            raise ProviderOperationError(
                capability="browser service credential capture",
                reason_code="invalid_capture_response",
            ) from None
        return refs or None

    async def session_status(self, session_id: str) -> tuple[bool, str]:
        """(exists, reason_code) straight from the service — never inferred."""

        try:
            response = await self._request(
                "GET", f"/internal/browser/sessions/{session_id}/status", timeout=15.0
            )
        except httpx.RequestError:
            return False, "browser_service_unreachable"
        if response.status_code == 404:
            return False, "session_not_found"
        if response.status_code >= 400:
            return False, self._reason(response)
        payload = response.json()
        lifecycle = str(payload.get("lifecycle") or "")
        return lifecycle == "ACTIVE", lifecycle.casefold() or "unknown"

    async def reconcile_session(self, session_id: str | None) -> ReconcileOutcome:
        """Decide whether a PERSISTED session id is still usable after a restart.

        A stored id is never trusted on its own: the service is queried, and only
        an ACTIVE session is reported ``resumable``.
        """

        if not session_id:
            return "session_lost"
        exists, reason = await self.session_status(session_id)
        if exists:
            return "resumable"
        if reason == "browser_service_unreachable":
            return "unreachable"
        return "session_lost"

    async def screenshot(self, session_id: str) -> bytes | None:
        try:
            response = await self._request(
                "GET", f"/internal/browser/sessions/{session_id}/screenshot", timeout=30.0
            )
        except httpx.RequestError:
            return None
        if response.status_code != 200:
            return None
        data = response.content
        return data if isinstance(data, bytes) and data else None

    def latest_screenshot(self, session_id: str) -> tuple[bytes, str] | None:
        """Fetch one current masked frame through the isolated-service RPC.

        ``RunService`` exposes a synchronous projection surface, so the production
        RPC adapter needs a synchronous counterpart to :meth:`screenshot`. The
        previous adapter omitted this method entirely; consequently every
        Playwright live-view request reported unavailable even while Chromium was
        active. The service remains the authority for capture safety and returns
        409 whenever a frame cannot be exposed.
        """

        url = f"{self._base_url}/internal/browser/sessions/{session_id}/screenshot"
        client = self._sync_client
        owns_client = client is None
        if client is None:
            client = httpx.Client(
                timeout=httpx.Timeout(30.0, connect=10.0),
                follow_redirects=False,
            )
        try:
            response = client.get(url, headers=self._headers(), timeout=30.0)
        except httpx.RequestError:
            return None
        finally:
            if owns_client:
                client.close()
        if response.status_code != 200:
            return None
        data = response.content
        if not data.startswith(_PNG_SIGNATURE) or len(data) > _MAX_SCREENSHOT_BYTES:
            return None
        return data, datetime.now(UTC).isoformat()

    async def request_live_view(self, session_id: str) -> tuple[str, str | None, str]:
        """Request an interactive grant: (mode, url_or_None, expires_at).

        The URL is for IMMEDIATE operator use and must never be persisted to run
        state, logs, or checkpoints.
        """

        try:
            response = await self._request(
                "POST", f"/internal/browser/sessions/{session_id}/live-view", timeout=20.0
            )
        except httpx.RequestError:
            return "screenshot", None, ""
        if response.status_code >= 400:
            return "screenshot", None, ""
        payload = response.json()
        return (
            str(payload.get("mode") or "screenshot"),
            payload.get("url"),
            str(payload.get("expires_at") or ""),
        )

    def request_live_view_sync(self, session_id: str) -> tuple[str, str, str] | None:
        """Mint one fresh interactive grant for immediate server-side projection.

        The returned URL is intentionally not cached on this client. Its only
        consumer converts it to a same-origin path in the Next.js server action.
        """

        url = f"{self._base_url}/internal/browser/sessions/{session_id}/live-view"
        client = self._sync_client
        owns_client = client is None
        if client is None:
            client = httpx.Client(
                timeout=httpx.Timeout(20.0, connect=10.0),
                follow_redirects=False,
            )
        try:
            response = client.post(url, headers=self._headers(), timeout=20.0)
        except httpx.RequestError:
            return None
        finally:
            if owns_client:
                client.close()
        if response.status_code >= 400:
            return None
        try:
            payload = response.json()
        except ValueError:
            return None
        mode = payload.get("mode")
        grant_url = payload.get("url")
        expires_at = payload.get("expires_at")
        if mode != "interactive_remote" or not isinstance(grant_url, str):
            return None
        return mode, grant_url, str(expires_at or "")

    async def stop(self, context: BrowserSessionContext) -> None:
        try:
            response = await self._request(
                "DELETE", f"/internal/browser/sessions/{context.session_id}", timeout=60.0
            )
        except httpx.RequestError:
            LOGGER.warning("browser service unreachable while stopping a session")
            return
        if response.status_code >= 400:
            LOGGER.warning("browser service refused session teardown")
            return
        try:
            reason_code = str(response.json().get("reason_code") or "")
        except (AttributeError, ValueError):
            LOGGER.warning("browser service returned an invalid teardown response")
            return
        if reason_code.endswith(":teardown_failed"):
            # Keep local bookkeeping so reconciliation/another stop can retry.
            LOGGER.warning("browser service session teardown remains pending")
            return
        self._sessions.pop(context.session_id, None)

    async def close(self) -> None:
        """Close the owned HTTP client (sessions live on in the service)."""

        if self._client is not None:
            return  # an injected client is owned by the caller
        return

    def provider_session_id(self, handle: str) -> str | None:
        """The service session id IS the durable provider id."""

        return handle if handle in self._sessions or handle else None

    def live_url(self, session_id: str) -> str | None:
        """No durable hosted URL exists for this provider."""

        del session_id
        return None

    async def health(self) -> BrowserServiceHealth:
        """Provider-aware health, including RPC version compatibility."""

        try:
            response = await self._request("GET", "/internal/health", timeout=30.0)
        except httpx.RequestError:
            return BrowserServiceHealth(
                state="unreachable", reason_code="browser_service_unreachable"
            )
        if response.status_code >= 400:
            return BrowserServiceHealth(state="degraded", reason_code=self._reason(response))
        payload = response.json()
        version = str(payload.get("version") or "")
        major = version.split(".", 1)[0] if version else ""
        if major and major.isdigit() and int(major) != SUPPORTED_SERVICE_MAJOR:
            return BrowserServiceHealth(
                state="version_mismatch",
                reason_code=f"service_major_{major}_client_major_{SUPPORTED_SERVICE_MAJOR}",
                version=version,
            )
        state = str(payload.get("state") or "configured_not_verified")
        return BrowserServiceHealth(
            state=state,  # type: ignore[arg-type]
            reason_code=str(payload.get("reason_code") or ""),
            version=version,
            chromium_installed=bool(payload.get("chromium_installed")),
            context_launch_ok=bool(payload.get("context_launch_ok")),
            capacity_total=int(payload.get("capacity_total") or 0),
            capacity_in_use=int(payload.get("capacity_in_use") or 0),
            janitor_running=bool(payload.get("janitor_running")),
        )


# The only credential field names that may cross the RPC boundary. An unknown name
# is refused rather than forwarded, so a new secret cannot be added by accident.
_ALLOWED_BROWSER_SECRET_FIELDS: frozenset[str] = frozenset(
    {"login_email", "login_password", "login_otp", "login_verification_url"}
)


def _vault_references_only(values: Mapping[str, str] | None) -> dict[str, str]:
    """Validate that every credential is an opaque ``vault://`` reference.

    Previously a raw value was silently DROPPED here. That looked safe but broke
    login in a way nobody could diagnose: the service received an empty mapping and
    reported a generic navigation failure, with no indication that credentials had
    been discarded. Raw values are now a typed ERROR, so the caller learns it must
    store a transient reference first.

    An unrecognised field name is likewise refused rather than forwarded.
    """

    if not values:
        return {}
    refs: dict[str, str] = {}
    for name, value in values.items():
        if name not in _ALLOWED_BROWSER_SECRET_FIELDS:
            raise ProviderOperationError(
                capability="browser service secrets",
                reason_code="browser_secret_field_not_allowed",
            )
        if not (isinstance(value, str) and value.startswith("vault://")):
            raise ProviderOperationError(
                capability="browser service secrets",
                reason_code="raw_credentials_not_allowed_over_rpc",
            )
        try:
            refs[name] = validate_vault_reference(value)
        except ValueError:
            raise ProviderOperationError(
                capability="browser service secrets",
                reason_code="malformed_vault_reference",
            ) from None
    return refs


__all__ = [
    "ALLOWED_BROWSER_SECRET_FIELDS",
    "OWNER_HEADER",
    "SUPPORTED_SERVICE_MAJOR",
    "TOKEN_HEADER",
    "BrowserServiceClient",
    "BrowserServiceHealth",
    "ProviderHealthState",
    "ReconcileOutcome",
]

# Public alias for tests and callers that need to know the permitted field set.
ALLOWED_BROWSER_SECRET_FIELDS = _ALLOWED_BROWSER_SECRET_FIELDS
