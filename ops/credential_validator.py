"""Read-only credential validation with exact trusted endpoint policies."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

import httpx

from ops.models import validate_https_url, validate_vault_reference
from ops.provider_errors import ConfigurationRequiredError, PhaseUnavailableError
from ops.secret_store import SecretStore, SecretStoreError

ValidationStatus = Literal["valid", "invalid", "unavailable", "failed"]
ValidationAuthScheme = Literal["bearer", "api_key_header"]

# On a 2xx response only, at most this many bytes are read to extract a single
# bounded account identifier. The response body itself is never persisted.
_MAX_VALIDATION_BODY_BYTES = 64 * 1024
_MAX_ACCOUNT_IDENTIFIER_LENGTH = 128


@dataclass(frozen=True, slots=True)
class CredentialValidationResult:
    """Sanitized validation metadata; response bodies are never represented."""

    status: ValidationStatus
    endpoint: str
    http_status: int | None
    checked_at: str
    reason_code: str
    account_identifier: str | None = None


@dataclass(frozen=True, slots=True)
class CredentialValidationPolicy:
    """App-specific immutable policy supplied by a trusted adapter."""

    app_slug: str
    allowed_endpoints: tuple[str, ...]
    auth_scheme: ValidationAuthScheme
    credential_field: str
    header_name: str = "Authorization"
    # Ordered dotted-path candidates read (bounded) from a 2xx body to derive a
    # single sanitized account identifier. The body is never persisted.
    account_identifier_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.app_slug or not self.allowed_endpoints:
            raise ValueError("validation policy requires an app and endpoint")
        normalized = tuple(_sanitize_endpoint(value) for value in self.allowed_endpoints)
        if len(set(normalized)) != len(normalized):
            raise ValueError("validation endpoints must be unique")
        object.__setattr__(self, "allowed_endpoints", normalized)
        if not self.credential_field or len(self.credential_field) > 100:
            raise ValueError("validation credential field is invalid")
        if (
            not self.header_name
            or len(self.header_name) > 100
            or "\r" in self.header_name
            or "\n" in self.header_name
        ):
            raise ValueError("validation header name is invalid")
        if self.auth_scheme == "bearer" and self.header_name.casefold() != "authorization":
            raise ValueError("bearer validation must use the Authorization header")


class CredentialValidator:
    def __init__(
        self,
        *,
        secret_store: SecretStore | None = None,
        http_client: httpx.AsyncClient | None = None,
        policies: tuple[CredentialValidationPolicy, ...] = (),
    ) -> None:
        self._secret_store = secret_store
        self._http_client = http_client
        self._policies = {policy.app_slug: policy for policy in policies}
        if len(self._policies) != len(policies):
            raise ValueError("credential validation policies must have unique app slugs")

    async def validate(
        self,
        *,
        app_slug: str,
        credential_refs: dict[str, str],
        read_only_endpoint: str,
    ) -> CredentialValidationResult:
        endpoint = _sanitize_endpoint(read_only_endpoint)
        policy = self._policies.get(app_slug)
        if self._secret_store is None or self._http_client is None or policy is None:
            raise ConfigurationRequiredError(
                phase=6,
                capability="credential validation",
                reason_code="trusted_validation_adapter_missing",
            )
        if endpoint not in policy.allowed_endpoints:
            raise PermissionError("validation endpoint is outside the trusted app policy")
        reference = credential_refs.get(policy.credential_field)
        if reference is None:
            return _result(
                status="invalid",
                endpoint=endpoint,
                http_status=None,
                reason_code="credential_reference_missing",
            )
        validate_vault_reference(reference)
        headers: dict[str, str] = {"Accept": "application/json"}
        try:
            raw_value = self._secret_store.get(reference)
            if policy.auth_scheme == "bearer":
                headers[policy.header_name] = f"Bearer {raw_value}"
            else:
                headers[policy.header_name] = raw_value
            del raw_value
            account_identifier: str | None = None
            try:
                async with self._http_client.stream(
                    "GET",
                    endpoint,
                    headers=headers,
                    follow_redirects=False,
                ) as response:
                    status_code = response.status_code
                    if 200 <= status_code < 300 and policy.account_identifier_paths:
                        raw = bytearray()
                        async for chunk in response.aiter_bytes():
                            raw.extend(chunk)
                            if len(raw) >= _MAX_VALIDATION_BODY_BYTES:
                                break
                        account_identifier = _extract_account_identifier(
                            bytes(raw[:_MAX_VALIDATION_BODY_BYTES]),
                            policy.account_identifier_paths,
                        )
                        # The body is intentionally discarded here; only the
                        # bounded, sanitized identifier survives.
            except (httpx.TimeoutException, httpx.NetworkError):
                return _result(
                    status="unavailable",
                    endpoint=endpoint,
                    http_status=None,
                    reason_code="validation_endpoint_unavailable",
                )
            except httpx.HTTPError:
                return _result(
                    status="failed",
                    endpoint=endpoint,
                    http_status=None,
                    reason_code="validation_request_failed",
                )
        except SecretStoreError:
            return _result(
                status="failed",
                endpoint=endpoint,
                http_status=None,
                reason_code="credential_reference_unavailable",
            )
        finally:
            headers.clear()

        if 200 <= status_code < 300:
            return _result(
                status="valid",
                endpoint=endpoint,
                http_status=status_code,
                reason_code="read_only_identity_confirmed",
                account_identifier=account_identifier,
            )
        if status_code in {401, 403}:
            return _result(
                status="invalid",
                endpoint=endpoint,
                http_status=status_code,
                reason_code="provider_rejected_credentials",
            )
        if status_code in {408, 425, 429, 500, 502, 503, 504}:
            return _result(
                status="unavailable",
                endpoint=endpoint,
                http_status=status_code,
                reason_code="provider_temporarily_unavailable",
            )
        return _result(
            status="failed",
            endpoint=endpoint,
            http_status=status_code,
            reason_code="unexpected_validation_status",
        )


# Current documented HubSpot read-only account metadata endpoint. The legacy
# ``/account-info/v3/details`` path is intentionally not used in new code.
HUBSPOT_ACCOUNT_INFO_ENDPOINT = "https://api.hubapi.com/account-info/2026-03/details"

# Current documented Pipedrive read-only identity endpoint. The API token is
# sent in the ``x-api-token`` header (never in the URL), per Pipedrive docs.
PIPEDRIVE_USERS_ME_ENDPOINT = "https://api.pipedrive.com/v1/users/me"


def hubspot_validation_policy() -> CredentialValidationPolicy:
    """Trusted read-only HubSpot bearer policy against the current endpoint."""

    return CredentialValidationPolicy(
        app_slug="hubspot",
        allowed_endpoints=(HUBSPOT_ACCOUNT_INFO_ENDPOINT,),
        auth_scheme="bearer",
        credential_field="access_token",
        account_identifier_paths=("portalId",),
    )


def pipedrive_validation_policy() -> CredentialValidationPolicy:
    """Trusted read-only Pipedrive API-token policy (``x-api-token`` header)."""

    return CredentialValidationPolicy(
        app_slug="pipedrive",
        allowed_endpoints=(PIPEDRIVE_USERS_ME_ENDPOINT,),
        auth_scheme="api_key_header",
        credential_field="api_token",
        header_name="x-api-token",
        account_identifier_paths=("data.company_id", "data.id"),
    )


class PolicyBoundCredentialValidator:
    """Adapt :class:`CredentialValidator` to the app-scoped run-service port.

    The read-only endpoint is fixed per app by a trusted policy, so callers pass
    only ``app_slug`` and vault references. Raw tokens are resolved from the vault
    inside :class:`CredentialValidator` and never handled here.
    """

    def __init__(
        self,
        *,
        validator: CredentialValidator,
        endpoints: dict[str, str],
    ) -> None:
        self._validator = validator
        self._endpoints = {slug: _sanitize_endpoint(url) for slug, url in endpoints.items()}

    async def validate(
        self,
        *,
        app_slug: str,
        credential_refs: dict[str, str],
    ) -> CredentialValidationResult:
        endpoint = self._endpoints.get(app_slug)
        if endpoint is None:
            raise ConfigurationRequiredError(
                phase=6,
                capability="credential validation",
                reason_code="no_read_only_endpoint_for_app",
            )
        return await self._validator.validate(
            app_slug=app_slug,
            credential_refs=credential_refs,
            read_only_endpoint=endpoint,
        )


def _sanitize_endpoint(value: str) -> str:
    validated = validate_https_url(value)
    parsed = urlsplit(validated)
    if parsed.query or parsed.fragment:
        raise ValueError("validation endpoints cannot contain query strings or fragments")
    if parsed.port not in (None, 443):
        raise ValueError("validation endpoints must use the standard HTTPS port")
    hostname = (parsed.hostname or "").casefold().rstrip(".")
    return urlunsplit(("https", hostname, parsed.path or "/", "", ""))


def _result(
    *,
    status: ValidationStatus,
    endpoint: str,
    http_status: int | None,
    reason_code: str,
    account_identifier: str | None = None,
) -> CredentialValidationResult:
    return CredentialValidationResult(
        status=status,
        endpoint=endpoint,
        http_status=http_status,
        checked_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        reason_code=reason_code,
        account_identifier=account_identifier,
    )


def _extract_account_identifier(body: bytes, paths: tuple[str, ...]) -> str | None:
    """Read one bounded scalar id from a JSON body; never return free text.

    Only digits, letters, hyphens, underscores, and dots are kept, capped in
    length. This is a non-sensitive account/tenant identifier (for example a
    Pipedrive ``company_id`` or a HubSpot ``portalId``), not a credential.
    """

    try:
        parsed: Any = json.loads(body.decode("utf-8", errors="strict"))
    except (ValueError, UnicodeDecodeError):
        return None
    for path in paths:
        current: Any = parsed
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                current = None
                break
        if isinstance(current, (str, int)):
            candidate = str(current)
            sanitized = "".join(
                character for character in candidate if character.isalnum() or character in "-_."
            )
            if sanitized:
                return sanitized[:_MAX_ACCOUNT_IDENTIFIER_LENGTH]
    return None


__all__ = [
    "HUBSPOT_ACCOUNT_INFO_ENDPOINT",
    "PIPEDRIVE_USERS_ME_ENDPOINT",
    "CredentialValidationPolicy",
    "CredentialValidationResult",
    "CredentialValidator",
    "PhaseUnavailableError",
    "PolicyBoundCredentialValidator",
    "ValidationAuthScheme",
    "ValidationStatus",
    "hubspot_validation_policy",
    "pipedrive_validation_policy",
]
