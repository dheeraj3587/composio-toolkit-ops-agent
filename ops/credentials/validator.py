"""Read-only credential validation with exact trusted endpoint policies."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

import httpx

from ops.core.models import validate_https_url, validate_vault_reference
from ops.core.secret_store import SecretStore, SecretStoreError
from ops.providers.errors import ConfigurationRequiredError, PhaseUnavailableError

ValidationStatus = Literal["valid", "invalid", "unavailable", "failed"]
# ``basic_auth`` carries a username plus the secret, so it is the only scheme that
# reads a second credential reference (``username_field``).
ValidationAuthScheme = Literal["bearer", "api_key_header", "basic_auth"]

# On a 2xx response only, at most this many bytes are read to extract a single
# bounded account identifier. The response body itself is never persisted.
_MAX_VALIDATION_BODY_BYTES = 64 * 1024
_MAX_ACCOUNT_IDENTIFIER_LENGTH = 128
# One segment of an identifier path: an optional object key followed by any
# number of list subscripts, so ``data[0]`` and a bare ``tasks`` both parse.
_PATH_SEGMENT = re.compile(r"(?P<key>[^\[\]]*)(?P<indexes>(?:\[\d+\])*)")
_PATH_INDEX = re.compile(r"\[(\d+)\]")


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
    # Literal text placed before the secret in the header value, for providers
    # whose scheme is neither bare nor ``Bearer`` (for example Klaviyo's
    # ``Klaviyo-API-Key <key>``). Applies to ``api_key_header`` only.
    header_value_prefix: str = ""
    # Static, non-secret headers a provider requires alongside the credential
    # (for example an API revision pin). Never used to carry secret material.
    extra_headers: tuple[tuple[str, str], ...] = ()
    # The non-secret username reference for ``basic_auth``, for the providers
    # whose basic pair is two real credentials (DataForSEO's login/password).
    username_field: str | None = None
    # The other two basic-auth shapes, where only ONE side is a credential and
    # the other is a fixed literal the vendor documents: Close sends the key as
    # the username with an EMPTY password, Help Scout with a dummy ``X``, and
    # Mailchimp sends a dummy username with the key as the password. Before these
    # existed such a provider had to be encoded as a second vaulted field that
    # does not exist, or left unvalidated -- which is what actually happened.
    #
    # Both are non-secret by construction: a literal lives in the reviewed
    # catalog, in git, so anything secret is unrepresentable here. Exactly one of
    # these three fields is set for ``basic_auth``, which is what fixes WHICH
    # side the credential occupies rather than leaving it to the caller.
    basic_username_literal: str | None = None
    basic_password_literal: str | None = None
    # ``POST`` exists for providers that publish no readable GET: a GraphQL-only
    # API, or a token mint whose success IS the proof the credentials work. The
    # body is reviewed static text carried verbatim from the recipe; no secret is
    # ever interpolated into it, so a probe that would need one is unbuildable
    # here rather than assembled from a template.
    method: Literal["GET", "POST"] = "GET"
    request_body: str | None = None
    request_content_type: str | None = None

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
        literals = (self.basic_username_literal, self.basic_password_literal)
        if self.auth_scheme == "basic_auth":
            if self.header_name.casefold() != "authorization":
                raise ValueError("basic validation must use the Authorization header")
            if self.username_field is not None and len(self.username_field) > 100:
                raise ValueError("basic validation requires a username field")
            # Exactly one, so the credential's side of the pair is decided by the
            # reviewed policy and never inferred at request time.
            if sum(value is not None for value in (self.username_field, *literals)) != 1:
                raise ValueError("basic validation needs exactly one counterpart")
            for literal in literals:
                if literal is not None and (len(literal) > 100 or ":" in literal):
                    # A colon is the separator basic auth splits on, so a literal
                    # containing one would silently move the boundary.
                    raise ValueError("basic validation literal is invalid")
        elif self.username_field is not None or any(value is not None for value in literals):
            raise ValueError("username field is only valid for basic validation")
        if self.auth_scheme != "api_key_header" and self.header_value_prefix:
            raise ValueError("header value prefix is only valid for api-key validation")
        if len(self.header_value_prefix) > 100 or _has_header_break(self.header_value_prefix):
            raise ValueError("header value prefix is invalid")
        if self.method == "POST":
            if not self.request_body or not self.request_content_type:
                raise ValueError("post validation requires a body and its content type")
        elif self.request_body is not None or self.request_content_type is not None:
            raise ValueError("a validation body is only valid for post validation")
        if self.request_content_type is not None and (
            len(self.request_content_type) > 100 or _has_header_break(self.request_content_type)
        ):
            raise ValueError("validation request media type is invalid")
        if self.request_body is not None and len(self.request_body) > 2_000:
            raise ValueError("validation request body is too long")
        if len(self.extra_headers) > 10:
            raise ValueError("too many static validation headers")
        seen = {self.header_name.casefold(), "accept", "content-type"}
        for name, value in self.extra_headers:
            if (
                not name
                or len(name) > 100
                or len(value) > 200
                or _has_header_break(name)
                or _has_header_break(value)
            ):
                raise ValueError("static validation header is invalid")
            if name.casefold() in seen:
                raise ValueError("static validation header collides with the credential header")
            seen.add(name.casefold())


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
        policy_override: CredentialValidationPolicy | None = None,
    ) -> CredentialValidationResult:
        endpoint = _sanitize_endpoint(read_only_endpoint)
        policy = policy_override or self._policies.get(app_slug)
        if policy is not None and policy.app_slug != app_slug:
            raise PermissionError("validation policy app does not match the run")
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
        username_reference: str | None = None
        if policy.auth_scheme == "basic_auth" and policy.username_field is not None:
            username_reference = credential_refs.get(policy.username_field)
            if username_reference is None:
                return _result(
                    status="invalid",
                    endpoint=endpoint,
                    http_status=None,
                    reason_code="credential_reference_missing",
                )
            validate_vault_reference(username_reference)
        headers: dict[str, str] = {"Accept": "application/json"}
        # Static, non-secret headers first so a provider requirement (such as an
        # API revision pin) can never overwrite the credential header below.
        for extra_name, extra_value in policy.extra_headers:
            headers[extra_name] = extra_value
        try:
            raw_value = self._secret_store.get(reference)
            if policy.auth_scheme == "bearer":
                headers[policy.header_name] = f"Bearer {raw_value}"
            elif policy.auth_scheme == "basic_auth":
                # Which side the credential occupies was decided by the reviewed
                # policy, not here: a second vault reference, a literal username,
                # or a literal password, in that order, exactly one of which the
                # policy guarantees is present.
                if username_reference is not None:
                    raw_username = self._secret_store.get(username_reference)
                    pair = f"{raw_username}:{raw_value}"
                    del raw_username
                elif policy.basic_username_literal is not None:
                    pair = f"{policy.basic_username_literal}:{raw_value}"
                else:
                    pair = f"{raw_value}:{policy.basic_password_literal}"
                encoded = base64.b64encode(pair.encode()).decode("ascii")
                headers[policy.header_name] = f"Basic {encoded}"
                del pair, encoded
            else:
                headers[policy.header_name] = f"{policy.header_value_prefix}{raw_value}"
            del raw_value
            account_identifier: str | None = None
            content: bytes | None = None
            if policy.method == "POST":
                headers["Content-Type"] = policy.request_content_type or ""
                content = (policy.request_body or "").encode()
            try:
                async with self._http_client.stream(
                    policy.method,
                    endpoint,
                    headers=headers,
                    content=content,
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
            if policy.account_identifier_paths and account_identifier is None:
                # A 2xx that named no account did not prove the credential works.
                # Some providers (Jira most notably) answer an unauthenticated or
                # badly-authenticated read with an ANONYMOUS 200 rather than a
                # 401, so "the request succeeded" and "the credential is good" are
                # different facts. Declaring identifier paths is how a policy says
                # which one it needs; a policy that cannot bind the response to an
                # account declares none and keeps the plain 2xx meaning.
                return _result(
                    status="invalid",
                    endpoint=endpoint,
                    http_status=status_code,
                    reason_code="validation_identity_unconfirmed",
                )
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
        policy: CredentialValidationPolicy | None = None,
    ) -> CredentialValidationResult:
        endpoint = (
            policy.allowed_endpoints[0] if policy is not None else self._endpoints.get(app_slug)
        )
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
            policy_override=policy,
        )


def _has_header_break(value: str) -> bool:
    """Reject any value that could split or inject an HTTP header."""

    return "\r" in value or "\n" in value or "\x00" in value


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


def _step(current: Any, part: str) -> Any:
    """Walk one ``key`` or ``key[index]`` segment of an identifier path.

    Index support exists because several providers answer the cheapest identity
    read with a COLLECTION rather than an object -- Klaviyo's ``/api/accounts``
    returns ``data[0].id``, DataForSEO's returns ``tasks[0].result[0].login`` --
    and without it those paths resolve to nothing. That is no longer a harmless
    miss: since a declared path that binds no account now makes the result
    ``invalid``, a path this reader could not follow would turn a working key
    into a reported failure. Out-of-range and non-list values return ``None``,
    which the caller treats the same as an absent key.
    """

    match = _PATH_SEGMENT.fullmatch(part)
    if match is None:
        return None
    key = match.group("key")
    if key:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    for raw_index in _PATH_INDEX.findall(match.group("indexes")):
        index = int(raw_index)
        if not isinstance(current, list) or index >= len(current):
            return None
        current = current[index]
    return current


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
            current = _step(current, part)
            if current is None:
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
