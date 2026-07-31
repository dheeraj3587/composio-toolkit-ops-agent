"""Narrow contracts and sanitized failures for the browser secret broker.

This is intentionally not a general vault API.  The isolated browser may:

* atomically consume one exact, run-scoped transient login secret; or
* write one reviewed captured credential and receive only its opaque reference.

There is no durable read, list, delete, or arbitrary-reference endpoint.
"""

from __future__ import annotations

import logging
import os
import re
import secrets
from typing import Any

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from starlette.concurrency import run_in_threadpool

from browser_service.auth import OWNER_HEADER
from ops.browser.session_capability import (
    CAPABILITY_HEADER,
    BrowserSessionCapabilityError,
    derive_browser_session_capability,
    validate_capability_owner,
)
from ops.core.secret_store import BrowserSecretGrantError
from ops.credentials.capture_specs import CredentialCaptureSpec
from ops.onboarding.capture_specs import (
    CaptureContractUnavailable,
    profile_capture_contract,
)
from ops.recipes.app_recipes import get_app_capture_spec

LOGGER = logging.getLogger("composio_ops.browser_secret_broker")

_APP_SLUG_PATTERN = r"^[a-z0-9]+(?:-[a-z0-9]+)*$"
_KIND_PATTERN = r"^[a-z0-9][a-z0-9_-]{0,99}$"
_RUN_SCOPE_PATTERN = r"^run_[0-9a-f]{32}$"
_SESSION_ID_PATTERN = r"^bs_[0-9a-f]{32}$"
_BROKER_GRANT_PATTERN = r"^bsg_[A-Za-z0-9_-]{43}$"
_VAULT_REFERENCE_PATTERN = (
    r"^vault://[a-z0-9]+(?:-[a-z0-9]+)*/"
    r"[a-z0-9][a-z0-9_-]{0,99}/[A-Za-z0-9_-]{8,200}$"
)
_ALLOWED_TRANSIENT_KINDS = frozenset(
    {
        "browser_login_login_email",
        "browser_login_login_password",
        "browser_login_login_otp",
        "browser_login_login_verification_url",
    }
)


class _BrokerModel(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class BrowserSecretConsumeRequest(_BrokerModel):
    grant: str = Field(min_length=47, max_length=47, pattern=_BROKER_GRANT_PATTERN, repr=False)
    reference: str = Field(min_length=24, max_length=512, pattern=_VAULT_REFERENCE_PATTERN)
    app_slug: str = Field(min_length=1, max_length=128, pattern=_APP_SLUG_PATTERN)
    kind: str = Field(min_length=1, max_length=100, pattern=_KIND_PATTERN)
    scope_id: str = Field(min_length=36, max_length=36, pattern=_RUN_SCOPE_PATTERN)
    session_id: str = Field(min_length=35, max_length=35, pattern=_SESSION_ID_PATTERN)


class BrowserSecretConsumeResponse(_BrokerModel):
    # A plain string is required for JSON serialization. repr=False prevents an
    # accidental model repr from including it in diagnostics.
    value: str = Field(min_length=1, max_length=32_768, repr=False)


class BrowserCredentialCaptureRequest(_BrokerModel):
    grant: str = Field(min_length=47, max_length=47, pattern=_BROKER_GRANT_PATTERN, repr=False)
    app_slug: str = Field(min_length=1, max_length=128, pattern=_APP_SLUG_PATTERN)
    kind: str = Field(min_length=1, max_length=100, pattern=_KIND_PATTERN)
    scope_id: str = Field(min_length=36, max_length=36, pattern=_RUN_SCOPE_PATTERN)
    session_id: str = Field(min_length=35, max_length=35, pattern=_SESSION_ID_PATTERN)
    value: SecretStr = Field(min_length=1, max_length=32_768, repr=False)


class BrowserCredentialCaptureResponse(_BrokerModel):
    reference: str = Field(min_length=24, max_length=512, pattern=_VAULT_REFERENCE_PATTERN)


class BrowserSecretBrokerError(RuntimeError):
    """Base class whose reason code is safe to return across the broker RPC."""

    reason_code = "browser_secret_broker_failed"

    def __init__(self) -> None:
        super().__init__(self.reason_code)


class BrowserSecretBrokerUnavailable(BrowserSecretBrokerError):
    reason_code = "browser_secret_broker_unavailable"


class BrowserSecretUnavailable(BrowserSecretBrokerError):
    # Deliberately folds absent, expired, already-consumed and binding mismatch
    # into one response so the endpoint cannot be used as a reference oracle.
    reason_code = "browser_secret_unavailable"


class BrowserCaptureNotAuthorized(BrowserSecretBrokerError):
    reason_code = "browser_capture_not_authorized"


def browser_secret_broker_auth_response(request: Request) -> JSONResponse | None:
    """Authenticate only broker routes with their independent capability token."""

    if not request.url.path.startswith("/internal/browser-secret-broker/"):
        return None
    expected = os.environ.get("BROWSER_SECRET_BROKER_TOKEN", "").strip()
    forbidden = {
        os.environ.get("OPS_INTERNAL_API_TOKEN", "").strip(),
        os.environ.get("BROWSER_SERVICE_TOKEN", "").strip(),
        os.environ.get("BROWSER_SESSION_CAPABILITY_KEY", "").strip(),
    }
    placeholder = any(
        marker in expected.casefold() for marker in ("replace-with", "change-me", "example")
    )
    if len(expected) < 32 or expected in forbidden or placeholder:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"error": BrowserSecretBrokerUnavailable.reason_code},
        )
    provided = request.headers.get("X-Browser-Secret-Broker-Token", "")
    if provided and secrets.compare_digest(provided, expected):
        return None
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"error": "unauthorized"},
        headers={"WWW-Authenticate": "BrowserSecretBrokerToken"},
    )


def _core_and_store(service: Any) -> tuple[Any, Any]:
    core = getattr(service, "_service", None)
    store = getattr(core, "_secret_store", None)
    if core is None or store is None:
        raise BrowserSecretBrokerUnavailable
    return core, store


def _run_capability_authorized(request: Request, *, scope_id: str) -> bool:
    key = os.environ.get("BROWSER_SESSION_CAPABILITY_KEY", "").strip()
    owner = request.headers.get(OWNER_HEADER, "").strip()
    provided = request.headers.get(CAPABILITY_HEADER, "")
    try:
        normalized_owner = validate_capability_owner(owner)
        expected = derive_browser_session_capability(
            key=key,
            owner=normalized_owner,
            scope=scope_id,
        )
    except BrowserSessionCapabilityError:
        return False
    return bool(provided and secrets.compare_digest(provided, expected))


def _bound_active_run(
    core: Any,
    *,
    scope_id: str,
    app_slug: str,
    session_id: str,
    capture: bool,
) -> dict[str, object]:
    # ``RunService.get_run`` is intentionally a public projection and omits the
    # browser session and side-effect identity. Broker authorization must instead
    # read the authoritative row; otherwise it can neither prove the binding nor
    # distinguish a delayed callback from the currently active operation.
    storage = getattr(core, "storage", None)
    get_authoritative_run = getattr(storage, "get_run", None)
    if not callable(get_authoritative_run):
        raise BrowserCaptureNotAuthorized if capture else BrowserSecretUnavailable
    record = get_authoritative_run(scope_id)
    if not isinstance(record, dict):
        raise BrowserCaptureNotAuthorized if capture else BrowserSecretUnavailable
    active = record.get("status") == "browser_running"
    bound = (
        record.get("run_id") == scope_id
        and record.get("app_slug") == app_slug
        and record.get("state_engine") == "canonical_v1"
        and record.get("browser_provider") == "playwright"
        and record.get("browser_session_id") == session_id
        and record.get("execution_mode") == "operations"
        and active
    )
    # Credential capture is a separately reserved side effect. Requiring this
    # durable phase means possession of the worker-wide broker token and an
    # unrelated active run are still insufficient to write a vault entry.
    expected_phase = "credential_capture_reserved" if capture else "authentication_submitted"
    bound = bound and record.get("phase") == expected_phase
    if not bound:
        raise BrowserCaptureNotAuthorized if capture else BrowserSecretUnavailable
    return record


def _current_operation_key(
    record: dict[str, object],
    *,
    action: str,
    kind: str,
) -> str:
    effect_identity = record.get("effect_identity")
    if not isinstance(effect_identity, str) or not effect_identity:
        raise BrowserCaptureNotAuthorized if action == "capture" else BrowserSecretUnavailable
    field = kind.removeprefix("browser_login_") if action == "consume" else kind
    return f"{effect_identity}:{action}:{field}"


def _consume_sync(
    service: Any,
    payload: BrowserSecretConsumeRequest,
    *,
    authorized: bool,
) -> str:
    if not authorized:
        raise BrowserSecretUnavailable
    if payload.kind not in _ALLOWED_TRANSIENT_KINDS:
        raise BrowserSecretUnavailable
    core, store = _core_and_store(service)
    lock_factory = getattr(core, "_run_lock", None)
    if not callable(lock_factory):
        raise BrowserSecretUnavailable
    lock = lock_factory(payload.scope_id)
    if not lock.acquire(timeout=5):
        raise BrowserSecretUnavailable
    try:
        record = _bound_active_run(
            core,
            scope_id=payload.scope_id,
            app_slug=payload.app_slug,
            session_id=payload.session_id,
            capture=False,
        )
        operation_key = _current_operation_key(
            record,
            action="consume",
            kind=payload.kind,
        )
        try:
            return str(
                store.consume_transient_with_grant(
                    payload.grant,
                    payload.reference,
                    expected_app_slug=payload.app_slug,
                    expected_kind=payload.kind,
                    expected_scope_id=payload.scope_id,
                    expected_session_id=payload.session_id,
                    expected_operation_key=operation_key,
                )
            )
        except BrowserSecretGrantError:
            raise BrowserSecretUnavailable from None
    finally:
        lock.release()


def _resolve_capture_spec(
    core: Any,
    payload: BrowserCredentialCaptureRequest,
) -> CredentialCaptureSpec:
    """Reviewed recipe first; otherwise the run's profile-derived contract.

    PRE:  ``payload.scope_id`` names a run of this owner. The stronger
          precondition — that the run is active and bound to
          ``payload.session_id`` — is re-proved under the run lock by
          :func:`_bound_active_run` before anything is written.
    POST: returns a contract whose ``value_pattern`` came from CHECKED-IN code
          and whose ``url`` / ``vendor_domain`` came from either a reviewed
          recipe or the run's immutable profile, or raises
          :class:`BrowserCaptureNotAuthorized`. Research never supplies a
          pattern.

    A checked-in recipe is the stronger authority, so it stays first. The
    profile contract is the runtime stand-in for the providers that have no
    reviewed recipe — every brand-new provider — which is exactly the set that
    used to be refused here because ``get_app_capture_spec`` returned ``None``.
    """

    reviewed = get_app_capture_spec(payload.app_slug)
    if reviewed is not None:
        return reviewed
    try:
        return profile_capture_contract(core, run_id=payload.scope_id, kind=payload.kind)
    except CaptureContractUnavailable as exc:
        # The orchestrator pauses the run on ``exc.reason_code``; the broker's
        # response vocabulary does not grow a third code. ``detail`` is closed
        # and carries no provider string, page text, or credential material, so
        # it is safe next to the run id and is the only diagnosable trace.
        LOGGER.warning(
            "browser capture contract unavailable",
            extra={"run_id": payload.scope_id, "detail": exc.detail},
        )
        raise BrowserCaptureNotAuthorized from None


def _capture_sync(
    service: Any,
    payload: BrowserCredentialCaptureRequest,
    *,
    authorized: bool,
) -> str:
    if not authorized:
        raise BrowserCaptureNotAuthorized
    core, store = _core_and_store(service)
    spec = _resolve_capture_spec(core, payload)
    # The requested kind must be one the reviewed contract declares; a contract
    # that declares no pattern for it authorizes nothing.
    field = spec.field(payload.kind)
    if field is None:
        raise BrowserCaptureNotAuthorized
    value = payload.value.get_secret_value()
    if re.fullmatch(field.value_pattern, value) is None:
        # The worker is trusted to transport a reviewed capture, not to redefine
        # its format. Re-apply the recipe's exact value contract at the API/vault
        # boundary so a compromised worker cannot persist arbitrary material.
        raise BrowserCaptureNotAuthorized
    lock_factory = getattr(core, "_run_lock", None)
    if not callable(lock_factory):
        raise BrowserCaptureNotAuthorized
    lock = lock_factory(payload.scope_id)
    if not lock.acquire(timeout=5):
        raise BrowserCaptureNotAuthorized
    try:
        record = _bound_active_run(
            core,
            scope_id=payload.scope_id,
            app_slug=payload.app_slug,
            session_id=payload.session_id,
            capture=True,
        )
        operation_key = _current_operation_key(
            record,
            action="capture",
            kind=payload.kind,
        )
        try:
            return str(
                store.capture_with_grant(
                    payload.grant,
                    app_slug=payload.app_slug,
                    kind=payload.kind,
                    scope_id=payload.scope_id,
                    session_id=payload.session_id,
                    value=value,
                    expected_operation_key=operation_key,
                )
            )
        except BrowserSecretGrantError:
            raise BrowserCaptureNotAuthorized from None
    finally:
        lock.release()


router = APIRouter(prefix="/internal/browser-secret-broker", include_in_schema=False)


@router.post("/consume", response_model=BrowserSecretConsumeResponse)
async def consume_browser_secret(
    payload: BrowserSecretConsumeRequest,
    request: Request,
) -> BrowserSecretConsumeResponse | JSONResponse:
    try:
        value = await run_in_threadpool(
            _consume_sync,
            request.app.state.run_service,
            payload,
            authorized=_run_capability_authorized(request, scope_id=payload.scope_id),
        )
    except BrowserSecretBrokerError as exc:
        code = (
            status.HTTP_503_SERVICE_UNAVAILABLE
            if isinstance(exc, BrowserSecretBrokerUnavailable)
            else status.HTTP_409_CONFLICT
        )
        return JSONResponse(status_code=code, content={"error": exc.reason_code})
    return BrowserSecretConsumeResponse(value=value)


@router.post("/capture", response_model=BrowserCredentialCaptureResponse)
async def capture_browser_credential(
    payload: BrowserCredentialCaptureRequest,
    request: Request,
) -> BrowserCredentialCaptureResponse | JSONResponse:
    try:
        reference = await run_in_threadpool(
            _capture_sync,
            request.app.state.run_service,
            payload,
            authorized=_run_capability_authorized(request, scope_id=payload.scope_id),
        )
    except BrowserSecretBrokerError as exc:
        code = (
            status.HTTP_503_SERVICE_UNAVAILABLE
            if isinstance(exc, BrowserSecretBrokerUnavailable)
            else status.HTTP_403_FORBIDDEN
        )
        return JSONResponse(status_code=code, content={"error": exc.reason_code})
    return BrowserCredentialCaptureResponse(reference=reference)


__all__ = [
    "BrowserCaptureNotAuthorized",
    "BrowserCredentialCaptureRequest",
    "BrowserCredentialCaptureResponse",
    "BrowserSecretBrokerError",
    "BrowserSecretBrokerUnavailable",
    "BrowserSecretConsumeRequest",
    "BrowserSecretConsumeResponse",
    "BrowserSecretUnavailable",
    "browser_secret_broker_auth_response",
    "router",
]
