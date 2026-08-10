"""FastAPI application factory with an injectable, sanitized service boundary."""

from __future__ import annotations

import logging
import os
import secrets
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, cast
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Header, Query, Request, status
from fastapi import Path as ApiPath
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import AfterValidator, BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response

from api.browser_secret_broker import browser_secret_broker_auth_response
from api.browser_secret_broker import router as browser_secret_broker_router
from api.models import (
    ActionReceipt,
    AdmissionDecisionRequest,
    AdmissionDecisionResponse,
    AppCatalogResponse,
    AppResearchResponse,
    AppSearchResponse,
    CreateRunBatchRequest,
    CreateRunBatchResponse,
    CreateRunRequest,
    CredentialSubmissionRequest,
    HealthResponse,
    IdempotencyConflictResponse,
    InternalErrorResponse,
    InvalidRequestResponse,
    LiveViewResponse,
    ManagedConnectionResponse,
    ManagedKeyConnectionResponse,
    ManagedKeySubmissionRequest,
    ModelCatalogResponse,
    PauseRequest,
    PauseResponse,
    PhaseUnavailableResponse,
    ProviderProfileView,
    ProviderReadinessResponse,
    ProviderState,
    ResetRequest,
    ResetResponse,
    ResourceNotFoundResponse,
    ResumeRequest,
    RetryRequest,
    RetryStepRequest,
    RetryStepResponse,
    RunConflictResponse,
    RunDetailResponse,
    RunListResponse,
    RunNotFoundResponse,
    RunOutputResponse,
    TimelineResponse,
)
from api.service import (
    AppNotFoundError,
    InvalidRequestError,
    LocalRunService,
    PhaseUnavailableError,
    RunNotFoundError,
    RunService,
)
from ops.core.logging_setup import configure_logging
from ops.core.redaction import install_redacting_filter
from ops.runs.errors import ProviderReadinessError
from ops.runs.service import (
    CredentialSubmissionError,
    IdempotencyConflictError,
    RunConflictError,
    validate_idempotency_key,
)

LOGGER = logging.getLogger("composio_ops.api")
RunId = Annotated[
    str,
    ApiPath(min_length=36, max_length=36, pattern=r"^run_[0-9a-f]{32}$"),
]
AppSlug = Annotated[
    str,
    ApiPath(min_length=1, max_length=128, pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$"),
]
IdempotencyKeyHeader = Annotated[
    str | None,
    Header(
        alias="Idempotency-Key",
        min_length=37,
        max_length=37,
        pattern=r"^idem_[0-9a-f]{32}$",
    ),
    AfterValidator(validate_idempotency_key),
]

_KNOWN_VALIDATION_FIELDS = frozenset(
    {
        "body",
        "body.app_name",
        # The batch create's app list (design LL-8.1). Named for the same reason
        # ``body.app_name`` is: a rejected list must say which field was wrong
        # rather than degrading to "unknown_field".
        "body.app_names",
        "body.account_mode",
        "body.company",
        "body.company.legal_name",
        "body.company.website",
        "body.company.work_email_ref",
        "body.company.use_case",
        "body.company.expected_volume",
        "body.company.callback_urls",
        "body.requested_scope_policy",
        "body.dry_run",
        # The run's pinned decision model. Named for the same reason the
        # onboarding control fields are: a rejected model id must say which
        # field was wrong, and both are closed vocabularies — one from the
        # deployment's own catalog, one from the effort ladder.
        "body.decision_model",
        "body.decision_effort",
        "body.capability",
        # The onboarding control bodies (design LL-6.3). Named so a refused
        # control reports which field was wrong instead of degrading to
        # "unknown_field"; every one of them is a closed vocabulary or a digest.
        "body.decision",
        "body.profile_digest",
        "body.idempotency_key",
        "body.expected_phase",
        "body.confirm",
        "body.reason",
        "header.idempotency-key",
        "path.run_id",
        "path.app_slug",
        "query.q",
        "query.limit",
        "query.offset",
    }
)
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# Everything under this prefix is machine-to-machine credential traffic driven by
# the browser worker, so the whole subtree stays behind the acceptance marker.
_ACCEPTANCE_GATED_PREFIXES = ("/internal/browser-secret-broker/",)
# The /api/ routes that exist solely to hand the deployment raw credential
# material. Operator reads and the other operator-initiated writes are admitted
# on an unaccepted release; only credential intake and background automation are
# withheld (background sweeps gate themselves on the same marker in ops/runs).
#
# ``managed-key`` is here for the same reason as ``credentials`` and not because
# of where the secret ends up: it takes custody of an owner's live API key in
# this process, and an unaccepted release must not hold one even briefly. That
# the key is forwarded to Composio rather than kept is irrelevant to this gate.
_CREDENTIAL_INTAKE_SUFFIXES = frozenset({"credentials", "managed-key"})


class DeploymentNotAcceptedError(Exception):
    """A request carrying credential material arrived before release acceptance.

    Raised from inside a handler rather than the middleware, because whether a
    request submits credentials can depend on its body (``browser_login`` on run
    creation and resume), which the middleware must not consume.
    """


def _environment_flag(name: str, *, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    normalized = value.strip().casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise RuntimeError(f"{name} must be true or false")


def _cors_origins() -> list[str]:
    configured = os.environ.get("OPS_CORS_ORIGINS", "")
    origins: list[str] = []
    for item in configured.split(","):
        origin = item.strip().rstrip("/")
        if not origin:
            continue
        # Reuse the request-model URL parser, then require an origin only.
        parsed = urlsplit(origin)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise RuntimeError("OPS_CORS_ORIGINS contains an invalid origin")
        origins.append(origin)
    return sorted(set(origins))


def _internal_api_auth_response(request: Request) -> JSONResponse | None:
    """Require the server-only internal token for every FastAPI API request."""

    if not request.url.path.startswith("/api/"):
        return None

    expected = os.environ.get("OPS_INTERNAL_API_TOKEN", "").strip()
    forbidden = {
        os.environ.get("BROWSER_SERVICE_TOKEN", "").strip(),
        os.environ.get("BROWSER_SESSION_CAPABILITY_KEY", "").strip(),
        os.environ.get("BROWSER_SECRET_BROKER_TOKEN", "").strip(),
    }
    placeholder = any(
        marker in expected.casefold() for marker in ("replace-with", "change-me", "example")
    )
    if len(expected) < 32 or expected in forbidden or placeholder:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "error": "internal_api_unavailable",
                "message": "Internal API authentication is not configured safely.",
            },
        )
    provided = request.headers.get("X-Ops-Internal-Token", "")
    if provided and secrets.compare_digest(provided, expected):
        return None

    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={
            "error": "unauthorized",
            "message": "Internal API token is required.",
        },
        headers={"WWW-Authenticate": "OpsInternalToken"},
    )


def _deployment_is_accepted(request: Request) -> bool:
    """Whether this exact release has been accepted, per the run service."""

    service = getattr(request.app.state, "run_service", None)
    checker = getattr(service, "deployment_mutations_allowed", None)
    if callable(checker):
        try:
            return bool(checker())
        except Exception:
            return False
    # An injected test adapter may omit the optional deployment hook. That is
    # safe only outside production automation mode; a production adapter that
    # cannot prove acceptance must never receive credential material.
    return not _environment_flag("OPS_STARTUP_AUTOMATION_ENABLED", default=False)


def _deployment_not_accepted_response() -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "error": "deployment_not_accepted",
            "message": "Release acceptance is still in progress; retry shortly.",
        },
        headers={"Retry-After": "5"},
    )


def _acceptance_gated_path(request: Request) -> bool:
    """Whether the marker alone decides admission for this path and method.

    Narrow on purpose. A release whose background maintenance is still inert is
    not a release an operator should be locked out of: they must be able to start
    a run, resume it, pause it, and watch its live view. What stays closed is
    credential intake — the broker subtree, and the credential-submission route —
    because an unaccepted deployment must not take custody of a secret.
    """

    path = request.url.path
    if path.startswith(_ACCEPTANCE_GATED_PREFIXES):
        return True
    if request.method not in _MUTATING_METHODS:
        return False
    parts = path.split("/")
    return bool(
        len(parts) == 5
        and parts[1:3] == ["api", "runs"]
        and parts[3]
        and parts[4] in _CREDENTIAL_INTAKE_SUFFIXES
    )


def _deployment_acceptance_response(request: Request) -> JSONResponse | None:
    """Fail closed on credential intake while a production release is pending.

    This is a per-request admission decision. The deploy/restore contract keeps
    acceptance monotonic for a running release and quiesces admission and services
    before changing the marker for rollback, so an admitted mutation cannot race
    a live marker revocation. The read itself is memoized on the marker's on-disk
    identity, so a hot path costs one ``lstat`` rather than an open-and-parse.
    """

    if not _acceptance_gated_path(request):
        return None
    if _deployment_is_accepted(request):
        return None
    return _deployment_not_accepted_response()


def get_run_service(request: Request) -> RunService:
    """Resolve the lifespan-managed service without exposing it as a request parameter."""

    return cast(RunService, request.app.state.run_service)


ServiceDependency = Annotated[RunService, Depends(get_run_service)]


def _model_response(model: BaseModel, *, status_code: int) -> JSONResponse:
    content = model.model_dump(mode="json", exclude_none=True)
    return JSONResponse(status_code=status_code, content=content)


def _validation_fields(exc: RequestValidationError) -> list[str]:
    fields: set[str] = set()
    for error in exc.errors():
        if error.get("type") == "extra_forbidden":
            fields.add("unknown_field")
            continue
        location = error.get("loc", ())
        parts = [str(part) for part in location if not isinstance(part, int)]
        if (
            len(parts) == 2
            and parts[0] == "header"
            and parts[1].lower().replace("_", "-") == "idempotency-key"
        ):
            normalized = "header.idempotency-key"
        else:
            normalized = ".".join(parts)
        fields.add(normalized if normalized in _KNOWN_VALIDATION_FIELDS else "unknown_field")
    return sorted(fields)


def create_app(
    *,
    service: RunService | None = None,
    db_path: str | Path | None = None,
    cors_origins: list[str] | None = None,
    enable_docs: bool | None = None,
) -> FastAPI:
    """Create an API instance; injected services are initialized through lifespan."""

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        active_service = service or LocalRunService(db_path)
        # Give the application a sink before anything else. Until this call
        # there is no handler on the root logger and its level is the stdlib
        # default, so every LOGGER.info below and throughout ops/ is discarded
        # unformatted -- which is why production had four log lines and no way
        # to see why a run failed. The handler carries its own redacting filter,
        # which is what actually covers the composio_ops.* loggers: the loop
        # below attaches filters to loggers, and a logger's filters are not
        # consulted for records that reach a handler by propagation.
        configure_logging()
        # Uvicorn installs its handlers before entering application lifespan.
        # Attach the general redactor now so access/error output receives the
        # same provider-key and credential filtering as application logs.
        for logger in (
            logging.getLogger(),
            LOGGER,
            logging.getLogger("uvicorn"),
            logging.getLogger("uvicorn.error"),
            logging.getLogger("uvicorn.access"),
        ):
            install_redacting_filter(logger)
        await active_service.startup()
        application.state.run_service = active_service
        try:
            yield
        finally:
            await active_service.shutdown()

    docs_enabled = (
        _environment_flag("OPS_ENABLE_API_DOCS", default=False)
        if enable_docs is None
        else enable_docs
    )
    application = FastAPI(
        title="Composio Toolkit Ops API",
        description=(
            "Sanitized control-plane API. Provider payloads, environment values, database paths, "
            "and vault values are never part of the public contract."
        ),
        version="0.2.0",
        lifespan=lifespan,
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
    application.include_router(browser_secret_broker_router)
    application.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins if cors_origins is not None else _cors_origins(),
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Accept", "Content-Type", "Idempotency-Key", "X-Ops-Internal-Token"],
        max_age=600,
    )

    @application.middleware("http")
    async def security_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        auth_response = browser_secret_broker_auth_response(request)
        if auth_response is None:
            auth_response = _internal_api_auth_response(request)
        if auth_response is None:
            auth_response = _deployment_acceptance_response(request)

        response: Response
        if auth_response is not None:
            response = auth_response
        else:
            response = await call_next(request)

        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        if docs_enabled and request.url.path in {"/docs", "/redoc"}:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "img-src 'self' data: https://fastapi.tiangolo.com; "
                "frame-ancestors 'none'; base-uri 'none'"
            )
        else:
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
            )
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

    @application.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        del request
        return _model_response(
            InvalidRequestResponse(fields=_validation_fields(exc)),
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )

    @application.exception_handler(InvalidRequestError)
    async def invalid_request_handler(
        request: Request,
        exc: InvalidRequestError,
    ) -> JSONResponse:
        # The same 422 body a shape failure produces. A field the request model
        # could not judge alone — one that is only valid against this
        # deployment's configuration — is still a rejected field, not a server
        # fault, so it must not surface as a 500.
        del request
        return _model_response(
            InvalidRequestResponse(fields=list(exc.fields)),
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )

    @application.exception_handler(RunNotFoundError)
    async def run_not_found_handler(request: Request, exc: RunNotFoundError) -> JSONResponse:
        del request
        return _model_response(
            RunNotFoundResponse(run_id=exc.run_id),
            status_code=status.HTTP_404_NOT_FOUND,
        )

    @application.exception_handler(AppNotFoundError)
    async def app_not_found_handler(request: Request, exc: AppNotFoundError) -> JSONResponse:
        del request, exc
        return _model_response(
            ResourceNotFoundResponse(),
            status_code=status.HTTP_404_NOT_FOUND,
        )

    @application.exception_handler(PhaseUnavailableError)
    async def phase_unavailable_handler(
        request: Request,
        exc: PhaseUnavailableError,
    ) -> JSONResponse:
        del request
        return _model_response(
            PhaseUnavailableResponse(
                error=exc.error,  # type: ignore[arg-type]
                message=exc.safe_message,
                run_id=exc.run_id,
                action=exc.action,
                available_in=list(exc.available_in),
                reason_code=exc.reason_code,
            ),
            status_code=status.HTTP_409_CONFLICT,
        )

    @application.exception_handler(ProviderReadinessError)
    async def provider_readiness_handler(
        request: Request,
        exc: ProviderReadinessError,
    ) -> JSONResponse:
        del request
        return _model_response(
            ProviderReadinessResponse(
                provider=exc.provider,
                reason_code=exc.reason_code,
            ),
            status_code=status.HTTP_409_CONFLICT,
        )

    @application.exception_handler(IdempotencyConflictError)
    async def idempotency_conflict_handler(
        request: Request,
        exc: IdempotencyConflictError,
    ) -> JSONResponse:
        del request, exc
        return _model_response(
            IdempotencyConflictResponse(),
            status_code=status.HTTP_409_CONFLICT,
        )

    @application.exception_handler(RunConflictError)
    async def run_conflict_handler(
        request: Request,
        exc: RunConflictError,
    ) -> JSONResponse:
        del request
        return _model_response(
            RunConflictResponse(run_id=exc.run_id, action=exc.action),
            status_code=status.HTTP_409_CONFLICT,
        )

    @application.exception_handler(CredentialSubmissionError)
    async def credential_submission_handler(
        request: Request,
        exc: CredentialSubmissionError,
    ) -> JSONResponse:
        del request
        # reason_code is a fixed, non-sensitive internal code (never a value).
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"error": "credential_submission_rejected", "reason_code": exc.reason_code},
        )

    @application.exception_handler(DeploymentNotAcceptedError)
    async def deployment_not_accepted_handler(
        request: Request,
        exc: DeploymentNotAcceptedError,
    ) -> JSONResponse:
        del request, exc
        return _deployment_not_accepted_response()

    @application.exception_handler(StarletteHTTPException)
    async def http_error_handler(
        request: Request,
        exc: StarletteHTTPException,
    ) -> JSONResponse:
        del request
        if exc.status_code == status.HTTP_404_NOT_FOUND:
            return _model_response(
                ResourceNotFoundResponse(),
                status_code=status.HTTP_404_NOT_FOUND,
            )
        return _model_response(
            InternalErrorResponse(),
            status_code=exc.status_code,
        )

    @application.exception_handler(Exception)
    async def internal_error_handler(request: Request, exc: Exception) -> JSONResponse:
        del request
        LOGGER.error("Unhandled API exception type=%s", type(exc).__name__)
        return _model_response(
            InternalErrorResponse(),
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    common_responses: dict[int | str, dict[str, Any]] = {
        404: {"model": RunNotFoundResponse},
        409: {"model": PhaseUnavailableResponse},
        422: {"model": InvalidRequestResponse},
        500: {"model": InternalErrorResponse},
    }

    @application.post(
        "/api/runs",
        response_model=RunDetailResponse,
        status_code=status.HTTP_201_CREATED,
        responses={
            409: {
                "model": IdempotencyConflictResponse | ProviderReadinessResponse,
            },
            422: {"model": InvalidRequestResponse},
            500: {"model": InternalErrorResponse},
        },
    )
    async def create_run(
        payload: CreateRunRequest,
        request: Request,
        run_service: ServiceDependency,
        idempotency_key: IdempotencyKeyHeader = None,
    ) -> RunDetailResponse:
        # Autonomous sign-in credentials at create time are an owner action
        # (same gate as resume-with-browser_login). They are injected into
        # the selected provider's secret boundary. Reusable pairs may be retained
        # only in the encrypted account vault, never in run state or logs.
        if payload.browser_login is not None:
            _require_owner_action(request)
            _require_accepted_deployment(request)
        # ``payload.onboarding`` used to be refused here with
        # ``onboarding_driver_not_wired``, and the refusal was true when it was
        # written: no ``LoopSessionFactory`` existed outside the test fakes, so
        # accepting the flag would have produced a run driven by the canonical
        # runtime while the caller believed it had opted into the phase machine.
        # Both halves now exist -- ``ops.onboarding.browser_session`` binds the
        # session over the browser service and ``ops.onboarding.worker`` pumps the
        # queue -- so the flag is served rather than refused. The route itself
        # stays a pure request: the run service enqueues, the worker drives, and
        # nothing about the create response waits on a browser.
        return await run_service.create_run(payload, idempotency_key=idempotency_key)

    @application.post(
        "/api/runs/batch",
        response_model=CreateRunBatchResponse,
        status_code=status.HTTP_201_CREATED,
        responses={
            422: {"model": InvalidRequestResponse},
            500: {"model": InternalErrorResponse},
        },
    )
    async def create_run_batch(
        payload: CreateRunBatchRequest,
        run_service: ServiceDependency,
        idempotency_key: IdempotencyKeyHeader = None,
    ) -> CreateRunBatchResponse:
        """Create one run per named app under a single reviewed configuration.

        Declared BEFORE ``/api/runs/{run_id}`` would be a routing hazard in a
        framework that matched in declaration order against a path parameter, but
        FastAPI's ``{run_id}`` is constrained by ``RunId``'s pattern and "batch"
        does not satisfy it, so the two cannot collide.

        No ``_require_owner_action`` gate: this model accepts no ``browser_login``
        and no other raw secret, so it carries none of the authority that gate
        exists to protect. The route is otherwise the create route's contract
        repeated N times.

        201 with per-app results even when every app was rejected — the batch was
        processed and each app's outcome is data. Only a malformed batch (422) or
        an infrastructure failure (500) is a transport error.
        """

        return await run_service.create_run_batch(payload, idempotency_key=idempotency_key)

    def _request_carries_internal_token(request: Request) -> bool:
        """True when the request presents the mandatory internal API token.

        The token is already required for every ``/api/`` route by
        ``_internal_api_auth_response``. In the containerized deployment only the
        trusted server-side caller (the Next.js UI) holds it, so a valid token
        identifies the authenticated operator when loopback is not available.
        """

        expected = os.environ.get("OPS_INTERNAL_API_TOKEN", "").strip()
        provided = request.headers.get("X-Ops-Internal-Token", "")
        return bool(expected and provided and secrets.compare_digest(provided, expected))

    def _client_is_loopback(request: Request) -> bool:
        client_host = request.client.host if request.client else None
        return client_host in {"127.0.0.1", "::1", "localhost", "testclient"}

    def _owner_secret_actions_allowed(request: Request) -> bool:
        """Whether this deployment accepts a raw secret, as the SERVICE sees it.

        The raw-secret opt-in has two readers: this gate, and
        ``LocalRunService._primary_action``, which draws the "Submit credentials"
        button from ``Settings.allow_local_credential_submission``. Reading
        ``os.environ`` here was a second statement of the same rule from a
        different source, and the two disagree whenever the service was handed an
        explicit ``Settings`` (any composition that does not go through
        ``load_settings``, including the deployed one if the flag is set in the
        process rather than in ``.env``). The visible symptom is the whole point
        of this gate's rewrite: an enabled button whose route answers 403.

        So ask the live service instead. ``owner_secret_actions_allowed`` is the
        single definition; the route now admits exactly what the button promised.

        The ``getattr`` follows ``deployment_mutations_allowed`` above: an
        injected test adapter may predate the hook, and for those we fall back to
        the process environment, which is the behaviour they were written
        against. A hook that raises is treated as "not allowed" -- this gate
        fails closed, because what it protects is raw credential material.
        """

        service = getattr(request.app.state, "run_service", None)
        checker = getattr(service, "owner_secret_actions_allowed", None)
        if callable(checker):
            try:
                return bool(checker())
            except Exception:
                return False
        return _environment_flag("ALLOW_LOCAL_CREDENTIAL_SUBMISSION", default=False)

    def _require_local_owner_submission(request: Request) -> None:
        """Gate the owner-only endpoints that touch raw credential material.

        Credential submission (and, where present, autonomous browser-login
        injection and raw-credential reveal) stay loopback-only. Raw secrets must
        never traverse the network boundary, so the deployed environment does not
        relax this gate.
        """

        if not _owner_secret_actions_allowed(request):
            raise StarletteHTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="local credential submission is disabled",
            )
        if not _client_is_loopback(request):
            raise StarletteHTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="credential submission is restricted to loopback",
            )

    def _require_accepted_deployment(request: Request) -> None:
        """Refuse credential material carried in a body before release acceptance.

        The path-based gate in the middleware cannot see these: ``browser_login``
        and ``browser_verification`` arrive inside otherwise-ordinary operator
        POSTs, which stay open on an unaccepted release.
        """

        if not _deployment_is_accepted(request):
            raise DeploymentNotAcceptedError

    def _require_owner_action(request: Request) -> None:
        """Gate the routes that carry a RAW SECRET inbound, and only those.

        After the agent/owner split this covers exactly three call sites, all of
        which take a credential in the request body: ``POST /api/runs`` with
        ``browser_login``, ``POST /api/runs/{run_id}/credentials``, and
        ``POST /api/runs/{run_id}/resume`` with ``browser_login`` or
        ``browser_verification``. Nothing else does, which is why nothing else
        is gated here any more -- see :func:`_require_agent_action`.

        These require the explicit opt-in and are then reachable from loopback
        or, in a deployed environment, through the trusted internal-token caller.
        The values cross the selected provider's secret boundary for one resume;
        reusable pairs may remain encrypted in the account vault, and no stored
        secret is ever read back to the network by this path. Endpoints that
        would return raw stored secrets (credential reveal, unimplemented) keep
        the stricter loopback-only :func:`_require_local_owner_submission`.
        """

        if not _owner_secret_actions_allowed(request):
            raise StarletteHTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="owner action is disabled",
            )
        _require_trusted_caller(request)

    def _require_trusted_caller(request: Request) -> None:
        """Admit loopback or the trusted internal-token caller; refuse everything else."""

        if _client_is_loopback(request) or _request_carries_internal_token(request):
            return
        raise StarletteHTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="owner action is restricted",
        )

    def _require_agent_action(request: Request) -> None:
        """Gate the operator controls that carry no credential material at all.

        Connect, poll-connection, outreach, admission decision, pause, reset,
        retry-step, the provider profile and the live view move no secret in
        either direction: their bodies name a run, a phase, or a decision, and
        their responses are closed vocabularies, references and digests.

        They used to sit behind :func:`_require_owner_action`, which additionally
        demands ``ALLOW_LOCAL_CREDENTIAL_SUBMISSION``. That flag authorizes an
        owner to hand the deployment a RAW SECRET, which is a different question
        from whether the operator may press "Connect account", and coupling them
        broke the console: ``ApiService._primary_action`` enables the managed-auth
        button on ``managed_auth_configuration_is_valid`` alone, so all 25
        managed-auth apps rendered an enabled control whose route answered 403.
        A button that is enabled and then refused is worse than a disabled one --
        it reads as a backend fault rather than as configuration.

        The trust boundary is unchanged: loopback, or the internal API token that
        only the server-side UI holds. The live view keeps its own, stricter and
        purpose-built authority on top of this one -- ``live_view_allowed`` is
        revoked the moment a run reaches a credential surface -- which is the
        control that actually protects secret material, rather than a flag named
        for submission.
        """

        _require_trusted_caller(request)

    @application.post(
        "/api/runs/{run_id}/credentials",
        response_model=RunDetailResponse,
        responses=common_responses,
    )
    async def submit_credentials(
        run_id: RunId,
        payload: CredentialSubmissionRequest,
        request: Request,
        run_service: ServiceDependency,
    ) -> RunDetailResponse:
        # Owner-only credential submission. The raw value is written straight to
        # the encrypted vault and never read back, so (like autonomous-login
        # injection) it is authorized by the internal-token owner gate and works
        # in the deployed environment. Raw-secret *readback* (reveal) stays
        # loopback-only.
        _require_owner_action(request)
        return await run_service.submit_credentials(run_id, payload)

    @application.get(
        "/api/models",
        response_model=ModelCatalogResponse,
        responses={500: {"model": InternalErrorResponse}},
    )
    async def get_model_catalog(run_service: ServiceDependency) -> ModelCatalogResponse:
        return await run_service.get_model_catalog()

    @application.get(
        "/api/runs",
        response_model=RunListResponse,
        response_model_exclude_none=True,
        responses={422: {"model": InvalidRequestResponse}, 500: {"model": InternalErrorResponse}},
    )
    async def list_runs(
        run_service: ServiceDependency,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> RunListResponse:
        return await run_service.list_runs(limit=limit, offset=offset)

    @application.get(
        "/api/runs/{run_id}",
        response_model=RunDetailResponse,
        responses=common_responses,
    )
    async def get_run(run_id: RunId, run_service: ServiceDependency) -> RunDetailResponse:
        return await run_service.get_run(run_id)

    @application.get(
        "/api/runs/{run_id}/timeline",
        response_model=TimelineResponse,
        responses=common_responses,
    )
    async def get_timeline(run_id: RunId, run_service: ServiceDependency) -> TimelineResponse:
        return await run_service.get_timeline(run_id)

    @application.post(
        "/api/runs/{run_id}/resume",
        response_model=ActionReceipt,
        response_model_exclude_none=True,
        responses=common_responses,
    )
    async def resume_run(
        run_id: RunId,
        request: Request,
        run_service: ServiceDependency,
        payload: ResumeRequest | None = None,
    ) -> ActionReceipt:
        browser_login = payload.browser_login if payload is not None else None
        browser_verification = payload.browser_verification if payload is not None else None
        signal = payload.signal if payload is not None else "completed"
        if browser_login is not None or browser_verification is not None:
            # Submitting app login credentials for autonomous injection is an
            # owner action. In a deployed environment it is authorized by the
            # internal API token boundary; locally it works over loopback. The
            # raw values cross the selected provider's secret boundary for a single
            # resume. Reusable login pairs may remain only in the encrypted,
            # account-scoped vault; one-time verification values never do.
            _require_owner_action(request)
            _require_accepted_deployment(request)
        return await run_service.resume(
            run_id,
            browser_login=browser_login,
            browser_verification=browser_verification,
            signal=signal,
        )

    @application.post(
        "/api/runs/{run_id}/connect",
        response_model=ManagedConnectionResponse,
        response_model_exclude_none=True,
        responses=common_responses,
    )
    async def connect_managed_run(
        run_id: RunId,
        request: Request,
        run_service: ServiceDependency,
    ) -> ManagedConnectionResponse:
        """Start or replay the run's managed-auth connection request."""

        _require_agent_action(request)
        return await run_service.connect_managed(run_id)

    @application.post(
        "/api/runs/{run_id}/managed-key",
        response_model=ManagedKeyConnectionResponse,
        response_model_exclude_none=True,
        responses=common_responses,
    )
    async def submit_managed_key(
        run_id: RunId,
        payload: ManagedKeySubmissionRequest,
        request: Request,
        run_service: ServiceDependency,
    ) -> ManagedKeyConnectionResponse:
        """Publish an owner-held key to Composio as an active connected account."""

        # The owner-secret gate, not the agent-action gate that guards /connect.
        # The distinction is what the request body carries, not which route kind
        # it serves: /connect asks the deployment to mint a link, while this hands
        # it a live credential, so it belongs with credential submission.
        _require_owner_action(request)
        return await run_service.submit_managed_key(run_id, payload)

    @application.post(
        "/api/runs/{run_id}/poll-connection",
        response_model=ManagedConnectionResponse,
        response_model_exclude_none=True,
        responses=common_responses,
    )
    async def poll_managed_run_connection(
        run_id: RunId,
        request: Request,
        run_service: ServiceDependency,
    ) -> ManagedConnectionResponse:
        """Refresh the stored managed connection request without browser fallback."""

        _require_agent_action(request)
        return await run_service.poll_managed_connection(run_id)

    @application.post(
        "/api/runs/{run_id}/outreach",
        response_model=ActionReceipt,
        response_model_exclude_none=True,
        responses=common_responses,
    )
    async def send_gated_run_outreach(
        run_id: RunId,
        request: Request,
        run_service: ServiceDependency,
    ) -> ActionReceipt:
        """Explicitly send reviewed outreach through the controlled-sink boundary."""

        _require_agent_action(request)
        return await run_service.send_gated_outreach(run_id)

    @application.get(
        "/api/runs/{run_id}/live-view",
        response_model=LiveViewResponse,
        response_model_exclude_none=True,
        responses=common_responses,
    )
    async def live_view(
        run_id: RunId,
        request: Request,
        run_service: ServiceDependency,
    ) -> LiveViewResponse:
        # Read-only ephemeral live URL, for loopback or the trusted internal-token
        # caller. The signed URL is read from the in-memory worker and is never
        # persisted anywhere, and the session's own ``live_view_allowed`` flag --
        # revoked the moment the run reaches a credential surface -- is what
        # withholds it from a page that could show a secret.
        _require_agent_action(request)
        return await run_service.get_live_view(run_id)

    @application.get(
        "/api/runs/{run_id}/live-view/screenshot",
        responses=common_responses,
    )
    async def live_view_screenshot(
        run_id: RunId,
        request: Request,
        run_service: ServiceDependency,
    ) -> Response:
        """Owner-only masked PNG frame for the self-hosted Playwright live view.

        Uses the SAME authorization gate as the live-view endpoint. The image is
        served from worker memory with no-store caching and is never persisted.
        """

        _require_agent_action(request)
        image, captured_at = await run_service.get_live_screenshot(run_id)
        return Response(
            content=image,
            media_type="image/png",
            headers={
                "Cache-Control": "no-store, max-age=0",
                "Pragma": "no-cache",
                "X-Content-Type-Options": "nosniff",
                "X-Captured-At": captured_at,
            },
        )

    @application.post(
        "/api/runs/{run_id}/poll-email",
        response_model=ActionReceipt,
        response_model_exclude_none=True,
        responses=common_responses,
    )
    async def poll_email(run_id: RunId, run_service: ServiceDependency) -> ActionReceipt:
        return await run_service.poll_email(run_id)

    @application.post(
        "/api/runs/{run_id}/retry",
        response_model=ActionReceipt | RetryStepResponse,
        response_model_exclude_none=True,
        responses=common_responses,
    )
    async def retry_run(
        run_id: RunId,
        payload: RetryRequest | RetryStepRequest,
        request: Request,
        run_service: ServiceDependency,
    ) -> ActionReceipt | RetryStepResponse:
        """Retry a legacy capability, or the onboarding run's current step.

        One path, two request shapes, discriminated by the body: the legacy form
        names a capability, and the onboarding form names the phase the operator
        believes the run is standing in. The phase is never a free choice — it is
        an optimistic check, so a client cannot ask for a step whose effect the
        ledger has already completed (design LL-6.3).
        """

        if isinstance(payload, RetryStepRequest):
            _require_agent_action(request)
            return await run_service.retry_onboarding_step(run_id, payload)
        return await run_service.retry(run_id, payload.capability)

    @application.post(
        "/api/runs/{run_id}/decision",
        response_model=AdmissionDecisionResponse,
        response_model_exclude_none=True,
        responses=common_responses,
    )
    async def decide_admission(
        run_id: RunId,
        payload: AdmissionDecisionRequest,
        request: Request,
        run_service: ServiceDependency,
    ) -> AdmissionDecisionResponse:
        """Record the operator's one admission decision (Requirements 3.8, 3.9).

        Owner-gated because account creation is the business decision this whole
        feature refuses to make autonomously. The response is built from the
        durable row, and it carries no credential reference.
        """

        _require_agent_action(request)
        return await run_service.decide_admission(run_id, payload)

    @application.post(
        "/api/runs/{run_id}/pause",
        response_model=PauseResponse,
        response_model_exclude_none=True,
        responses=common_responses,
    )
    async def pause_run(
        run_id: RunId,
        request: Request,
        run_service: ServiceDependency,
        payload: PauseRequest | None = None,
    ) -> PauseResponse:
        """Stop the run at its next safe boundary, keeping the browser session."""

        _require_agent_action(request)
        return await run_service.pause_onboarding(
            run_id,
            reason=payload.reason if payload is not None else None,
        )

    @application.post(
        "/api/runs/{run_id}/reset",
        response_model=ResetResponse,
        response_model_exclude_none=True,
        responses=common_responses,
    )
    async def reset_run(
        run_id: RunId,
        payload: ResetRequest,
        request: Request,
        run_service: ServiceDependency,
    ) -> ResetResponse:
        """Restart the walk at research. Never destroys a vault reference.

        ``confirm: true`` is required by the request model, so an unconfirmed reset
        is refused as a validation error before any session is released
        (Requirement 14.12).
        """

        _require_agent_action(request)
        return await run_service.reset_onboarding(run_id, confirm=payload.confirm)

    @application.get(
        "/api/runs/{run_id}/profile",
        response_model=ProviderProfileView,
        response_model_exclude_none=True,
        responses=common_responses,
    )
    async def get_provider_profile(
        run_id: RunId,
        request: Request,
        run_service: ServiceDependency,
    ) -> ProviderProfileView:
        """The sanitized provider profile: citations and hosts, never excerpts."""

        _require_agent_action(request)
        return await run_service.get_provider_profile(run_id)

    @application.get(
        "/api/runs/{run_id}/output",
        response_model=RunOutputResponse,
        response_model_exclude_none=True,
        responses=common_responses,
    )
    async def get_output(run_id: RunId, run_service: ServiceDependency) -> RunOutputResponse:
        return await run_service.get_output(run_id)

    @application.get(
        "/api/apps",
        response_model=AppCatalogResponse,
        response_model_exclude_none=True,
        responses={500: {"model": InternalErrorResponse}},
    )
    async def list_apps(run_service: ServiceDependency) -> AppCatalogResponse:
        """Every verified app, so the UI can offer a selector instead of a guess.

        Declared BEFORE /api/apps/search so the static path is matched first.
        """

        return await run_service.list_apps()

    @application.get(
        "/api/apps/search",
        response_model=AppSearchResponse,
        response_model_exclude_none=True,
        responses={422: {"model": InvalidRequestResponse}, 500: {"model": InternalErrorResponse}},
    )
    async def search_apps(
        run_service: ServiceDependency,
        q: Annotated[str, Query(min_length=0, max_length=200)] = "",
    ) -> AppSearchResponse:
        return await run_service.search_apps(q)

    @application.get(
        "/api/apps/{app_slug}/research",
        response_model=AppResearchResponse,
        responses={
            404: {"model": ResourceNotFoundResponse},
            422: {"model": InvalidRequestResponse},
            500: {"model": InternalErrorResponse},
        },
    )
    async def app_research(
        app_slug: AppSlug,
        run_service: ServiceDependency,
    ) -> AppResearchResponse:
        return await run_service.get_app_research(app_slug)

    @application.get(
        "/api/system/signup-readiness",
        response_model=ProviderState,
        response_model_exclude_none=True,
        responses={500: {"model": InternalErrorResponse}},
    )
    async def signup_readiness(run_service: ServiceDependency) -> ProviderState:
        return await run_service.signup_readiness()

    @application.get(
        "/api/system/health",
        response_model=HealthResponse,
        response_model_exclude_none=True,
        responses={500: {"model": InternalErrorResponse}},
    )
    async def system_health(run_service: ServiceDependency) -> HealthResponse:
        return await run_service.health()

    return application


app = create_app()
