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

from api.models import (
    ActionReceipt,
    AppResearchResponse,
    AppSearchResponse,
    CreateRunRequest,
    CredentialSubmissionRequest,
    HealthResponse,
    IdempotencyConflictResponse,
    InternalErrorResponse,
    InvalidRequestResponse,
    LiveViewResponse,
    PhaseUnavailableResponse,
    ResourceNotFoundResponse,
    RetryRequest,
    RunConflictResponse,
    RunDetailResponse,
    RunListResponse,
    RunNotFoundResponse,
    RunOutputResponse,
    TimelineResponse,
)
from api.service import (
    AppNotFoundError,
    LocalRunService,
    PhaseUnavailableError,
    RunNotFoundError,
    RunService,
)
from ops.redaction import install_redacting_filter
from ops.run_service import (
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
        "body.company",
        "body.company.legal_name",
        "body.company.website",
        "body.company.work_email_ref",
        "body.company.use_case",
        "body.company.expected_volume",
        "body.company.callback_urls",
        "body.requested_scope_policy",
        "body.dry_run",
        "body.outreach_recipient_override",
        "body.capability",
        "header.idempotency-key",
        "path.run_id",
        "path.app_slug",
        "query.q",
        "query.limit",
        "query.offset",
    }
)


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
    provided = request.headers.get("X-Ops-Internal-Token", "")
    if expected and provided and secrets.compare_digest(provided, expected):
        return None

    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={
            "error": "unauthorized",
            "message": "Internal API token is required.",
        },
        headers={"WWW-Authenticate": "OpsInternalToken"},
    )


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
        install_redacting_filter(LOGGER)
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
        response = _internal_api_auth_response(request)
        if response is None:
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
            409: {"model": IdempotencyConflictResponse},
            422: {"model": InvalidRequestResponse},
            500: {"model": InternalErrorResponse},
        },
    )
    async def create_run(
        payload: CreateRunRequest,
        run_service: ServiceDependency,
        idempotency_key: IdempotencyKeyHeader = None,
    ) -> RunDetailResponse:
        return await run_service.create_run(payload, idempotency_key=idempotency_key)

    def _require_local_owner_submission(request: Request) -> None:
        """Gate credential submission to an opted-in loopback-only owner request."""

        if not _environment_flag("ALLOW_LOCAL_CREDENTIAL_SUBMISSION", default=False):
            raise StarletteHTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="local credential submission is disabled",
            )
        client_host = request.client.host if request.client else None
        if client_host not in {"127.0.0.1", "::1", "localhost", "testclient"}:
            raise StarletteHTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="credential submission is restricted to loopback",
            )

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
        _require_local_owner_submission(request)
        return await run_service.submit_credentials(run_id, payload)

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
    async def resume_run(run_id: RunId, run_service: ServiceDependency) -> ActionReceipt:
        return await run_service.resume(run_id)

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
        # Owner-only, loopback-only. The signed live URL is read from the
        # in-memory worker and is never persisted anywhere.
        _require_local_owner_submission(request)
        return await run_service.get_live_view(run_id)

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
        response_model=ActionReceipt,
        response_model_exclude_none=True,
        responses=common_responses,
    )
    async def retry_run(
        run_id: RunId,
        payload: RetryRequest,
        run_service: ServiceDependency,
    ) -> ActionReceipt:
        return await run_service.retry(run_id, payload.capability)

    @application.get(
        "/api/runs/{run_id}/output",
        response_model=RunOutputResponse,
        response_model_exclude_none=True,
        responses=common_responses,
    )
    async def get_output(run_id: RunId, run_service: ServiceDependency) -> RunOutputResponse:
        return await run_service.get_output(run_id)

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
        "/api/system/health",
        response_model=HealthResponse,
        response_model_exclude_none=True,
        responses={500: {"model": InternalErrorResponse}},
    )
    async def system_health(run_service: ServiceDependency) -> HealthResponse:
        return await run_service.health()

    return application


app = create_app()
