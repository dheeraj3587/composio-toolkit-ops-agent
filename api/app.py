"""FastAPI application factory with an injectable, sanitized service boundary."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, cast

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
    CreateRunRequest,
    HealthResponse,
    IdempotencyConflictResponse,
    InternalErrorResponse,
    InvalidRequestResponse,
    PhaseUnavailableResponse,
    ResourceNotFoundResponse,
    RunDetailResponse,
    RunListResponse,
    RunNotFoundResponse,
    RunOutputResponse,
    TimelineResponse,
)
from api.service import LocalRunService, PhaseUnavailableError, RunNotFoundError, RunService
from ops.redaction import install_redacting_filter
from ops.run_service import IdempotencyConflictError, validate_idempotency_key

LOGGER = logging.getLogger("composio_ops.api")
LOCAL_FRONTEND_ORIGINS = (
    "http://127.0.0.1:3000",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://localhost:5173",
)
RunId = Annotated[
    str,
    ApiPath(min_length=36, max_length=36, pattern=r"^run_[0-9a-f]{32}$"),
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
        "header.idempotency-key",
        "path.run_id",
        "query.limit",
        "query.offset",
    }
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

    application = FastAPI(
        title="Composio Toolkit Ops API",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(LOCAL_FRONTEND_ORIGINS),
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Accept", "Content-Type", "Idempotency-Key"],
        max_age=600,
    )

    @application.middleware("http")
    async def security_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
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

    @application.exception_handler(PhaseUnavailableError)
    async def phase_unavailable_handler(
        request: Request,
        exc: PhaseUnavailableError,
    ) -> JSONResponse:
        del request
        return _model_response(
            PhaseUnavailableResponse(
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
        responses=common_responses,
    )
    async def resume_run(run_id: RunId, run_service: ServiceDependency) -> ActionReceipt:
        return await run_service.resume(run_id)

    @application.post(
        "/api/runs/{run_id}/poll-email",
        response_model=ActionReceipt,
        responses=common_responses,
    )
    async def poll_email(run_id: RunId, run_service: ServiceDependency) -> ActionReceipt:
        return await run_service.poll_email(run_id)

    @application.get(
        "/api/runs/{run_id}/output",
        response_model=RunOutputResponse,
        response_model_exclude_none=True,
        responses=common_responses,
    )
    async def get_output(run_id: RunId, run_service: ServiceDependency) -> RunOutputResponse:
        return await run_service.get_output(run_id)

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
