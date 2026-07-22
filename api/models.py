"""Strict, frontend-safe request and response contracts."""

from __future__ import annotations

from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from ops.models import OperationalResearch
from ops.state import AccessRoute, RunStatus

VaultReference = Annotated[
    str,
    StringConstraints(
        pattern=r"^vault://[a-z0-9-]+/[a-z0-9_-]+/[A-Za-z0-9_-]+$",
        min_length=12,
        max_length=512,
    ),
]

BoundedHttpUrl = Annotated[
    str,
    StringConstraints(min_length=8, max_length=2048),
]


def _validate_http_url(value: str) -> str:
    """Accept a bounded parsed HTTP URL without embedded credentials."""

    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("URL must not contain whitespace or control characters")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("URL is malformed") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or not hostname:
        raise ValueError("URL must use HTTP or HTTPS and include a host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL must not include user information")
    if parsed.netloc.rsplit("@", 1)[-1].endswith(":"):
        raise ValueError("URL port is malformed")
    return value


class StrictApiModel(BaseModel):
    """Reject contract drift and suppress rejected input values in validation text."""

    model_config = ConfigDict(
        extra="forbid",
        hide_input_in_errors=True,
        strict=True,
        str_strip_whitespace=True,
    )


class CompanyInput(StrictApiModel):
    legal_name: str = Field(min_length=1, max_length=200)
    website: BoundedHttpUrl
    work_email_ref: VaultReference
    use_case: str = Field(min_length=1, max_length=2000)
    expected_volume: str | None = Field(default=None, max_length=200)
    callback_urls: list[BoundedHttpUrl] = Field(default_factory=list, max_length=20)

    @field_validator("website")
    @classmethod
    def website_is_http(cls, value: str) -> str:
        return _validate_http_url(value)

    @field_validator("callback_urls")
    @classmethod
    def callback_urls_are_http(cls, values: list[str]) -> list[str]:
        return [_validate_http_url(value) for value in values]


class CreateRunRequest(StrictApiModel):
    app_name: str = Field(min_length=1, max_length=200)
    company: CompanyInput
    requested_scope_policy: Literal["minimum", "recommended", "maximum"] = "maximum"
    dry_run: Literal[True] = True
    outreach_recipient_override: str | None = Field(default=None, max_length=320)

    @field_validator("outreach_recipient_override")
    @classmethod
    def outreach_override_is_email_safe(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if (
            value.count("@") != 1
            or any(character.isspace() for character in value)
            or any(character in value for character in "<>,;\r\n")
        ):
            raise ValueError("outreach recipient override must be a single email address")
        local_part, domain = value.rsplit("@", 1)
        if not local_part or not domain:
            raise ValueError("outreach recipient override must be a single email address")
        return value


class PhaseState(StrictApiModel):
    key: Literal["research", "browser", "hitl", "email", "output"]
    name: str
    phase: str
    status: Literal["ready", "waiting", "unavailable"]
    detail: str
    available: bool


class SecurityState(StrictApiModel):
    redaction: Literal["enabled"] = "enabled"
    secret_vault: Literal["not_initialized"] = "not_initialized"
    owner_only_storage: Literal["verified_owner_only", "verification_failed"]
    live_vendor_email: Literal["disabled_in_phase_2"] = "disabled_in_phase_2"
    external_actions: Literal[False] = False
    raw_secrets_exposed: Literal[False] = False
    notes: list[str] = Field(default_factory=list)


class RunSummary(StrictApiModel):
    run_id: str
    thread_id: str
    app_name: str
    app_slug: str
    status: RunStatus
    access_route: AccessRoute | None = None
    created_at: str
    updated_at: str
    execution_mode: Literal["local_dry_run", "operations"]
    external_actions: bool


class RunDetailResponse(StrictApiModel):
    run: RunSummary
    research: OperationalResearch | None
    phases: list[PhaseState] | None
    security: SecurityState | None


class RunListResponse(StrictApiModel):
    items: list[RunSummary]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class TimelineEvent(StrictApiModel):
    event_type: str
    summary: str
    status: Literal["recorded", "completed", "blocked", "failed"]
    created_at: str


class TimelineResponse(StrictApiModel):
    run_id: str
    items: list[TimelineEvent]


class ActionReceipt(StrictApiModel):
    run_id: str
    action: Literal["resume", "poll_email"]
    status: Literal["accepted"] = "accepted"


class IntegratorBundleView(StrictApiModel):
    app_name: str
    app_slug: str
    readiness: Literal[
        "credentials_ready",
        "awaiting_provider",
        "human_action_required",
        "blocked",
        "failed",
    ]
    api_type: str
    api_base_url: str | None
    auth_scheme: str
    authorization_url: str | None
    token_url: str | None
    scopes: list[str]
    callback_urls: list[str]
    credential_refs: dict[str, VaultReference]
    access_route: AccessRoute
    evidence_urls: list[str]
    operational_notes: list[str]
    created_at: str


class RunOutputResponse(StrictApiModel):
    run_id: str
    integrator_bundle: IntegratorBundleView


class SnapshotHealth(StrictApiModel):
    verified: bool
    source_repository: str | None = None
    source_commit: str | None = None
    copied_at: str | None = None
    results_sha256: str | None = None
    coverage_sha256: str | None = None


class HealthCheck(StrictApiModel):
    name: str
    status: Literal["pass", "fail"]


class HealthResponse(StrictApiModel):
    status: Literal["healthy", "degraded"]
    phase: Literal["2"] = "2"
    version: Literal["0.1.0"] = "0.1.0"
    snapshot: SnapshotHealth
    checks: list[HealthCheck]


class InvalidRequestResponse(StrictApiModel):
    error: Literal["invalid_request"] = "invalid_request"
    message: Literal["Request validation failed."] = "Request validation failed."
    fields: list[str]


class RunNotFoundResponse(StrictApiModel):
    error: Literal["run_not_found"] = "run_not_found"
    message: Literal["Run was not found."] = "Run was not found."
    run_id: str


class ResourceNotFoundResponse(StrictApiModel):
    error: Literal["not_found"] = "not_found"
    message: Literal["Resource was not found."] = "Resource was not found."


class PhaseUnavailableResponse(StrictApiModel):
    error: Literal["phase_unavailable"] = "phase_unavailable"
    message: Literal["Action is unavailable in the current implementation phase."] = (
        "Action is unavailable in the current implementation phase."
    )
    run_id: str
    action: str
    available_in: list[str] = Field(min_length=1, max_length=8)
    external_actions: Literal[False] = False


class IdempotencyConflictResponse(StrictApiModel):
    error: Literal["idempotency_conflict"] = "idempotency_conflict"
    message: Literal["Idempotency key was already used for another request."] = (
        "Idempotency key was already used for another request."
    )
    external_actions: Literal[False] = False


class InternalErrorResponse(StrictApiModel):
    error: Literal["internal_error"] = "internal_error"
    message: Literal["Request could not be completed."] = "Request could not be completed."
