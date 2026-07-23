"""Strict, frontend-safe request and response contracts."""

from __future__ import annotations

from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    StringConstraints,
    field_validator,
    model_validator,
)

from ops.models import OperationalResearch
from ops.state import AccessRoute, RunStatus

CredentialFieldName = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z0-9][a-z0-9_-]{0,99}$", min_length=1, max_length=100),
]

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
    if parsed.scheme != "https" or not parsed.netloc or not hostname:
        raise ValueError("URL must use HTTPS and include a host")
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
    execution_mode: Literal["plan_only", "execute_when_configured"] = "plan_only"
    # Deprecated compatibility alias for execution_mode="plan_only". Only an
    # explicitly supplied dry_run=true carries intent; execution_mode is the single
    # canonical control and dry_run is never rewritten from it.
    dry_run: bool = True
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

    @model_validator(mode="after")
    def _reject_conflicting_dry_run_alias(self) -> CreateRunRequest:
        # dry_run is a deprecated alias for execution_mode="plan_only". Only an
        # explicitly supplied dry_run=true carries intent, and it must not
        # contradict an explicit execution_mode="execute_when_configured".
        # execution_mode defaults to plan_only and only becomes
        # execute_when_configured when explicitly provided, so no other
        # normalization is required and dry_run is never rewritten.
        dry_run_explicitly_true = "dry_run" in self.model_fields_set and self.dry_run is True
        if dry_run_explicitly_true and self.execution_mode == "execute_when_configured":
            raise ValueError(
                "dry_run=true is a deprecated alias for execution_mode='plan_only' "
                "and cannot be combined with execution_mode='execute_when_configured'"
            )
        return self


class CredentialSubmissionRequest(StrictApiModel):
    """Owner-only credential submission. Raw values are wrapped as ``SecretStr``.

    The values are written straight to the encrypted vault and are never echoed
    in responses, logs, timeline, checkpoints, or the IntegratorBundle.
    """

    company: CompanyInput
    credentials: dict[CredentialFieldName, SecretStr] = Field(min_length=1, max_length=20)


class PhaseState(StrictApiModel):
    key: Literal["research", "browser", "hitl", "email", "output"]
    name: str
    phase: str
    status: Literal[
        "not_started",
        "ready",
        "running",
        "waiting",
        "configuration_required",
        "unavailable",
        "blocked",
        "failed",
        "complete",
    ]
    detail: str
    available: bool


class ProviderState(StrictApiModel):
    provider: Literal["langgraph", "vault", "perplexity", "gemini", "composio", "browser_use"]
    status: Literal[
        "not_configured",
        "disabled",
        "configured_not_verified",
        "ready",
        "schema_incompatible",
    ]
    detail: str


class RouteDecisionView(StrictApiModel):
    route: AccessRoute
    reason_code: str
    explanation: str
    is_final: bool


class HitlRequestView(StrictApiModel):
    action_type: str
    message: str
    expected_completion_signal: str
    resumable: bool


class SecurityState(StrictApiModel):
    redaction: Literal["enabled"] = "enabled"
    secret_vault: Literal[
        "not_configured",
        "configured_not_verified",
        "ready",
    ] = "not_configured"
    owner_only_storage: Literal["verified_owner_only", "verification_failed"]
    live_vendor_email: Literal["disabled", "enabled"] = "disabled"
    live_browser: Literal["disabled", "enabled"] = "disabled"
    external_actions: bool = False
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
    execution_mode: Literal["plan_only", "execute_when_configured"]
    external_actions: bool


class RunDetailResponse(StrictApiModel):
    run: RunSummary
    research: OperationalResearch | None
    phases: list[PhaseState] | None
    security: SecurityState | None
    route_decision: RouteDecisionView | None = None
    missing_fields: list[str] = Field(default_factory=list)
    provider_states: list[ProviderState] = Field(default_factory=list)
    hitl_request: HitlRequestView | None = None


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


class LiveViewResponse(StrictApiModel):
    """Owner-only, loopback-only ephemeral live-view URL.

    This is the single, deliberate place a signed Browser Use live URL crosses
    the API boundary. It is read live from the in-memory worker and is never
    persisted to run state, checkpoints, the ledger, logs, or Git.
    """

    run_id: str
    available: bool
    live_url: str | None = None


class ResumeRequest(StrictApiModel):
    signal: Literal["completed", "cancelled"] = "completed"


class RetryRequest(StrictApiModel):
    capability: Literal["research", "browser", "email", "validation"]


class ActionReceipt(StrictApiModel):
    run_id: str
    action: Literal["resume", "poll_email", "retry"]
    status: Literal["accepted", "configuration_required", "no_change"] = "accepted"
    detail: str | None = None


class IntegratorBundleView(StrictApiModel):
    app_name: str
    app_slug: str
    readiness: Literal[
        "credentials_ready",
        "awaiting_provider",
        "human_action_required",
        "configuration_required",
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
    provider_account_id: str | None = None
    developer_app_id: str | None = None
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
    status: Literal["pass", "fail", "configuration_required", "disabled"]


class HealthResponse(StrictApiModel):
    status: Literal["healthy", "degraded"]
    phase: Literal["2"] = "2"
    version: Literal["0.2.0"] = "0.2.0"
    snapshot: SnapshotHealth
    checks: list[HealthCheck]
    providers: list[ProviderState] = Field(default_factory=list)


class AppSummary(StrictApiModel):
    app_name: str
    app_slug: str
    category: str
    api_type: str
    auth_methods: list[str]
    access_route: AccessRoute
    buildability: str
    verification_status: str
    confidence: float = Field(ge=0.0, le=1.0)


class AppSearchResponse(StrictApiModel):
    query: str
    items: list[AppSummary]
    total: int = Field(ge=0)


class AppResearchResponse(StrictApiModel):
    app: AppSummary
    research: OperationalResearch
    provenance: SnapshotHealth


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
    error: Literal["phase_unavailable", "configuration_required"] = "phase_unavailable"
    message: str = "Action is unavailable in the current runtime configuration."
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


class RunConflictResponse(StrictApiModel):
    error: Literal["run_conflict"] = "run_conflict"
    message: Literal["A competing command is already modifying this run."] = (
        "A competing command is already modifying this run."
    )
    run_id: str
    action: str
    external_actions: Literal[False] = False


class InternalErrorResponse(StrictApiModel):
    error: Literal["internal_error"] = "internal_error"
    message: Literal["Request could not be completed."] = "Request could not be completed."
