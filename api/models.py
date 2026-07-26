"""Strict, frontend-safe request and response contracts."""

from __future__ import annotations

import re
from typing import Annotated, Literal
from urllib.parse import parse_qsl, urlsplit

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
from ops.state import AccessRoute, BrowserProvider, CredentialCreationPolicy, RunStatus

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

# How the owner can watch (and possibly drive) a live browser session.
LiveViewMode = Literal["hosted_url", "screenshot", "interactive_remote", "unavailable"]

# A bounded, same-origin RELATIVE viewer path. Deliberately not a URL type: the
# private browser-service/noVNC address must never cross the API boundary, so an
# absolute URL (of any host) is rejected by construction.
RelativeViewerPath = Annotated[
    str,
    StringConstraints(
        pattern=r"^/api/runs/[A-Za-z0-9_-]{1,180}/live-view/(?:screenshot|interactive)$",
        min_length=1,
        max_length=300,
    ),
]

# Private, one-use projection from browser-worker to the Next.js SERVER. The
# server converts this exact address to the same-origin Caddy path; browser client
# state must never retain this absolute URL.
InteractiveGrantUrl = Annotated[
    str,
    StringConstraints(min_length=32, max_length=2300),
]

# A sanitized, value-free explanation code (never provider or page text).
ReasonCode = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z0-9][a-z0-9_:-]{0,63}$", min_length=1, max_length=64),
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


class BrowserLoginInput(StrictApiModel):
    """Owner-submitted app login credentials for autonomous sign-in.

    The values cross the selected provider's secret boundary only for session
    creation or one resume call and are never persisted to run state,
    checkpoints, audit events, logs, or the IntegratorBundle.
    OTP/CAPTCHA/passkey/billing still require a human.
    """

    email: SecretStr
    password: SecretStr


class CreateRunRequest(StrictApiModel):
    app_name: str = Field(min_length=1, max_length=200)
    company: CompanyInput
    requested_scope_policy: Literal["minimum", "recommended", "maximum"] = "maximum"
    execution_mode: Literal["plan_only", "execute_when_configured"] = "plan_only"
    browser_provider: BrowserProvider = "browser_use"
    credential_creation_policy: CredentialCreationPolicy = "reuse_only"
    # Deprecated compatibility alias for execution_mode="plan_only". Only an
    # explicitly supplied dry_run=true carries intent; execution_mode is the single
    # canonical control and dry_run is never rewritten from it.
    dry_run: bool = True
    outreach_recipient_override: str | None = Field(default=None, max_length=320)
    # Optional app sign-in credentials for autonomous login. When present they are
    # injected through the selected provider's secret boundary at session
    # creation; they are never persisted to run state, checkpoints, the ledger,
    # logs, or the IntegratorBundle.
    browser_login: BrowserLoginInput | None = None

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
    provider: Literal[
        "langgraph",
        "vault",
        "perplexity",
        "gemini",
        "composio",
        "browser_use",
        # The self-hosted harness reports under its own identity so a Playwright
        # deployment is never described as Browser Use.
        "playwright",
    ]
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
    checkpoint_encryption: Literal["ready", "not_configured"] = "not_configured"
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
    browser_provider: BrowserProvider
    credential_creation_policy: CredentialCreationPolicy
    external_actions: bool


# The browser session's observable lifecycle, as the backend actually recorded it.
BrowserLifecycle = Literal[
    "not_started",
    "running",
    "waiting_for_hitl",
    "credential_page_ready",
    "failed",
    "session_lost",
    "unavailable",
]


class BrowserUiState(StrictApiModel):
    """Backend-authoritative browser capabilities for one run.

    The interface must not infer what it may do from ``run.status``: whether a
    credential can be submitted, whether a resume is legal, and whether the view is
    interactive all depend on provider capability, trusted recorded events, and
    policy opt-ins that only the backend can see. Every boolean here is a decision,
    not a hint, and each one is false unless the backend can prove otherwise.
    """

    provider: BrowserProvider
    lifecycle: BrowserLifecycle
    live_view_mode: LiveViewMode

    # Viewing capabilities.
    live_view_available: bool = False
    interaction_available: bool = False
    screenshot_available: bool = False

    # Trusted progress: set only by a recorded credential_page_ready event.
    credential_page_verified: bool = False

    # Mutation capabilities. Each requires the matching backend surface to exist.
    can_submit_login: bool = False
    can_submit_otp: bool = False
    can_resume: bool = False
    can_submit_credential: bool = False

    reason_code: ReasonCode | None = None


class RunDetailResponse(StrictApiModel):
    run: RunSummary
    research: OperationalResearch | None
    phases: list[PhaseState] | None
    security: SecurityState | None
    route_decision: RouteDecisionView | None = None
    missing_fields: list[str] = Field(default_factory=list)
    provider_states: list[ProviderState] = Field(default_factory=list)
    hitl_request: HitlRequestView | None = None
    # Explicit browser permissions. Optional for contract compatibility with
    # existing clients, but always populated by this API.
    browser: BrowserUiState | None = None


class RunListResponse(StrictApiModel):
    items: list[RunSummary]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class TimelineEvent(StrictApiModel):
    event_id: int = Field(gt=0)
    event_type: str
    summary: str
    status: Literal["recorded", "completed", "blocked", "failed"]
    created_at: str


class TimelineResponse(StrictApiModel):
    run_id: str
    items: list[TimelineEvent]


class LiveViewResponse(StrictApiModel):
    """Owner-only, loopback-only ephemeral live view.

    This is the single, deliberate place a signed live-session URL crosses the API
    boundary. It is read live from the in-memory worker and is never persisted to
    run state, checkpoints, the ledger, logs, or Git.

    ``provider`` and ``mode`` are ALWAYS present so a client renders what the wired
    backend actually offers instead of assuming a hosted URL:

    * ``hosted_url`` — a hosted provider (Browser Use) supplies a signed
      ``live_url``, which the owner can interact with directly.
    * ``screenshot`` — the self-hosted Playwright harness has no hosted URL, so the
      client polls ``screenshot_url`` for masked PNG frames. Frames are viewable
      but not interactive, so ``interaction_available`` is False.
    * ``interactive_remote`` — an exact, short-lived private grant consumed by the
      Next.js server and converted to the reviewed same-origin viewer path.
    * ``unavailable`` — no viewer exists, so no viewer URL may be present.

    ``screenshot_url`` is a bounded same-origin API path. ``interactive_url`` is
    allowed only for the exact private browser-worker relay and a bounded signed
    session/token query; it is never durable or logged.
    """

    run_id: str
    provider: BrowserProvider
    available: bool
    mode: LiveViewMode = "unavailable"
    live_url: str | None = None
    screenshot_url: RelativeViewerPath | None = None
    interactive_url: InteractiveGrantUrl | None = None
    captured_at: str | None = None
    # Whether the owner can actually drive the browser through this view.
    interaction_available: bool = False
    reason_code: ReasonCode | None = None

    @field_validator("live_url")
    @classmethod
    def live_url_is_hosted_https(cls, value: str | None) -> str | None:
        """A hosted live URL is absolute HTTPS; its signed query is left intact."""

        return _validate_http_url(value) if value is not None else None

    @field_validator("interactive_url")
    @classmethod
    def interactive_url_is_exact_private_grant(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value):
            raise ValueError("interactive grant contains invalid characters")
        try:
            parsed = urlsplit(value)
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
        except ValueError as exc:
            raise ValueError("interactive grant is malformed") from exc
        if (
            parsed.scheme != "http"
            or parsed.netloc != "browser-worker:8081"
            or parsed.path != "/internal/browser/live-view/novnc"
            or parsed.fragment
            or len(pairs) != 2
        ):
            raise ValueError("interactive grant target is not approved")
        query = dict(pairs)
        session = query.get("session", "")
        token = query.get("token", "")
        if (
            set(query) != {"session", "token"}
            or re.fullmatch(r"[A-Za-z0-9_-]{1,180}", session) is None
            or len(token) > 2048
            or re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token) is None
        ):
            raise ValueError("interactive grant query is invalid")
        return value

    @model_validator(mode="after")
    def _validate_mode_contract(self) -> LiveViewResponse:
        viewer_urls = {
            "hosted_url": self.live_url,
            "screenshot": self.screenshot_url,
            "interactive_remote": self.interactive_url,
        }
        if self.mode == "unavailable":
            present = sorted(name for name, url in viewer_urls.items() if url is not None)
            if present:
                raise ValueError(
                    "an unavailable live view must not carry a viewer URL "
                    f"(got: {', '.join(present)})"
                )
            if self.available or self.interaction_available:
                raise ValueError("an unavailable live view cannot be available or interactive")
        else:
            if viewer_urls[self.mode] is None:
                raise ValueError(f"live view mode '{self.mode}' requires its matching viewer URL")
            if not self.available:
                raise ValueError(f"live view mode '{self.mode}' must report available=true")
            # Masked frames can be viewed but not driven, so a screenshot view must
            # never claim interaction. Only a hosted or interactive viewer may.
            if self.mode == "screenshot" and self.interaction_available:
                raise ValueError("a screenshot live view is not interactive")
        if self.screenshot_url is not None and not self.screenshot_url.startswith(
            f"/api/runs/{self.run_id}/"
        ):
            raise ValueError("a viewer path must address this run on the same origin")
        return self


class ResumeRequest(StrictApiModel):
    signal: Literal["completed", "cancelled"] = "completed"
    # Optional owner-only login credentials. When present the agent logs in
    # autonomously with injected secure placeholders instead of the human driving
    # the live browser. Accepted only on an opted-in, loopback-only request.
    browser_login: BrowserLoginInput | None = None


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


class RevealCredentialsResponse(StrictApiModel):
    """Owner-only, loopback-only raw credential reveal.

    This is the single, deliberate boundary where obtained credential VALUES
    cross the API, for the authenticated owner who initiated the run to use
    directly in their own application. The values are resolved live from the
    encrypted vault via the run's ``vault://`` references; they are never
    persisted to run state, checkpoints, the ledger, logs, or Git. Everywhere
    else in the contract credentials remain reference-only.
    """

    run_id: str
    credentials: dict[CredentialFieldName, str] = Field(min_length=1, max_length=20)


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


class AppCatalogResponse(StrictApiModel):
    """Every verified app, so a selector can offer a choice without a query.

    Deliberately separate from ``AppSearchResponse``: this response has no query
    to echo, and its ``total`` is the size of the verified snapshot rather than a
    match count.
    """

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
