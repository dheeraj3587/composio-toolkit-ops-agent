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

from ops.browser.setup_values import normalize_provider_setup_fields
from ops.core.model_catalog import EFFORT_VALUES
from ops.core.models import AccountMode, OperationalResearch
from ops.core.state import AccessRoute, BrowserProvider, CredentialCreationPolicy, RunStatus
from ops.onboarding.action_loop import LoopStage
from ops.onboarding.admission import AdmissionDecider, AdmissionInput, AdmissionRoute
from ops.onboarding.effects import OnboardingEffect
from ops.onboarding.phase import OnboardingPhase, OnboardingReasonCode
from ops.providers.profile import (
    ApprovalRequirement,
    AuxiliaryHostKind,
    BillingRequirement,
    CredentialKind,
    FlowKind,
    ProfileField,
)
from ops.recipes.app_recipes import ReadinessTier, RouteKind

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
#
# There used to be a fourth mode, ``hosted_url``, carrying a signed URL that a
# cloud backend hosted and the console embedded in a cross-origin iframe. It went
# with that backend: every worker that can run here is self-hosted and serves the
# session through this control plane, so there is no external viewer to point at.
# Unlike ``browser_provider``, this value is computed live per request and never
# stored, so dropping it cannot orphan a historical row.
LiveViewMode = Literal["screenshot", "interactive_remote", "unavailable"]

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

# A bounded, opaque identifier: a run id, a correlation id, a browser session id,
# the id segment of a vault reference, or a provider-side object id. The character
# class admits no whitespace, so a page excerpt, a prompt, or a credential value
# cannot be carried by one.
BoundedIdentifier = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9._-]{1,200}$", min_length=1, max_length=200),
]

# A discovery adapter's slug (``perplexity_search``), never its output.
AdapterName = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$", min_length=1, max_length=64),
]

# A lowercase DNS hostname or registrable domain. Not a URL and not text.
HostName = Annotated[
    str,
    StringConstraints(
        pattern=(
            r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
            r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
        ),
        min_length=4,
        max_length=253,
    ),
]

# A hex SHA-256 digest, as produced by the provider-profile digest.
Sha256Digest = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{64}$", min_length=64, max_length=64),
]

# An ISO-8601 instant. Bounded and pattern-constrained so a timestamp field is
# not a place free text can be parked.
IsoTimestamp = Annotated[
    str,
    StringConstraints(
        pattern=(
            r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
            r"(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?$"
        ),
        min_length=19,
        max_length=40,
    ),
]


# One allow-list entry: an exact host or a single-level vendor wildcard
# (``*.provider.com``). Deliberately not free text, so a projected allow-list
# cannot describe a pattern the reviewed browser policy would never produce.
HostPattern = Annotated[
    str,
    StringConstraints(
        pattern=(
            r"^(?:\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
            r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
        ),
        min_length=4,
        max_length=255,
    ),
]

# The canonical app slug ``ops.providers.profile`` already enforces at construction.
AppSlug = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", min_length=1, max_length=120),
]

# A cited evidence value: a URL, a registrable domain, or an enum member. The
# whitespace-free character class is what keeps a page excerpt or a prose
# justification out of the field, which ``str`` alone would admit.
EvidenceValue = Annotated[
    str,
    StringConstraints(pattern=r"^\S{1,2000}$", min_length=1, max_length=2000),
]

# One non-secret flow step label, bounded exactly as ``ops.providers.profile``
# bounds it (``MAX_FLOW_STEP_CHARACTERS``).
FlowStepText = Annotated[str, StringConstraints(min_length=1, max_length=200)]


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
    # Optional for operators. The service derives the deterministic app-bound
    # reference ``vault://company/work_email/<app-slug>`` when omitted.
    work_email_ref: VaultReference | None = None
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
    creation or one resume call. Reusable email/password pairs may be retained in
    the encrypted, account-scoped owner vault, but never in run state,
    checkpoints, audit events, logs, or the IntegratorBundle.
    OTP/CAPTCHA/passkey/billing still require a human.
    """

    email: SecretStr
    password: SecretStr


class BrowserVerificationInput(StrictApiModel):
    """Owner-supplied one-time email verification fallback.

    Exactly one value is accepted. It crosses the same one-time browser secret
    boundary as autonomous Gmail verification and is never written to run state,
    checkpoints, audit events, or logs.
    """

    code: SecretStr | None = None
    url: SecretStr | None = None

    @model_validator(mode="after")
    def _validate_one_time_value(self) -> BrowserVerificationInput:
        if (self.code is None) == (self.url is None):
            raise ValueError("provide exactly one verification code or URL")
        if self.code is not None:
            value = self.code.get_secret_value().strip().replace(" ", "").replace("-", "")
            if re.fullmatch(r"(?:\d{4,8}|[A-Z0-9]{5,8})", value) is None:
                raise ValueError("verification code format is invalid")
            self.code = SecretStr(value)
        if self.url is not None:
            value = self.url.get_secret_value().strip()
            parsed = urlsplit(value)
            if (
                len(value) > 2_048
                or parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
            ):
                raise ValueError("verification URL must be an HTTPS URL")
            self.url = SecretStr(value)
        return self


class CreateRunRequest(StrictApiModel):
    app_name: str = Field(min_length=1, max_length=200)
    company: CompanyInput
    account_mode: AccountMode
    requested_scope_policy: Literal["minimum", "recommended", "maximum"] = "maximum"
    execution_mode: Literal["plan_only", "execute_when_configured"] = "plan_only"
    # Narrower than the read type on purpose. ``BrowserProvider`` still accepts the
    # retired "browser_use" so historical rows render as history, but a NEW run may
    # not be created on a backend that no longer exists: the value is frozen onto
    # the run and decides which backend a retry or resume is allowed to use.
    browser_provider: Literal["playwright"] = "playwright"
    credential_creation_policy: CredentialCreationPolicy = "reuse_only"
    provider_setup: dict[str, str] = Field(default_factory=dict, max_length=20)
    # Deprecated compatibility alias for execution_mode="plan_only". Only an
    # explicitly supplied dry_run=true carries intent; execution_mode is the single
    # canonical control and dry_run is never rewritten from it.
    dry_run: bool = True
    # Optional app sign-in credentials for autonomous login. When present they are
    # injected through the selected provider's secret boundary at session
    # creation. The reusable pair may be retained in the encrypted account vault,
    # but never in run state, checkpoints, logs, or the IntegratorBundle.
    browser_login: BrowserLoginInput | None = None
    # Opt into the autonomous onboarding driver (design LL-6.3). Additive and
    # default-false, so an existing client's request keeps its current meaning.
    # NOT SERVABLE YET: the driver has no browser binding in this deployment, so
    # ``true`` is refused at the route with ``onboarding_driver_not_wired``. The
    # field stays in the contract because the refusal is the honest answer and a
    # removed field would 422 as an unknown key, which says nothing useful.
    onboarding: bool = False
    # Optional operator hint for provider research. A bounded HTTPS URL, never a
    # search phrase, so a hint cannot smuggle prose into the research prompt.
    provider_hint_url: BoundedHttpUrl | None = None
    # The decision model this run is pinned to, as a catalog id from
    # ``GET /api/models`` (``"<provider>:<model>"``), and the reasoning effort it
    # runs at. Shape is checked here; whether the id names a provider THIS
    # deployment has a key for is checked at the route, where the settings the
    # catalog is derived from are in hand. Both absent is the ordinary case and
    # means "use the deployment's chain unchanged".
    decision_model: str | None = Field(default=None, max_length=120)
    decision_effort: str | None = Field(default=None, max_length=20)

    @field_validator("decision_model")
    @classmethod
    def decision_model_is_catalog_shaped(cls, value: str | None) -> str | None:
        if value is None:
            return None
        candidate = value.strip()
        if not candidate:
            return None
        provider, separator, model = candidate.partition(":")
        if not separator or not provider or not model:
            raise ValueError("decision_model must be '<provider>:<model>'")
        return candidate

    @field_validator("decision_effort")
    @classmethod
    def decision_effort_is_known(cls, value: str | None) -> str | None:
        if value is None:
            return None
        candidate = value.strip()
        if not candidate:
            return None
        if candidate not in EFFORT_VALUES:
            raise ValueError("decision_effort is not a recognized reasoning effort")
        return candidate

    @field_validator("provider_setup")
    @classmethod
    def provider_setup_is_reviewed(cls, value: dict[str, str]) -> dict[str, str]:
        return normalize_provider_setup_fields(value)

    @field_validator("provider_hint_url")
    @classmethod
    def provider_hint_is_https(cls, value: str | None) -> str | None:
        return _validate_http_url(value) if value is not None else None

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
        if self.account_mode == "create_account" and self.browser_login is not None:
            raise ValueError("browser_login is only accepted when account_mode='existing_account'")
        if self.decision_effort is not None and self.decision_model is None:
            # An effort names a dial on a specific model. Accepting one with no
            # model would record a preference on the run that nothing applied.
            raise ValueError("decision_effort requires decision_model")
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
        "recipes",
        "composio_managed_auth",
        "gmail",
        "langgraph",
        "vault",
        "perplexity",
        "gemini",
        "composio",
        # The only browser backend, reporting under its own identity.
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
    reason_code: ReasonCode | None = None
    checked_at: str | None = None
    expires_at: str | None = None


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
    operational_state_storage: Literal["sqlite_not_app_encrypted"] = "sqlite_not_app_encrypted"
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
    account_mode: AccountMode | None = None
    status: RunStatus
    access_route: AccessRoute | None = None
    created_at: str
    updated_at: str
    execution_mode: Literal["plan_only", "execute_when_configured"]
    browser_provider: BrowserProvider
    credential_creation_policy: CredentialCreationPolicy
    recipe_version: str | None = None
    route_kind: RouteKind | None = None
    readiness_tier: ReadinessTier | None = None
    attempt: int = Field(default=0, ge=0)
    phase: str = "legacy"
    reason_code: ReasonCode | None = None
    state_engine: Literal["canonical_v1", "legacy"] = "legacy"
    external_actions: bool


class PrimaryAction(StrictApiModel):
    """The single backend-authorized next action for one run."""

    kind: Literal[
        "connect_account",
        "poll_connection",
        "open_browser",
        "submit_credentials",
        "review_outreach",
        "poll_reply",
        "none",
    ]
    enabled: bool
    reason_code: ReasonCode


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


# The step an operator may retry: the subset of phases whose work can be
# re-attempted in place. A terminal or gate phase is deliberately absent, so the
# controls view cannot offer a retry the backend would refuse.
RetryableStep = Literal[
    "research",
    "signup",
    "email_verification",
    "developer_app",
    "credential_generation",
    "credential_validation",
]


class OnboardingStateView(StrictApiModel):
    """The onboarding sub-state projected onto the run detail response.

    Every field is either a closed vocabulary, a digest, a bounded identifier, a
    counter, or one of three short decision-shaped labels. There is no field for a
    prompt, a reasoning trace, or page content, so Requirement 19.13 holds by
    construction rather than by review.
    """

    phase: OnboardingPhase
    phase_at_pause: OnboardingPhase | None = None
    profile_digest: Sha256Digest
    reason_code: OnboardingReasonCode | None = None
    goal: str = Field(default="", max_length=200)
    step: str = Field(default="", max_length=200)
    # Decision-shaped ("Opening the developer portal"), never chain-of-thought.
    latest_decision: str = Field(default="", max_length=300)
    attempt: int = Field(ge=0, le=1_000)
    admission_prompts: int = Field(ge=0, le=1)
    captcha_prompts: int = Field(ge=0, le=1_000)
    correlation_id: BoundedIdentifier


class OnboardingControlsView(StrictApiModel):
    """Capability projected by the backend, following the ``BrowserUiState`` pattern.

    The console never infers a control's availability from status: each flag is a
    backend decision and is false unless the backend can prove otherwise.
    """

    can_decide_admission: bool = False
    can_pause: bool = False
    can_resume: bool = False
    can_cancel: bool = False
    can_reset: bool = False
    can_retry_step: bool = False
    retryable_step: RetryableStep | None = None
    reason_code: OnboardingReasonCode | None = None
    # Why the resume control is absent from a run paused on a human-only gate, so
    # the console can say that rather than render nothing.
    resume_withheld_reason: OnboardingReasonCode | None = None

    @model_validator(mode="after")
    def _retry_names_its_step(self) -> OnboardingControlsView:
        # A retry control the console cannot name is a control it cannot render,
        # and a named step with the control disabled would invite a 409.
        if self.can_retry_step != (self.retryable_step is not None):
            raise ValueError("a retryable step is named exactly when retry is available")
        return self


class AutonomyOutcomeView(StrictApiModel):
    """The durable per-run autonomy record, projected once the run is terminal."""

    verdict: Literal["fully_autonomous", "operator_assisted", "blocked", "cancelled"]
    terminal_phase: OnboardingPhase
    reason_code: OnboardingReasonCode
    admission_prompts: int = Field(ge=0, le=1)
    captcha_prompts: int = Field(ge=0, le=1_000)
    duration_seconds: int = Field(ge=0, le=86_400)

    @model_validator(mode="after")
    def _fully_autonomous_had_no_captcha_prompt(self) -> AutonomyOutcomeView:
        # Requirement 20.7, enforced at the wire: the measured rate is only
        # trustworthy if the verdict cannot disagree with the counters beside it.
        if self.verdict == "fully_autonomous" and self.captcha_prompts != 0:
            raise ValueError("a fully autonomous run prompted the operator for no CAPTCHA")
        return self


class FieldEvidenceView(StrictApiModel):
    """Why one profile field is believed. Carries the citation, never the excerpt."""

    field: ProfileField
    # A URL, a registrable domain, or an enum member — never prose.
    value: EvidenceValue
    source_url: BoundedHttpUrl
    source_digest: Sha256Digest
    adapters: list[AdapterName] = Field(max_length=8)
    corroborations: int = Field(ge=1, le=64)
    confidence: float = Field(ge=0.0, le=1.0)

    @field_validator("source_url")
    @classmethod
    def source_is_https(cls, value: str) -> str:
        return _validate_http_url(value)


class FlowSpecView(StrictApiModel):
    """One credential-producing path through the provider's own site."""

    kind: FlowKind
    supported: bool
    entry_url: BoundedHttpUrl | None = None
    steps: list[FlowStepText] = Field(default_factory=list, max_length=8)
    produces: list[CredentialKind] = Field(default_factory=list, max_length=4)
    requires_approval: bool = False
    requires_billing: bool = False

    @field_validator("entry_url")
    @classmethod
    def entry_is_https(cls, value: str | None) -> str | None:
        return _validate_http_url(value) if value is not None else None


class AuxiliaryHostView(StrictApiModel):
    """A typed non-primary host. Never a second primary domain."""

    host: HostName
    kind: AuxiliaryHostKind


class ProviderProfileView(StrictApiModel):
    """Sanitized profile. Deliberately omits: raw evidence excerpts, prompts,
    adapter API responses, and anything that could carry page content."""

    run_id: BoundedIdentifier
    profile_digest: Sha256Digest
    provider_name: str = Field(max_length=200)
    app_slug: AppSlug
    registrable_domain: HostName
    allowed_host_patterns: list[HostPattern] = Field(max_length=32)
    auxiliary_hosts: list[AuxiliaryHostView] = Field(default_factory=list, max_length=16)
    developer_portal_url: BoundedHttpUrl | None = None
    signup_url: BoundedHttpUrl | None = None
    login_url: BoundedHttpUrl | None = None
    developer_docs_url: BoundedHttpUrl | None = None
    flows: list[FlowSpecView] = Field(max_length=5)
    approval_requirement: ApprovalRequirement
    billing_requirement: BillingRequirement
    evidence: list[FieldEvidenceView] = Field(max_length=64)
    confidence: float = Field(ge=0.0, le=1.0)
    built_at: IsoTimestamp

    @field_validator(
        "developer_portal_url",
        "signup_url",
        "login_url",
        "developer_docs_url",
    )
    @classmethod
    def profile_urls_are_https(cls, value: str | None) -> str | None:
        return _validate_http_url(value) if value is not None else None


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
    primary_action: PrimaryAction | None = None
    # Onboarding projections (design LL-6.3). All three are absent on a legacy
    # (non-onboarding) run; ``autonomy`` is present only once the run is terminal.
    onboarding: OnboardingStateView | None = None
    controls: OnboardingControlsView | None = None
    autonomy: AutonomyOutcomeView | None = None


class ManagedConnectionResponse(StrictApiModel):
    """Immediate managed-auth result; redirect_url is ephemeral and no-store."""

    run: RunSummary
    connection_request_id: str = Field(min_length=1, max_length=200)
    state: Literal["pending", "active", "terminal"]
    redirect_url: BoundedHttpUrl | None = None
    replayed: bool = False

    @field_validator("redirect_url")
    @classmethod
    def redirect_is_https(cls, value: str | None) -> str | None:
        return _validate_http_url(value) if value is not None else None


class RunListResponse(StrictApiModel):
    items: list[RunSummary]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class TimelineCorrelation(StrictApiModel):
    """The correlation set carried by every onboarding timeline event.

    Note what is absent: no vault reference VALUE, no live URL, no page text.
    ``vault_reference_id`` is the opaque id segment of ``vault://app/kind/ID``,
    which is a random identifier and not derived from the secret.
    """

    run_id: BoundedIdentifier
    correlation_id: BoundedIdentifier
    onboarding_phase: OnboardingPhase
    profile_digest: Sha256Digest
    attempt: int = Field(ge=0, le=1_000)
    reason_code: OnboardingReasonCode
    browser_session_id: BoundedIdentifier | None = None
    vault_reference_id: BoundedIdentifier | None = None


class TimelineDetail(StrictApiModel):
    """A closed union of non-secret detail fields.

    ``extra="forbid"`` plus the absence of any free-text field is what makes "no
    page content, no prompts, no reasoning traces" structurally true rather than
    review-enforced. Every string field here is an enum, a hostname, a domain, an
    HTTPS URL, a bounded identifier, or a timestamp.
    """

    # Research
    adapters_engaged: list[AdapterName] | None = Field(default=None, max_length=8)
    registrable_domain: HostName | None = None
    evidence_count: int | None = Field(default=None, ge=0, le=64)
    # Admission
    credentials_present: bool | None = None
    decision: Literal["create_account", "cancel"] | None = None
    decided_by: Literal["system", "operator"] | None = None
    # Navigation / hosts
    host: HostName | None = None
    # Verification
    sender_domain: HostName | None = None
    verification_kind: Literal["link", "code"] | None = None
    # Developer app / credentials
    developer_app_id: BoundedIdentifier | None = None
    credential_kind: (
        Literal[
            "oauth_client_id",
            "oauth_client_secret",
            "api_key",
            "personal_access_token",
            "client_credentials_pair",
        ]
        | None
    ) = None
    validation_endpoint: BoundedHttpUrl | None = None
    validation_http_status: int | None = Field(default=None, ge=100, le=599)
    checked_at: IsoTimestamp | None = None
    # Terminal
    duration_seconds: int | None = Field(default=None, ge=0, le=86_400)
    verdict: Literal["fully_autonomous", "operator_assisted", "blocked", "cancelled"] | None = None

    @field_validator("validation_endpoint")
    @classmethod
    def validation_endpoint_is_https(cls, value: str | None) -> str | None:
        return _validate_http_url(value) if value is not None else None


class TimelineEvent(StrictApiModel):
    event_id: int = Field(gt=0)
    event_type: str
    summary: str
    status: Literal["recorded", "completed", "blocked", "failed"]
    created_at: str
    # Onboarding attribution. Both are absent on legacy (non-onboarding) events.
    correlation: TimelineCorrelation | None = None
    detail: TimelineDetail | None = None


class RunProgressEventView(StrictApiModel):
    """One completed loop iteration, over the bounded window (Requirement 4.2)."""

    step_index: int = Field(ge=1, le=100_000)
    stage: LoopStage
    elapsed_ms: int = Field(ge=0, le=3_600_000)
    onboarding_phase: OnboardingPhase
    recorded_at: IsoTimestamp


class RunDecisionView(StrictApiModel):
    """What the agent chose on one loop iteration, and what it said about it.

    Joins to :class:`RunProgressEventView` on ``step_index`` within a phase —
    one-to-one, because the loop writes exactly one progress row per iteration.

    ``reason`` is MODEL-AUTHORED PROSE read off a live third-party page. It was
    length-capped, control-character-stripped and secret-screened before it was
    stored, and it must be rendered inert: never as markdown, never linkified,
    and never allowed to drive a control, a URL, or an enabled state.
    ``reason_withheld`` is true when the screen refused the text — the honest
    answer is "withheld", not a blank line.
    """

    step_index: int = Field(ge=1, le=100_000)
    onboarding_phase: OnboardingPhase
    decision: Literal["select_candidate", "report_hitl", "report_blocked", "rejected"]
    reason_code: str | None = Field(default=None, max_length=120)
    # The chosen control's sanitized accessible name — never a selector.
    candidate_label: str | None = Field(default=None, max_length=120)
    action: str | None = Field(default=None, max_length=40)
    # Host only. A full URL with a query is never projected here.
    target_host: str | None = Field(default=None, max_length=253)
    reason: str | None = Field(default=None, max_length=400)
    reason_withheld: bool = False
    recorded_at: IsoTimestamp


class RunCitationView(StrictApiModel):
    """One source this run's conclusions rest on.

    Assembled ENTIRELY from URLs that were already fetched and host-policy
    validated during research or signup. Nothing here is fetched to build the
    timeline and no new host is ever introduced: a citation the run did not
    already earn does not appear.
    """

    # Which claim this source backs: an operational URL field, "evidence" for a
    # page the research read, or the signup step that recorded it.
    kind: str = Field(max_length=60)
    url: BoundedHttpUrl
    # The page the claim was read ON, when the claim names one.
    source_url: BoundedHttpUrl | None = None

    @field_validator("url", "source_url")
    @classmethod
    def citation_is_https(cls, value: str | None) -> str | None:
        return _validate_http_url(value) if value is not None else None


class TimelineResponse(StrictApiModel):
    run_id: str
    items: list[TimelineEvent]
    # Newest first, capped by ``onboarding_progress_window``. A separate field
    # rather than rows in ``items``, which keeps ``event_id`` uniqueness intact.
    progress: list[RunProgressEventView] = []
    # The agent's own chain of thought, and the sources under it. Both are
    # additive and default empty, so a legacy run and an older client keep
    # exactly the response they had.
    decisions: list[RunDecisionView] = []
    citations: list[RunCitationView] = []
    # What decided, when the run pinned a model. Absent means the deployment's
    # own chain — the honest answer, rather than naming a default that may have
    # changed since the run started.
    decision_model: str | None = Field(default=None, max_length=120)
    decision_effort: str | None = Field(default=None, max_length=20)


class LiveViewResponse(StrictApiModel):
    """Owner-only, loopback-only ephemeral live view.

    This is the single, deliberate place a signed live-session URL crosses the API
    boundary. It is read live from the in-memory worker and is never persisted to
    run state, checkpoints, the ledger, logs, or Git.

    ``provider`` and ``mode`` are ALWAYS present so a client renders what the wired
    backend actually offers instead of assuming a hosted URL:

    * ``screenshot`` — the self-hosted Playwright harness has no hosted URL, so the
      client polls ``screenshot_url`` for masked PNG frames. Frames are viewable
      but not interactive, so ``interaction_available`` is False.
    * ``interactive_remote`` — an exact, short-lived private grant consumed by the
      Next.js server and converted to the reviewed same-origin viewer path. It may
      be server-enforced view-only while automation is running; control is exposed
      only when ``interaction_available`` is true.
    * ``unavailable`` — no viewer exists, so no viewer URL may be present.

    ``screenshot_url`` is a bounded same-origin API path. ``interactive_url`` is
    allowed only for the exact private browser-worker relay and a bounded signed
    session/token query; it is never durable or logged.
    """

    run_id: str
    provider: BrowserProvider
    available: bool
    mode: LiveViewMode = "unavailable"
    screenshot_url: RelativeViewerPath | None = None
    interactive_url: InteractiveGrantUrl | None = None
    captured_at: str | None = None
    # Whether the owner can actually drive the browser through this view.
    interaction_available: bool = False
    reason_code: ReasonCode | None = None

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
            # never claim interaction. Only the interactive remote may.
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
    # Secure fallback when connected Gmail is unavailable or cannot parse the
    # provider message. Accepted only at an email-verification HITL gate.
    browser_verification: BrowserVerificationInput | None = None

    @model_validator(mode="after")
    def _one_injected_secret_source(self) -> ResumeRequest:
        if self.browser_login is not None and self.browser_verification is not None:
            raise ValueError("login credentials and email verification are mutually exclusive")
        return self


class RetryRequest(StrictApiModel):
    capability: Literal["research", "browser", "email", "validation"]


class ActionReceipt(StrictApiModel):
    run_id: str
    # ``cancel`` is additive: cancelling an onboarding run releases its browser
    # session and reports through the same receipt (design LL-6.3).
    action: Literal["resume", "poll_email", "retry", "send_outreach", "cancel"]
    status: Literal["accepted", "configuration_required", "no_change"] = "accepted"
    detail: str | None = None
    # The phase the run resumed (or cancelled) into, so the console does not have
    # to re-fetch the run to learn what its command did. Omitted for legacy runs.
    onboarding: OnboardingStateView | None = None


# --- Onboarding operator controls (design LL-6.3) ----------------------------
#
# One request and one response model per control. Every field is a closed
# vocabulary, a digest, a bounded identifier, a counter, or a boolean: there is no
# free-text field on any response here, so a credential value, a one-time code, a
# verification link, a signed live URL, a prompt, and a page excerpt are all
# unrepresentable rather than merely absent (Requirement 19.13).


# An operator-supplied replay token. Bounded and whitespace-free, so it can be
# compared and logged as an identifier without carrying anything else.
IdempotencyToken = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9._:-]{8,128}$", min_length=8, max_length=128),
]

# Mirrors ``ops.runs.reconciliation.ExpectedRoute``. Restated rather than imported
# so the model module keeps its light import graph.
ExpectedRestartRoute = Literal["login", "signup", "undetermined"]


class AdmissionDecisionRequest(StrictApiModel):
    """The operator's answer to the one admission prompt.

    ``profile_digest`` is optimistic concurrency, not decoration: the operator
    decides about the profile they were shown, so a decision that names a
    different digest is refused rather than silently applied to another profile.
    """

    decision: AdmissionInput
    profile_digest: Sha256Digest
    idempotency_key: IdempotencyToken | None = None


class AdmissionDecisionResponse(StrictApiModel):
    """The decision as it was durably recorded (Requirements 3.8, 3.9, 3.11)."""

    run_id: BoundedIdentifier
    route: AdmissionRoute
    reason_code: OnboardingReasonCode
    decided_by: AdmissionDecider
    decided_at: IsoTimestamp
    # True when the run already held a decision, in which case the body above is
    # the ORIGINAL record and nothing was rewritten.
    replayed: bool = False
    onboarding: OnboardingStateView


class PauseRequest(StrictApiModel):
    """An optional operator note. Deliberately never persisted — see api/service.py."""

    reason: str | None = Field(default=None, max_length=200)


class PauseResponse(StrictApiModel):
    """Where the pause takes effect, and the guarantee that the session stayed up."""

    run_id: BoundedIdentifier
    accepted: bool
    # Pause stops the run at the next safe boundary; this names the phase it
    # stops after (Requirement 14.2).
    pausing_after_phase: OnboardingPhase
    reason_code: OnboardingReasonCode
    # Always false: a pause keeps the authenticated session the operator will
    # come back to. Projected so the console reads the guarantee off the response.
    browser_session_released: Literal[False] = False
    onboarding: OnboardingStateView


class ResetRequest(StrictApiModel):
    """Reset is destructive to workflow state, so the acknowledgement is explicit.

    ``confirm`` has no default and admits only ``True``, which is what makes an
    unconfirmed reset a validation error before any side effect runs
    (Requirement 14.12).
    """

    confirm: Literal[True]


class ResetResponse(StrictApiModel):
    """The four facts an operator needs to trust a reset (Requirement 14.11)."""

    run_id: BoundedIdentifier
    reason_code: OnboardingReasonCode
    phase: OnboardingPhase
    browser_session_released: bool
    workflow_state_cleared: bool
    # Property 13, surfaced: reset never destroys credentials.
    vault_references_preserved: int = Field(ge=0, le=64)
    expected_route_on_restart: ExpectedRestartRoute


class RetryStepRequest(StrictApiModel):
    """Retry the CURRENT failed step only.

    The phase is not a parameter. ``expected_phase`` is an optimistic check the
    backend compares against the run's committed phase, so a client cannot name a
    step whose effect already completed and have it re-attempted.
    """

    expected_phase: OnboardingPhase
    idempotency_key: IdempotencyToken | None = None


class RetryStepResponse(StrictApiModel):
    """What the retry re-attempted, and what the ledger proved it must skip."""

    run_id: BoundedIdentifier
    accepted: bool
    phase: OnboardingPhase
    attempt: int = Field(ge=0, le=1_000)
    reason_code: OnboardingReasonCode
    # Property 1 made observable: an operator sees that the signup form will not
    # be submitted twice (Requirement 14.14).
    skipped_effects: list[OnboardingEffect] = Field(default_factory=list, max_length=8)


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


class BrowserServiceHealthView(StrictApiModel):
    """Sanitized cached state returned by the isolated browser service."""

    state: Literal[
        "disabled",
        "not_configured",
        "configured_not_verified",
        "ready",
        "degraded",
        "capacity_exhausted",
        "unreachable",
        "version_mismatch",
    ]
    reason_code: str
    version: str
    chromium_installed: bool
    context_launch_ok: bool
    capacity_total: int = Field(ge=0)
    capacity_in_use: int = Field(ge=0)
    janitor_running: bool


class HealthResponse(StrictApiModel):
    status: Literal["healthy", "degraded"]
    phase: Literal["2"] = "2"
    version: Literal["0.2.0"] = "0.2.0"
    snapshot: SnapshotHealth
    checks: list[HealthCheck]
    providers: list[ProviderState] = Field(default_factory=list)
    browser_service: BrowserServiceHealthView | None = None


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
    # Where ``research.signup_url`` came from. "reviewed" is a human-approved
    # catalog entry; "runtime_research" means no route is known yet and the
    # signup research agent resolves one from the app's own site when the run
    # starts. The console must not present the two identically, so the
    # distinction is part of the contract rather than something the caller
    # infers.
    signup_source: Literal["reviewed", "runtime_research", "unavailable"] = "unavailable"
    # The page a reviewed URL was found on, when one is recorded.
    signup_evidence_url: str | None = None
    # How this app is connected at all, straight off the reviewed recipe's
    # ``route_kind``. "unavailable" signup and "managed_auth" connect is not a
    # broken app -- it is an app whose reviewed route is Composio's managed
    # OAuth, where an account is signed in rather than registered. Without this
    # the console could only say a signup route was missing, which read as "this
    # app does not work" for the 36 of 50 apps that connect this way.
    connect_route: Literal["managed_auth", "playwright", "gated"] | None = None


class ModelOptionView(StrictApiModel):
    """One decision model this deployment can actually run a run on.

    Mirrors :class:`ops.core.model_catalog.ModelOption` field for field. Only
    configured providers ever reach this view, so an option the operator can see
    is one the chain would build.
    """

    id: str
    provider: str
    model: str
    label: str
    description: str
    supports_effort: bool
    effort_values: list[str]
    is_default: bool


class ModelCatalogResponse(StrictApiModel):
    """The picker's whole world.

    ``models`` is empty when no provider key is set — the same condition under
    which a run cannot make a model decision at all. The UI says so rather than
    rendering an empty dropdown.
    """

    models: list[ModelOptionView]
    default_model_id: str | None = None
    default_effort: str | None = None


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


class ProviderReadinessResponse(StrictApiModel):
    error: Literal["provider_not_ready"] = "provider_not_ready"
    message: Literal["Required provider capability is not ready; no run was created."] = (
        "Required provider capability is not ready; no run was created."
    )
    provider: Literal["gmail", "playwright"]
    reason_code: ReasonCode


class PhaseUnavailableResponse(StrictApiModel):
    error: Literal["phase_unavailable", "configuration_required"] = "phase_unavailable"
    message: str = "Action is unavailable in the current runtime configuration."
    run_id: str
    action: str
    available_in: list[str] = Field(min_length=1, max_length=8)
    # The refusal's own code, drawn from the closed onboarding vocabulary
    # (design LL-6.4). Omitted entirely for a refusal that predates the
    # onboarding surface, so the legacy 409 body is unchanged.
    reason_code: OnboardingReasonCode | None = None
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
