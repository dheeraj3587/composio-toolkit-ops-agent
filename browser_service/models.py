"""Strict RPC contracts for the browser service.

Every model forbids extra fields, so a malformed or hostile payload is rejected
at the boundary. No model carries a credential value, a cookie, a storage-state
blob, or the service token: secrets move only as opaque references or as
code-owned values the service itself resolves.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ops.models import validate_vault_reference

SessionLifecycle = Literal["ACTIVE", "CLOSING", "CLOSED"]
LiveViewMode = Literal["screenshot", "interactive_remote"]
_BROKER_GRANT_PATTERN = re.compile(r"^bsg_[A-Za-z0-9_-]{43}$")

# Health states for the Playwright provider path (no Browser Use wording).
ProviderHealthState = Literal[
    "disabled",
    "not_configured",
    "configured_not_verified",
    "ready",
    "degraded",
    "capacity_exhausted",
    "unreachable",
    "version_mismatch",
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class CreateSessionRequest(_Strict):
    """Create a browser session for one run."""

    # Reviewed app slug; the service resolves its own host policy from this.
    app_slug: str = Field(min_length=1, max_length=120)
    recipe_snapshot: dict[str, object] | None = None
    # Opaque profile identifier (never a filesystem path from the caller).
    profile_id: str | None = Field(default=None, max_length=200)
    live_view_mode: LiveViewMode = "screenshot"
    # Whether the service may restore previously saved authenticated state.
    use_storage_state: bool = False
    # An OPAQUE account reference used to bind stored state. Deliberately not an
    # email address: the binding fingerprint must not be derived from, or reveal,
    # a real account identifier.
    account_ref: str | None = Field(default=None, max_length=200)
    # Run/session scope that binds transient login references. One-time credential
    # references may be consumed only for the matching scope, so a reference minted
    # for one run cannot be replayed by another.
    secret_scope: str = Field(default="", max_length=200, pattern=r"^[A-Za-z0-9_-]*$")

    @model_validator(mode="after")
    def _storage_state_requires_account_binding(self) -> CreateSessionRequest:
        if self.use_storage_state and not self.account_ref:
            raise ValueError("storage state requires an account reference")
        if (
            self.account_ref is not None
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,199}", self.account_ref) is None
        ):
            raise ValueError("account reference is invalid")
        return self


class ReconcileSessionsRequest(_Strict):
    """Find sessions created for one exact persisted browser-start intent."""

    app_slug: str = Field(min_length=1, max_length=120)
    secret_scope: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_-]+$")
    account_ref: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,199}$",
    )


class ReconcileSessionsResponse(_Strict):
    """Opaque service session ids matching one exact start binding."""

    session_ids: tuple[str, ...] = ()


class DrainStatus(_Strict):
    """Minimal release-drain state; intentionally contains no session metadata."""

    accepting_new_sessions: bool
    capacity_in_use: int
    capacity_total: int


class SessionSummary(_Strict):
    """Sanitized session state. No URLs with query strings, no cookies."""

    session_id: str
    lifecycle: SessionLifecycle
    app_slug: str
    created_at: str
    last_active_at: str
    maximum_expires_at: str
    active_operations: int
    live_view_mode: LiveViewMode
    live_view_available: bool
    hitl_pending: bool
    # Four DISTINCT capability facts, so a caller is never misled by one boolean:
    #   screenshot_supported   - the worker can produce screenshots at all
    #   screenshot_available   - a current, non-sensitive frame exists right now
    #   interactive_supported  - the build includes the interactive components
    #   interactive_available  - THIS session has a usable, authorized interactive path
    screenshot_supported: bool = True
    screenshot_available: bool = False
    interactive_supported: bool = False
    interactive_available: bool = False
    current_url_path: str = ""
    reason_code: str = ""


class NavigateRequest(_Strict):
    """Drive the reviewed onboarding trace toward the credential page."""

    # The verified OperationalResearch payload (non-secret, strict upstream).
    research: dict[str, object]
    # Creation-time AppRecipe snapshot supplied by the canonical API. Legacy
    # callers may omit it, but canonical operations always bind it explicitly.
    recipe_snapshot: dict[str, object] | None = None
    # Vault REFERENCES only — never raw credential values.
    credential_refs: dict[str, str] = Field(default_factory=dict)
    # One durable, exact broker grant per reference. The sets must match so the
    # worker cannot redeem an unreserved reference or substitute a different one.
    secret_grants: dict[str, str] = Field(default_factory=dict)
    # Explicit local intent. The service never infers account existence from a
    # page, research content, or a model response.
    account_creation_requested: bool = False
    # Strictly approved non-secret OperationsRequest projections. Raw credentials
    # remain vault references in ``credential_refs``.
    signup_fields: dict[str, str] = Field(default_factory=dict)
    credential_creation_policy: Literal["reuse_only", "create_if_missing"] = "reuse_only"

    @field_validator("signup_fields")
    @classmethod
    def _approved_signup_fields(cls, values: dict[str, str]) -> dict[str, str]:
        from ops.browser_signup import normalize_signup_fields

        return normalize_signup_fields(values)

    @model_validator(mode="after")
    def _exact_secret_grants(self) -> NavigateRequest:
        if set(self.secret_grants) != set(self.credential_refs) or any(
            _BROKER_GRANT_PATTERN.fullmatch(grant) is None for grant in self.secret_grants.values()
        ):
            raise ValueError("every credential reference requires one exact broker grant")
        return self


class ResumeRequest(_Strict):
    """Resume after a human completed a gate."""

    signal: str = Field(min_length=1, max_length=64)
    research: dict[str, object] | None = None
    recipe_snapshot: dict[str, object] | None = None
    credential_refs: dict[str, str] = Field(default_factory=dict)
    secret_grants: dict[str, str] = Field(default_factory=dict)
    account_creation_requested: bool = False
    signup_fields: dict[str, str] = Field(default_factory=dict)
    credential_creation_policy: Literal["reuse_only", "create_if_missing"] = "reuse_only"

    @field_validator("signup_fields")
    @classmethod
    def _approved_signup_fields(cls, values: dict[str, str]) -> dict[str, str]:
        from ops.browser_signup import normalize_signup_fields

        return normalize_signup_fields(values)

    @model_validator(mode="after")
    def _exact_secret_grants(self) -> ResumeRequest:
        if set(self.secret_grants) != set(self.credential_refs) or any(
            _BROKER_GRANT_PATTERN.fullmatch(grant) is None for grant in self.secret_grants.values()
        ):
            raise ValueError("every credential reference requires one exact broker grant")
        return self


class ObservationResponse(_Strict):
    """The bounded observation the API consumes (mirrors BrowserObservation)."""

    status: str
    current_url: str
    page_title: str
    developer_app_id: str | None = None
    human_action_type: str | None = None
    human_instruction: str | None = None
    credential_field_labels: tuple[str, ...] = ()
    non_secret_notes: tuple[str, ...] = ()
    # Bounded, value-free reason code mirrored from BrowserObservation.
    reason_code: str | None = None
    session: SessionSummary | None = None


class CaptureCredentialsResponse(_Strict):
    """Reference-only result of deterministic broker-backed capture.

    A credential value has no representable field in this contract. Validation
    also prevents a malformed/raw value from escaping if a worker implementation
    violates its boundary.
    """

    credential_refs: dict[str, str] = Field(default_factory=dict)

    @field_validator("credential_refs")
    @classmethod
    def _references_only(cls, values: dict[str, str]) -> dict[str, str]:
        references: dict[str, str] = {}
        for name, value in values.items():
            if re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,99}", name) is None:
                raise ValueError("invalid credential kind")
            references[name] = validate_vault_reference(value)
        return references


class CaptureCredentialsRequest(_Strict):
    """Creation-time recipe needed for selector-bound deterministic capture."""

    recipe_snapshot: dict[str, object] | None = None
    broker_grant: str = Field(
        min_length=47,
        max_length=47,
        pattern=r"^bsg_[A-Za-z0-9_-]{43}$",
        repr=False,
    )


class LiveViewGrant(_Strict):
    """A short-lived, session-bound view or control grant.

    The URL is returned ONCE for immediate operator use and is never durably
    persisted by the API (see ops.browser_live_view).
    """

    mode: LiveViewMode
    # Present only for interactive_remote; omitted for screenshot mode.
    url: str | None = None
    expires_at: str = ""
    session_id: str = ""
    view_allowed: bool = False
    control_allowed: bool = False

    @model_validator(mode="after")
    def _capabilities_match_mode(self) -> LiveViewGrant:
        if self.control_allowed and not self.view_allowed:
            raise ValueError("control requires view capability")
        if self.mode == "screenshot":
            if self.url is not None or self.view_allowed or self.control_allowed:
                raise ValueError("screenshot mode cannot carry a remote capability")
        elif self.url is None or not self.view_allowed:
            raise ValueError("remote mode requires a view grant")
        return self


class HealthResponse(_Strict):
    """Provider-aware health for the Playwright path."""

    state: ProviderHealthState
    reason_code: str
    version: str
    chromium_installed: bool
    context_launch_ok: bool
    capacity_total: int
    capacity_in_use: int
    janitor_running: bool
    detail: str = ""


class ErrorResponse(_Strict):
    """A sanitized error: a stable reason code, never provider/page content."""

    reason_code: str
    detail: str = ""


__all__ = [
    "CaptureCredentialsResponse",
    "CreateSessionRequest",
    "DrainStatus",
    "ErrorResponse",
    "HealthResponse",
    "LiveViewGrant",
    "LiveViewMode",
    "NavigateRequest",
    "ObservationResponse",
    "ProviderHealthState",
    "ReconcileSessionsRequest",
    "ReconcileSessionsResponse",
    "ResumeRequest",
    "SessionLifecycle",
    "SessionSummary",
]
