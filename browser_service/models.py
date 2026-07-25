"""Strict RPC contracts for the browser service.

Every model forbids extra fields, so a malformed or hostile payload is rejected
at the boundary. No model carries a credential value, a cookie, a storage-state
blob, or the service token: secrets move only as opaque references or as
code-owned values the service itself resolves.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SessionLifecycle = Literal["ACTIVE", "CLOSING", "CLOSED"]
LiveViewMode = Literal["screenshot", "interactive_remote"]

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
    # Opaque profile identifier (never a filesystem path from the caller).
    profile_id: str | None = Field(default=None, max_length=200)
    live_view_mode: LiveViewMode = "screenshot"
    # Whether the service may restore previously saved authenticated state.
    use_storage_state: bool = False


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
    current_url_path: str = ""
    reason_code: str = ""


class NavigateRequest(_Strict):
    """Drive the reviewed onboarding trace toward the credential page."""

    # The verified OperationalResearch payload (non-secret, strict upstream).
    research: dict[str, object]
    # Vault REFERENCES only — never raw credential values.
    credential_refs: dict[str, str] = Field(default_factory=dict)


class ResumeRequest(_Strict):
    """Resume after a human completed a gate."""

    signal: str = Field(min_length=1, max_length=64)
    research: dict[str, object] | None = None
    credential_refs: dict[str, str] = Field(default_factory=dict)


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
    session: SessionSummary | None = None


class LiveViewGrant(_Strict):
    """A short-lived, session-bound interactive-HITL grant.

    The URL is returned ONCE for immediate operator use and is never durably
    persisted by the API (see ops.browser_live_view).
    """

    mode: LiveViewMode
    # Present only for interactive_remote; omitted for screenshot mode.
    url: str | None = None
    expires_at: str = ""
    session_id: str = ""


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
    "CreateSessionRequest",
    "ErrorResponse",
    "HealthResponse",
    "LiveViewGrant",
    "LiveViewMode",
    "NavigateRequest",
    "ObservationResponse",
    "ProviderHealthState",
    "ResumeRequest",
    "SessionLifecycle",
    "SessionSummary",
]
