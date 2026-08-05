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

from ops.browser.host_policy import MAX_ALLOWED_HOST_PATTERNS
from ops.browser.worker import HumanActionType
from ops.core.models import validate_vault_reference

SessionLifecycle = Literal["ACTIVE", "CLOSING", "CLOSED"]
LiveViewMode = Literal["screenshot", "interactive_remote"]
_BROKER_GRANT_PATTERN = re.compile(r"^bsg_[A-Za-z0-9_-]{43}$")

# Why a gate clearance answer can name only these four causes. A free-form string
# would let page-derived text ride out of the container on the one field nobody
# checks, so the reason is closed data like every other reason code on this
# boundary: the page was read, the operation lock was held so nothing was read, the
# read could not complete, or the session was already closed by the absolute
# lifetime bound.
#
# ``ops/browser/takeover.py::ClearanceProbeReason`` is the API-side set and is a
# strict SUPERSET of this one: it adds ``session_not_found``, because a 404 never
# produces a report at all, so this service can never name it — it can only
# describe a session it still has. Every member here is spelled identically
# there, and the two must stay in step: a member added to one and not the other
# is a contract break, not a widening.
ClearanceProbeReason = Literal[
    "observed",
    "operation_in_flight",
    "probe_failed",
    "session_max_age_exceeded",
]

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
    # The run this session is bound to, alongside the app slug and account
    # reference. Defaults to secret_scope, which canonical callers already set to
    # the run id.
    run_id: str = Field(default="", max_length=200, pattern=r"^[A-Za-z0-9_-]*$")
    # The run's allow-list, serialized exactly as ``BrowserAllowedHosts.patterns()``
    # produces it. The service rebuilds a ``BrowserAllowedHosts`` from this list and
    # enforces it inside the container, so confinement does not depend on the caller
    # checking first. Empty means no run allow-list: the reviewed recipe policy in
    # the worker stays the only boundary.
    allowed_host_patterns: tuple[str, ...] = Field(default=(), max_length=MAX_ALLOWED_HOST_PATTERNS)
    # The decision model this run was pinned to, as a catalog id
    # ("<provider>:<model>"), and the reasoning effort it asked for. Advisory:
    # the service resolves them against its OWN keys and silently keeps its
    # deployment chain for a model it cannot serve, because a preference must
    # never be able to fail a run. Bounded and pattern-checked so an unusable
    # value is refused here rather than reaching the chain builder.
    decision_model: str | None = Field(default=None, max_length=120, pattern=r"^[A-Za-z0-9_.:/-]*$")
    decision_effort: str | None = Field(default=None, max_length=20, pattern=r"^[a-z]*$")

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
    # Part of the same binding as the created session. Empty means "the run scope
    # is the run id", which is what canonical callers send.
    run_id: str = Field(default="", max_length=200, pattern=r"^[A-Za-z0-9_-]*$")


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
    # Monotonic browser-service pause generation. Zero is reserved for sessions
    # that have never entered HITL and cannot authorize canonical takeover.
    hitl_generation: int = Field(default=0, ge=0)
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
    # The allow-list this container will actually enforce for the session. Echoed
    # so a caller can verify enforcement rather than assume it; empty means the
    # session carries no run allow-list.
    allowed_host_patterns: tuple[str, ...] = ()


class GateClearanceReport(_Strict):
    """Whether the human gate a paused run is waiting on is still on the page.

    This is an OBSERVATION with no verb on it: the API decides what a cleared gate
    means for a run, and this container only reports what it saw. ``_Strict``
    forbids extra fields, so a future field cannot arrive here unreviewed.

    It carries NO URL, NO page text and NO prompt — deliberately, because it is
    read on a 5 second interval while a person may be typing inside the session,
    and a report that carried page content would turn a watcher into a leak. What
    is left is a closed gate type, four booleans, a closed probe reason code, and a
    count.
    """

    session_id: str
    lifecycle: SessionLifecycle
    hitl_pending: bool
    attached: bool
    final_probe_owed: bool
    gate: HumanActionType | None
    cleared: bool
    probe_reason_code: ClearanceProbeReason
    # The pause this observation belongs to, so an answer cannot be attributed to a
    # later gate. A count, never a timestamp of a human's presence.
    hitl_generation: int = Field(ge=0)


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
    setup_fields: dict[str, str] = Field(default_factory=dict, max_length=20)
    credential_creation_policy: Literal["reuse_only", "create_if_missing"] = "reuse_only"

    @field_validator("setup_fields")
    @classmethod
    def _approved_setup_fields(cls, values: dict[str, str]) -> dict[str, str]:
        from ops.browser.setup_values import normalize_browser_setup_fields

        return normalize_browser_setup_fields(values)

    @field_validator("signup_fields")
    @classmethod
    def _approved_signup_fields(cls, values: dict[str, str]) -> dict[str, str]:
        from ops.browser.signup import normalize_signup_fields

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
    setup_fields: dict[str, str] = Field(default_factory=dict, max_length=20)
    credential_creation_policy: Literal["reuse_only", "create_if_missing"] = "reuse_only"
    # Optional for owner/manual resumes; canonical takeover supplies the positive
    # generation it observed so the service can reject a race into a later gate
    # before any browser action runs.
    expected_hitl_generation: int | None = Field(default=None, ge=1)

    @field_validator("setup_fields")
    @classmethod
    def _approved_setup_fields(cls, values: dict[str, str]) -> dict[str, str]:
        from ops.browser.setup_values import normalize_browser_setup_fields

        return normalize_browser_setup_fields(values)

    @field_validator("signup_fields")
    @classmethod
    def _approved_signup_fields(cls, values: dict[str, str]) -> dict[str, str]:
        from ops.browser.signup import normalize_signup_fields

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
    """Creation-time recipe plus one exact broker grant per captured field."""

    recipe_snapshot: dict[str, object] | None = None
    # Compatibility for older single-field callers.
    broker_grant: str | None = Field(
        default=None,
        min_length=47,
        max_length=47,
        pattern=r"^bsg_[A-Za-z0-9_-]{43}$",
        repr=False,
    )
    broker_grants: dict[str, str] = Field(default_factory=dict, max_length=20, repr=False)

    @model_validator(mode="after")
    def _exact_capture_grants(self) -> CaptureCredentialsRequest:
        if self.broker_grant is not None and self.broker_grants:
            raise ValueError("use either a single or per-field capture grant")
        if self.broker_grant is None and not self.broker_grants:
            raise ValueError("at least one capture grant is required")
        for kind, grant in self.broker_grants.items():
            if (
                re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,99}", kind) is None
                or re.fullmatch(r"bsg_[A-Za-z0-9_-]{43}", grant) is None
            ):
                raise ValueError("capture grant binding is invalid")
        return self


class LiveViewGrant(_Strict):
    """A short-lived, session-bound view or control grant.

    The URL is returned ONCE for immediate operator use and is never durably
    persisted by the API (see ops.browser.live_view).
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
    "ClearanceProbeReason",
    "CreateSessionRequest",
    "DrainStatus",
    "ErrorResponse",
    "GateClearanceReport",
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
