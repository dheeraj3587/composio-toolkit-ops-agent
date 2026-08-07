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

from ops.browser.decider import MAX_ELEMENTS
from ops.browser.host_policy import MAX_ALLOWED_HOST_PATTERNS
from ops.browser.worker import MAX_OBSERVATION_STEPS, HumanActionType
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
    # The run's approved, NON-SECRET value-reference map, in the same closed
    # vocabulary and with the same validator ``NavigateRequest`` uses. Seeded onto
    # the session at creation so a caller driving it one action at a time through
    # observe/act can fill a form at all: outside ``navigate``/``resume`` the map
    # was empty, and ``_approved_value`` could then resolve exactly one reference
    # (``application_name``, derived from the slug) and raised for every other.
    # A value action never carries literal text from a caller — the model emits a
    # reference and the executor resolves it HERE — so this map is the only way
    # text a human approved can reach a page.
    setup_fields: dict[str, str] = Field(default_factory=dict, max_length=20)

    @field_validator("setup_fields")
    @classmethod
    def _approved_setup_fields(cls, values: dict[str, str]) -> dict[str, str]:
        from ops.browser.setup_values import normalize_browser_setup_fields

        return normalize_browser_setup_fields(values)

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
    #
    # Optional since the recipe became able to answer the same question. It used
    # to be required, which forced every caller to carry a full research payload
    # even when it held a reviewed recipe stating the same URLs — the recipe IS
    # the reviewed statement of them, and ``recipe_to_operational_research``
    # already projects one onto this contract. Omitting both is still refused
    # below: the operation has to navigate somewhere, and neither present means
    # no reviewed destination exists.
    research: dict[str, object] | None = None
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
    def _reviewed_destination(self) -> NavigateRequest:
        """One of the two reviewed statements of where this run may go.

        Refused at the wire rather than deep in the drive, because "no research
        and no recipe" is not a policy denial about a page — it is a request that
        never named a destination, and the caller should hear that as a 422.
        """

        if self.research is None and self.recipe_snapshot is None:
            raise ValueError("navigate requires research or a recipe snapshot")
        return self

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


class RetainSessionRequest(_Strict):
    """Keep a bound session ACTIVE across a wait the caller owns.

    The counterpart to closing it. ``SessionManager.retain`` has enforced the
    continuity-event vocabulary since it was written but had no route, so the only
    way to keep a session alive was to keep driving it: a run parked for an email,
    a CAPTCHA, or an API restart had no way to SAY it was still there, and the
    janitor reaped it on the idle clock. The event is validated here against the
    same closed set the manager checks, so a typo is a 422 rather than a silently
    unretained session.
    """

    event: Literal[
        "email_verification",
        "captcha_paused",
        "navigation_retry",
        "worker_restart",
        "api_restart",
        "live_view_client_disconnect",
    ]


class StepRecordModel(_Strict):
    """One action-loop iteration on the wire (mirrors ``BrowserStepRecord``).

    Every bound here is the same bound the dataclass enforces, restated as a
    field constraint so a malformed trail is rejected at the boundary rather
    than raising a ``ValueError`` out of a dataclass constructor on the API
    side. Nothing here is a URL, a selector, or markup: ``target_host`` is a
    hostname with no path or query, ``candidate_label`` is an accessible name
    the snapshot already sanitized, and ``reason`` is the model's own one line
    of prose, which the storage layer re-screens for secret material before it
    is ever written.
    """

    step_index: int = Field(ge=1, le=100_000)
    stage: str = Field(min_length=1, max_length=40)
    elapsed_ms: int = Field(ge=0, le=3_600_000)
    decision: str = Field(min_length=1, max_length=40)
    reason_code: str | None = Field(default=None, min_length=1, max_length=100)
    candidate_label: str | None = Field(default=None, min_length=1, max_length=120)
    action: str | None = Field(default=None, min_length=1, max_length=40)
    target_host: str | None = Field(default=None, min_length=1, max_length=253)
    reason: str | None = Field(default=None, min_length=1, max_length=400)


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
    # What the action loop did on the way here, oldest first. Additive with an
    # empty default, so a worker that reports no trail is exactly unchanged. The
    # cap is the same one the worker enforces when it appends, restated here so
    # the boundary refuses an oversized trail rather than trusting the sender.
    steps: tuple[StepRecordModel, ...] = Field(default=(), max_length=MAX_OBSERVATION_STEPS)
    session: SessionSummary | None = None


class SnapshotElementModel(_Strict):
    """One interactive element on the wire (mirrors ``SnapshotElement``).

    Every field here is already sanitized at its source: ``build_ranked_snapshot``
    collects accessible names through the DLP projection, ``href_path`` is a PATH
    with no query or fragment so a token in a link cannot ride out on it, and no
    field can hold an input's value — ``has_value`` says only WHETHER a non-secret
    field is filled. What deliberately does not appear is the Playwright locator:
    it is a live handle bound to this process's browser loop and has no meaning
    anywhere else, which is why the caller re-identifies its target by
    role/name/type instead of by position.
    """

    index: int = Field(ge=0, le=10_000)
    role: str = Field(max_length=60)
    name: str = Field(max_length=300)
    element_type: str = Field(default="", max_length=60)
    has_value: bool = False
    secretish: bool = False
    visible: bool = True
    enabled: bool = True
    checked: bool | None = None
    selected: bool | None = None
    expanded: bool | None = None
    frame_path: tuple[str, ...] = Field(default=(), max_length=16)
    href_path: str | None = Field(default=None, max_length=500)
    test_id: str | None = Field(default=None, max_length=200)
    nearby_heading: str | None = Field(default=None, max_length=300)
    selected_label: str | None = Field(default=None, max_length=300)


class ObserveResponse(_Strict):
    """One reading of the page, and the generation a matching act must quote.

    The service used to offer only ``navigate`` and ``resume``, each of which ran
    a whole closed loop inside this container — inspect, call a model, act, repeat
    — so a planner outside the process could not take a single step; it could only
    hand over the wheel and read the outcome. This is the observe half of the pair
    that makes one step possible.

    ``generation`` and ``url`` are the load-bearing fields, not decoration: the
    caller sends them back on the act request, and the executor refuses to act if
    the page has moved since. Without them the staleness check would compare a
    fresh reading against itself and pass every time.
    """

    url: str = Field(max_length=2000)
    title: str = Field(default="", max_length=500)
    visible_text: str = Field(default="", max_length=20_000)
    fingerprint: str = Field(default="", max_length=128)
    generation: int = Field(ge=0)
    elements: tuple[SnapshotElementModel, ...] = Field(default=(), max_length=MAX_ELEMENTS)
    session: SessionSummary | None = None


class ElementIdentityModel(_Strict):
    """The stable identity an act request re-resolves its target by."""

    role: str = Field(max_length=60)
    name: str = Field(max_length=300)
    element_type: str = Field(default="", max_length=60)
    frame_path: tuple[str, ...] = Field(default=(), max_length=16)
    test_id: str | None = Field(default=None, max_length=200)
    href_path: str | None = Field(default=None, max_length=500)
    nearby_heading: str | None = Field(default=None, max_length=300)


class ActionCandidateModel(_Strict):
    """One action to execute, described only in terms the executor can verify.

    Note what a caller CANNOT say here. There is no selector and no positional
    index: the target is named by role/name/type and must resolve to exactly one
    element or the request comes back ``stale``. There is no literal text: a value
    action carries a ``value_ref`` that is resolved against the session's reviewed
    approved-value map, so a caller cannot type a string of its own choosing and
    cannot reach a credential. A ``url`` is re-checked against the session's
    reviewed navigation patterns before the request is issued.

    There is also no ``risk``. The executor never read it, and accepting one would
    imply the sender's own verdict about its own action is authoritative — which
    is exactly the thing the risk policy exists to not do.
    """

    candidate_id: str = Field(min_length=1, max_length=64)
    action: Literal[
        "click",
        "fill",
        "type",
        "press",
        "goto",
        "select_option",
        "check",
        "uncheck",
        "scroll_into_view",
        "focus",
    ]
    semantic_target: str = Field(default="", max_length=300)
    identity: ElementIdentityModel | None = None
    value_ref: str | None = Field(default=None, max_length=100)
    press_key: str | None = Field(default=None, max_length=40)
    url: str | None = Field(default=None, max_length=2000)
    hint_index: int | None = Field(default=None, ge=0, le=10_000)

    @model_validator(mode="after")
    def _target_is_addressable(self) -> ActionCandidateModel:
        # ``goto`` is the one action that names a destination instead of an
        # element; every other action must resolve one, and an act request with
        # neither would reach the executor only to fail there with a less specific
        # reason than the boundary can give.
        if self.action == "goto":
            if not self.url:
                raise ValueError("a goto candidate needs a url")
        elif self.identity is None:
            raise ValueError("a non-goto candidate needs an element identity")
        return self


class ActRequest(_Strict):
    """Execute one candidate against the observation that planned it.

    ``observed_url`` and ``observed_generation`` are required and unfaked: they
    are the caller's statement of what it planned against, and the executor
    re-inspects and holds it to them.
    """

    candidate: ActionCandidateModel
    observed_url: str = Field(min_length=1, max_length=2000)
    observed_generation: int = Field(ge=0)


class ActionExecutionResultModel(_Strict):
    """The typed outcome of one action (mirrors ``ActionExecutionResult``).

    Four statuses, each meaning something the caller must respond to differently
    — which is the whole point of returning them separately. ``executed`` ran;
    ``stale`` means the page moved and the plan must be remade against a fresh
    observation; ``blocked`` means policy refused it and a different action is
    needed; ``failed`` means the action itself did not complete.
    """

    status: Literal["executed", "stale", "blocked", "failed"]
    candidate_id: str = Field(max_length=64)
    before_url: str = Field(default="", max_length=2000)
    after_url: str = Field(default="", max_length=2000)
    before_generation: int = Field(ge=0)
    after_generation: int = Field(ge=0)
    reason_code: str | None = Field(default=None, max_length=100)
    expected_selected_label: str | None = Field(default=None, max_length=300)
    session: SessionSummary | None = None


class ArmCredentialSurfaceRequest(_Strict):
    """The reviewed recipe whose success predicate must hold to arm the surface."""

    recipe_snapshot: dict[str, object] | None = None


class CredentialSurfaceResponse(_Strict):
    """Whether the credential surface is armed, and whether pixels are permitted.

    Both facts are reported because they answer different questions and can differ:
    ``armed`` says capture may run, ``live_view_allowed`` says a human may still
    see the screen. Arming turns the second off; a proven release turns it back on.
    """

    armed: bool
    live_view_allowed: bool
    # A closed, non-secret code. Empty on success; on refusal it says which proof
    # failed — never what was on the page.
    reason_code: str = Field(default="", max_length=100)
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
    "ActRequest",
    "ActionCandidateModel",
    "ActionExecutionResultModel",
    "ArmCredentialSurfaceRequest",
    "CaptureCredentialsResponse",
    "ClearanceProbeReason",
    "CreateSessionRequest",
    "CredentialSurfaceResponse",
    "DrainStatus",
    "ElementIdentityModel",
    "ErrorResponse",
    "GateClearanceReport",
    "HealthResponse",
    "LiveViewGrant",
    "LiveViewMode",
    "NavigateRequest",
    "ObservationResponse",
    "ObserveResponse",
    "ProviderHealthState",
    "ReconcileSessionsRequest",
    "ReconcileSessionsResponse",
    "ResumeRequest",
    "RetainSessionRequest",
    "SessionLifecycle",
    "SessionSummary",
    "SnapshotElementModel",
]
