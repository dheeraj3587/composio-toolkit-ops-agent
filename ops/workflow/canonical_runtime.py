"""Canonical SQLite-backed execution for reviewed app recipes.

New runs use this service directly.  The database transaction boundary is kept
deliberately small: intent/state is committed first, provider I/O happens with no
SQLite transaction open, and the sanitized outcome is appended afterward.  Raw
credentials cross only the existing one-shot Playwright/vault boundaries.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import secrets
import threading
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Literal, Protocol, cast, get_args
from uuid import uuid4

from pydantic import SecretStr

from ops.access.gated_route import GatedRoute, GatedRoutePolicyError
from ops.browser.account_binding import (
    derive_browser_account_ref,
    validate_browser_account_ref,
)
from ops.browser.link_log import log_event
from ops.browser.provider import BrowserProvider as BrowserWorker
from ops.browser.readiness import browser_configuration_state
from ops.browser.setup_values import browser_setup_values
from ops.browser.signup import normalize_signup_fields
from ops.browser.worker import (
    HOST_POLICY_REASON_CODE,
    MAX_OBSERVATION_STEPS,
    BrowserObservation,
    BrowserSessionContext,
    HumanActionType,
)
from ops.core.logging_setup import run_context
from ops.core.model_catalog import ModelSelection
from ops.core.models import OperationalResearch, OperationsRequest
from ops.core.secret_store import AccountLoginStateError, SQLiteSecretStore, parse_vault_reference
from ops.core.state import BrowserProvider, RunStatus
from ops.core.storage import (
    CANDIDATE_ACTION_VALUES,
    MAX_PROGRESS_STEP_INDEX,
    OperationsStorage,
    OperationsUnitOfWork,
)
from ops.onboarding.composition import OnboardingPorts, build_onboarding_ports
from ops.onboarding.driver import RunPlanningPorts, SQLitePhaseHistoryStore, plan_admission
from ops.onboarding.phase import (
    INITIAL_PHASE,
    ONBOARDING_REASON_CODES,
    OnboardingPhase,
    OnboardingReasonCode,
    is_legal_phase_transition,
)
from ops.planner.adherence import AdherenceOutcome
from ops.planner.plan import RunPlan, canonical_surface
from ops.providers.composio_managed_auth import (
    ComposioManagedAuthProvider,
    validate_managed_auth_callback_base_url,
)
from ops.providers.errors import ConfigurationRequiredError
from ops.recipes.app_recipes import (
    AppRecipe,
    get_app_recipe,
    get_app_recipe_for_name,
    load_app_recipe_catalog,
    recipe_to_operational_research,
)
from ops.research.p1_adapter import P1LookupFound, P1OperationalAdapter
from ops.runs.errors import (
    CredentialSubmissionError,
    IdempotencyConflictError,
    ProviderReadinessError,
    RunConflictError,
)
from ops.runs.idempotency import (
    _legacy_request_fingerprints,
    _request_fingerprint,
    validate_idempotency_key,
)
from ops.runs.liveness import AWAITING_OWNER_PHASES
from ops.runs.projections import _PERSISTED_EXECUTION_MODE, _public_run, _slugify
from ops.runs.recipe_snapshot import (
    RecipeSnapshotError,
    build_recipe_snapshot,
    recipe_from_run,
)
from ops.workflow.integrator import build_integrator_bundle

ExecutionMode = Literal["plan_only", "execute_when_configured"]
# Runtime mirror of ``HumanActionType``, derived from the type itself rather than
# hand-listed, so a gate added in ops.browser.worker stays recognized here instead
# of being downgraded to ``provider_verification`` by the resume path below.
_HUMAN_ACTION_TYPES: frozenset[str] = frozenset(get_args(HumanActionType))
_STALE_ROUTE_OBSERVATION: Final = object()

# The one onboarding phase every canonical browser step is filed under, and the
# one correlation id that joins a progress event to its decision.
#
# Both are constants on purpose. The canonical runtime's phase strings are a
# different vocabulary from ONBOARDING_PHASES, so any per-step mapping would be
# invented rather than observed; and because ``step_index`` is made unique across
# a run's drives before it is written, the correlation id carries no further
# distinguishing work. ``developer_app`` is the phase every canonical browser
# drive is actually working toward: reaching the vendor's own application or API
# settings surface.
_CANONICAL_TELEMETRY_PHASE: Final = "developer_app"
_CANONICAL_TELEMETRY_CORRELATION_ID: Final = "canonical-browser-loop"

# The correlation id every canonical phase boundary is filed under.
#
# One constant, and that is what makes the boundary writes idempotent for free:
# ``onboarding_phase_history`` is unique on
# ``(run_id, COALESCE(from_phase, ''), to_phase, attempt, correlation_id)``, so a
# boundary this runtime re-derives after a restart, a duplicated observation, or
# a re-entered code path collides with the row already there and comes back as
# ``False`` — the store's own replay no-op — instead of appending a second copy.
_CANONICAL_PHASE_CORRELATION_ID: Final = "canonical-phase-boundary"

# The onboarding-vocabulary spine a canonical run walks, in order.
#
# Why a spine rather than a table keyed by the runtime's own phase strings: the
# canonical runtime has ~28 phase strings and ``ops.onboarding.phase`` has 17,
# and the legal-transition table refuses all but a handful of pairs. Naming the
# ordered sequence instead means every consecutive pair here is legal by
# construction, so advancing along it can never raise ``IllegalPhaseTransition``
# and can never need a transition the state machine does not already declare.
#
# Nothing here is invented: each of these is a fact the canonical runtime proves
# before the boundary is written — the run was created from reviewed research,
# the vault was consulted for a stored login, a browser session was created on
# the recipe's login entry, the vendor's own in-policy surface answered, the
# credential surface was reached, a credential was captured, vaulted, and
# validated.
_CANONICAL_PHASE_SPINE: Final[tuple[OnboardingPhase, ...]] = (
    "research",
    "vault_check",
    "route_selected_login",
    "authenticated",
    "developer_app",
    "credential_generation",
    "vault_storage",
    "credential_validation",
    "completed",
)
_CANONICAL_SPINE_INDEX: Final[dict[OnboardingPhase, int]] = {
    phase: index for index, phase in enumerate(_CANONICAL_PHASE_SPINE)
}

# The reason code an intermediate spine boundary carries when it is crossed on
# the way to a later one. Every member is in ``OnboardingReasonCode`` and names
# what that phase established, so the console never renders a code invented here.
_CANONICAL_SPINE_REASON: Final[dict[OnboardingPhase, OnboardingReasonCode]] = {
    "research": "profile_corroborated",
    "vault_check": "credentials_present",
    "route_selected_login": "session_recreated",
    "authenticated": "host_in_app_policy",
    "developer_app": "developer_app_created",
    "credential_generation": "credential_generated",
    "vault_storage": "credential_stored",
    "credential_validation": "credential_valid",
    "completed": "credential_valid",
}

# Which projected browser outcome crosses which onboarding boundary.
#
# Deliberately partial. ``target_probe_pending`` crosses nothing — the run is
# still inside the phase it was already in. ``failed``, ``blocked``,
# ``effect_reconciliation``, ``host_policy_review_required`` and
# ``credential_validation_failed`` are canonical-only recovery states with no
# onboarding counterpart: ``blocked`` in particular is reachable in the
# transition table only from ``research`` and ``vault_check``, so claiming it for
# a run that already opened a browser would be a boundary the state machine does
# not admit. Those outcomes leave the history at the last boundary that was
# actually proven, which is the honest reading.
_CANONICAL_OUTCOME_BOUNDARY: Final[dict[str, tuple[OnboardingPhase, OnboardingReasonCode]]] = {
    "challenge_pending": ("captcha_paused", "captcha_detected"),
    "entry_reached": ("developer_app", "developer_app_created"),
    "credential_ready": ("developer_app", "developer_app_created"),
    "completed": ("completed", "credential_valid"),
}

# Phases :meth:`CanonicalRuntime.retry_browser_run` refuses to restart from.
#
# This was an ALLOW-list of four phases — browser_unavailable, browser_start_failed,
# failed, session_lost — which are the four ways Chromium itself dies. Nine other
# phases also write ``configuration_required``: effect_reconciliation,
# login_credential_staging, signup_identity_required, login_account_selection,
# signup_login_promotion, login_credential_promotion, plan_refused,
# outreach_send_failed and credential_validation_failed. Every one of them named a
# state the operator was explicitly told to recover from, and every one of them
# answered Retry with ``browser_retry_requires_reconciliation`` — the run was
# recoverable by design and unrecoverable in practice.
#
# Inverting it makes the default *recoverable*, which is the right default for a
# status whose whole meaning is "an operator can fix this". A retry is safe by
# construction for these nine: the docstring invariant below holds regardless of
# phase — each attempt takes a fresh effect identity while capture reconciliation
# stays bound to the run, so a restart cannot duplicate a credential-generation
# side effect. ``effect_reconciliation`` is the one phase that names an ambiguous
# external outcome rather than a local failure, so it gets its own check.
#
# What stays denied, and why each is not merely an omission:
#   blocked           - terminal by policy; ops/core/state.py gives it no outgoing
#                       status transition, so a restart would be refused downstream
#                       anyway, with a worse error.
#   completed         - there is nothing to retry, and re-running a finished trace
#                       would act on the vendor a second time.
#   credential_ready  - the run is parked on the page a human was asked to visit.
#   entry_reached       Restarting throws away exactly the submission window
#                       AWAITING_OWNER_PHASES in ops/runs/liveness.py exists to
#                       protect. Same invariant, enforced against the operator's
#                       own button instead of against a sweep.
RETRY_DENIED_PHASES: Final[frozenset[str]] = frozenset(
    {"blocked", "completed", "credential_ready", "entry_reached"}
)


def _projection_discard_reason(
    record: Mapping[str, Any] | None,
    *,
    session_id: str,
    projection_effect_identity: str | None,
    expected_state_revision: int | None,
) -> str | None:
    """Which compare-and-set guard refuses this projection, or ``None`` to write it.

    Extracted from the boolean chain it replaces so that a lost race can SAY which
    guard it lost on. The conditions and their order are unchanged; only the return
    type is, from "may I write" to "why may I not". Every code is a fixed internal
    token and carries no run data, so it is safe to persist in an audit payload.
    """

    if record is None:
        return "run_row_absent"
    if record.get("state_engine") != "canonical_v1":
        return "run_is_not_canonical"
    if record.get("browser_provider") != "playwright":
        return "run_is_not_playwright"
    if record.get("browser_session_id") != session_id:
        # A different browser session is bound to the run than the one that
        # produced this observation.
        return "session_rebound"
    if str(record.get("status") or "") not in {"browser_running", "waiting_for_hitl"}:
        return "run_left_browser_statuses"
    if (
        projection_effect_identity is not None
        and record.get("effect_identity") != projection_effect_identity
    ):
        # Typically a retry: ``retry_browser_run`` mints a fresh effect identity, so
        # the previous attempt's projection must not land on the new attempt.
        return "effect_identity_superseded"
    if (
        expected_state_revision is not None
        and int(record.get("state_revision", 0) or 0) != expected_state_revision
    ):
        return "state_revision_superseded"
    return None


# The statuses a discarded projection may durably annotate.
#
# Both mean the same thing: whatever took this row away from the browser has
# already STOPPED it, so no writer is stepping it any more and a phase written
# here fights nobody. Every other discard reason leaves the run inside a browser
# status with a live writer that won the race, and the loser must not overwrite
# the winner — which is why the annotation below is conditional rather than
# unconditional. ``completed`` and ``blocked`` are excluded by the same rule:
# they are terminal, and re-phasing a terminal run would resurrect it.
_RECONCILABLE_DISCARD_STATUSES: Final[frozenset[str]] = frozenset(
    {"failed", "configuration_required"}
)


def _record_discarded_credential_custody(
    transaction: OperationsUnitOfWork,
    run_id: str,
    *,
    record: Mapping[str, Any],
    outcome: _AppliedBrowserOutcome,
    discard_reason: str,
) -> None:
    """Keep custody of a credential whose projection lost its compare-and-set.

    The dangerous discard is the one that happens AFTER automatic capture: the
    vendor has issued a key, the worker has written it to the vault, and the
    side-effect ledger says ``completed``/``credential_vaulted`` — and then the
    projection carrying the references loses the race and is dropped. The ledger
    row alone is not enough to recover from: it proves a credential exists but
    not where, because the id inside a ``vault://`` reference is minted per write
    and cannot be re-derived. Losing the references orphans a live secret — one
    nobody can hand to the integrator and nobody can revoke.

    Two durable facts are written, and the second one deliberately only
    sometimes:

    * **The custody event, always.** ``credential_refs`` is a mapping of
      ``vault://`` pointers, which is exactly what ``credentials_stored``
      already persists on the happy path and what the redactor keeps rather
      than masks (``ops/core/redaction.py`` ``_is_reference_payload``). No value
      is written here, only the address of one.
    * **The phase, only on a run that has already stopped.** A run still inside
      a browser status has a live writer that won this race, and annotating it
      would be the loser overwriting the winner one level up. A run the sweeps
      or a failure already parked at ``failed``/``configuration_required`` has
      no such writer, and there ``effect_reconciliation`` is the phase that says
      what is true — a credential exists and the run has not accounted for it.
      That phase is also the one ``retry_browser_run`` reconciles rather than
      blindly restarts, so the annotation is what makes the run recoverable from
      the operator's Retry instead of merely explicable in the audit log.
    """

    refs = dict(outcome.vaulted_credential_refs or {})
    if not refs:
        return
    transaction.append_audit_event(
        run_id=run_id,
        event_type="credential_reconciliation_required",
        payload={
            "reason_code": "credential_vaulted_projection_discarded",
            "discard_reason_code": discard_reason,
            "kinds": sorted(refs),
            "credential_refs": dict(sorted(refs.items())),
            "effect_identity": outcome.effect_identity,
            "external_actions": True,
        },
    )
    if str(record.get("status") or "") not in _RECONCILABLE_DISCARD_STATUSES:
        return
    revision = int(record.get("state_revision", 0) or 0) + 1
    transaction.update_run(
        run_id,
        phase="effect_reconciliation",
        reason_code="credential_vaulted_projection_discarded",
        external_actions=True,
        state_revision=revision,
        last_projected_revision=revision,
    )


def _canonical_profile_digest(app_slug: str) -> str:
    """The profile digest every canonical row for one app is filed under.

    Derived rather than looked up, for the reason ``_record_step_telemetry``
    already states: the digest is never projected to the API, it exists to
    satisfy the storage validator and to join a run's rows to each other, so
    deriving it from the recipe slug keeps it stable across drives without
    pretending a research profile was involved. Shared with the telemetry writer
    so a run's progress events and its phase history carry the same value.
    """

    return hashlib.sha256(f"canonical_v1:{app_slug}".encode()).hexdigest()


def _next_phase_boundary(phase: OnboardingPhase, target: OnboardingPhase) -> OnboardingPhase | None:
    """The one boundary to commit next on the way from ``phase`` to ``target``.

    ``None`` means there is no legal way forward, and the caller then records
    nothing rather than forcing a transition the state machine refuses.

    Three cases, in the order they are tried:

    * the direct boundary is already legal — take it;
    * both phases sit on the spine and the target is ahead — take one step
      along the spine, which is legal by the spine's construction;
    * ``phase`` is off the spine (a CAPTCHA pause is the only way that happens
      today) — rejoin at the furthest spine phase the pause may legally reach
      without overshooting the target.
    """

    if is_legal_phase_transition(phase, target):
        return target
    there = _CANONICAL_SPINE_INDEX.get(target)
    if there is None:
        return None
    here = _CANONICAL_SPINE_INDEX.get(phase)
    if here is not None:
        return _CANONICAL_PHASE_SPINE[here + 1] if there > here else None
    rejoin = [
        candidate
        for candidate in _CANONICAL_PHASE_SPINE[:there]
        if is_legal_phase_transition(phase, candidate)
    ]
    return rejoin[-1] if rejoin else None


class CanonicalRuntimeContext(Protocol):
    storage: OperationsStorage
    p1_adapter: P1OperationalAdapter
    _settings: Any
    _browser_threads: list[threading.Thread]
    _secret_store: SQLiteSecretStore | None
    _credential_validator: Any
    _managed_auth_provider: ComposioManagedAuthProvider | None
    _gmail_worker: Any

    def _run_lock(self, run_id: str) -> Any: ...

    def _browser_worker_for(
        self, source: Mapping[str, object] | BrowserProvider
    ) -> BrowserWorker | None: ...

    def _browser_login_payload(
        self,
        *,
        provider: BrowserProvider,
        app_slug: str,
        scope_id: str,
        values: Mapping[str, SecretStr],
    ) -> dict[str, str]: ...

    def _remember_reusable_login(
        self,
        *,
        app_slug: str,
        account_ref: str,
        values: Mapping[str, SecretStr],
    ) -> tuple[str, ...]: ...

    def _reusable_login_values(self, app_slug: str, account_ref: str) -> dict[str, SecretStr]: ...

    def _stage_signup_login(
        self,
        *,
        app_slug: str,
        account_ref: str,
        run_id: str,
        values: Mapping[str, SecretStr],
    ) -> dict[str, SecretStr]: ...

    def _staged_signup_login_values(
        self,
        *,
        app_slug: str,
        account_ref: str,
        run_id: str,
    ) -> dict[str, SecretStr]: ...

    def _promote_staged_signup_login(
        self,
        *,
        app_slug: str,
        account_ref: str,
        run_id: str,
    ) -> tuple[str, ...]: ...

    def gmail_signup_preflight(self, *, timeout_seconds: float = 10.0) -> Any: ...

    def _finalize_captured_credentials(
        self,
        research: OperationalResearch,
        request: OperationsRequest,
        credential_refs: Mapping[str, str],
        *,
        recipe: AppRecipe,
    ) -> Any: ...

    def _session_context_for(self, run_id: str) -> BrowserSessionContext | None: ...

    def _release_browser_session(
        self,
        context: BrowserSessionContext | None,
        provider: BrowserProvider,
        *,
        reason: str,
    ) -> None: ...

    def observe_run_surface(
        self, *, run_id: str, step_index: int, observed_url: str
    ) -> AdherenceOutcome: ...

    def replan_run_route(
        self,
        *,
        run_id: str,
        recipe: AppRecipe,
        expected_state_revision: int,
        expected_effect_identity: str | None,
        evidence: str = "",
    ) -> bool | None: ...


@dataclass(frozen=True, slots=True)
class _AppliedBrowserOutcome:
    status: RunStatus
    phase: str
    reason_code: str
    provider_browser: str
    # The exact durable operation whose result may still be projected. A worker
    # response arriving after another operation took ownership of the run is
    # discarded instead of overwriting newer state.
    effect_identity: str | None = None
    # Only the exact run revision evaluated by this observation may be projected.
    expected_state_revision: int | None = None
    hitl: dict[str, object] | None = None
    changes: Mapping[str, object] | None = None
    events: tuple[tuple[str, Mapping[str, object]], ...] = ()
    # The ``vault://`` pointers to material that is ALREADY in the vault by the
    # time this outcome exists. Automatic capture writes the secret inside the
    # browser worker, so from the moment it returns references the vault holds a
    # value whose only address is this mapping: the id in a reference is minted
    # per put() and cannot be re-derived from the app slug or the account.
    # Carrying it here is what lets the projection's discard branch record the
    # custody fact instead of dropping the last copy of the address (item 1.6).
    # References, never values — the same boundary every audit payload uses.
    vaulted_credential_refs: Mapping[str, str] | None = None


@dataclass(frozen=True, slots=True)
class _RouteAdherenceOverride:
    """Adherence override plus the run revision it leaves authoritative."""

    outcome: _AppliedBrowserOutcome | None
    expected_state_revision: int


def _recipe_version() -> str:
    catalog = load_app_recipe_catalog()
    return f"{catalog.catalog_id}@{catalog.schema_version}"


def _access_route(recipe: AppRecipe) -> str:
    if recipe.route_kind == "gated":
        return "approval_required"
    return "self_serve"


def _initial_reason(recipe: AppRecipe) -> str:
    if recipe.route_kind == "managed_auth":
        return "managed_connection_required"
    if recipe.route_kind == "gated":
        return (
            "controlled_outreach_ready"
            if recipe.readiness_tier == "outreach_ready"
            else "outreach_contact_review_required"
        )
    return (
        "reviewed_browser_route_ready"
        if recipe.readiness_tier == "browser_ready"
        else "owner_submission_route_ready"
    )


def _safe_reason(exc: BaseException, fallback: str) -> str:
    reason = getattr(exc, "reason_code", None)
    if isinstance(reason, str) and reason and len(reason) <= 100:
        return reason
    return fallback


def _signup_fields_for(request: OperationsRequest) -> dict[str, str]:
    """Project the approved non-secret company fields into the browser contract."""

    if not request.account_creation_requested:
        return {}
    values: dict[str, object] = {
        "company_name": request.company.legal_name,
        "company_website": request.company.website,
        "use_case": request.company.use_case,
    }
    if request.company.expected_volume:
        values["expected_volume"] = request.company.expected_volume
    return normalize_signup_fields(values)


def _setup_fields_for(request: OperationsRequest, recipe: AppRecipe) -> dict[str, str]:
    """Project immutable non-secret values into browser setup references."""

    company = request.company
    return browser_setup_values(
        request.provider_setup,
        company_name=company.legal_name,
        company_website=company.website,
        use_case=company.use_case,
        expected_volume=company.expected_volume,
        callback_urls=company.callback_urls,
        app_slug=recipe.app_slug,
    )


class CanonicalRuntime:
    """Execute managed, Playwright and gated recipes without LangGraph."""

    def __init__(
        self,
        context: CanonicalRuntimeContext,
        *,
        planning: RunPlanningPorts | None = None,
    ) -> None:
        self._context = context
        self._planning = planning
        self._onboarding_ports: OnboardingPorts | None = None
        self._phases: SQLitePhaseHistoryStore | None = None
        self._phases_lock = threading.Lock()

    def onboarding_ports(self) -> OnboardingPorts:
        """Bind the onboarding ports from this runtime's own settings and vault.

        The application-boundary composition for a process that already holds the
        run ledger and the credential vault: the durable stores are opened against
        the same ledger file this runtime writes, and the vault handle is reused
        rather than re-derived, so the run's phase history, its leases, its profile
        store, and its secrets cannot end up pointing at different files.

        Built once per runtime and cached: the ports are handles over SQLite files
        rather than open connections, so sharing them across runs is what keeps a
        worker from re-opening five databases per claim. Which ports are absent —
        and why — is reported on :attr:`OnboardingPorts.unavailable` rather than
        raised, because a deployment with no mailbox or no model key can still
        serve its API and refuse the phases it cannot drive.
        """

        if self._onboarding_ports is None:
            self._onboarding_ports = build_onboarding_ports(
                self._context._settings,
                ledger_path=self._context.storage.db_path,
                secret_store=self._context._secret_store,
            )
        return self._onboarding_ports

    def _phase_store(self) -> SQLitePhaseHistoryStore | None:
        """The run ledger's phase history, opened once per runtime.

        The SAME store the API reads through ``_ApiOnboardingProjection`` and the
        same one the phase driver writes through — opened against this runtime's
        own ledger path so there is exactly one ``onboarding_phase_history`` for a
        deployment. Opened lazily rather than in ``__init__`` because it runs the
        ledger DDL, and returned as ``None`` if that fails: phase history is a
        console projection, and a run must not fail because its projection could
        not be opened.
        """

        with self._phases_lock:
            if self._phases is None:
                try:
                    self._phases = SQLitePhaseHistoryStore(self._context.storage.db_path)
                except Exception:  # pragma: no cover - a ledger that cannot be opened
                    return None
            return self._phases

    def _commit_phase_boundary(
        self,
        run_id: str,
        *,
        target: OnboardingPhase,
        reason_code: OnboardingReasonCode,
        app_slug: str,
        attempt: int = 0,
    ) -> None:
        """Record the onboarding boundaries this run has now provably crossed.

        Why this exists at all: ``api.service`` decides a run is an onboarding run
        exactly when ``SQLitePhaseHistoryStore.history`` is non-empty for it, and
        the only writer of that table was the phase driver, which
        ``api/app.py`` refuses. Every live run therefore had empty history, which
        made reset, pause, decision and retry-step answer ``phase_unavailable``
        and left the console's agent panel blank. Committing the boundaries the
        canonical runtime already proves closes that without any driver work.

        Three properties, each of which is a constraint rather than a preference:

        * **It is called only after a compare-and-set has already won.** Every
          call site sits after its unit of work has committed. A projection that
          loses its CAS returns before reaching here, so a lost race can never
          leave a history row describing work the run never recorded — the same
          ordering, and the same reason, as ``_record_step_telemetry``.
        * **It opens its own transaction, never a nested one.** The store takes
          its own ``BEGIN IMMEDIATE`` on its own connection; calling it inside an
          open ``unit_of_work`` would have two writers of ``ops.db`` in one
          thread. Because it is outside the run's transaction it also cannot
          abort, delay, or roll back a projection: the worst a failure here does
          is leave the console a boundary short.
        * **It never raises and never forces a transition.** Illegal boundaries
          are declined by :func:`_next_phase_boundary` rather than pushed at the
          store, a replay stops the walk (the row is already durable), and every
          remaining failure is swallowed into a log line.
        """

        store = self._phase_store()
        if store is None:
            return
        digest = _canonical_profile_digest(app_slug)
        try:
            current = store.current_phase(run_id=run_id)
            phase = None if current is None else current[0]
            if phase is None:
                # A run's history necessarily opens at INITIAL_PHASE: it is the
                # only phase the transition table admits from no phase at all.
                if not store.commit_phase(
                    run_id=run_id,
                    from_phase=None,
                    to_phase=INITIAL_PHASE,
                    reason_code=_CANONICAL_SPINE_REASON[INITIAL_PHASE],
                    profile_digest=digest,
                    attempt=attempt,
                    correlation_id=_CANONICAL_PHASE_CORRELATION_ID,
                ):
                    return
                phase = INITIAL_PHASE
            # Bounded by the spine's length: the walk advances by one boundary per
            # iteration and stops on a replay, so it cannot spin.
            for _ in range(len(_CANONICAL_PHASE_SPINE)):
                if phase == target:
                    return
                step = _next_phase_boundary(phase, target)
                if step is None:
                    return
                if not store.commit_phase(
                    run_id=run_id,
                    from_phase=phase,
                    to_phase=step,
                    reason_code=(reason_code if step == target else _CANONICAL_SPINE_REASON[step]),
                    profile_digest=digest,
                    attempt=attempt,
                    correlation_id=_CANONICAL_PHASE_CORRELATION_ID,
                ):
                    # The store rolled its own unit of work back and the boundary
                    # is already durable, so there is nothing left to add here.
                    return
                phase = step
        except Exception:  # pragma: no cover - a projection must not fail a run
            log_event("canonical.phase_history.not_recorded", run_id=run_id)

    @staticmethod
    def _requires_broker_grants(worker: object) -> bool:
        return bool(getattr(worker, "requires_secret_broker_grants", False))

    def _discard_pre_dispatch_browser_secrets(
        self,
        *,
        sensitive: dict[str, str] | None,
        app_slug: str,
        run_id: str,
        transient: bool,
    ) -> None:
        """Best-effort rollback for a payload that never reached the worker.

        The scoped store operation can only delete an unconsumed one-time row
        matching this exact run, app, and browser-login field. Durable/reusable
        credentials are therefore outside the deletion surface. Callers must
        transfer ownership to the worker immediately before invoking navigation
        or resume and must never use this rollback after that point.
        """

        if sensitive is None:
            return
        try:
            store = self._context._secret_store
            if transient and store is not None:
                for field_name, reference in tuple(sensitive.items()):
                    with contextlib.suppress(Exception):
                        store.delete_transient(
                            reference,
                            expected_app_slug=app_slug,
                            expected_kind=f"browser_login_{field_name}",
                            expected_scope_id=run_id,
                        )
        finally:
            sensitive.clear()

    def _reserve_consume_grants_locked(
        self,
        *,
        worker: object,
        operation_key: str,
        run_id: str,
        session_id: str,
        app_slug: str,
        references: Mapping[str, str] | None,
    ) -> dict[str, str]:
        """Reserve exact one-time-secret grants while the caller owns the run lock."""

        if not self._requires_broker_grants(worker):
            return {}
        if not references:
            return {}
        store = self._context._secret_store
        if store is None:
            raise CredentialSubmissionError("secret_vault_required_for_browser_service")
        grants: dict[str, str] = {}
        for field_name, reference in references.items():
            expected_kind = f"browser_login_{field_name}"
            try:
                parts = parse_vault_reference(reference)
            except ValueError:
                raise CredentialSubmissionError("malformed_vault_reference") from None
            if parts.app_slug != app_slug or parts.kind != expected_kind:
                raise CredentialSubmissionError("browser_secret_reference_binding_mismatch")
            grants[field_name] = store.reserve_browser_secret_grant(
                operation_key=f"{operation_key}:consume:{field_name}",
                run_id=run_id,
                session_id=session_id,
                app_slug=app_slug,
                kind=expected_kind,
                action="consume",
                reference=reference,
            )
        return grants

    def _reserve_capture_grants_locked(
        self,
        *,
        worker: object,
        operation_key: str,
        run_id: str,
        session_id: str,
        recipe: AppRecipe,
    ) -> dict[str, str]:
        """Reserve one idempotent broker grant for every captured field."""

        if not self._requires_broker_grants(worker):
            return {}
        store = self._context._secret_store
        field_kinds = tuple(field.field_name for field in recipe.capture.capture_fields)
        if store is None or not field_kinds:
            raise CredentialSubmissionError("automatic_capture_grant_unavailable")
        return {
            field_kind: store.reserve_browser_secret_grant(
                operation_key=f"{operation_key}:capture:{field_kind}",
                run_id=run_id,
                session_id=session_id,
                app_slug=recipe.app_slug,
                kind=field_kind,
                action="capture",
            )
            for field_kind in field_kinds
        }

    def _bound_browser_record_locked(
        self,
        *,
        run_id: str,
        session_id: str,
        statuses: frozenset[str],
        phases: frozenset[str] | None = None,
        effect_identity: str | None = None,
        state_revision: int | None = None,
    ) -> dict[str, Any] | None:
        """Return the authoritative row only while the exact browser op owns it.

        The caller must hold the per-run lock. This small predicate is shared by
        reservation and projection so a delayed worker response cannot be applied
        to a replacement session or a later operation that happens to use the same
        broad phase name.
        """

        record = self._context.storage.get_run(run_id)
        if record is None:
            return None
        if (
            record.get("state_engine") != "canonical_v1"
            or record.get("browser_provider") != "playwright"
            or record.get("browser_session_id") != session_id
            or str(record.get("status") or "") not in statuses
            or (phases is not None and str(record.get("phase") or "") not in phases)
            or (effect_identity is not None and record.get("effect_identity") != effect_identity)
            or (
                state_revision is not None
                and int(record.get("state_revision", 0) or 0) != state_revision
            )
        ):
            return None
        return record

    def recipe_for_request(self, request: OperationsRequest) -> AppRecipe | None:
        return get_app_recipe_for_name(request.app_name) or get_app_recipe(
            _slugify(request.app_name)
        )

    @staticmethod
    def _recipe_for_run(record: Mapping[str, Any]) -> AppRecipe:
        try:
            return recipe_from_run(record)
        except RecipeSnapshotError as exc:
            raise CredentialSubmissionError(exc.reason_code) from None

    def _continue_pristine_playwright_run(
        self,
        record: Mapping[str, Any],
        *,
        browser_login: Mapping[str, SecretStr] | None,
    ) -> dict[str, Any] | None:
        """Dispatch a committed Playwright run whose first effect never started.

        A durable run can exist before login staging/browser dispatch because
        provider I/O intentionally happens after the creation transaction. Only
        the pristine ``attempt=0`` state with no reserved effect is safe to
        continue automatically. Any evidence that an effect was reserved is an
        unknown-outcome boundary and is moved to explicit reconciliation.
        """

        if (
            record.get("state_engine") != "canonical_v1"
            or record.get("execution_mode") != "operations"
            or record.get("route_kind") != "playwright"
            or record.get("browser_provider") != "playwright"
            or record.get("status") != "route_selected"
        ):
            return None
        run_id = str(record.get("run_id") or "")
        if not run_id:
            return None
        attempt = int(record.get("attempt", 0) or 0)
        first_effect = self._context.storage.get_side_effect(
            run_id,
            f"{run_id}:browser-start:v1",
        )
        phase = str(record.get("phase") or "")
        if (
            attempt != 0
            or first_effect is not None
            or bool(record.get("effect_identity"))
            or phase != "browser_pending"
        ):
            return self._record_provider_failure(
                run_id,
                status="configuration_required",
                phase="effect_reconciliation",
                reason_code="browser_start_reconciliation_required",
                external_actions=first_effect is not None,
            )

        recipe = self._recipe_for_run(record)
        request_payload = record.get("request")
        research_payload = record.get("operational_research")
        if not isinstance(request_payload, Mapping) or not isinstance(research_payload, Mapping):
            return self._record_provider_failure(
                run_id,
                status="configuration_required",
                phase="browser_unavailable",
                reason_code="run_state_incomplete",
            )
        request = OperationsRequest.model_validate(dict(request_payload))
        research = OperationalResearch.model_validate(dict(research_payload))
        try:
            account_ref = validate_browser_account_ref(record.get("browser_account_ref"))
        except ValueError:
            return self._record_provider_failure(
                run_id,
                status="configuration_required",
                phase="browser_unavailable",
                reason_code="browser_account_binding_missing",
            )

        retry_login: Mapping[str, SecretStr] | None = None
        staged_existing = False
        if request.account_creation_requested:
            retry_login = self._context._staged_signup_login_values(
                app_slug=recipe.app_slug,
                account_ref=account_ref,
                run_id=run_id,
            )
            if not retry_login:
                signup_address = getattr(self._context._settings, "gmail_signup_address", None)
                if signup_address is None:
                    return self._record_provider_failure(
                        run_id,
                        status="configuration_required",
                        phase="signup_identity_required",
                        reason_code="gmail_signup_address_not_configured",
                    )
                try:
                    retry_login = self._context._stage_signup_login(
                        app_slug=recipe.app_slug,
                        account_ref=account_ref,
                        run_id=run_id,
                        values={
                            "login_email": SecretStr(signup_address.get_secret_value()),
                            "login_password": SecretStr(f"Rr7!{secrets.token_urlsafe(24)}"),
                        },
                    )
                except Exception as exc:
                    return self._record_provider_failure(
                        run_id,
                        status="configuration_required",
                        phase="signup_identity_required",
                        reason_code=_safe_reason(exc, "signup_login_vault_required"),
                    )
        else:
            store = self._context._secret_store
            staged_values = (
                store.get_staged_existing_login_pair(
                    app_slug=recipe.app_slug,
                    account_ref=account_ref,
                    run_id=run_id,
                )
                if store is not None
                else {}
            )
            if set(staged_values) == {"login_email", "login_password"}:
                staged_existing = True
                retry_login = {
                    field: SecretStr(staged_values[field])
                    for field in ("login_email", "login_password")
                }
            elif browser_login:
                if store is None:
                    return self._record_provider_failure(
                        run_id,
                        status="configuration_required",
                        phase="login_credential_staging",
                        reason_code="existing_login_vault_required",
                    )
                try:
                    staged_values = store.stage_existing_login_pair(
                        app_slug=recipe.app_slug,
                        account_ref=account_ref,
                        run_id=run_id,
                        email=browser_login["login_email"].get_secret_value(),
                        password=browser_login["login_password"].get_secret_value(),
                    )
                except Exception as exc:
                    return self._record_provider_failure(
                        run_id,
                        status="configuration_required",
                        phase="login_credential_staging",
                        reason_code=_safe_reason(exc, "existing_login_stage_failed"),
                    )
                staged_existing = True
                retry_login = {
                    field: SecretStr(staged_values[field])
                    for field in ("login_email", "login_password")
                }
            else:
                retry_login = self._context._reusable_login_values(
                    recipe.app_slug,
                    account_ref,
                )
                if (
                    not retry_login
                    and store is not None
                    and bool(
                        getattr(
                            self._context._settings,
                            "browser_login_credential_reuse",
                            True,
                        )
                    )
                ):
                    try:
                        selected = store.get_unique_account_login_pair(app_slug=recipe.app_slug)
                    except AccountLoginStateError as exc:
                        return self._record_provider_failure(
                            run_id,
                            status="configuration_required",
                            phase="login_account_selection",
                            reason_code=exc.reason_code,
                        )
                    except Exception:
                        return self._record_provider_failure(
                            run_id,
                            status="configuration_required",
                            phase="login_account_selection",
                            reason_code="stored_login_lookup_failed",
                        )
                    if selected is not None:
                        selected_account_ref, selected_values = selected
                        if selected_account_ref != account_ref:
                            # The account binding is immutable once the run is
                            # committed. Guessing a different profile during crash
                            # recovery could cross account state, so require a new
                            # explicit run instead.
                            return self._record_provider_failure(
                                run_id,
                                status="configuration_required",
                                phase="login_account_selection",
                                reason_code="stored_login_account_binding_mismatch",
                            )
                        retry_login = {
                            field: SecretStr(selected_values[field])
                            for field in ("login_email", "login_password")
                        }

        return self._start_playwright(
            run_id,
            request=request,
            research=research,
            recipe=recipe,
            browser_login=retry_login,
            attempt=1,
            use_storage_state=not staged_existing,
        )

    def create_run(
        self,
        request: OperationsRequest,
        *,
        idempotency_key: str | None,
        execution_mode: ExecutionMode,
        browser_login: Mapping[str, SecretStr] | None,
        selection: ModelSelection | None = None,
    ) -> dict[str, Any]:
        recipe = self.recipe_for_request(request)
        if recipe is None:
            raise KeyError("reviewed app recipe was not found")
        validated_key = validate_idempotency_key(idempotency_key)
        fingerprint = (
            _request_fingerprint(request, execution_mode) if validated_key is not None else None
        )

        def replay(
            existing: tuple[dict[str, Any], str] | None,
        ) -> dict[str, Any] | None:
            if existing is None:
                return None
            record, stored_fingerprint = existing
            legacy_match = stored_fingerprint in _legacy_request_fingerprints(
                request, execution_mode
            )
            if stored_fingerprint != fingerprint and not legacy_match:
                raise IdempotencyConflictError(
                    "idempotency key was already used for another request"
                )
            return _public_run(record)

        # A retry of an already-committed request must remain available even if a
        # provider is temporarily down. This read is repeated under the write
        # transaction below to close the concurrent-create race.
        if validated_key is not None:
            existing = self._context.storage.get_idempotent_run(validated_key)
            existing_replay = replay(existing)
            if existing_replay is not None:
                assert existing is not None
                replayed_record = existing[0]
                run_id = str(replayed_record.get("run_id") or "")
                lock = self._context._run_lock(run_id)
                if not lock.acquire(blocking=False):
                    return existing_replay
                try:
                    current = self._context.storage.get_run(run_id)
                    if current is None:
                        raise KeyError("run was not found")
                    continued = self._continue_pristine_playwright_run(
                        current,
                        browser_login=browser_login,
                    )
                    return continued if continued is not None else _public_run(current)
                finally:
                    lock.release()

        executable_signup = (
            execution_mode != "plan_only" and request.account_mode == "create_account"
        )
        if executable_signup:
            if recipe.route_kind != "playwright" or recipe.urls.signup is None:
                raise ProviderReadinessError(
                    provider="playwright",
                    reason_code="reviewed_signup_recipe_not_available",
                )
            if request.browser_provider != "playwright":
                raise ProviderReadinessError(
                    provider="playwright",
                    reason_code="playwright_required_for_reviewed_signup",
                )
            if not browser_configuration_state(self._context._settings, "playwright"):
                raise ProviderReadinessError(
                    provider="playwright",
                    reason_code="playwright_configuration_required",
                )
            signup_address = getattr(self._context._settings, "gmail_signup_address", None)
            if signup_address is None:
                raise ProviderReadinessError(
                    provider="gmail",
                    reason_code="gmail_signup_address_not_configured",
                )
            preflight = self._context.gmail_signup_preflight(
                timeout_seconds=float(
                    getattr(
                        self._context._settings,
                        "gmail_signup_preflight_timeout_seconds",
                        10.0,
                    )
                )
            )
            if not bool(getattr(preflight, "ready", False)):
                raise ProviderReadinessError(
                    provider="gmail",
                    reason_code=str(
                        getattr(
                            preflight,
                            "reason_code",
                            "gmail_signup_preflight_failed",
                        )
                    ),
                )

        # The same readiness question for the sign-in path, asked before a row
        # exists. Every credential handling step below runs inside
        # ``route_kind == "playwright"``, so on any other route a submitted
        # password was accepted, never staged, never injected, and never
        # mentioned again -- the run simply proceeded as though the operator
        # had supplied nothing. Refusing here says so while the answer is
        # still actionable, and leaves no dead run row behind. Only
        # credentials the operator actually submitted are gated: an
        # existing-account run with none is the managed-auth path and is
        # unaffected.
        executable_login = (
            execution_mode != "plan_only"
            and request.account_mode == "existing_account"
            and browser_login is not None
        )
        if executable_login:
            if recipe.route_kind != "playwright" or recipe.browser is None:
                raise ProviderReadinessError(
                    provider="playwright",
                    reason_code="reviewed_login_recipe_not_available",
                )
            if not browser_configuration_state(self._context._settings, "playwright"):
                raise ProviderReadinessError(
                    provider="playwright",
                    reason_code="playwright_configuration_required",
                )
            if self._context._secret_store is None:
                raise ProviderReadinessError(
                    provider="playwright",
                    reason_code="existing_login_vault_required",
                )

        run_id = f"run_{uuid4().hex}"
        thread_id = f"sqlite_{uuid4().hex}"
        submitted_existing_login = (
            browser_login if request.account_mode == "existing_account" and browser_login else None
        )
        stored_login_selection_error: str | None = None
        binding_login = browser_login
        if request.account_creation_requested:
            signup_address = getattr(self._context._settings, "gmail_signup_address", None)
            if signup_address is not None:
                # Bind every retry and later run for this generated vendor identity
                # to the same opaque account scope without persisting the address.
                binding_login = {"login_email": signup_address}
        browser_account_ref = (
            derive_browser_account_ref(
                run_id=run_id,
                app_slug=recipe.app_slug,
                work_email_ref=request.company.work_email_ref,
                browser_login=binding_login,
                binding_secret=getattr(self._context._settings, "secret_vault_key", None),
            )
            if recipe.route_kind == "playwright"
            else None
        )
        if (
            execution_mode != "plan_only"
            and recipe.route_kind == "playwright"
            and request.account_mode == "existing_account"
            and browser_login is None
            and bool(
                getattr(
                    self._context._settings,
                    "browser_login_credential_reuse",
                    True,
                )
            )
            and self._context._secret_store is not None
        ):
            try:
                selected = self._context._secret_store.get_unique_account_login_pair(
                    app_slug=recipe.app_slug
                )
            except AccountLoginStateError as exc:
                stored_login_selection_error = exc.reason_code
            except Exception:
                stored_login_selection_error = "stored_login_lookup_failed"
            else:
                if selected is not None:
                    selected_account_ref, selected_values = selected
                    try:
                        browser_account_ref = validate_browser_account_ref(selected_account_ref)
                    except ValueError:
                        stored_login_selection_error = "stored_login_account_binding_invalid"
                    else:
                        if set(selected_values) != {"login_email", "login_password"}:
                            stored_login_selection_error = "stored_login_pair_incomplete"
                        else:
                            browser_login = {
                                field: SecretStr(selected_values[field])
                                for field in ("login_email", "login_password")
                            }
        research = recipe_to_operational_research(recipe)
        recipe_version = _recipe_version()
        recipe_snapshot = build_recipe_snapshot(recipe, recipe_version)
        plan_only = execution_mode == "plan_only"
        status: RunStatus = (
            "route_selected"
            if plan_only or recipe.route_kind != "managed_auth"
            else "connection_required"
        )
        phase = (
            "route_selected"
            if plan_only
            else "connection_required"
            if recipe.route_kind == "managed_auth"
            else "browser_pending"
            if recipe.route_kind == "playwright"
            else "outreach_review"
        )
        reason = _initial_reason(recipe)
        provider_status = {
            "recipe": recipe.readiness_tier,
            "composio": "connection_required"
            if recipe.route_kind == "managed_auth"
            else "not_started",
            "browser": "not_started",
            "email": "not_started",
            "validation": "not_started",
        }

        with self._context.storage.unit_of_work() as transaction:
            if validated_key is not None:
                existing_replay = replay(transaction.get_idempotent_run(validated_key))
                if existing_replay is not None:
                    return existing_replay

            lookup = self._context.p1_adapter.lookup(recipe.app_name)
            p1_summary: dict[str, object] | None = None
            if isinstance(lookup, P1LookupFound):
                p1_summary = {
                    "category": lookup.record.category,
                    "one_liner": lookup.record.one_liner,
                    "auth_methods": list(lookup.record.auth_methods),
                    "buildability": lookup.record.buildability,
                    "verification_status": lookup.record.verification_status,
                    "confidence": lookup.record.confidence,
                    "last_verified": lookup.record.last_verified,
                }
            transaction.create_run(
                run_id=run_id,
                thread_id=thread_id,
                app_name=recipe.app_name,
                app_slug=recipe.app_slug,
                status=status,
                access_route=cast(Any, _access_route(recipe)),
                p1_summary=p1_summary,
                operational_research=research.model_dump(mode="json"),
                request=request.model_dump(mode="json"),
                route_reason_code=reason,
                route_explanation=(
                    "This run is bound to a reviewed, versioned application recipe."
                ),
                missing_fields=[],
                provider_status=provider_status,
                scope_policy=request.requested_scope_policy,
                decision_model=None
                if selection is None
                else f"{selection.provider}:{selection.model}",
                decision_effort=None if selection is None else (selection.effort or None),
                execution_mode=_PERSISTED_EXECUTION_MODE[execution_mode],
                browser_provider=request.browser_provider,
                credential_creation_policy=request.credential_creation_policy,
                recipe_version=recipe_version,
                recipe_snapshot=recipe_snapshot,
                route_kind=recipe.route_kind,
                readiness_tier=recipe.readiness_tier,
                browser_account_ref=browser_account_ref,
                attempt=0,
                phase=phase,
                reason_code=reason,
                state_engine="canonical_v1",
                external_actions=False,
                idempotency_key=validated_key,
                request_fingerprint=fingerprint,
            )
            transaction.update_run(
                run_id,
                state_revision=1,
                last_projected_revision=1,
            )
            transaction.append_audit_event(
                run_id=run_id,
                event_type="run_created",
                payload={
                    "status": "created",
                    "state_engine": "canonical_v1",
                    "recipe_version": recipe_version,
                    "route_kind": recipe.route_kind,
                    "readiness_tier": recipe.readiness_tier,
                    "browser_provider": request.browser_provider,
                    "browser_account_scope": (
                        "account_scoped"
                        if isinstance(browser_account_ref, str)
                        and browser_account_ref.startswith("acct_")
                        else "run_scoped"
                        if browser_account_ref is not None
                        else "not_applicable"
                    ),
                    "external_actions": False,
                },
            )
            transaction.append_audit_event(
                run_id=run_id,
                event_type="route_selected",
                payload={
                    "status": "route_selected",
                    "route_kind": recipe.route_kind,
                    "phase": phase,
                    "reason_code": reason,
                    "external_actions": False,
                },
            )
            created = transaction.get_run(run_id)
            if created is None:  # pragma: no cover - SQLite invariant
                raise RuntimeError("created run could not be read")

        # The run's opening phase boundary, written once the run row is durable
        # (the history table has a foreign key onto it) and outside the unit of
        # work that made it so. Every route kind gets it, not just Playwright:
        # reset, pause and the decision endpoint are gated on this history for
        # managed-auth and gated runs too.
        self._commit_phase_boundary(
            run_id,
            target=INITIAL_PHASE,
            reason_code=_CANONICAL_SPINE_REASON[INITIAL_PHASE],
            app_slug=recipe.app_slug,
        )
        persisted_recipe = self._recipe_for_run(created)
        if not plan_only and persisted_recipe.route_kind == "playwright":
            if stored_login_selection_error is not None:
                return self._record_provider_failure(
                    run_id,
                    status="configuration_required",
                    phase="login_account_selection",
                    reason_code=stored_login_selection_error,
                )
            if submitted_existing_login is not None:
                store = self._context._secret_store
                if store is None:
                    return self._record_provider_failure(
                        run_id,
                        status="configuration_required",
                        phase="login_credential_staging",
                        reason_code="existing_login_vault_required",
                    )
                try:
                    staged_existing = store.stage_existing_login_pair(
                        app_slug=persisted_recipe.app_slug,
                        account_ref=validate_browser_account_ref(browser_account_ref),
                        run_id=run_id,
                        email=submitted_existing_login["login_email"].get_secret_value(),
                        password=submitted_existing_login["login_password"].get_secret_value(),
                    )
                except Exception as exc:
                    return self._record_provider_failure(
                        run_id,
                        status="configuration_required",
                        phase="login_credential_staging",
                        reason_code=_safe_reason(exc, "existing_login_stage_failed"),
                    )
                if set(staged_existing) != {"login_email", "login_password"}:
                    return self._record_provider_failure(
                        run_id,
                        status="configuration_required",
                        phase="login_credential_staging",
                        reason_code="existing_login_pair_incomplete",
                    )
                browser_login = {
                    field: SecretStr(staged_existing[field])
                    for field in ("login_email", "login_password")
                }
            if request.account_mode == "create_account":
                signup_address = getattr(self._context._settings, "gmail_signup_address", None)
                if signup_address is None:  # pragma: no cover - pre-persistence invariant
                    raise RuntimeError("validated signup address disappeared")
                # Generate the vendor password inside the trusted backend and
                # retain it only in the encrypted run-scoped signup stage. The
                # raw value is passed to the current browser attempt in memory
                # and never enters the request snapshot, run state, or audit.
                generated_login: dict[str, SecretStr] = {
                    "login_email": SecretStr(signup_address.get_secret_value()),
                    "login_password": SecretStr(f"Rr7!{secrets.token_urlsafe(24)}"),
                }
                try:
                    staged_login = self._context._stage_signup_login(
                        app_slug=persisted_recipe.app_slug,
                        account_ref=validate_browser_account_ref(browser_account_ref),
                        run_id=run_id,
                        values=generated_login,
                    )
                except Exception as exc:
                    return self._record_provider_failure(
                        run_id,
                        status="configuration_required",
                        phase="signup_identity_required",
                        reason_code=_safe_reason(exc, "signup_login_vault_required"),
                    )
                if set(staged_login) != {"login_email", "login_password"}:
                    return self._record_provider_failure(
                        run_id,
                        status="configuration_required",
                        phase="signup_identity_required",
                        reason_code="signup_login_pair_incomplete",
                    )
                browser_login = staged_login
            return self._start_playwright(
                run_id,
                request=request,
                research=research,
                recipe=persisted_recipe,
                browser_login=browser_login,
                use_storage_state=submitted_existing_login is None,
            )
        return _public_run(created)

    def _start_playwright(
        self,
        run_id: str,
        *,
        request: OperationsRequest,
        research: OperationalResearch,
        recipe: AppRecipe,
        browser_login: Mapping[str, SecretStr] | None,
        attempt: int | None = None,
        use_storage_state: bool = True,
    ) -> dict[str, Any]:
        if request.browser_provider != "playwright":
            return self._record_provider_failure(
                run_id,
                status="configuration_required",
                phase="browser_unavailable",
                reason_code="playwright_required_for_recipe",
            )
        if recipe.browser is None:
            return self._record_provider_failure(
                run_id,
                status="configuration_required",
                phase="browser_unavailable",
                reason_code="reviewed_browser_entry_required",
            )
        # The model this run was pinned to at creation, carried to whichever
        # process actually decides. Read here rather than threaded through three
        # callers so a resumed run decides with the same model its first attempt
        # did. A run that pinned nothing sends nothing.
        record = self._context.storage.get_run(run_id) or {}
        pinned_model = record.get("decision_model") or None
        pinned_effort = record.get("decision_effort") or None
        worker = self._context._browser_worker_for("playwright")
        if worker is None:
            return self._record_provider_failure(
                run_id,
                status="configuration_required",
                phase="browser_unavailable",
                reason_code="playwright_not_configured",
            )

        persisted = self._context.storage.get_run(run_id)
        if persisted is None:
            raise KeyError("run was not found")
        try:
            browser_account_ref = validate_browser_account_ref(persisted.get("browser_account_ref"))
        except ValueError:
            return self._record_provider_failure(
                run_id,
                status="configuration_required",
                phase="browser_unavailable",
                reason_code="browser_account_binding_missing",
            )

        planning = self._planning
        if planning is not None:
            plans = planning.plans
            active_plan = plans.read_active_plan(run_id=run_id) if plans is not None else None
            # Release compatibility: a run that crossed the browser-admission
            # boundary before plan storage existed is not retroactively refused.
            # With no plan row, adherence remains inert for that already-advanced
            # run.  Pristine attempt zero still plans before the first worker.start.
            already_advanced_without_plan = active_plan is None and (
                int(persisted.get("attempt", 0) or 0) > 0
                or bool(persisted.get("browser_session_id"))
                or bool(persisted.get("external_actions"))
            )
            if not already_advanced_without_plan:
                refusal = plan_admission(
                    run_id=run_id,
                    profile=None,
                    recipe=recipe,
                    deps=planning,
                )
                if refusal is not None:
                    return self._record_provider_failure(
                        run_id,
                        status="configuration_required",
                        phase="plan_refused",
                        reason_code=refusal.reason_code,
                    )

        sensitive: dict[str, str] | None = None
        transient_secrets = self._requires_broker_grants(worker)
        if browser_login:
            sensitive = self._context._browser_login_payload(
                provider="playwright",
                app_slug=recipe.app_slug,
                scope_id=run_id,
                values=browser_login,
            )

        try:
            with self._context.storage.unit_of_work() as transaction:
                current = transaction.get_run(run_id)
                if current is None:
                    raise KeyError("run was not found")
                next_attempt = attempt or int(current.get("attempt", 0) or 0) + 1
                if next_attempt < 1:
                    raise ValueError("browser attempt must be positive")
                effect_identity = f"{run_id}:browser-start:v{next_attempt}"
                _intent, reserved = transaction.reserve_side_effect(
                    run_id=run_id,
                    operation_key=effect_identity,
                    provider="playwright",
                )
                transaction.update_run(
                    run_id,
                    phase="authentication_submitted" if sensitive else "browser_starting",
                    reason_code="browser_start_reserved",
                    effect_identity=effect_identity,
                    attempt=next_attempt,
                    state_revision=int(current.get("state_revision", 0) or 0) + 1,
                )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="browser_start_reserved",
                    payload={
                        "provider": "playwright",
                        "attempt": next_attempt,
                        "authentication_substate": ("submitted" if sensitive else "not_submitted"),
                        "external_actions": False,
                    },
                )
        except BaseException:
            self._discard_pre_dispatch_browser_secrets(
                sensitive=sensitive,
                app_slug=recipe.app_slug,
                run_id=run_id,
                transient=transient_secrets,
            )
            raise
        # The reservation above committed, which is the run's own proof that the
        # vault question has been answered: ``sensitive`` is exactly "a stored
        # login was found and is being submitted".
        self._commit_phase_boundary(
            run_id,
            target="vault_check",
            reason_code="credentials_present" if sensitive else "credentials_missing",
            app_slug=recipe.app_slug,
            attempt=next_attempt,
        )
        if not reserved:
            self._discard_pre_dispatch_browser_secrets(
                sensitive=sensitive,
                app_slug=recipe.app_slug,
                run_id=run_id,
                transient=transient_secrets,
            )
            return self._record_provider_failure(
                run_id,
                status="configuration_required",
                phase="effect_reconciliation",
                reason_code="browser_start_reconciliation_required",
            )

        context: BrowserSessionContext | None = None
        try:
            context = asyncio.run(
                worker.start(
                    None,
                    recipe=recipe,
                    app_slug=recipe.app_slug,
                    account_ref=browser_account_ref,
                    secret_scope=run_id,
                    use_storage_state=use_storage_state,
                    live_view_mode="interactive_remote",
                    decision_model=pinned_model,
                    decision_effort=pinned_effort,
                )
            )
            if context is None:
                raise RuntimeError("browser worker returned no session context")
            self._context.storage.update_side_effect(
                run_id=run_id,
                operation_key=effect_identity,
                status="completed",
                external_id=context.session_id,
            )
        except Exception as exc:
            if context is not None:
                with contextlib.suppress(Exception):
                    self._context._release_browser_session(
                        context,
                        "playwright",
                        reason="canonical_start_pre_dispatch_failed",
                    )
            with contextlib.suppress(Exception):
                self._context.storage.update_side_effect(
                    run_id=run_id,
                    operation_key=effect_identity,
                    status="failed",
                )
            self._discard_pre_dispatch_browser_secrets(
                sensitive=sensitive,
                app_slug=recipe.app_slug,
                run_id=run_id,
                transient=transient_secrets,
            )
            return self._record_provider_failure(
                run_id,
                status=(
                    "configuration_required"
                    if isinstance(exc, ConfigurationRequiredError)
                    else "failed"
                ),
                phase="browser_start_failed",
                reason_code=_safe_reason(exc, "browser_start_failed"),
                external_actions=True,
            )
        except BaseException:
            if context is not None:
                with contextlib.suppress(Exception):
                    self._context._release_browser_session(
                        context,
                        "playwright",
                        reason="canonical_start_pre_dispatch_interrupted",
                    )
            self._discard_pre_dispatch_browser_secrets(
                sensitive=sensitive,
                app_slug=recipe.app_slug,
                run_id=run_id,
                transient=transient_secrets,
            )
            raise

        provider_session = context.session_id
        session_getter = getattr(worker, "provider_session_id", None)
        if callable(session_getter):
            with contextlib.suppress(Exception):
                provider_session = str(session_getter(context.session_id) or context.session_id)
        try:
            with self._context.storage.unit_of_work() as transaction:
                current = transaction.get_run(run_id)
                if current is None:
                    raise KeyError("run was not found")
                transaction.update_run(
                    run_id,
                    status="browser_running",
                    browser_session_id=context.session_id,
                    provider_session_id=provider_session,
                    phase="authentication_submitted" if sensitive else "browser_running",
                    reason_code="browser_session_started",
                    provider_status={
                        "recipe": recipe.readiness_tier,
                        "composio": "not_started",
                        "browser": "running",
                        "email": "not_started",
                        "validation": "not_started",
                    },
                    external_actions=True,
                    state_revision=int(current.get("state_revision", 0) or 0) + 1,
                    last_projected_revision=int(current.get("state_revision", 0) or 0) + 1,
                )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="browser_session_started",
                    payload={
                        "provider": "playwright",
                        "status": "browser_running",
                        "live_view_available": context.live_view_available,
                        "external_actions": True,
                    },
                )
                updated = transaction.get_run(run_id)
                if updated is None:  # pragma: no cover
                    raise RuntimeError("browser run disappeared")
        except BaseException:
            with contextlib.suppress(Exception):
                self._context._release_browser_session(
                    context,
                    "playwright",
                    reason="canonical_start_state_persistence_failed",
                )
            self._discard_pre_dispatch_browser_secrets(
                sensitive=sensitive,
                app_slug=recipe.app_slug,
                run_id=run_id,
                transient=transient_secrets,
            )
            raise
        # A browser session exists and is bound to the run: the login route was
        # taken, which is the boundary the transition table reaches from
        # ``vault_check``.
        self._commit_phase_boundary(
            run_id,
            target="route_selected_login",
            reason_code="session_recreated",
            app_slug=recipe.app_slug,
            attempt=next_attempt,
        )

        thread: threading.Thread | None = None
        try:
            thread = threading.Thread(
                target=self._drive_browser,
                kwargs={
                    "run_id": run_id,
                    "context": context,
                    "request": request,
                    "research": research,
                    "recipe": recipe,
                    "sensitive": sensitive,
                    "transient_secrets": transient_secrets,
                },
                name=f"canonical-browser-{run_id[:16]}",
                daemon=True,
            )
            self._context._browser_threads = [
                item for item in self._context._browser_threads if item.is_alive()
            ]
            self._context._browser_threads.append(thread)
            thread.start()
        except Exception as exc:
            # If a non-standard Thread implementation started and then raised,
            # ownership may already have crossed into ``_drive_browser``. Leave
            # its session and payload alone in that outcome-unknown case.
            if thread is not None and thread.ident is not None:
                raise
            self._context._browser_threads = [
                item for item in self._context._browser_threads if item is not thread
            ]
            with contextlib.suppress(Exception):
                self._context._release_browser_session(
                    context,
                    "playwright",
                    reason="canonical_browser_thread_start_failed",
                )
            self._discard_pre_dispatch_browser_secrets(
                sensitive=sensitive,
                app_slug=recipe.app_slug,
                run_id=run_id,
                transient=transient_secrets,
            )
            return self._record_provider_failure(
                run_id,
                status="failed",
                phase="browser_start_failed",
                reason_code=_safe_reason(exc, "browser_dispatch_failed"),
                external_actions=True,
            )
        except BaseException:
            if thread is not None and thread.ident is not None:
                raise
            self._context._browser_threads = [
                item for item in self._context._browser_threads if item is not thread
            ]
            with contextlib.suppress(Exception):
                self._context._release_browser_session(
                    context,
                    "playwright",
                    reason="canonical_browser_thread_start_interrupted",
                )
            self._discard_pre_dispatch_browser_secrets(
                sensitive=sensitive,
                app_slug=recipe.app_slug,
                run_id=run_id,
                transient=transient_secrets,
            )
            raise
        return _public_run(updated)

    def _reconcile_capture_effect(
        self,
        run_id: str,
        current: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        """Resolve the capture effect BEFORE a restart re-runs it.

        ``effect_reconciliation`` is the only ``configuration_required`` phase that
        names an ambiguous EXTERNAL outcome rather than a local failure: the run
        reserved the credential-generation effect and then lost the answer. The
        recorded intent is the only durable evidence of what the vendor actually
        did, so it is read here rather than guessed at.

        Three answers, and which one is returned is decided entirely by the ledger:

        * ``None`` — restart the trace. An absent row means the effect was never
          reserved; ``failed`` means it definitively did not take; and
          ``completed`` carrying ``no_credential_found`` means the capture ran to
          the end and the reviewed page held no credential, so nothing was minted
          and re-running mints nothing twice. That last case used to be refused
          along with the rest of ``completed``, which dead-ended precisely the
          runs where automatic capture came back empty — the ones an operator
          most wants to retry.
        * a run record — reconciled, do not restart. The vendor issued a key and
          the worker vaulted it; re-running the trace would press Create again
          and leave an orphaned key nothing in this system knows about. Instead
          the run is handed to its owner-submission window, which is a recovery
          that touches the vendor not at all.
        * a raised ``CredentialSubmissionError`` — ``outcome_unknown`` and
          ``pending`` are the two states where the ledger cannot say whether a
          key exists, so neither a restart nor a reconciliation is honest. This
          is the one genuinely human question in this method, and it stays fenced
          rather than guessed.
        """

        effect = self._context.storage.get_side_effect(
            run_id,
            f"{run_id}:credential-capture:v1",
        )
        if effect is None:
            return None
        status = str(effect.get("status") or "")
        if status == "completed":
            if str(effect.get("external_id") or "") == "no_credential_found":
                return None
            return self._reconcile_vaulted_capture(run_id, current)
        if status in {"outcome_unknown", "pending"}:
            # Reserved, then the answer was lost — ``pending`` for the same reason
            # as ``outcome_unknown``, because a process that died between reserving
            # and completing left exactly as little evidence. Neither is a state a
            # blind restart may resolve.
            raise CredentialSubmissionError("credential_effect_outcome_unknown")
        return None

    def _reconcile_vaulted_capture(
        self,
        run_id: str,
        current: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Hand a run whose credential already exists back to its owner window.

        The state this recovers from is real and was a dead end: capture succeeds
        and vaults, and before the projection commits a sweep or a stop moves the
        run — so the compare-and-set loses, the run sits at
        ``effect_reconciliation``, and Retry refuses forever because the ledger
        correctly says a key was already minted. The credential existed, the run
        could not reach it, and no button changed that.

        Reopening the owner-submission window is the recovery that costs the
        vendor nothing: ``browser_running`` plus ``credential_ready`` is exactly
        the pair ``RunCredentialService.submit_owner_credentials`` accepts, and
        every automatic-capture recipe in the catalog also declares the
        ``credential_fields`` that submission needs, so the owner can hand over
        the key the vendor already issued. ``failed -> browser_running`` and
        ``configuration_required -> browser_running`` are both legal in
        ``ops/core/state.py``, so this widens no transition table.

        The stale browser session id is cleared rather than kept. It named a
        session that was released when the run stopped, and leaving it would
        both advertise a dead live view and let a late projection from that
        session match the compare-and-set again.

        A human is genuinely required here — only a person can read a key off the
        vendor's page — so this is a pause that was always going to exist. What
        it replaces is not autonomy, it is a permanently unrecoverable run.
        """

        recipe = self._recipe_for_run(current)
        if not recipe.credential_fields:
            # Nothing for the owner to submit, so the window would be a second
            # dead end. Keep the honest refusal instead of inventing a state.
            raise CredentialSubmissionError("credential_effect_already_completed")
        with self._context.storage.unit_of_work() as transaction:
            record = transaction.get_run(run_id)
            if record is None:
                raise KeyError("run was not found")
            if (
                str(record.get("status") or "") not in _RECONCILABLE_DISCARD_STATUSES
                or str(record.get("phase") or "") != "effect_reconciliation"
            ):
                # Re-read under the transaction: something moved the run between
                # the caller's read and this write, and that writer owns it.
                raise CredentialSubmissionError("credential_effect_already_completed")
            revision = int(record.get("state_revision", 0) or 0) + 1
            updated = transaction.update_run(
                run_id,
                status="browser_running",
                phase="credential_ready",
                reason_code="owner_credential_submission_required",
                route_reason_code="owner_credential_submission_required",
                browser_session_id=None,
                hitl_request=None,
                provider_status={
                    "recipe": record.get("readiness_tier"),
                    "composio": "not_started",
                    "browser": "credential_page_ready",
                    "email": "not_started",
                    "validation": "not_started",
                },
                external_actions=True,
                state_revision=revision,
                last_projected_revision=revision,
            )
            transaction.append_audit_event(
                run_id=run_id,
                event_type="credential_effect_reconciled",
                payload={
                    "reason_code": "owner_credential_submission_required",
                    "effect_status": "completed",
                    # The vendor was not touched to get here; the effect that did
                    # touch it is the one being reconciled, not repeated.
                    "external_actions": False,
                },
            )
        return _public_run(updated)

    def retry_browser_run(self, run_id: str) -> dict[str, Any]:
        """Start a fresh Playwright attempt after a recoverable browser failure.

        Signup and newly submitted existing-account pairs are loaded only from
        this exact run's encrypted stage. Already verified existing-account pairs
        may be loaded from the exact persisted account binding. Each attempt
        receives a new effect identity, while capture reconciliation remains bound
        to the run so a retry cannot duplicate a credential-generation side effect.
        """

        lock = self._context._run_lock(run_id)
        if not lock.acquire(blocking=False):
            raise RunConflictError(run_id, "retry_browser")
        try:
            # An operator retry refunds the autonomous sweeps' gate budgets for
            # this run. Those budgets are durable now, so without this a run that
            # exhausted them once would be retried into the same gate with no
            # attempts left to resolve it — the retry would start a browser and
            # then wait for a human who was never told to come.
            with contextlib.suppress(Exception):
                self._context.storage.clear_gate_attempts(run_id)
            current = self._context.storage.get_run(run_id)
            if current is None:
                raise KeyError("run was not found")
            if current.get("state_engine") != "canonical_v1":
                raise CredentialSubmissionError("legacy_run_is_read_only")
            if current.get("execution_mode") != "operations":
                raise CredentialSubmissionError("plan_only_run_is_read_only")
            if current.get("route_kind") != "playwright":
                raise CredentialSubmissionError("run_is_not_playwright")
            if current.get("browser_provider") != "playwright":
                raise CredentialSubmissionError("playwright_required_for_recipe")
            if current.get("status") == "route_selected":
                continued = self._continue_pristine_playwright_run(
                    current,
                    browser_login=None,
                )
                if continued is not None:
                    return continued
            if current.get("status") not in {"failed", "configuration_required"}:
                raise CredentialSubmissionError("browser_retry_not_available")
            current_phase = str(current.get("phase") or "")
            if current_phase in RETRY_DENIED_PHASES:
                raise CredentialSubmissionError("browser_retry_requires_reconciliation")
            if current_phase == "effect_reconciliation":
                # Read the ledger before restarting anything: this phase exists
                # precisely because a restart that has not read it may re-run a
                # committed effect. A reconciliation that resolved the run
                # returns it here, and no browser is started.
                reconciled = self._reconcile_capture_effect(run_id, current)
                if reconciled is not None:
                    return reconciled
            recipe = self._recipe_for_run(current)
            if recipe.route_kind != "playwright":
                raise CredentialSubmissionError("run_is_not_playwright")
            request_payload = current.get("request")
            research_payload = current.get("operational_research")
            if not isinstance(request_payload, Mapping) or not isinstance(
                research_payload, Mapping
            ):
                raise CredentialSubmissionError("run_state_incomplete")
            request = OperationsRequest.model_validate(dict(request_payload))
            research = OperationalResearch.model_validate(dict(research_payload))
            account_ref = validate_browser_account_ref(current.get("browser_account_ref"))
            staged_existing = False
            if request.account_creation_requested:
                retry_login = self._context._staged_signup_login_values(
                    app_slug=recipe.app_slug,
                    account_ref=account_ref,
                    run_id=run_id,
                )
                if not retry_login:
                    raise CredentialSubmissionError("signup_login_vault_required")
            else:
                store = self._context._secret_store
                staged_values = (
                    store.get_staged_existing_login_pair(
                        app_slug=recipe.app_slug,
                        account_ref=account_ref,
                        run_id=run_id,
                    )
                    if store is not None
                    else {}
                )
                staged_existing = set(staged_values) == {
                    "login_email",
                    "login_password",
                }
                retry_login = (
                    {
                        field: SecretStr(staged_values[field])
                        for field in ("login_email", "login_password")
                    }
                    if staged_existing
                    else self._context._reusable_login_values(recipe.app_slug, account_ref)
                )
            return self._start_playwright(
                run_id,
                request=request,
                research=research,
                recipe=recipe,
                browser_login=retry_login,
                attempt=int(current.get("attempt", 0) or 0) + 1,
                use_storage_state=not staged_existing,
            )
        finally:
            lock.release()

    def _adherence_step_index(
        self,
        *,
        run_id: str,
        observation: BrowserObservation,
    ) -> tuple[RunPlan, int] | None:
        """Resolve the observed endpoint to one active-plan ordinal.

        Exact planned surfaces are authoritative. A human-only challenge may
        redirect within a reviewed provider host, so an unmatched HITL URL stays
        inert instead of turning a solvable gate into a route failure. Successful
        terminal observations are compared with the credential surface, and the
        only other non-terminal worker outcome is compared with the route entry.
        """

        plans = self._planning.plans if self._planning is not None else None
        if plans is None or observation.status in {"blocked", "failed"}:
            return None
        plan = plans.read_active_plan(run_id=run_id)
        if plan is None:
            return None
        try:
            observed = canonical_surface(observation.current_url, purpose="entry")
        except ValueError:
            observed = None
        if observed is not None:
            for index, surface in enumerate(plan.surfaces):
                if (surface.host, surface.path) == (observed.host, observed.path):
                    return plan, index
        if observation.status == "human_action_required":
            return None
        if observation.status in {"credential_page_ready", "developer_console_ready"}:
            # An entry_only plan names no credential surface, so its terminal
            # observation is the last surface it planned rather than an unmatched one.
            credential = plan.credential_surface
            if credential is not None:
                for index, surface in enumerate(plan.surfaces):
                    if (surface.host, surface.path) == (credential.host, credential.path):
                        return plan, index
            return plan, len(plan.surfaces) - 1
        if observation.status == "navigating":
            return plan, 0
        return None

    def _route_adherence_override(
        self,
        *,
        run_id: str,
        observation: BrowserObservation,
        recipe: AppRecipe,
        expected_state_revision: int,
        expected_effect_identity: str | None,
    ) -> _RouteAdherenceOverride | object:
        resolved = self._adherence_step_index(run_id=run_id, observation=observation)
        observer = getattr(self._context, "observe_run_surface", None)
        if resolved is None or not callable(observer):
            return _RouteAdherenceOverride(
                outcome=None,
                expected_state_revision=expected_state_revision,
            )
        _plan, step_index = resolved
        projection_revision = expected_state_revision
        outcome = observer(
            run_id=run_id,
            step_index=step_index,
            observed_url=observation.current_url,
        )
        if outcome.action == "replan":
            replanner = getattr(self._context, "replan_run_route", None)
            replanned: bool | None = False
            if callable(replanner):
                replanned = replanner(
                    run_id=run_id,
                    recipe=recipe,
                    expected_state_revision=expected_state_revision,
                    expected_effect_identity=expected_effect_identity,
                    # The divergence the observer just measured, as sanitized prose.
                    # ``getattr`` because the context is duck-typed here: an older
                    # outcome without the field degrades to the evidence-free
                    # re-plan rather than raising.
                    evidence=getattr(outcome, "evidence", ""),
                )
            if replanned is None:
                return _STALE_ROUTE_OBSERVATION
            if replanned:
                projection_revision += 1
                replacement = self._adherence_step_index(
                    run_id=run_id,
                    observation=observation,
                )
                if replacement is None:
                    return _RouteAdherenceOverride(
                        outcome=None,
                        expected_state_revision=projection_revision,
                    )
                _plan, step_index = replacement
                outcome = observer(
                    run_id=run_id,
                    step_index=step_index,
                    observed_url=observation.current_url,
                )
        if outcome.action == "proceed":
            return _RouteAdherenceOverride(
                outcome=None,
                expected_state_revision=projection_revision,
            )
        return _RouteAdherenceOverride(
            outcome=_AppliedBrowserOutcome(
                status="blocked",
                phase="blocked",
                reason_code="route_divergence_unresolved",
                provider_browser="blocked",
                expected_state_revision=projection_revision,
            ),
            expected_state_revision=projection_revision,
        )

    def _drive_browser(
        self,
        *,
        run_id: str,
        context: BrowserSessionContext,
        request: OperationsRequest,
        research: OperationalResearch,
        recipe: AppRecipe,
        sensitive: dict[str, str] | None,
        transient_secrets: bool,
    ) -> None:
        """Bind the run id for the thread, then drive it.

        A thread target starts from an empty context, so a ContextVar the caller
        set never arrives here. Binding at the top of the target is what makes
        every log line this run emits -- across the whole navigate -- carry the
        run id an operator greps for.
        """

        with run_context(run_id):
            self._drive_browser_bound(
                run_id=run_id,
                context=context,
                request=request,
                research=research,
                recipe=recipe,
                sensitive=sensitive,
                transient_secrets=transient_secrets,
            )

    def _drive_browser_bound(
        self,
        *,
        run_id: str,
        context: BrowserSessionContext,
        request: OperationsRequest,
        research: OperationalResearch,
        recipe: AppRecipe,
        sensitive: dict[str, str] | None,
        transient_secrets: bool,
    ) -> None:
        expected_effect_identity: str | None = None
        navigation_dispatched = False
        try:
            worker = self._context._browser_worker_for("playwright")
            if worker is None:
                self._record_provider_failure(
                    run_id,
                    status="configuration_required",
                    phase="browser_unavailable",
                    reason_code="playwright_not_configured",
                )
                return
            secret_grants: dict[str, str] = {}
            lock = self._context._run_lock(run_id)
            with lock:
                current = self._bound_browser_record_locked(
                    run_id=run_id,
                    session_id=context.session_id,
                    statuses=frozenset({"browser_running"}),
                    phases=(
                        frozenset({"authentication_submitted"})
                        if sensitive
                        else frozenset({"browser_running"})
                    ),
                )
                if current is None:
                    return
                raw_effect_identity = current.get("effect_identity")
                if not isinstance(raw_effect_identity, str) or not raw_effect_identity:
                    return
                expected_effect_identity = raw_effect_identity
                secret_grants = self._reserve_consume_grants_locked(
                    worker=worker,
                    operation_key=expected_effect_identity,
                    run_id=run_id,
                    session_id=context.session_id,
                    app_slug=recipe.app_slug,
                    references=sensitive,
                )
            navigate_kwargs: dict[str, object] = {
                "recipe": recipe,
                "sensitive_data": sensitive,
                "account_creation_requested": request.account_creation_requested,
                "signup_fields": _signup_fields_for(request),
                "setup_fields": _setup_fields_for(request, recipe),
                "credential_creation_policy": request.credential_creation_policy,
            }
            if self._requires_broker_grants(worker):
                navigate_kwargs["secret_grants"] = secret_grants
            navigate = cast(Any, worker.navigate_onboarding)
            navigation_call = navigate(
                context,
                research,
                **navigate_kwargs,
            )
            navigation_dispatched = True
            observation = asyncio.run(navigation_call)
        except Exception as exc:
            observation = BrowserObservation(
                status="failed",
                current_url="https://unknown.invalid/",
                page_title="Browser step",
                reason_code=_safe_reason(exc, "browser_navigation_failed"),
            )
        finally:
            if navigation_dispatched:
                if sensitive is not None:
                    sensitive.clear()
            else:
                self._discard_pre_dispatch_browser_secrets(
                    sensitive=sensitive,
                    app_slug=recipe.app_slug,
                    run_id=run_id,
                    transient=transient_secrets,
                )
        self._apply_browser_observation(
            run_id,
            observation=observation,
            research=research,
            request=request,
            recipe=recipe,
            context=context,
            expected_effect_identity=expected_effect_identity,
        )

    def _resolve_browser_outcome(
        self,
        *,
        run_id: str,
        observation: BrowserObservation,
        research: OperationalResearch,
        request: OperationsRequest,
        recipe: AppRecipe,
        context: BrowserSessionContext,
        expected_effect_identity: str | None = None,
        expected_state_revision: int | None = None,
    ) -> _AppliedBrowserOutcome:
        if observation.status == "human_action_required":
            action_type = observation.human_action_type or "login_required"
            hitl = {
                "type": action_type,
                "message": observation.human_instruction or "Complete the browser step.",
                "expected_completion_signal": "human_completed",
                "live_view_available": True,
                "hitl_generation": observation.hitl_generation,
            }
            if action_type == "email_otp":
                hitl["verification_requested_at"] = (
                    datetime.now(UTC).isoformat().replace("+00:00", "Z")
                )
            return _AppliedBrowserOutcome(
                status="waiting_for_hitl",
                phase="challenge_pending",
                reason_code=observation.reason_code or "human_action_required",
                provider_browser="waiting_for_hitl",
                hitl=hitl,
                events=(("browser_hitl_required", hitl),),
            )
        if observation.status == "blocked":
            # A host-policy refusal is not a policy STOP, it is an incomplete
            # reviewed host list — the vendor redirected through an identity
            # provider, moved a settings page, or the list never covered the
            # whole flow. Every one of those is fixed by editing the recipe and
            # pressing Retry, so it projects as ``configuration_required``: a
            # status ``ops/core/state.py`` lets a run leave, on a phase that is
            # not in ``RETRY_DENIED_PHASES``. Terminal ``blocked`` is reserved
            # for the refusals nothing an operator types can undo — the model's
            # own unproven ``report_blocked``, and route divergence.
            if observation.reason_code == HOST_POLICY_REASON_CODE:
                return _AppliedBrowserOutcome(
                    status="configuration_required",
                    phase="host_policy_review_required",
                    reason_code=HOST_POLICY_REASON_CODE,
                    provider_browser="blocked",
                )
            return _AppliedBrowserOutcome(
                status="blocked",
                phase="blocked",
                reason_code=observation.reason_code or "browser_policy_blocked",
                provider_browser="blocked",
            )
        if (
            observation.status == "failed"
            and observation.reason_code == "browser_resume_outcome_unknown"
        ):
            return _AppliedBrowserOutcome(
                status="configuration_required",
                phase="effect_reconciliation",
                reason_code="browser_resume_outcome_unknown",
                provider_browser="outcome_unknown",
            )
        if observation.status == "failed":
            return _AppliedBrowserOutcome(
                status="failed",
                phase="failed",
                reason_code=observation.reason_code or "browser_navigation_failed",
                provider_browser="failed",
            )
        if observation.status not in {"credential_page_ready", "developer_console_ready"}:
            return _AppliedBrowserOutcome(
                status="browser_running",
                phase="target_probe_pending",
                reason_code=observation.reason_code or "browser_navigation_in_progress",
                provider_browser="running",
            )

        if (
            recipe.browser is not None
            and recipe.browser.scope == "entry_only"
            and observation.status == "developer_console_ready"
        ):
            entry_event = (
                "browser_entry_reached",
                {
                    "status": "browser_running",
                    "reason_code": "reviewed_public_entry_reached",
                    "external_actions": True,
                },
            )
            return _AppliedBrowserOutcome(
                status="browser_running",
                phase="entry_reached",
                reason_code="owner_credential_submission_available",
                provider_browser="entry_reached",
                events=(entry_event,),
            )

        ready_event = (
            "credential_page_ready",
            {
                "status": "browser_running",
                "reason_code": "reviewed_success_predicate_satisfied",
                "external_actions": True,
            },
        )
        if recipe.capture.mode != "automatic":
            return _AppliedBrowserOutcome(
                status="browser_running",
                phase="credential_ready",
                reason_code="owner_credential_submission_required",
                provider_browser="credential_page_ready",
                events=(ready_event,),
            )

        worker = self._context._browser_worker_for("playwright")
        capture = getattr(worker, "auto_capture_credentials", None)
        if not callable(capture):
            return _AppliedBrowserOutcome(
                status="browser_running",
                phase="credential_ready",
                reason_code="automatic_capture_unavailable",
                provider_browser="credential_page_ready",
                events=(ready_event,),
            )

        effect_identity = f"{run_id}:credential-capture:v1"
        broker_grants: dict[str, str] = {}
        lock = self._context._run_lock(run_id)
        with lock:
            current = self._bound_browser_record_locked(
                run_id=run_id,
                session_id=context.session_id,
                statuses=frozenset({"browser_running", "waiting_for_hitl"}),
                effect_identity=expected_effect_identity,
                state_revision=expected_state_revision,
            )
            if current is None:
                return _AppliedBrowserOutcome(
                    status="configuration_required",
                    phase="effect_reconciliation",
                    reason_code="browser_observation_no_longer_current",
                    provider_browser="outcome_unknown",
                    effect_identity=expected_effect_identity,
                    events=(ready_event,),
                )
            with self._context.storage.unit_of_work() as transaction:
                current = transaction.get_run(run_id)
                if (
                    current is None
                    or current.get("state_engine") != "canonical_v1"
                    or current.get("browser_provider") != "playwright"
                    or current.get("browser_session_id") != context.session_id
                    or str(current.get("status") or "")
                    not in {"browser_running", "waiting_for_hitl"}
                    or (
                        expected_effect_identity is not None
                        and current.get("effect_identity") != expected_effect_identity
                    )
                    or (
                        expected_state_revision is not None
                        and int(current.get("state_revision", 0) or 0) != expected_state_revision
                    )
                ):
                    return _AppliedBrowserOutcome(
                        status="configuration_required",
                        phase="effect_reconciliation",
                        reason_code="browser_observation_no_longer_current",
                        provider_browser="outcome_unknown",
                        effect_identity=expected_effect_identity,
                        events=(ready_event,),
                    )
                _intent, reserved = transaction.reserve_side_effect(
                    run_id=run_id,
                    operation_key=effect_identity,
                    provider="playwright_vault",
                )
                transaction.update_run(
                    run_id,
                    status="browser_running",
                    phase="credential_capture_reserved",
                    reason_code="credential_capture_reserved",
                    effect_identity=effect_identity,
                    hitl_request=None,
                    state_revision=int(current.get("state_revision", 0) or 0) + 1,
                )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="credential_capture_reserved",
                    payload={"provider": "playwright", "external_actions": False},
                )
            if reserved:
                try:
                    broker_grants = self._reserve_capture_grants_locked(
                        worker=worker,
                        operation_key=effect_identity,
                        run_id=run_id,
                        session_id=context.session_id,
                        recipe=recipe,
                    )
                except Exception as exc:
                    with contextlib.suppress(Exception):
                        self._context.storage.update_side_effect(
                            run_id=run_id,
                            operation_key=effect_identity,
                            status="failed",
                        )
                    return _AppliedBrowserOutcome(
                        status="configuration_required",
                        phase="effect_reconciliation",
                        reason_code=_safe_reason(
                            exc,
                            "automatic_capture_grant_unavailable",
                        ),
                        provider_browser="credential_page_ready",
                        effect_identity=effect_identity,
                        events=(ready_event,),
                    )
        if not reserved:
            return _AppliedBrowserOutcome(
                status="configuration_required",
                phase="effect_reconciliation",
                reason_code="credential_capture_reconciliation_required",
                provider_browser="credential_page_ready",
                effect_identity=effect_identity,
                events=(ready_event,),
            )
        try:
            capture_scope_kwargs: dict[str, object] = {}
            if bool(getattr(worker, "requires_session_capability_scope", False)):
                capture_scope_kwargs["capability_scope"] = run_id
            if self._requires_broker_grants(worker):
                if not broker_grants:  # pragma: no cover - reservation invariant
                    raise CredentialSubmissionError("automatic_capture_grant_unavailable")
                if len(broker_grants) == 1:
                    capture_scope_kwargs["broker_grant"] = next(iter(broker_grants.values()))
                else:
                    capture_scope_kwargs["broker_grants"] = broker_grants
            refs = asyncio.run(
                capture(
                    context.session_id,
                    recipe.app_slug,
                    self._context._secret_store,
                    recipe=recipe,
                    **capture_scope_kwargs,
                )
            )
        except Exception:
            # The broker grant makes an exact capture retry idempotent, but loss of
            # the outer worker RPC can still hide whether the reviewed page state
            # changed. Keep the run at explicit reconciliation rather than infer
            # an outcome from transport failure.
            self._context.storage.update_side_effect(
                run_id=run_id,
                operation_key=effect_identity,
                status="outcome_unknown",
            )
            return _AppliedBrowserOutcome(
                status="configuration_required",
                phase="effect_reconciliation",
                reason_code="credential_capture_outcome_unknown",
                provider_browser="credential_page_ready",
                effect_identity=effect_identity,
                events=(ready_event,),
            )
        if not refs:
            self._context.storage.update_side_effect(
                run_id=run_id,
                operation_key=effect_identity,
                status="completed",
                external_id="no_credential_found",
            )
            return _AppliedBrowserOutcome(
                status="browser_running",
                phase="credential_ready",
                reason_code="automatic_capture_failed_owner_submission_available",
                provider_browser="credential_page_ready",
                effect_identity=effect_identity,
                events=(ready_event,),
            )
        try:
            final = self._context._finalize_captured_credentials(
                research,
                request,
                refs,
                recipe=recipe,
            )
        except Exception:
            self._context.storage.update_side_effect(
                run_id=run_id,
                operation_key=effect_identity,
                status="completed",
                external_id="credential_vaulted",
            )
            return _AppliedBrowserOutcome(
                status="configuration_required",
                phase="credential_validation_failed",
                reason_code="credential_finalization_failed",
                provider_browser="credential_page_ready",
                effect_identity=effect_identity,
                events=(ready_event,),
                vaulted_credential_refs=dict(refs),
            )
        self._context.storage.update_side_effect(
            run_id=run_id,
            operation_key=effect_identity,
            status="completed",
            external_id="credential_vaulted",
        )
        changes: dict[str, object] = {}
        if final.bundle is not None:
            changes["integrator_bundle"] = final.bundle
        return _AppliedBrowserOutcome(
            status=cast(RunStatus, final.status),
            phase="completed" if final.status == "completed" else "credential_ready",
            reason_code=final.reason_code,
            provider_browser="credential_page_ready",
            effect_identity=effect_identity,
            changes=changes,
            events=(ready_event, *tuple(final.events)),
            # Both post-capture outcomes carry the references, not just the happy
            # one: the vault write is the worker's, and it has already happened in
            # either branch. The ledger row above says a credential exists; this
            # says where it is, so the two together survive a lost projection.
            vaulted_credential_refs=dict(refs),
        )

    def _record_step_telemetry(
        self,
        run_id: str,
        *,
        observation: BrowserObservation,
        recipe: AppRecipe,
    ) -> None:
        """Write the action loop's trail as the two telemetry rows the console reads.

        The operator console's *Chain of thought* renders
        ``onboarding_progress_events`` and ``onboarding_step_decisions``, and the
        only writer of either was ``DurableLoopTelemetry``, which is wired solely
        to the driver the API still refuses. So on the live canonical path the
        panel had nothing to render — not because the agent was silent, but
        because every fact it produced was computed inside the browser container
        and discarded there. This is the bridge: the worker now carries a
        bounded, value-free trail back on the observation, and this writes it.

        Four choices worth stating, because each of them is a constraint rather
        than a preference:

        * ``phase`` is the constant ``developer_app`` for every canonical browser
          step. The canonical runtime's own ~40 phase strings are a different
          vocabulary from :data:`ONBOARDING_PHASES`, and inventing a per-step
          mapping would make the console claim the run crossed phase boundaries
          the runtime never crossed. One honest phase beats seventeen invented
          ones.
        * ``profile_digest`` is derived, not looked up. It is never projected to
          the API — it exists to satisfy the storage validator and to join rows —
          so deriving it from the recipe slug keeps it stable across drives
          without pretending a research profile was involved.
        * ``step_index`` is offset past whatever the run already recorded. The
          worker numbers steps from 1 within a single drive; a run that drives
          twice would otherwise write two rows numbered 1, and the console's
          one-to-one join of a progress event to its decision would become
          ambiguous.
        * ``reason_code`` and ``action`` are dropped unless they are members of
          the vocabularies storage enforces. ``record_step_decision`` RAISES on an
          unknown reason code, and the browser's execution reason codes are a
          different, wider set — so a code from that set must not cost the run
          its telemetry row.

        The whole method is best-effort. Telemetry that failed to write must
        never fail the run that produced it: the observation has already been
        projected by the time this is called, and the vendor-side work it
        describes has already happened.
        """

        steps = getattr(observation, "steps", ())
        if not steps:
            return
        try:
            storage = self._context.storage
            digest = _canonical_profile_digest(recipe.app_slug)
            recorded = storage.list_progress_events(run_id)
            offset = max((int(row.get("step_index") or 0) for row in recorded), default=0)
            for step in steps[:MAX_OBSERVATION_STEPS]:
                index = offset + step.step_index
                if index > MAX_PROGRESS_STEP_INDEX:
                    break
                storage.record_progress_event(
                    run_id=run_id,
                    phase=_CANONICAL_TELEMETRY_PHASE,
                    profile_digest=digest,
                    correlation_id=_CANONICAL_TELEMETRY_CORRELATION_ID,
                    step_index=index,
                    stage=step.stage,
                    elapsed_ms=step.elapsed_ms,
                )
                storage.record_step_decision(
                    run_id=run_id,
                    phase=_CANONICAL_TELEMETRY_PHASE,
                    correlation_id=_CANONICAL_TELEMETRY_CORRELATION_ID,
                    step_index=index,
                    decision=step.decision,
                    reason_code=(
                        step.reason_code if step.reason_code in ONBOARDING_REASON_CODES else None
                    ),
                    candidate_label=step.candidate_label,
                    action=(step.action if step.action in CANDIDATE_ACTION_VALUES else None),
                    target_host=step.target_host,
                    reason=step.reason,
                )
        except Exception:  # pragma: no cover - telemetry must never fail a run
            log_event("canonical.browser.telemetry_not_recorded", run_id=run_id)

    def _apply_browser_observation(
        self,
        run_id: str,
        *,
        observation: BrowserObservation,
        research: OperationalResearch,
        request: OperationsRequest,
        recipe: AppRecipe,
        context: BrowserSessionContext,
        expected_effect_identity: str | None = None,
    ) -> dict[str, Any] | None:
        # Prove that this exact session/effect still owns the run before doing any
        # follow-up provider work. The lock is deliberately released before
        # capture/validation so a broker callback can acquire it.
        lock = self._context._run_lock(run_id)
        with lock:
            bound = self._bound_browser_record_locked(
                run_id=run_id,
                session_id=context.session_id,
                statuses=frozenset({"browser_running", "waiting_for_hitl"}),
                effect_identity=expected_effect_identity,
            )
            if bound is None:
                return None
            expected_state_revision = int(bound.get("state_revision", 0) or 0)
        route_override = self._route_adherence_override(
            run_id=run_id,
            observation=observation,
            recipe=recipe,
            expected_state_revision=expected_state_revision,
            expected_effect_identity=expected_effect_identity,
        )
        if route_override is _STALE_ROUTE_OBSERVATION:
            return None
        if not isinstance(route_override, _RouteAdherenceOverride):
            return None
        outcome = route_override.outcome or self._resolve_browser_outcome(
            run_id=run_id,
            observation=observation,
            research=research,
            request=request,
            recipe=recipe,
            context=context,
            expected_effect_identity=expected_effect_identity,
            expected_state_revision=route_override.expected_state_revision,
        )
        projection_revision = route_override.expected_state_revision
        if (
            outcome.effect_identity is not None
            and outcome.effect_identity != expected_effect_identity
        ):
            projection_revision += 1
        outcome = replace(outcome, expected_state_revision=projection_revision)
        projection_effect_identity = outcome.effect_identity or expected_effect_identity
        with lock:
            current = self._bound_browser_record_locked(
                run_id=run_id,
                session_id=context.session_id,
                statuses=frozenset({"browser_running", "waiting_for_hitl"}),
                effect_identity=projection_effect_identity,
                state_revision=outcome.expected_state_revision,
            )
            if current is None:
                return None
            persisted_hitl = dict(outcome.hitl) if outcome.hitl is not None else None
            if (
                persisted_hitl is not None
                and persisted_hitl.get("type") == "email_otp"
                and isinstance(current.get("hitl_request"), Mapping)
                and current["hitl_request"].get("type") == "email_otp"
            ):
                previous_requested_at = current["hitl_request"].get("verification_requested_at")
                if isinstance(previous_requested_at, str) and previous_requested_at:
                    persisted_hitl["verification_requested_at"] = previous_requested_at
            if request.account_creation_requested and observation.status in {
                "credential_page_ready",
                "developer_console_ready",
            }:
                try:
                    promoted = self._context._promote_staged_signup_login(
                        app_slug=recipe.app_slug,
                        account_ref=validate_browser_account_ref(
                            current.get("browser_account_ref")
                        ),
                        run_id=run_id,
                    )
                except Exception as exc:
                    outcome = replace(
                        outcome,
                        status="configuration_required",
                        phase="signup_login_promotion",
                        reason_code=_safe_reason(exc, "signup_login_promotion_failed"),
                        events=(
                            *(event for event in outcome.events if event[0] != "run_completed"),
                            (
                                "signup_login_promotion_failed",
                                {
                                    "reason_code": _safe_reason(
                                        exc, "signup_login_promotion_failed"
                                    ),
                                    "external_actions": False,
                                },
                            ),
                        ),
                    )
                else:
                    if set(promoted) != {"login_email", "login_password"}:
                        outcome = replace(
                            outcome,
                            status="configuration_required",
                            phase="signup_login_promotion",
                            reason_code="signup_login_promotion_incomplete",
                        )
                    else:
                        outcome = replace(
                            outcome,
                            events=(
                                (
                                    "signup_login_promoted",
                                    {
                                        "fields": list(promoted),
                                        "external_actions": False,
                                    },
                                ),
                                *outcome.events,
                            ),
                        )
            elif (
                request.account_mode == "existing_account"
                and observation.status == "credential_page_ready"
                and bool(
                    getattr(
                        self._context._settings,
                        "browser_login_credential_reuse",
                        True,
                    )
                )
                and self._context._secret_store is not None
            ):
                # ``credential_page_ready`` is emitted only after the reviewed
                # protected-page predicate is freshly satisfied. Form submission,
                # navigation, and entry-only public pages never reach this branch.
                # The staged pair is therefore promoted only after positive
                # authentication evidence, never when a typo merely gets typed.
                try:
                    promoted = self._context._secret_store.promote_staged_existing_login_pair(
                        app_slug=recipe.app_slug,
                        account_ref=validate_browser_account_ref(
                            current.get("browser_account_ref")
                        ),
                        run_id=run_id,
                    )
                except Exception as exc:
                    outcome = replace(
                        outcome,
                        status="configuration_required",
                        phase="login_credential_promotion",
                        reason_code=_safe_reason(exc, "existing_login_promotion_failed"),
                        events=(
                            *(event for event in outcome.events if event[0] != "run_completed"),
                            (
                                "existing_login_promotion_failed",
                                {
                                    "reason_code": _safe_reason(
                                        exc, "existing_login_promotion_failed"
                                    ),
                                    "external_actions": False,
                                },
                            ),
                        ),
                    )
                else:
                    if promoted and set(promoted) != {"login_email", "login_password"}:
                        outcome = replace(
                            outcome,
                            status="configuration_required",
                            phase="login_credential_promotion",
                            reason_code="existing_login_promotion_incomplete",
                        )
                    elif promoted:
                        outcome = replace(
                            outcome,
                            events=(
                                (
                                    "existing_login_promoted",
                                    {
                                        "fields": list(promoted),
                                        "external_actions": False,
                                    },
                                ),
                                *outcome.events,
                            ),
                        )
            with self._context.storage.unit_of_work() as transaction:
                record = transaction.get_run(run_id)
                discarded = _projection_discard_reason(
                    record,
                    session_id=context.session_id,
                    projection_effect_identity=projection_effect_identity,
                    expected_state_revision=outcome.expected_state_revision,
                )
                if discarded is not None:
                    # The compare-and-set lost: another writer owns this row now.
                    # Returning silently was the bug — by this point
                    # ``_finalize_captured_credentials`` may already have vaulted a
                    # secret and the vendor may already have issued it, and the only
                    # record of that work was a projection about to be thrown away.
                    #
                    # What is written here is an AUDIT EVENT and nothing else. It is
                    # deliberately not a status or phase write: every branch of
                    # ``_projection_discard_reason`` means some other authority is
                    # already responsible for this run — a retry took a fresh effect
                    # identity, an operator paused it, a newer projection landed —
                    # so forcing a phase would be this loser overwriting the winner,
                    # which is the same race one level up. An append-only fact
                    # conflicts with nobody and still leaves the evidence.
                    #
                    # Committed on the same transaction: appending it is what this
                    # unit of work now exists to do. ``record is None`` is the one
                    # case with nothing to attach the event to.
                    if record is not None:
                        transaction.append_audit_event(
                            run_id=run_id,
                            event_type="browser_projection_discarded",
                            payload={
                                "reason_code": discarded,
                                "discarded_status": outcome.status,
                                "discarded_phase": outcome.phase,
                                "discarded_reason_code": outcome.reason_code,
                                # The projection is dropped, but the work it
                                # describes may already have reached the vendor.
                                "external_actions": True,
                            },
                        )
                        _record_discarded_credential_custody(
                            transaction,
                            run_id,
                            record=record,
                            outcome=outcome,
                            discard_reason=discarded,
                        )
                    return None
                revision = int(record.get("state_revision", 0) or 0) + 1
                changes: dict[str, object] = {
                    "status": outcome.status,
                    "phase": outcome.phase,
                    "reason_code": outcome.reason_code,
                    "route_reason_code": outcome.reason_code,
                    "hitl_request": persisted_hitl,
                    "provider_status": {
                        "recipe": recipe.readiness_tier,
                        "composio": "not_started",
                        "browser": outcome.provider_browser,
                        "email": "not_started",
                        "validation": ("ready" if outcome.status == "completed" else "not_started"),
                    },
                    "external_actions": True,
                    "state_revision": revision,
                    "last_projected_revision": revision,
                    **dict(outcome.changes or {}),
                }
                updated = transaction.update_run(run_id, **changes)
                for event_type, payload in outcome.events:
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type=event_type,
                        payload={**dict(payload), "external_actions": True},
                    )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="browser_outcome_recorded",
                    payload={
                        "status": outcome.status,
                        "phase": outcome.phase,
                        "reason_code": outcome.reason_code,
                        "external_actions": True,
                    },
                )
        if outcome.status in {"completed", "failed", "blocked", "configuration_required"}:
            self._context._release_browser_session(
                context,
                "playwright",
                reason=f"canonical_{outcome.status}",
            )
        # After the projection commits, not before: a trail written for a
        # projection that then lost its CAS race would describe work the run
        # never recorded, and the console would show steps belonging to a
        # different writer's version of the run. The phase boundary below is
        # written here for the same reason and under the same rule — the
        # discard branch returns above, so a loser writes no history.
        self._record_step_telemetry(run_id, observation=observation, recipe=recipe)
        boundary = _CANONICAL_OUTCOME_BOUNDARY.get(outcome.phase)
        if boundary is not None:
            self._commit_phase_boundary(
                run_id,
                target=boundary[0],
                reason_code=boundary[1],
                app_slug=recipe.app_slug,
                attempt=int(updated.get("attempt", 0) or 0),
            )
        log_event("canonical.browser.applied", run_id=run_id, status=outcome.status)
        return _public_run(updated)

    def resume_after_takeover(
        self,
        run_id: str,
        *,
        expected_state_revision: int,
        expected_session_id: str,
        expected_gate: HumanActionType,
        expected_hitl_generation: int,
    ) -> Mapping[str, object]:
        """Continue only the exact canonical CAPTCHA pause that was observed."""

        result = self.resume_run(
            run_id,
            signal="completed",
            browser_login=None,
            expected_state_revision=expected_state_revision,
            expected_session_id=expected_session_id,
            expected_gate=expected_gate,
            expected_hitl_generation=expected_hitl_generation,
        )
        if result.get("reason_code") in {
            "hitl_generation_mismatch",
            "hitl_generation_invalid",
        }:
            raise RunConflictError(run_id, "takeover_generation")
        return result

    def _stop_canonical_browser(
        self,
        run_id: str,
        *,
        expected_status: RunStatus,
        status: RunStatus,
        phase: str,
        reason_code: str,
        expected_state_revision: int,
        expected_session_id: str,
        expected_gate: HumanActionType,
        expected_hitl_generation: int,
    ) -> bool:
        """Guard and terminate one observed canonical state, then release its session."""

        lock = self._context._run_lock(run_id)
        context: BrowserSessionContext | None = None
        with lock:
            current = self._context.storage.get_run(run_id)
            hitl = current.get("hitl_request") if current is not None else None
            if (
                current is None
                or current.get("state_engine") != "canonical_v1"
                or current.get("status") != expected_status
                or int(current.get("state_revision", 0) or 0) != expected_state_revision
                or str(current.get("browser_session_id") or "") != expected_session_id
                or not isinstance(hitl, Mapping)
                or hitl.get("type") != expected_gate
                or hitl.get("hitl_generation") != expected_hitl_generation
            ):
                return False
            context = self._context._session_context_for(run_id)
            self._record_provider_failure(
                run_id,
                status=status,
                phase=phase,
                reason_code=reason_code,
                external_actions=bool(current.get("external_actions")),
            )
        self._context._release_browser_session(
            context,
            "playwright",
            reason=f"canonical_{reason_code}",
        )
        return True

    def pause_after_takeover(
        self,
        run_id: str,
        *,
        reason_code: str,
        expected_state_revision: int,
        expected_session_id: str,
        expected_gate: HumanActionType,
        expected_hitl_generation: int,
    ) -> bool:
        """Stop polling an unrecoverable canonical human gate durably."""

        phase = (
            "session_lost"
            if reason_code in {"session_lifetime_exceeded", "session_unreattachable"}
            else "challenge_unavailable"
        )
        return self._stop_canonical_browser(
            run_id,
            expected_status="waiting_for_hitl",
            status="configuration_required",
            phase=phase,
            reason_code=reason_code,
            expected_state_revision=expected_state_revision,
            expected_session_id=expected_session_id,
            expected_gate=expected_gate,
            expected_hitl_generation=expected_hitl_generation,
        )

    def pause_stale_run(
        self,
        run_id: str,
        *,
        reason_code: str,
        expected_updated_at: str,
        stale_seconds: int,
    ) -> bool:
        """Atomically fence a canonical browser RPC that is still stale.

        Never a run parked for a person. ``RunLivenessService`` already excludes
        the awaiting-owner phases from its own staleness clock, but this method is
        the authority that actually writes ``failed`` — and an invariant enforced
        only in the caller is one sweep away from being lost again. The bug it
        prevents is worth restating: ``browser_running`` plus ``credential_ready``
        or ``entry_reached`` is the exact pair
        ``RunCredentialService.submit_owner_credentials`` requires, so failing such
        a run five minutes after it reached the page a human was asked to visit
        made the run refuse the very submission it had just invited.
        """

        try:
            last_updated = datetime.fromisoformat(expected_updated_at.replace("Z", "+00:00"))
        except ValueError:
            return False
        if last_updated.tzinfo is None:
            last_updated = last_updated.replace(tzinfo=UTC)
        if last_updated > datetime.now(UTC) - timedelta(seconds=stale_seconds):
            return False

        lock = self._context._run_lock(run_id)
        context: BrowserSessionContext | None = None
        with lock:
            current = self._context.storage.get_run(run_id)
            if (
                current is None
                or str(current.get("phase") or "") in AWAITING_OWNER_PHASES
                or current.get("state_engine") != "canonical_v1"
                or current.get("status") != "browser_running"
                or str(current.get("updated_at") or "") != expected_updated_at
            ):
                return False
            context = self._context._session_context_for(run_id)
            with self._context.storage.unit_of_work() as transaction:
                record = transaction.get_run(run_id)
                if (
                    record is None
                    or str(record.get("phase") or "") in AWAITING_OWNER_PHASES
                    or record.get("state_engine") != "canonical_v1"
                    or record.get("status") != "browser_running"
                    or str(record.get("updated_at") or "") != expected_updated_at
                ):
                    return False
                revision = int(record.get("state_revision", 0) or 0) + 1
                transaction.update_run(
                    run_id,
                    status="failed",
                    phase="failed",
                    reason_code=reason_code,
                    route_reason_code=reason_code,
                    hitl_request=None,
                    provider_status={
                        "recipe": record.get("readiness_tier"),
                        "composio": "not_started",
                        "browser": "failed",
                        "email": "not_started",
                        "validation": "not_started",
                    },
                    external_actions=bool(record.get("external_actions")),
                    state_revision=revision,
                    last_projected_revision=revision,
                )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="onboarding_progress_stale",
                    payload={
                        "reason_code": reason_code,
                        "stale_seconds": stale_seconds,
                        "external_actions": False,
                    },
                )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="provider_operation_failed",
                    payload={
                        "status": "failed",
                        "phase": "failed",
                        "reason_code": reason_code,
                        "external_actions": bool(record.get("external_actions")),
                    },
                )
        self._context._release_browser_session(
            context,
            "playwright",
            reason=f"canonical_{reason_code}",
        )
        return True

    def resume_run(
        self,
        run_id: str,
        *,
        signal: str,
        browser_login: Mapping[str, SecretStr] | None,
        expected_state_revision: int | None = None,
        expected_session_id: str | None = None,
        expected_gate: HumanActionType | None = None,
        expected_hitl_generation: int | None = None,
    ) -> dict[str, Any]:
        lock = self._context._run_lock(run_id)
        if not lock.acquire(blocking=False):
            raise RunConflictError(run_id, "resume")
        sensitive: dict[str, str] | None = None
        sensitive_app_slug: str | None = None
        transient_secrets = False
        secret_grants: dict[str, str] = {}
        reserved_state_revision: int | None = None
        try:
            current = self._context.storage.get_run(run_id)
            if current is None:
                raise KeyError("run was not found")
            if current.get("state_engine") != "canonical_v1":
                raise CredentialSubmissionError("legacy_run_is_read_only")
            if current.get("status") != "waiting_for_hitl":
                raise CredentialSubmissionError("run_not_waiting_for_hitl")
            if expected_state_revision is not None:
                hitl = current.get("hitl_request")
                if (
                    int(current.get("state_revision", 0) or 0) != expected_state_revision
                    or str(current.get("browser_session_id") or "")
                    != str(expected_session_id or "")
                    or not isinstance(hitl, Mapping)
                    or hitl.get("type") != expected_gate
                    or (
                        expected_hitl_generation is not None
                        and hitl.get("hitl_generation") != expected_hitl_generation
                    )
                ):
                    raise RunConflictError(run_id, "takeover_resume")
            if current.get("browser_provider") != "playwright":
                raise CredentialSubmissionError("playwright_required_for_recipe")
            try:
                account_ref = validate_browser_account_ref(current.get("browser_account_ref"))
            except ValueError:
                raise CredentialSubmissionError("browser_account_binding_missing") from None
            worker = self._context._browser_worker_for("playwright")
            context = self._context._session_context_for(run_id)
            if worker is None or context is None:
                return self._record_provider_failure(
                    run_id,
                    status="configuration_required",
                    phase="session_lost",
                    reason_code="session_lost",
                )
            research = OperationalResearch.model_validate(current.get("operational_research"))
            request = OperationsRequest.model_validate(current.get("request"))
            recipe = self._recipe_for_run(current)
            sensitive_app_slug = recipe.app_slug
            transient_secrets = self._requires_broker_grants(worker)
            if recipe.route_kind != "playwright":
                raise CredentialSubmissionError("run_is_not_playwright")

            if browser_login:
                login_values = browser_login
                if request.account_mode == "existing_account":
                    store = self._context._secret_store
                    if store is None:
                        raise CredentialSubmissionError("existing_login_vault_required")
                    try:
                        staged = store.stage_existing_login_pair(
                            app_slug=recipe.app_slug,
                            account_ref=account_ref,
                            run_id=run_id,
                            email=browser_login["login_email"].get_secret_value(),
                            password=browser_login["login_password"].get_secret_value(),
                        )
                    except Exception as exc:
                        raise CredentialSubmissionError(
                            _safe_reason(exc, "existing_login_stage_failed")
                        ) from None
                    login_values = {
                        field: SecretStr(staged[field])
                        for field in ("login_email", "login_password")
                    }
                elif request.account_creation_requested and set(browser_login).issubset(
                    {"login_otp", "login_verification_url"}
                ):
                    # A verification challenge can occur between the reviewed
                    # email-first entry and the password/details continuation.
                    # Preserve the one-time verification value while re-issuing
                    # this exact run's generated signup pair; otherwise the worker
                    # consumes the OTP/link successfully and then has no password
                    # with which to finish the same signup session.
                    staged_signup = self._context._staged_signup_login_values(
                        app_slug=recipe.app_slug,
                        account_ref=account_ref,
                        run_id=run_id,
                    )
                    if set(staged_signup) != {"login_email", "login_password"}:
                        raise CredentialSubmissionError("signup_login_vault_required")
                    login_values = {**staged_signup, **browser_login}
                sensitive = self._context._browser_login_payload(
                    provider="playwright",
                    app_slug=recipe.app_slug,
                    scope_id=run_id,
                    values=login_values,
                )
            elif request.account_creation_requested:
                # Generated signup credentials are part of this authorized account
                # creation attempt. A CAPTCHA/legal gate may occur before they were
                # filled, while the service-local transient references have already
                # been consumed. Re-issue fresh one-time references from the
                # encrypted reusable-login vault so the SAME session can continue.
                # Existing-account runs retain the explicit-submission-only rule.
                staged_signup = self._context._staged_signup_login_values(
                    app_slug=recipe.app_slug,
                    account_ref=account_ref,
                    run_id=run_id,
                )
                if staged_signup:
                    sensitive = self._context._browser_login_payload(
                        provider="playwright",
                        app_slug=recipe.app_slug,
                        scope_id=run_id,
                        values=staged_signup,
                    )
            elif self._context._secret_store is not None:
                # Re-issue only this run's staged submission first (for a CAPTCHA
                # or another same-session retry). If none exists, an already
                # verified account-scoped pair may be reused. Neither path mutates
                # durable credentials.
                staged_existing = self._context._secret_store.get_staged_existing_login_pair(
                    app_slug=recipe.app_slug,
                    account_ref=account_ref,
                    run_id=run_id,
                )
                reusable = (
                    {
                        field: SecretStr(staged_existing[field])
                        for field in ("login_email", "login_password")
                    }
                    if set(staged_existing) == {"login_email", "login_password"}
                    else self._context._reusable_login_values(recipe.app_slug, account_ref)
                )
                if reusable:
                    sensitive = self._context._browser_login_payload(
                        provider="playwright",
                        app_slug=recipe.app_slug,
                        scope_id=run_id,
                        values=reusable,
                    )
            attempt = int(current.get("attempt", 0) or 0) + 1
            effect_identity = f"{run_id}:browser-resume:{attempt}"
            # Reserve the exact vault grants while the old HITL state is still
            # authoritative. They are unusable until the transaction below moves
            # this exact effect into ``authentication_submitted``; an abandoned
            # reservation therefore cannot authorize a callback.
            secret_grants = self._reserve_consume_grants_locked(
                worker=worker,
                operation_key=effect_identity,
                run_id=run_id,
                session_id=context.session_id,
                app_slug=recipe.app_slug,
                references=sensitive,
            )
            with self._context.storage.unit_of_work() as transaction:
                _intent, reserved = transaction.reserve_side_effect(
                    run_id=run_id,
                    operation_key=effect_identity,
                    provider="playwright",
                )
                record = transaction.get_run(run_id)
                if record is None:
                    raise KeyError("run was not found")
                reserved_state_revision = int(record.get("state_revision", 0) or 0) + 1
                transaction.update_run(
                    run_id,
                    status="browser_running",
                    phase="authentication_submitted" if sensitive else "target_probe_pending",
                    reason_code="resume_reserved",
                    effect_identity=effect_identity,
                    attempt=attempt,
                    hitl_request=None,
                    state_revision=reserved_state_revision,
                )
            if not reserved:
                raise CredentialSubmissionError("resume_reconciliation_required")
        except BaseException:
            if sensitive_app_slug is not None:
                self._discard_pre_dispatch_browser_secrets(
                    sensitive=sensitive,
                    app_slug=sensitive_app_slug,
                    run_id=run_id,
                    transient=transient_secrets,
                )
            elif sensitive is not None:  # pragma: no cover - defensive invariant
                sensitive.clear()
            raise
        finally:
            lock.release()

        # Never retain the per-run lock across the worker RPC: the isolated worker
        # calls back into the broker, which must take that same lock to linearize
        # one-time consume/capture against the current run phase.
        resume_dispatched = False
        try:
            resume_kwargs: dict[str, object] = {
                "recipe": recipe,
                "sensitive_data": sensitive,
                "account_creation_requested": request.account_creation_requested,
                "signup_fields": _signup_fields_for(request),
                "setup_fields": _setup_fields_for(request, recipe),
                "credential_creation_policy": request.credential_creation_policy,
                "provider_session_id": str(current.get("provider_session_id") or "") or None,
            }
            if self._requires_broker_grants(worker):
                resume_kwargs["secret_grants"] = secret_grants
            if expected_hitl_generation is not None and bool(
                getattr(worker, "supports_hitl_generation_cas", False)
            ):
                resume_kwargs["expected_hitl_generation"] = expected_hitl_generation
            resume = cast(Any, worker.resume_after_hitl)
            resume_call = resume(
                context,
                signal,
                research,
                **resume_kwargs,
            )
            resume_dispatched = True
            observation = asyncio.run(resume_call)
            self._context.storage.update_side_effect(
                run_id=run_id,
                operation_key=effect_identity,
                status="completed",
            )
        except Exception as exc:
            reason_code = _safe_reason(exc, "browser_resume_failed")
            retryable_pre_action = reason_code.startswith("browser_secret_") or reason_code in {
                "hitl_generation_mismatch",
                "hitl_generation_invalid",
            }
            with contextlib.suppress(Exception):
                self._context.storage.update_side_effect(
                    run_id=run_id,
                    operation_key=effect_identity,
                    status=(
                        "outcome_unknown"
                        if reason_code == "browser_resume_outcome_unknown"
                        else "failed"
                    ),
                )
            if retryable_pre_action:
                hitl = current.get("hitl_request")
                raw_action_type = (
                    str(hitl.get("type") or "provider_verification")
                    if isinstance(hitl, Mapping)
                    else "provider_verification"
                )
                action_type = cast(
                    HumanActionType,
                    raw_action_type
                    if raw_action_type in _HUMAN_ACTION_TYPES
                    else "provider_verification",
                )
                observation = BrowserObservation(
                    status="human_action_required",
                    current_url="https://unknown.invalid/",
                    page_title="Browser resume",
                    human_action_type=action_type,
                    human_instruction="The secure browser handoff did not run. Retry this same step.",
                    reason_code=reason_code,
                )
            else:
                observation = BrowserObservation(
                    status="failed",
                    current_url="https://unknown.invalid/",
                    page_title="Browser resume",
                    reason_code=reason_code,
                )
        finally:
            if resume_dispatched:
                if sensitive is not None:
                    sensitive.clear()
            else:
                self._discard_pre_dispatch_browser_secrets(
                    sensitive=sensitive,
                    app_slug=recipe.app_slug,
                    run_id=run_id,
                    transient=transient_secrets,
                )
        result = self._apply_browser_observation(
            run_id,
            observation=observation,
            research=research,
            request=request,
            recipe=recipe,
            context=context,
            expected_effect_identity=effect_identity,
        )
        if result is None:
            raise RunConflictError(run_id, "resume")
        return result

    def connect_managed_run(self, run_id: str) -> dict[str, Any]:
        provider = self._context._managed_auth_provider
        settings = self._context._settings
        lock = self._context._run_lock(run_id)
        if not lock.acquire(blocking=False):
            raise RunConflictError(run_id, "connect")
        try:
            current = self._context.storage.get_run(run_id)
            if current is None:
                raise KeyError("run was not found")
            if current.get("state_engine") != "canonical_v1":
                raise CredentialSubmissionError("legacy_run_is_read_only")
            if current.get("execution_mode") != "operations":
                raise CredentialSubmissionError("plan_only_run_is_read_only")
            if current.get("status") != "connection_required":
                raise CredentialSubmissionError("run_not_awaiting_connection")
            recipe = self._recipe_for_run(current)
            if recipe.route_kind != "managed_auth":
                raise CredentialSubmissionError("run_is_not_managed_auth")
            if provider is None:
                raise CredentialSubmissionError("composio_managed_auth_not_configured")
            callback_base = getattr(settings, "managed_auth_callback_base_url", None)
            try:
                callback_base = validate_managed_auth_callback_base_url(callback_base)
            except (TypeError, ValueError):
                raise CredentialSubmissionError("managed_auth_callback_not_configured") from None
            effect_identity = f"{run_id}:managed-connect:v1"
            with self._context.storage.unit_of_work() as transaction:
                record = transaction.get_run(run_id)
                if record is None:
                    raise KeyError("run was not found")
                transaction.update_run(
                    run_id,
                    phase="connection_starting",
                    reason_code="connection_start_reserved",
                    effect_identity=effect_identity,
                    state_revision=int(record.get("state_revision", 0) or 0) + 1,
                )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="managed_connection_reserved",
                    payload={"status": "connection_required", "external_actions": False},
                )
            # Provider I/O occurs only after the intent transaction has committed.
            try:
                started = asyncio.run(
                    provider.start_connection(
                        toolkit_slug=recipe.toolkit_slug,
                        callback_url=f"{callback_base.rstrip('/')}/runs/{run_id}",
                        effect_identity=effect_identity,
                    )
                )
            except Exception as exc:
                reason = _safe_reason(exc, "managed_connection_start_failed")
                with self._context.storage.unit_of_work() as transaction:
                    record = transaction.get_run(run_id)
                    if record is None:
                        raise KeyError("run was not found") from None
                    revision = int(record.get("state_revision", 0) or 0) + 1
                    transaction.update_run(
                        run_id,
                        status="connection_required",
                        phase="connection_start_failed",
                        reason_code=reason,
                        external_actions=True,
                        state_revision=revision,
                        last_projected_revision=revision,
                    )
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="managed_connection_failed",
                        payload={
                            "status": "connection_required",
                            "reason_code": reason,
                            "external_actions": True,
                        },
                    )
                raise CredentialSubmissionError(reason) from None
            with self._context.storage.unit_of_work() as transaction:
                record = transaction.get_run(run_id)
                if record is None:
                    raise KeyError("run was not found")
                revision = int(record.get("state_revision", 0) or 0) + 1
                transaction.update_run(
                    run_id,
                    status="connection_required",
                    connection_request_id=started.connection_request_id,
                    phase="waiting_for_connection",
                    reason_code="managed_connection_pending",
                    provider_status={
                        "recipe": recipe.readiness_tier,
                        "composio": "pending",
                        "browser": "not_started",
                        "email": "not_started",
                        "validation": "not_started",
                    },
                    external_actions=True,
                    state_revision=revision,
                    last_projected_revision=revision,
                )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="managed_connection_started",
                    payload={
                        "status": "connection_required",
                        "replayed": started.replayed,
                        "external_actions": True,
                    },
                )
                updated = transaction.get_run(run_id)
                if updated is None:  # pragma: no cover
                    raise RuntimeError("managed run disappeared")
            return {
                "run": _public_run(updated),
                "connection_request_id": started.connection_request_id,
                "redirect_url": started.redirect_url,
                "replayed": started.replayed,
                "state": "pending",
            }
        finally:
            lock.release()

    def poll_managed_connection(self, run_id: str) -> dict[str, Any]:
        provider = self._context._managed_auth_provider
        lock = self._context._run_lock(run_id)
        if not lock.acquire(blocking=False):
            raise RunConflictError(run_id, "poll_connection")
        try:
            current = self._context.storage.get_run(run_id)
            if current is None:
                raise KeyError("run was not found")
            if current.get("state_engine") != "canonical_v1":
                raise CredentialSubmissionError("legacy_run_is_read_only")
            if current.get("execution_mode") != "operations":
                raise CredentialSubmissionError("plan_only_run_is_read_only")
            if current.get("status") != "connection_required":
                raise CredentialSubmissionError("run_not_awaiting_connection")
            recipe = self._recipe_for_run(current)
            if recipe.route_kind != "managed_auth":
                raise CredentialSubmissionError("run_is_not_managed_auth")
            if provider is None:
                raise CredentialSubmissionError("composio_managed_auth_not_configured")
            try:
                validate_managed_auth_callback_base_url(
                    getattr(self._context._settings, "managed_auth_callback_base_url", None)
                )
            except (TypeError, ValueError):
                raise CredentialSubmissionError("managed_auth_callback_not_configured") from None
            request_id = current.get("connection_request_id")
            if not isinstance(request_id, str) or not request_id:
                raise CredentialSubmissionError("connection_request_missing")
            # Read provider state outside a database transaction.
            try:
                polled = asyncio.run(
                    provider.poll_connection(
                        request_id,
                        toolkit_slug=recipe.toolkit_slug,
                    )
                )
            except Exception as exc:
                reason = _safe_reason(exc, "connection_poll_failed")
                with self._context.storage.unit_of_work() as transaction:
                    record = transaction.get_run(run_id)
                    if record is None:
                        raise KeyError("run was not found") from None
                    revision = int(record.get("state_revision", 0) or 0) + 1
                    transaction.update_run(
                        run_id,
                        status="connection_required",
                        phase="connection_poll_failed",
                        reason_code=reason,
                        external_actions=True,
                        state_revision=revision,
                        last_projected_revision=revision,
                    )
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="managed_connection_poll_failed",
                        payload={
                            "status": "connection_required",
                            "reason_code": reason,
                            "external_actions": True,
                        },
                    )
                raise CredentialSubmissionError(reason) from None
            status: RunStatus = (
                "completed"
                if polled.state == "active"
                else "failed"
                if polled.state == "terminal"
                else "connection_required"
            )
            phase = (
                "completed"
                if polled.state == "active"
                else "connection_failed"
                if polled.state == "terminal"
                else "waiting_for_connection"
            )
            bundle: dict[str, object] | None = None
            if polled.state == "active":
                research = OperationalResearch.model_validate(current.get("operational_research"))
                request = OperationsRequest.model_validate(current.get("request"))
                bundle = build_integrator_bundle(
                    research=research,
                    company=request.company,
                    credential_refs={},
                    validation=None,
                    stage="managed_connection_ready",
                    provider_account_id=request_id,
                    operational_notes=("Composio reported the managed connected account ACTIVE.",),
                ).model_dump(mode="json")
            with self._context.storage.unit_of_work() as transaction:
                record = transaction.get_run(run_id)
                if record is None:
                    raise KeyError("run was not found")
                revision = int(record.get("state_revision", 0) or 0) + 1
                updated = transaction.update_run(
                    run_id,
                    status=status,
                    phase=phase,
                    reason_code=polled.reason_code,
                    provider_status={
                        "recipe": record.get("readiness_tier"),
                        "composio": polled.state,
                        "browser": "not_started",
                        "email": "not_started",
                        "validation": "ready" if polled.state == "active" else "not_started",
                    },
                    integrator_bundle=bundle,
                    external_actions=True,
                    state_revision=revision,
                    last_projected_revision=revision,
                )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="managed_connection_polled",
                    payload={
                        "status": status,
                        "connection_state": polled.state,
                        "reason_code": polled.reason_code,
                        "external_actions": True,
                    },
                )
                if bundle is not None:
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="integrator_bundle_generated",
                        payload={
                            "readiness": "credentials_ready",
                            "auth_scheme": "oauth2",
                            "credential_ref_count": 0,
                            "external_actions": True,
                        },
                    )
            return {
                "run": _public_run(updated),
                "connection_request_id": request_id,
                "redirect_url": None,
                "replayed": False,
                "state": polled.state,
            }
        finally:
            lock.release()

    def send_gated_outreach(self, run_id: str) -> dict[str, Any]:
        """Send one explicitly requested, controlled-sink outreach operation."""

        gmail = self._context._gmail_worker
        lock = self._context._run_lock(run_id)
        if not lock.acquire(blocking=False):
            raise RunConflictError(run_id, "send_outreach")
        try:
            current = self._context.storage.get_run(run_id)
            if current is None:
                raise KeyError("run was not found")
            if current.get("state_engine") != "canonical_v1":
                raise CredentialSubmissionError("legacy_run_is_read_only")
            if current.get("execution_mode") != "operations":
                raise CredentialSubmissionError("plan_only_run_is_read_only")
            if current.get("status") != "route_selected":
                raise CredentialSubmissionError("run_not_awaiting_outreach")
            recipe = self._recipe_for_run(current)
            if recipe.route_kind != "gated":
                raise CredentialSubmissionError("run_is_not_gated")
            if gmail is None:
                raise CredentialSubmissionError("gmail_not_configured")
            request_payload = current.get("request")
            if not isinstance(request_payload, Mapping):
                raise CredentialSubmissionError("run_request_missing")
            request = OperationsRequest.model_validate(dict(request_payload))
            try:
                route = GatedRoute(recipe=recipe, request=request, gmail=gmail)
            except GatedRoutePolicyError as exc:
                raise CredentialSubmissionError(exc.reason_code) from None

            effect_identity = f"{run_id}:gated-outreach:v1"
            with self._context.storage.unit_of_work() as transaction:
                record = transaction.get_run(run_id)
                if record is None:
                    raise KeyError("run was not found")
                transaction.update_run(
                    run_id,
                    phase="outreach_sending",
                    reason_code="outreach_send_reserved",
                    effect_identity=effect_identity,
                    state_revision=int(record.get("state_revision", 0) or 0) + 1,
                )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="outreach_send_reserved",
                    payload={"status": "route_selected", "external_actions": False},
                )

            try:
                receipt = asyncio.run(route.send_outreach(effect_identity=effect_identity))
            except Exception as exc:
                reason = _safe_reason(exc, "outreach_send_failed")
                with self._context.storage.unit_of_work() as transaction:
                    record = transaction.get_run(run_id)
                    if record is None:
                        raise KeyError("run was not found") from None
                    revision = int(record.get("state_revision", 0) or 0) + 1
                    transaction.update_run(
                        run_id,
                        status="configuration_required",
                        phase="outreach_send_failed",
                        reason_code=reason,
                        external_actions=True,
                        state_revision=revision,
                        last_projected_revision=revision,
                    )
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="outreach_send_failed",
                        payload={
                            "status": "configuration_required",
                            "reason_code": reason,
                            "external_actions": True,
                        },
                    )
                raise CredentialSubmissionError(reason) from None

            with self._context.storage.unit_of_work() as transaction:
                record = transaction.get_run(run_id)
                if record is None:
                    raise KeyError("run was not found")
                revision = int(record.get("state_revision", 0) or 0) + 1
                updated = transaction.update_run(
                    run_id,
                    status="waiting_for_reply",
                    phase="waiting_for_reply",
                    reason_code="controlled_outreach_sent",
                    gmail_session_id=receipt.session_id,
                    gmail_thread_id=receipt.thread_id,
                    provider_status={
                        "recipe": recipe.readiness_tier,
                        "composio": "not_started",
                        "browser": "not_started",
                        "email": "waiting_for_reply",
                        "validation": "not_started",
                    },
                    external_actions=True,
                    state_revision=revision,
                    last_projected_revision=revision,
                )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="outreach_sent",
                    payload={
                        "status": "waiting_for_reply",
                        "template_id": route.target.template_id,
                        "recipient_overridden": (
                            receipt.actual_recipient != receipt.intended_recipient
                        ),
                        "external_actions": True,
                    },
                )
            return _public_run(updated)
        finally:
            lock.release()

    def _record_provider_failure(
        self,
        run_id: str,
        *,
        status: RunStatus,
        phase: str,
        reason_code: str,
        external_actions: bool = False,
    ) -> dict[str, Any]:
        with self._context.storage.unit_of_work() as transaction:
            current = transaction.get_run(run_id)
            if current is None:
                raise KeyError("run was not found")
            revision = int(current.get("state_revision", 0) or 0) + 1
            updated = transaction.update_run(
                run_id,
                status=status,
                phase=phase,
                reason_code=reason_code,
                route_reason_code=reason_code,
                provider_status={
                    "recipe": current.get("readiness_tier"),
                    "composio": "not_started",
                    "browser": "failed" if status == "failed" else "configuration_required",
                    "email": "not_started",
                    "validation": "not_started",
                },
                external_actions=bool(current.get("external_actions")) or external_actions,
                state_revision=revision,
                last_projected_revision=revision,
            )
            transaction.append_audit_event(
                run_id=run_id,
                event_type="provider_operation_failed",
                payload={
                    "status": status,
                    "phase": phase,
                    "reason_code": reason_code,
                    "external_actions": external_actions,
                },
            )
        return _public_run(updated)


__all__ = ["CanonicalRuntime", "CanonicalRuntimeContext", "recipe_to_operational_research"]
