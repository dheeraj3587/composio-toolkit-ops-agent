"""Application service for durable, sanitized operations-ledger runs.

This module is the single application boundary shared by HTTP, CLI, LangGraph,
and internal debugging surfaces. Creating a run is intentionally side-effect
free: it verifies the immutable P1 snapshot, builds a conservative research
baseline, records the deterministic route, and leaves provider execution to
explicit retry/resume actions guarded by runtime policy.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Literal, Protocol, cast
from uuid import uuid4

import httpx
from pydantic import SecretStr

from ops.browser_api_trace_catalog import get_browser_api_trace
from ops.browser_link_log import log_event
from ops.browser_worker import BrowserSessionContext, BrowserWorker
from ops.composio_capability import ComposioCapabilityPreflight, ComposioCapabilityReport
from ops.config import Settings
from ops.credential_validator import (
    CredentialValidationResult,
    CredentialValidator,
    PolicyBoundCredentialValidator,
    hubspot_validation_policy,
    pipedrive_validation_policy,
)
from ops.effect_ledger import SQLiteEffectStore
from ops.email_verification import (
    ResolvedVerification,
    VerificationDecision,
    VerificationEvidence,
    VerificationPurpose,
)
from ops.email_verification import link_host as verification_link_host
from ops.gmail_worker import GmailWorker
from ops.graph import (
    DurableOperationsWorkflow,
    WorkflowDependencies,
    browser_account_ref,
    build_graph,
)
from ops.integrator import build_integrator_bundle
from ops.models import (
    CapabilityAvailability,
    CompanyProfile,
    OperationalResearch,
    OperationsRequest,
    validate_vault_reference,
)
from ops.network_endpoint_policy import validation_endpoint as network_validation_endpoint
from ops.operational_baselines import apply_reviewed_operational_baseline
from ops.operational_research import (
    GeminiStructuredExtractor,
    OfficialEvidenceFetcher,
    OperationalResearchEnricher,
    PerplexitySearchDiscovery,
    ResearchEnricher,
    ResearchEnrichmentOutcome,
)
from ops.p1_adapter import (
    DEFAULT_P1_ROOT,
    P1AppRecord,
    P1LookupFound,
    P1OperationalAdapter,
    P1SnapshotProvenance,
    load_verified_snapshot,
    to_operational_research,
)
from ops.provider_errors import (
    ConfigurationRequiredError,
    ProviderContractError,
    ProviderOperationError,
)
from ops.research_cache import SqliteResearchCache
from ops.routing import RoutingDecision, decide_access

# Explicitly re-exported (the ``X as X`` form): ``api.app`` and ``api.service``
# import these from ``ops.run_service``, which remains their public home, and the
# type checker forbids implicit re-export.
from ops.run_advance import _AUTO_ADVANCEABLE_GATES, RunAdvanceService  # noqa: F401
from ops.run_errors import CredentialSubmissionError as CredentialSubmissionError
from ops.run_errors import IdempotencyConflictError as IdempotencyConflictError
from ops.run_errors import InvalidIdempotencyKeyError as InvalidIdempotencyKeyError
from ops.run_errors import RunConflictError as RunConflictError
from ops.run_idempotency import (  # noqa: F401
    IDEMPOTENCY_KEY_PATTERN,
    _legacy_request_fingerprint,
    _legacy_request_fingerprints,
    _request_fingerprint,
)
from ops.run_idempotency import validate_idempotency_key as validate_idempotency_key
from ops.run_live_view import RunLiveViewService

# Imported for use below AND deliberately re-exported: tests and debugging
# surfaces import these internals from ``ops.run_service``, which stays their
# stable home even though the implementations now live in a leaf module. The
# noqa markers are uniform so this block does not need editing every time
# another cluster moves out.
from ops.run_projections import (  # noqa: F401
    _LOGICAL_EXECUTION_MODE,
    _PERSISTED_EXECUTION_MODE,
    _PUBLIC_RUN_FIELDS,
    _TERMINAL_BROWSER_STATUSES,
    _app_projection,
    _browser_result_reason,
    _capability_reason_code,
    _clean_credential_value,
    _missing_operational_fields,
    _parse_timestamp,
    _public_run,
    _sanitized_app_list,
    _slugify,
    _strip_quoted_reply,
    decode_stored_payload,
)
from ops.run_queries import RunQueryService
from ops.run_reconciliation import RunReconciliationService
from ops.secret_store import REUSABLE_LOGIN_FIELDS, SQLiteSecretStore
from ops.state import (
    AccessRoute,
    BrowserProvider,
    OperationsState,
    RunStatus,
    validate_status_transition,
)
from ops.storage import OperationsStorage, OperationsUnitOfWork
from ops.you_research import (
    CompositeEvidenceDiscovery,
    FallbackEvidenceContentFetcher,
    GuardedHTTPEvidenceFetcher,
    LegacyDiscoveryAdapter,
    ResearchHostPolicy,
    YouContentsFetcher,
    YouResearchFallback,
    YouSearchDiscovery,
)

LOGGER = logging.getLogger("composio_ops.run_service")

_GATED_OUTREACH_ROUTES = frozenset({"approval_required", "partner_gated"})


class _YouComWiringMarker:
    """Display-only marker so the wiring audit can show "You.com is
    configured" without fabricating a reference to internal pipeline
    objects that only exist inside ``_build_research_enricher``'s closures."""


@dataclass(frozen=True, slots=True)
class _VerificationBinding:
    """The bindings available for consuming an emailed verification secret.

    ``reviewed_patterns`` is never empty: an instance only exists when the app has a
    reviewed host set, which makes it impossible to run the strict path with a
    recipient but no host restriction - a combination that would authorize opening an
    arbitrary link from a correctly addressed but spoofed message.

    ``expected_recipient`` is ``None`` when this run's verification mailbox is not
    known yet, which downgrades the read to preference-only rather than pretending a
    binding exists.
    """

    app_slug: str
    expected_recipient: str | None
    reviewed_patterns: tuple[str, ...]


def _verification_backoff(base_delay: float, attempt: int) -> float:
    """Exponential backoff with bounded jitter for inbox polling.

    Jitter matters because several runs waiting on the same provider would otherwise
    poll in lockstep and burst against the shared per-account quota.
    """

    if base_delay <= 0:
        return 0.0
    delay = min(base_delay * (2**attempt), 30.0)
    return float(delay * (0.8 + 0.4 * random.random()))


# create_run collapses several legal graph transitions into one initial
# projection (for example a gated run that reaches waiting_for_reply). The chain
# is validated hop-by-hop through the single transition authority so no illegal
# jump is ever written to the ledger.
_CREATE_PROJECTION_CHAINS: dict[str, tuple[RunStatus, ...]] = {
    "waiting_for_reply": ("route_selected", "outreach_sent", "waiting_for_reply"),
    "outreach_sent": ("route_selected", "outreach_sent"),
    "browser_running": ("route_selected", "browser_running"),
    "waiting_for_hitl": ("route_selected", "browser_running", "waiting_for_hitl"),
    "credentials_ready": ("route_selected", "browser_running", "credentials_ready"),
    "completed": ("route_selected", "browser_running", "credentials_ready", "completed"),
}


class CredentialCapturePort(Protocol):
    """Injectable deterministic credential capture returning vault references only."""

    async def capture(self, *, app_slug: str, app_name: str) -> dict[str, str]: ...


class CredentialValidationPort(Protocol):
    """Injectable read-only credential validation over stored vault references."""

    async def validate(
        self, *, app_slug: str, credential_refs: dict[str, str]
    ) -> CredentialValidationResult: ...


@dataclass(frozen=True, slots=True)
class _CredentialOutcome:
    """Internal result of the M6 capture -> store -> validate -> bundle flow."""

    status: str
    reason_code: str
    validation_status: str | None
    bundle: dict[str, Any] | None
    external_actions: bool
    events: list[tuple[str, dict[str, object]]] = field(default_factory=list)


def _validate_created_projection(final_status: str) -> None:
    chain = _CREATE_PROJECTION_CHAINS.get(final_status)
    if chain is None:
        validate_status_transition("created", cast(RunStatus, final_status), "create")
        return
    previous: RunStatus = "created"
    for nxt in chain:
        validate_status_transition(previous, nxt, "create")
        previous = nxt


class RunService:
    """Coordinate verified P1 lookup, routing, and sanitized persistence."""

    def __init__(
        self,
        *,
        storage: OperationsStorage,
        p1_adapter: P1OperationalAdapter | None = None,
        settings: Settings | None = None,
        workflow: DurableOperationsWorkflow | None = None,
        research_enricher: ResearchEnricher | None = None,
        capability_preflight: ComposioCapabilityPreflight | None = None,
        credential_capturer: CredentialCapturePort | None = None,
        credential_validator: CredentialValidationPort | None = None,
    ) -> None:
        self.storage = storage
        self.p1_adapter = p1_adapter or P1OperationalAdapter()
        self._settings = settings
        self._workflow = workflow
        # Optional, injected one-probe enrichment boundary. When absent (the
        # default), run creation performs no enrichment and stays byte-identical
        # to the plan-only baseline; the enricher never performs a browser,
        # Gmail, or credential side effect.
        self._enricher = research_enricher
        # Optional Composio capability preflight. It gates gated outreach and is
        # read-only. When absent, a gated execute_when_configured run fails closed
        # (configuration_required) rather than sending blindly.
        self._capability_preflight = capability_preflight
        # Optional credential capture + read-only validation adapters. When both
        # are present, a self-serve run that reaches the credential page captures
        # test credentials into the encrypted vault (references only), validates
        # read-only, and builds the sanitized IntegratorBundle. When absent, the
        # run truthfully stops at browser_running (M5 behavior).
        self._credential_capturer = credential_capturer
        self._credential_validator = credential_validator
        self._run_locks: dict[str, threading.RLock] = {}
        self._run_locks_guard = threading.Lock()
        # Resources owned and closed by this service when built at startup.
        self._http_client: httpx.AsyncClient | None = None
        self._validation_http_client: httpx.AsyncClient | None = None
        # Persistent research cache shared by the You.com adapters (Search /
        # Contents / Research). The adapters manage their own SDK client
        # lifecycle per call via ``async with``; no You.com async client is
        # stored on the service (that would be unsafe across the per-enrichment
        # ``asyncio.run`` event loops). Only built when YDC_API_KEY is present.
        self._research_cache: SqliteResearchCache | None = None
        self._browser_workers: dict[BrowserProvider, BrowserWorker] = {}
        # Compatibility alias for older tests and assignment patches. Runtime
        # operations always resolve from _browser_workers using the persisted run.
        self._browser_worker: BrowserWorker | None = None
        self._gmail_worker: GmailWorker | None = None
        # In-memory marker of the last inbound reply id handled per run, so the
        # autonomous poller acts once per new reply (no reprocessing/resend).
        self._last_processed_reply: dict[str, str] = {}
        # Bounded per-run count of autonomous email-OTP resume attempts.
        self._otp_attempts: dict[str, int] = {}
        # Background email poller (autonomous "listen for replies").
        self._email_poller_thread: threading.Thread | None = None
        self._email_poller_stop = threading.Event()
        # Autonomous advancement: bounded per-run count of machine-resolved human
        # gates (e.g. a login form we already hold credentials for), plus its own
        # sweep thread. Kept separate from the email poller because it must run
        # even when Gmail is not configured.
        self._autonomous_advances: dict[str, int] = {}
        self._advance_thread: threading.Thread | None = None
        self._advance_stop = threading.Event()
        # Asynchronous browser execution: when enabled (production live mode), a
        # self-serve browser run commits at browser_running with the live view
        # available immediately, and the bounded onboarding task runs in a
        # background thread that applies the terminal observation to the run.
        # This keeps the run creation request fast and the embedded live view /
        # HITL available for the entire duration of the autonomous task, instead
        # of blocking the request until the multi-minute task finishes.
        self._async_browser_enabled = False
        self._browser_threads: list[threading.Thread] = []
        self._secret_store: SQLiteSecretStore | None = None
        self._effect_store: SQLiteEffectStore | None = None
        # Sanitized startup wiring audit rows; never contains secrets.
        self._wiring: list[dict[str, object]] = []

    # --- extracted collaborators -------------------------------------------
    #
    # Resolved lazily on access rather than assigned in __init__ for two
    # reasons. First, each one is stateless: it holds only a reference back to
    # this service and reads storage, settings and adapters through it on every
    # call, so constructing one is free and late-assigned adapters are always
    # honored. Second, several tests build a service with
    # ``RunService.__new__`` and hand-assign only the attributes they need,
    # which never runs __init__; a collaborator assigned there would be missing.

    @property
    def _queries(self) -> RunQueryService:
        """Read-only run and catalog queries."""

        return RunQueryService(self)

    @property
    def _live_view(self) -> RunLiveViewService:
        """Ephemeral screenshot, live-URL and interactive-grant resolution."""

        return RunLiveViewService(self)

    @property
    def _reconciliation(self) -> RunReconciliationService:
        """Startup and periodic recovery of runs holding a dead browser."""

        return RunReconciliationService(self)

    @property
    def _advance(self) -> RunAdvanceService:
        """Autonomous continuation of machine-resolvable human gates."""

        return RunAdvanceService(self)

    @classmethod
    def from_paths(
        cls,
        *,
        db_path: str | Path,
        snapshot_root: str | Path = DEFAULT_P1_ROOT,
        settings: Settings | None = None,
        workflow: DurableOperationsWorkflow | None = None,
        research_enricher: ResearchEnricher | None = None,
        capability_preflight: ComposioCapabilityPreflight | None = None,
        credential_capturer: CredentialCapturePort | None = None,
        credential_validator: CredentialValidationPort | None = None,
    ) -> RunService:
        return cls(
            storage=OperationsStorage(db_path),
            p1_adapter=P1OperationalAdapter(snapshot_root),
            settings=settings,
            workflow=workflow,
            research_enricher=research_enricher,
            capability_preflight=capability_preflight,
            credential_capturer=credential_capturer,
            credential_validator=credential_validator,
        )

    def initialize(self) -> None:
        """Validate application-owned storage and the pinned snapshot."""

        self.storage.initialize()
        load_verified_snapshot(self.p1_adapter.snapshot_root)

    def startup(self) -> None:
        """Initialize storage and construct real dependencies only when configured.

        Explicit constructor injection (used by unit tests) always takes
        priority: startup fills only the dependencies left as ``None``. Missing
        provider keys leave the corresponding adapter unbuilt so the run reports
        ``configuration_required`` truthfully. No secret value is ever logged or
        recorded in the wiring audit.
        """

        self.initialize()
        settings = self._settings or Settings.from_env()
        self._wiring = []

        # Read-only Composio capability preflight; fails closed when unconfigured.
        if self._capability_preflight is None:
            self._capability_preflight = ComposioCapabilityPreflight(settings=settings)
        self._record_wiring("composio_preflight", self._capability_preflight, configured=True)

        # One-probe research enricher (Perplexity discovery optional, Gemini
        # extraction mandatory). Only built when Gemini is configured; the owned
        # httpx client performs bounded official-evidence fetches.
        if self._enricher is None:
            self._enricher = self._build_research_enricher(settings)
        self._record_wiring(
            "research_enricher",
            self._enricher,
            configured=settings.google_genai_api_key is not None,
        )
        # You.com is a sanitized wiring-audit ENTRY, never a live probe: a
        # normal health/startup check must never spend a You.com credit. See
        # `python -m ops.cli probe-you` for the explicit, opt-in live check.
        # A key that is present but unused is NOT an active integration, so the
        # audit reports You.com only when a capability flag actually enables it.
        you_enabled = settings.any_you_feature_configured
        self._record_wiring(
            "you_com",
            _YouComWiringMarker() if you_enabled else None,
            configured=you_enabled,
        )

        # Read-only credential validator (HubSpot bearer, current endpoint).
        if self._credential_validator is None:
            self._credential_validator = self._build_credential_validator(settings)
        self._record_wiring(
            "credential_validator",
            self._credential_validator,
            configured=self._credential_validator is not None,
        )

        # Owner-only vault. Credential capture is intentionally NOT auto-injected
        # at startup: raw credentials are submitted explicitly by the owner, never
        # scraped from the browser.
        if self._secret_store is None and settings.secret_vault_key is not None:
            try:
                self._secret_store = SQLiteSecretStore(
                    settings.secret_vault_db_path,
                    settings.secret_vault_key.get_secret_value(),
                )
            except (ValueError, TypeError) as exc:
                # A malformed vault key must not crash-loop the container. Fail
                # closed (no vault) and log a clear, value-free diagnostic.
                LOGGER.error(
                    "SECRET_VAULT_KEY is invalid (%s); the credential vault is "
                    "disabled. Expected a url-safe base64 Fernet key.",
                    type(exc).__name__,
                )
                self._secret_store = None
        self._record_wiring(
            "secret_store", self._secret_store, configured=settings.secret_vault_key is not None
        )
        self._record_wiring(
            "credential_capturer",
            self._credential_capturer,
            configured=self._credential_capturer is not None,
        )

        if self._workflow is not None:
            self._record_wiring("workflow", self._workflow, configured=True, wired=True)
            return
        if settings.langgraph_aes_key is None:
            self._record_wiring("workflow", None, configured=False)
            return
        try:
            self._workflow = build_graph(
                checkpoint_path=settings.checkpoint_db_path,
                encryption_key=settings.langgraph_aes_key,
                dependencies=self._build_workflow_dependencies(settings),
            )
        except ConfigurationRequiredError:
            self._workflow = None
        except (ValueError, TypeError) as exc:
            # A malformed LANGGRAPH_AES_KEY (wrong byte length) must not crash-loop
            # the container. Fail closed (no durable workflow) with a clear,
            # value-free diagnostic; runs then report configuration_required.
            LOGGER.error(
                "LANGGRAPH_AES_KEY is invalid (%s); the durable workflow is "
                "disabled. Expected a 16, 24, or 32-byte key.",
                type(exc).__name__,
            )
            self._workflow = None
        self._record_wiring("workflow", self._workflow, configured=True)
        # Recover any runs stranded by the previous shutdown before serving.
        self._reconcile_stranded_runs()
        # Start the autonomous email poller so the agent listens for and answers
        # provider replies on its own, with no manual polling.
        self._start_email_poller()
        # Start the autonomous advancement sweep so a human gate the agent can
        # resolve itself (a login form whose credentials are already authorized)
        # is retried without anyone pressing Resume.
        self._start_autonomous_advancer()

    def _reconcile_stranded_runs(self) -> None:
        """Recover runs stranded by the previous shutdown."""

        self._reconciliation.reconcile_stranded_runs()

    def _browser_session_is_live(self, record: Mapping[str, Any]) -> bool | None:
        """Ask the browser service whether a persisted session id still exists."""

        return self._reconciliation.browser_session_is_live(record)

    def _reconcile_one_stranded(
        self,
        run_id: str,
        *,
        stranded_statuses: tuple[str, ...] = ("browser_running",),
        reason: str = "api_restart_stranded_browser_run",
    ) -> None:
        self._reconciliation.reconcile_one_stranded(
            run_id,
            stranded_statuses=stranded_statuses,
            reason=reason,
        )

    def _start_email_poller(self) -> None:
        """Start the background thread that polls waiting runs for new replies."""

        if self._gmail_worker is None:
            return
        if self._email_poller_thread is not None and self._email_poller_thread.is_alive():
            return
        settings = self._settings or Settings.from_env()
        interval = max(10, int(settings.email_poll_interval_seconds))
        self._email_poller_stop.clear()
        thread = threading.Thread(
            target=self._email_poller_loop,
            args=(interval,),
            name="email-poller",
            daemon=True,
        )
        self._email_poller_thread = thread
        thread.start()

    def _email_poller_loop(self, interval: int) -> None:
        while not self._email_poller_stop.wait(interval):
            try:
                self.poll_waiting_runs()
            except Exception:  # pragma: no cover - the loop must never die
                pass
            try:
                self.resolve_pending_otps()
            except Exception:  # pragma: no cover - the loop must never die
                pass

    def _hitl_action_type(self, record: Mapping[str, object]) -> str | None:
        """Return the pending HITL action type from the record or checkpoint."""

        hitl = record.get("hitl_request")
        if isinstance(hitl, Mapping) and hitl.get("type"):
            return str(hitl.get("type"))
        if self._workflow is None:
            return None
        thread_id = str(record.get("thread_id") or "")
        if not thread_id:
            return None
        try:
            state = self._workflow.get_state(thread_id)
        except Exception:
            return None
        observation = state.get("browser_observation")
        if isinstance(observation, Mapping):
            action = observation.get("human_action_type")
            return str(action) if action else None
        return None

    def _start_autonomous_advancer(self) -> None:
        """Start the sweep that auto-resumes machine-resolvable human gates."""

        self._advance.start()

    def reconcile_idle_browser_runs(self, *, limit: int = 100) -> int:
        """Recover runs stuck at ``browser_running`` with nothing driving them."""

        return self._reconciliation.reconcile_idle_browser_runs(limit=limit)

    def advance_autonomous_runs(self, *, limit: int = 100) -> int:
        """Resume every waiting run whose human gate the agent can resolve itself."""

        return self._advance.advance_autonomous_runs(limit=limit)

    def resolve_pending_otps(self, *, limit: int = 100) -> int:
        """Autonomously resolve every run waiting on an emailed login code."""

        if self._gmail_worker is None:
            return 0
        resolved = 0
        for record in self.storage.list_runs(limit=limit, offset=0):
            if record.get("status") != "waiting_for_hitl":
                continue
            if self._hitl_action_type(record) != "email_otp":
                continue
            run_id = str(record.get("run_id") or "")
            if not run_id:
                continue
            try:
                if self.resolve_email_otp(run_id) is not None:
                    resolved += 1
            except Exception:
                continue
        return resolved

    def resolve_email_otp(self, run_id: str) -> dict[str, Any] | None:
        """Resolve an emailed LOGIN verification and resume the browser with it.

        Retained entry point for the ``email_otp`` human gate; the purpose-aware
        implementation lives in :meth:`resolve_email_verification`.
        """

        return self.resolve_email_verification(run_id, purpose="login_verification")

    def resolve_email_verification(
        self,
        run_id: str,
        *,
        purpose: VerificationPurpose = "login_verification",
        expected_recipient: str | None = None,
    ) -> dict[str, Any] | None:
        """Read the verification email for a waiting run and resume the browser.

        Keeps the whole step in one autonomous task: the one-time secret is read
        from the connected inbox, wrapped as a provider ``sensitive_data``
        placeholder (never logged or persisted), and the SAME browser session is
        resumed so the agent types the code or opens the link and continues.

        ``purpose`` selects the flow this verification belongs to, so an autonomous
        signup confirmation and a login device check are ledgered independently and
        can never consume each other's message. ``expected_recipient`` lets a signup
        flow bind to the address it just registered, which is not yet the app's
        remembered sign-in email; when omitted the remembered login email is used.

        A magic SIGN-IN LINK takes priority over a numeric code because providers
        such as HubSpot device verification send a one-time link that must be opened
        in the agent's own live session to finish signing in.

        Returns ``None`` - leaving the run truthfully waiting for a human - whenever
        the message cannot be found, cannot be bound to this run, or is stale.
        """

        if self._gmail_worker is None:
            return None
        record = self.storage.get_run(run_id)
        if record is None or record.get("status") != "waiting_for_hitl":
            return None
        if self._hitl_action_type(record) != "email_otp":
            return None
        settings = self._settings or Settings.from_env()
        budget = max(1, int(getattr(settings, "gmail_verification_max_attempts", 3)))
        if self._otp_attempts.get(run_id, 0) >= budget:
            return None
        self._otp_attempts[run_id] = self._otp_attempts.get(run_id, 0) + 1

        app_slug = str(record.get("app_slug") or "unknown")
        binding = self._verification_binding(app_slug, expected_recipient=expected_recipient)
        if binding is None and bool(getattr(settings, "gmail_verification_require_binding", False)):
            # Fail closed: this deployment requires proof that the message belongs
            # to this run, and that proof is unavailable.
            log_event(
                "browser.verification.binding_required",
                run_id=run_id,
                app_slug=app_slug,
                purpose=purpose,
            )
            return None

        # The verification email routinely lags the browser request, so poll a few
        # times with jittered backoff. The wait is interruptible so a shutdown does
        # not have to sit through the whole window.
        decision: VerificationDecision | None = None
        base_delay = float(getattr(settings, "gmail_verification_poll_seconds", 5.0))
        for attempt in range(budget):
            decision = self._fetch_bound_verification(
                run_id=run_id, purpose=purpose, binding=binding
            )
            if decision is not None and decision.is_resolved:
                break
            if attempt == budget - 1:
                break
            if self._email_poller_stop.wait(_verification_backoff(base_delay, attempt)):
                break

        if decision is None or decision.resolved is None:
            log_event(
                "browser.verification.unresolved",
                run_id=run_id,
                app_slug=app_slug,
                purpose=purpose,
                reason_code=(decision.reason_code if decision is not None else "unavailable"),
                recipient_bound=binding is not None and binding.expected_recipient is not None,
            )
            return None

        evidence = decision.resolved.evidence
        log_event(
            "browser.verification.resolved",
            run_id=run_id,
            app_slug=app_slug,
            purpose=purpose,
            # Deliberately not named "secret_*": the sanitized logger redacts any
            # field whose NAME looks credential-bearing, which would hide this
            # otherwise inert diagnostic.
            verification_kind=evidence.verification_kind,
            sender_domain=evidence.sender_domain or None,
            link_host=evidence.link_host or None,
            code_length=evidence.code_length or None,
            age_seconds=evidence.age_seconds,
            recipient_binding=evidence.recipient_binding,
            sender_reviewed=evidence.sender_reviewed,
        )
        field = "login_verification_url" if evidence.verification_kind == "link" else "login_otp"
        return self.resume_run(
            run_id,
            signal="completed",
            browser_login={field: decision.resolved.secret},
        )

    def _verification_binding(
        self,
        app_slug: str,
        *,
        expected_recipient: str | None = None,
    ) -> _VerificationBinding | None:
        """Resolve the bindings available for an emailed verification.

        Returns ``None`` only when the app has no reviewed host set at all, because
        without one there is nothing to restrict a magic link to. When a reviewed set
        exists but the run's recipient is unknown, a binding is still returned with
        ``expected_recipient=None``: the link host and sender preference still apply,
        but the strict recipient-bound path is not available.

        The expected recipient is the address the provider sends verification to -
        supplied explicitly by a signup flow for the identity it just registered, or
        otherwise the app's remembered sign-in email. Reviewed sender and link-host
        patterns come from the same per-app browser policy the navigation boundary
        enforces, so the email boundary can never authorize a host the browser would
        refuse to open.
        """

        from ops.browser_host_policy import get_browser_policy

        policy = get_browser_policy(app_slug)
        if policy is None:
            return None
        patterns = (
            *policy.exact_hosts,
            *(f"*.{domain}" for domain in policy.vendor_wildcard_domains),
        )
        if not patterns:
            return None
        recipient = (expected_recipient or "").strip() or None
        if recipient is None:
            recipient_secret = self._reusable_login_values(app_slug).get("login_email")
            if recipient_secret is not None:
                recipient = recipient_secret.get_secret_value().strip() or None
        return _VerificationBinding(
            app_slug=app_slug,
            expected_recipient=recipient,
            reviewed_patterns=patterns,
        )

    def _fetch_bound_verification(
        self,
        *,
        run_id: str,
        purpose: str,
        binding: _VerificationBinding | None,
    ) -> VerificationDecision | None:
        """Read one verification message, preferring the fully bound path.

        With an exact recipient every check is mandatory (recency, recipient,
        reviewed sender, reviewed link host) and the message is claimed exactly once
        in the effect ledger, so one expired code can never be replayed in a loop.
        Without a recipient the legacy read is used: still under a real freshness
        bound, and still restricted to reviewed link hosts when the app has a
        reviewed set, but unable to prove the message belongs to this run.
        """

        worker = self._gmail_worker
        if worker is None:
            return None
        settings = self._settings or Settings.from_env()
        max_age = int(getattr(settings, "gmail_verification_max_age_seconds", 900))
        patterns = binding.reviewed_patterns if binding is not None else ()
        if binding is not None and binding.expected_recipient is not None:
            try:
                return asyncio.run(
                    worker.fetch_verification(
                        purpose=cast("VerificationPurpose", purpose),
                        expected_recipient=binding.expected_recipient,
                        reviewed_sender_patterns=patterns,
                        allowed_link_host_patterns=patterns,
                        run_id=run_id,
                        max_age_seconds=max_age,
                    )
                )
            except Exception:
                log_event("browser.verification.error", level=40, run_id=run_id)
                return None
        return self._legacy_verification_read(
            worker,
            run_id=run_id,
            purpose=purpose,
            allowed_link_host_patterns=patterns,
            max_age_seconds=max_age,
        )

    def _legacy_verification_read(
        self,
        worker: Any,
        *,
        run_id: str,
        purpose: str,
        allowed_link_host_patterns: tuple[str, ...] = (),
        max_age_seconds: int = 900,
    ) -> VerificationDecision | None:
        """Preference-only inbox read for runs without an exact recipient binding."""

        link: str | None = None
        try:
            link = asyncio.run(
                worker.fetch_latest_login_link(
                    allowed_link_host_patterns=allowed_link_host_patterns,
                    max_age_seconds=max_age_seconds,
                )
            )
        except Exception:
            link = None
        if link:
            return VerificationDecision(
                resolved=ResolvedVerification(
                    secret=SecretStr(link),
                    evidence=VerificationEvidence(
                        purpose=cast("VerificationPurpose", purpose),
                        verification_kind="link",
                        message_id=f"legacy:{run_id}"[:200],
                        recipient_binding="no_match",
                        sender_reviewed=False,
                        received_at_ms=0,
                        age_seconds=0,
                        link_host=verification_link_host(link),
                    ),
                ),
                reason_code="verification_resolved_unbound",
            )
        try:
            code = asyncio.run(worker.fetch_latest_otp(max_age_seconds=max_age_seconds))
        except Exception:
            code = None
        if code:
            return VerificationDecision(
                resolved=ResolvedVerification(
                    secret=SecretStr(code),
                    evidence=VerificationEvidence(
                        purpose=cast("VerificationPurpose", purpose),
                        verification_kind="code",
                        message_id=f"legacy:{run_id}"[:200],
                        recipient_binding="no_match",
                        sender_reviewed=False,
                        received_at_ms=0,
                        age_seconds=0,
                        code_length=len(code),
                    ),
                ),
                reason_code="verification_resolved_unbound",
            )
        return VerificationDecision(resolved=None, reason_code="verification_message_not_found")

    def poll_waiting_runs(self, *, limit: int = 100) -> int:
        """Poll every run awaiting a provider reply; returns how many were polled.

        Idempotent: poll_email acts only on a genuinely new inbound reply, so
        repeated cycles over the same runs are safe no-ops.
        """

        if self._gmail_worker is None:
            return 0
        polled = 0
        for record in self.storage.list_runs(limit=limit, offset=0):
            if record.get("status") not in {"waiting_for_reply", "outreach_sent"}:
                continue
            run_id = str(record.get("run_id") or "")
            if not run_id:
                continue
            try:
                self.poll_email(run_id)
                polled += 1
            except Exception:
                continue
        return polled

    def _build_research_enricher(self, settings: Settings) -> ResearchEnricher | None:
        """Build the enricher only when Gemini is configured; own its HTTP client(s).

        Discovery order: You.com Search (primary, when ``you_search_configured``)
        then Perplexity (fallback, when configured) via
        ``CompositeEvidenceDiscovery``. Content-fetch order: You.com Contents
        (primary, when ``you_contents_configured``) then the pre-existing
        guarded HTTP fetcher (fallback, always available). You.com Research is
        optional, disabled by default, and only ever supplies MORE candidate
        pages for the SAME canonical Gemini extraction below.

        Fully backward-compatible: when ``YDC_API_KEY`` is absent, this
        builds the EXACT pre-existing Perplexity + guarded-HTTP wiring with
        none of the new dependencies set, so ``OperationalResearchEnricher``
        runs its original code path unchanged.
        """

        if settings.google_genai_api_key is None:
            return None

        extractor = GeminiStructuredExtractor(
            settings.google_genai_api_key,
            model=settings.gemini_model_chain,
        )
        self._http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(20.0, connect=10.0),
            follow_redirects=False,
        )

        # A key alone must not change runtime wiring: with every You.com flag off
        # this builds the EXACT pre-existing Perplexity + guarded-HTTP pipeline and
        # never opens the research cache.
        if not settings.any_you_feature_configured:
            discovery = (
                PerplexitySearchDiscovery(settings.perplexity_api_key)
                if settings.perplexity_api_key is not None
                else None
            )
            return OperationalResearchEnricher(
                discovery=discovery,
                extractor=extractor,
                http_client=self._http_client,
            )

        you_api_key = settings.you_api_key
        if you_api_key is None:  # pragma: no cover - every *_configured requires the key
            raise ConfigurationRequiredError(
                phase=2,
                capability="You.com research",
                reason_code="you_api_key_required",
            )
        # One persistent research cache shared by all three You.com adapters, so
        # identical app research does not re-spend credits across enrichments.
        # The You.com adapters themselves manage their SDK client lifecycle via
        # ``async with`` per call — no persistent async client is stored here
        # (that would be unsafe across the per-enrichment asyncio.run loops).
        if self._research_cache is None:
            self._research_cache = SqliteResearchCache(settings.research_cache_db_path)
        research_cache = self._research_cache

        discovery_providers: list[object] = []
        if settings.you_search_configured:
            discovery_providers.append(
                YouSearchDiscovery(
                    you_api_key,
                    count=settings.you_search_count,
                    timeout_seconds=settings.you_search_timeout_seconds,
                    max_calls=settings.you_max_search_calls_per_enrichment,
                    cache=research_cache,
                )
            )
        if settings.perplexity_api_key is not None:
            discovery_providers.append(
                LegacyDiscoveryAdapter(PerplexitySearchDiscovery(settings.perplexity_api_key))
            )
        rich_discovery = (
            CompositeEvidenceDiscovery(discovery_providers)  # type: ignore[arg-type]
            if discovery_providers
            else None
        )

        content_fetcher_factory = None
        if settings.you_contents_configured:
            contents_timeout = settings.you_contents_timeout_seconds
            contents_max_age = settings.you_contents_max_age_seconds
            contents_max_pages = settings.you_max_contents_pages_per_enrichment
            guarded_http_client = self._http_client

            def _build_content_fetcher(host_policy: ResearchHostPolicy) -> object:
                primary = YouContentsFetcher(
                    you_api_key,
                    policy=host_policy,
                    max_age=contents_max_age,
                    request_timeout=contents_timeout,
                    max_pages=contents_max_pages,
                    cache=research_cache,
                )
                fallback_policy = host_policy.official_url_policy
                if fallback_policy is None:
                    return primary
                fallback = GuardedHTTPEvidenceFetcher(
                    OfficialEvidenceFetcher(guarded_http_client, fallback_policy)
                )
                return FallbackEvidenceContentFetcher(primary=primary, fallback=fallback)

            content_fetcher_factory = _build_content_fetcher

        research_fallback = None
        if settings.you_research_configured:
            research_fallback = YouResearchFallback(
                you_api_key,
                timeout_seconds=settings.you_research_timeout_seconds,
                cache=research_cache,
            )

        return OperationalResearchEnricher(
            discovery=None,
            extractor=extractor,
            http_client=self._http_client,
            rich_discovery=rich_discovery,
            # ops.operational_research declares these as small structural
            # Protocols typed with `policy: object` (it cannot import the
            # concrete ResearchHostPolicy without a circular import). The
            # concrete you_research classes correctly narrow that parameter
            # to ResearchHostPolicy, which mypy's Protocol contravariance
            # check flags even though it is safe here: _enrich_rich always
            # calls both with the exact ResearchHostPolicy it just built.
            content_fetcher_factory=content_fetcher_factory,  # type: ignore[arg-type]
            research_fallback=research_fallback,  # type: ignore[arg-type]
            # Cache the fully validated projection in the same SQLite cache as
            # Search/Contents so a warm run can be resumed without a fresh Gemini
            # extraction. Cached documents and claims are revalidated on every hit.
            outcome_cache=research_cache,
            outcome_cache_ttl=timedelta(
                seconds=max(1, settings.you_contents_max_age_seconds or 86_400)
            ),
        )

    def _build_credential_validator(
        self, settings: Settings
    ) -> PolicyBoundCredentialValidator | None:
        """Build the read-only HubSpot validator when the vault key is present."""

        if settings.secret_vault_key is None:
            return None
        if self._secret_store is None:
            self._secret_store = SQLiteSecretStore(
                settings.secret_vault_db_path,
                settings.secret_vault_key.get_secret_value(),
            )
        client = httpx.AsyncClient(
            timeout=httpx.Timeout(10.0, connect=5.0),
            follow_redirects=False,
        )
        self._validation_http_client = client
        validator = CredentialValidator(
            secret_store=self._secret_store,
            http_client=client,
            policies=(hubspot_validation_policy(), pipedrive_validation_policy()),
        )
        # Read-only validation endpoints come from the reviewed NetworkEndpointPolicy
        # (the single source of truth for exact backend endpoints).
        endpoints: dict[str, str] = {}
        for slug in ("hubspot", "pipedrive"):
            endpoint = network_validation_endpoint(slug)
            if endpoint is not None:
                endpoints[slug] = endpoint
        return PolicyBoundCredentialValidator(validator=validator, endpoints=endpoints)

    def _build_workflow_dependencies(self, settings: Settings) -> WorkflowDependencies:
        """Inject controlled Gmail and every configured browser adapter.

        Gmail outreach requires Composio configuration AND a configured
        OUTREACH_RECIPIENT_OVERRIDE so every send is delivered to the controlled
        recipient, never the discovered vendor address. Browser adapters are
        evaluated independently and registered under their canonical identities.
        """

        # Build the effect ledger up front so the Gmail worker can share it for
        # effectively-once sends.
        if self._effect_store is None:
            self._effect_store = SQLiteEffectStore(settings.provider_effects_db_path)

        gmail: GmailWorker | None = None
        if (
            settings.composio_api_key is not None
            and settings.composio_gmail_connected_account_id is not None
            and settings.outreach_recipient_override is not None
        ):
            # Wire the encrypted vault + effect ledger: a reply that carries a
            # credential is then stored as a vault:// reference instead of raising
            # secret_store_missing (which previously wedged the email path), and
            # sends stay idempotent.
            gmail = GmailWorker(
                settings=settings,
                secret_store=self._secret_store,
                effect_store=self._effect_store,
            )
            # Retain the Gmail worker so the poll-email action can fetch and
            # classify replies on the same controlled account.
            self._gmail_worker = gmail
        self._record_wiring("gmail", gmail, configured=gmail is not None)

        browsers: dict[BrowserProvider, BrowserWorker] = {}
        for provider_name in ("browser_use", "playwright"):
            if not self._browser_provider_enabled(settings, provider_name):
                self._record_wiring(
                    f"browser:{provider_name}",
                    None,
                    configured=False,
                )
                continue
            provider_settings = settings.model_copy(update={"browser_provider": provider_name})
            worker = self._build_browser_worker(provider_settings, provider=provider_name)
            browsers[provider_name] = worker
            self._record_wiring(
                f"browser:{provider_name}",
                worker,
                configured=True,
            )
        self._browser_workers = browsers
        browser = browsers.get(settings.browser_provider)
        self._browser_worker = browser
        self._record_wiring("browser", browser, configured=browser is not None)

        self._record_wiring("effect_store", self._effect_store, configured=True)

        return WorkflowDependencies(
            browser=browser,
            browsers=browsers,
            gmail=gmail,
            effect_store=self._effect_store,
            outreach_recipient=settings.outreach_recipient_override,
        )

    def _browser_provider_enabled(
        self,
        settings: Settings,
        provider: BrowserProvider | None = None,
    ) -> bool:
        """Whether a browser worker should be wired for the selected provider.

        ``browser_use`` keeps the exact prod condition (live opt-in + an API key).
        ``playwright`` needs the live opt-in AND an execution location: the browser
        service (URL + token) or the explicit in-process sandbox. No Browser Use
        key is ever required for it.
        """

        from ops.browser_readiness import browser_configuration_state

        # One shared, provider-aware helper (also used by health + retry eligibility)
        # so a Playwright deployment is never judged by a Browser Use key.
        return browser_configuration_state(settings, provider)

    def _browser_worker_for(
        self,
        source: Mapping[str, object] | BrowserProvider,
    ) -> BrowserWorker | None:
        provider = (
            source
            if isinstance(source, str)
            else cast(BrowserProvider, source.get("browser_provider", "browser_use"))
        )
        workers = cast(
            dict[BrowserProvider, BrowserWorker],
            getattr(self, "_browser_workers", {}),
        )
        worker = workers.get(provider)
        if worker is not None:
            return worker
        # Compatibility for narrow tests and older embedders that injected the
        # former single-worker attribute directly. Never cross-route a worker
        # whose provider identity is known to differ from the run.
        legacy_worker = cast(BrowserWorker | None, getattr(self, "_browser_worker", None))
        legacy_provider = getattr(legacy_worker, "provider_name", provider)
        return legacy_worker if legacy_provider == provider else None

    def _browser_login_payload(
        self,
        *,
        provider: BrowserProvider,
        app_slug: str,
        scope_id: str,
        values: Mapping[str, SecretStr],
    ) -> dict[str, str]:
        """Build the credential payload for the ACTIVE browser provider.

        Browser Use receives raw values in-process, exactly as before. The browser
        SERVICE must never receive a raw value over RPC, so each permitted secret is
        first stored as a TRANSIENT (one-time, run-scoped, expiring) ``vault://``
        reference and only the reference travels; the service consumes it once.
        """

        raw = {name: secret.get_secret_value() for name, secret in values.items()}
        worker = self._browser_worker_for(provider)
        if getattr(worker, "provider_name", "") != "playwright":
            return raw
        if not callable(getattr(worker, "reconcile_session", None)):
            # In-process Playwright: same process, no RPC boundary to cross.
            return raw
        return self._store_transient_browser_secrets(
            app_slug=app_slug, scope_id=scope_id, values=raw
        )

    def _remember_reusable_login(
        self, *, app_slug: str, values: Mapping[str, SecretStr]
    ) -> tuple[str, ...]:
        """Persist the owner's reusable sign-in credentials for this app.

        Only ``login_email``/``login_password`` are durable; a one-time OTP or
        verification link is deliberately never remembered. Returns the sanitized
        field names actually stored (never a value) so the caller can audit the
        act of remembering without recording the secret.

        A vault failure here must not break the run in progress: the credentials
        were already injected for THIS run, so failing to remember them only
        costs autonomy on a later run.
        """

        store = self._secret_store
        settings = self._settings or Settings.from_env()
        if store is None or not getattr(settings, "browser_login_credential_reuse", True):
            return ()
        remembered: list[str] = []
        for login_field in sorted(REUSABLE_LOGIN_FIELDS):
            secret = values.get(login_field)
            if secret is None:
                continue
            value = secret.get_secret_value()
            if not value:
                continue
            try:
                store.put_account_login(app_slug=app_slug, field=login_field, value=value)
            except Exception:
                continue  # sanitized: never log the value or the failure detail
            remembered.append(login_field)
        return tuple(remembered)

    def _reusable_login_values(self, app_slug: str) -> dict[str, SecretStr]:
        """Load the remembered sign-in credentials for an app, if complete.

        A partial pair is useless to the deterministic login state machine (it
        would type an email and then stop at the password), so an incomplete set
        is treated as "nothing stored" and the run still asks the owner once.
        """

        store = self._secret_store
        settings = self._settings or Settings.from_env()
        if store is None or not getattr(settings, "browser_login_credential_reuse", True):
            return {}
        reader = getattr(store, "get_account_login", None)
        if not callable(reader):
            return {}
        values: dict[str, SecretStr] = {}
        for login_field in sorted(REUSABLE_LOGIN_FIELDS):
            try:
                value = reader(app_slug=app_slug, field=login_field)
            except Exception:
                return {}
            if not value:
                return {}
            values[login_field] = SecretStr(value)
        return values

    def _store_transient_browser_secrets(
        self, *, app_slug: str, scope_id: str, values: Mapping[str, str]
    ) -> dict[str, str]:
        """Vault each permitted secret as a one-time, run-scoped reference.

        A field outside the reviewed set is refused. A vault-write failure is NOT
        suppressed: every reference created so far is rolled back (deleted) and the
        whole payload fails, so a run never proceeds with a partial secret set or a
        raw value on the wire.
        """

        from ops.browser_service_client import ALLOWED_BROWSER_SECRET_FIELDS

        store = self._secret_store
        if store is None:
            raise ConfigurationRequiredError(
                phase=5,
                capability="browser service secrets",
                reason_code="secret_vault_required_for_browser_service",
            )
        references: dict[str, str] = {}
        created: list[str] = []
        try:
            for name, value in values.items():
                if name not in ALLOWED_BROWSER_SECRET_FIELDS:
                    raise ProviderOperationError(
                        capability="browser service secrets",
                        reason_code="browser_secret_field_not_allowed",
                    )
                if not value:
                    continue
                reference = store.put_transient(
                    app_slug=app_slug,
                    # Namespaced so a browser-login secret is distinguishable from a
                    # captured integration credential in the vault.
                    kind=f"browser_login_{name}",
                    scope_id=scope_id,
                    value=value,
                    ttl_seconds=600,
                )
                references[name] = reference
                created.append(reference)
        except Exception:
            for reference in created:
                with contextlib.suppress(Exception):
                    store.delete(reference)
            raise ProviderOperationError(
                capability="browser service secrets",
                reason_code="browser_secret_store_failed",
            ) from None
        return references

    def _build_browser_worker(
        self,
        settings: Settings,
        *,
        provider: BrowserProvider | None = None,
    ) -> BrowserWorker:
        """Select the browser backend.

        Default resolves the (possibly assignment-patched) ``BrowserWorker`` in this
        module's namespace, so the Browser Use path is byte-for-byte unchanged.

        For ``playwright`` the NORMAL path is now the isolated browser service over
        authenticated RPC. Previously this always returned the in-process worker, so
        the service, its RPC auth, restart reattachment, health and lifecycle manager
        were never used by the real application. Running Chromium inside the API is
        still possible but must be requested explicitly via
        ``playwright_in_process_sandbox`` — it is for isolated tests and local
        debugging, not a silent fallback when the service is unconfigured.
        """

        selected = provider or settings.browser_provider
        if selected == "playwright":
            if getattr(settings, "playwright_in_process_sandbox", False):
                try:
                    from ops.playwright_worker import PlaywrightBrowserWorker
                except ImportError:
                    raise ConfigurationRequiredError(
                        phase=5,
                        capability="Playwright browser provider",
                        reason_code="playwright_provider_unavailable",
                    ) from None
                return cast("BrowserWorker", PlaywrightBrowserWorker(settings=settings))

            if not settings.browser_service_url or settings.browser_service_token is None:
                # Fail closed with an actionable reason rather than quietly starting
                # a browser in the control plane.
                raise ConfigurationRequiredError(
                    phase=5,
                    capability="Playwright browser service",
                    reason_code="browser_service_configuration_required",
                )
            from ops.browser_service_client import BrowserServiceClient

            return cast(
                "BrowserWorker",
                BrowserServiceClient(
                    base_url=settings.browser_service_url,
                    token=settings.browser_service_token,
                    owner=settings.browser_service_owner,
                ),
            )
        return BrowserWorker(settings=settings)

    def _record_wiring(
        self,
        dependency: str,
        instance: object | None,
        *,
        configured: bool,
        wired: bool | None = None,
    ) -> None:
        """Append a sanitized wiring-audit row (class name only, never secrets)."""

        self._wiring = [row for row in self._wiring if row.get("dependency") != dependency]
        self._wiring.append(
            {
                "dependency": dependency,
                "class": type(instance).__name__ if instance is not None else None,
                "configured": configured,
                "runtime_wired": (instance is not None) if wired is None else wired,
                "live_verified": False,
            }
        )

    def wiring_audit(self) -> list[dict[str, object]]:
        """Return the sanitized startup wiring audit (dependency/class/state)."""

        return [dict(row) for row in self._wiring]

    def shutdown(self) -> None:
        """Close the durable workflow, owned provider clients, and connections."""

        self._email_poller_stop.set()
        if self._email_poller_thread is not None:
            self._email_poller_thread.join(timeout=5)
        self._advance_stop.set()
        if self._advance_thread is not None:
            self._advance_thread.join(timeout=5)
            self._email_poller_thread = None
        workflow = self._workflow
        self._workflow = None
        if workflow is not None:
            workflow.close()
        for client_attr in ("_http_client", "_validation_http_client"):
            client = getattr(self, client_attr, None)
            if isinstance(client, httpx.AsyncClient):
                try:
                    asyncio.run(client.aclose())
                except RuntimeError:  # pragma: no cover - already within a loop
                    pass
                setattr(self, client_attr, None)
        if self._research_cache is not None:
            try:
                self._research_cache.close()
            except Exception:  # pragma: no cover - best-effort cleanup
                pass
            self._research_cache = None
        for worker in dict.fromkeys(self._browser_workers.values()):
            try:
                asyncio.run(worker.close())
            except Exception:  # pragma: no cover - best-effort cleanup
                pass
        self._browser_workers = {}
        self._browser_worker = None

    def create_run(
        self,
        request: OperationsRequest,
        *,
        idempotency_key: str | None = None,
        execution_mode: Literal["plan_only", "execute_when_configured"] = "plan_only",
        browser_login: Mapping[str, SecretStr] | None = None,
    ) -> dict[str, Any]:
        """Create and route one run without invoking an external provider.

        ``execution_mode`` is the single canonical control. ``plan_only`` runs the
        verified P1 lookup, deterministic routing, and sanitized persistence with
        no provider or network action. ``execute_when_configured`` may perform a
        bounded, policy-gated provider operation when the relevant dependency is
        configured; provider failures retain the verified baseline and are
        recorded as sanitized capability state. The deprecated ``request.dry_run``
        flag is no longer consulted as a runtime control.
        """

        persisted_execution_mode = _PERSISTED_EXECUTION_MODE[execution_mode]
        created_event_type = "dry_run_created" if execution_mode == "plan_only" else "run_created"
        validated_idempotency_key = validate_idempotency_key(idempotency_key)
        request_fingerprint = (
            _request_fingerprint(request, execution_mode)
            if validated_idempotency_key is not None
            else None
        )

        # Verify all immutable inputs before writing any run state.
        lookup = self.p1_adapter.lookup(request.app_name)
        research_payload: Mapping[str, object] | None = None
        research_source = "verified_p1_snapshot"
        enrichment_attempts = 0
        enrichment_documents = 0
        enrichment_metrics: dict[str, object] = {}
        enrichment_capability: CapabilityAvailability | None = None
        reviewed_baseline_version: str | None = None
        if isinstance(lookup, P1LookupFound):
            research = to_operational_research(lookup.record)
            research, reviewed_baseline_version = apply_reviewed_operational_baseline(research)
            # Plan-only runs are strictly local: no provider or network action is
            # permitted. An explicit execute request may use one bounded,
            # allowlisted official-evidence probe when the baseline is incomplete.
            # Browser, Gmail, and credential side effects remain separately gated.
            if (
                execution_mode == "execute_when_configured"
                and self._enricher is not None
                and _missing_operational_fields(research.model_dump(mode="json"))
            ):
                outcome = self._run_enrichment_probe(lookup.record, research)
                research = outcome.research
                enrichment_capability = outcome.capability
                enrichment_documents = outcome.documents_fetched
                enrichment_metrics = dict(outcome.provider_metrics)
                if outcome.capability.status == "ready":
                    enrichment_attempts = 1
                    research_source = "official_evidence_combined"
                decision = decide_access(research, unknown_probe_attempts=enrichment_attempts)
            else:
                decision = decide_access(research)
            research_payload = research.model_dump(mode="json")
        else:
            decision = RoutingDecision(
                route="unknown",
                reason_code="insufficient_evidence_probe_available",
                explanation=(
                    "The app is not present in the verified P1 snapshot. One bounded enrichment "
                    "probe remains available, but no external provider was invoked."
                ),
                is_final=False,
                unknown_probe_attempts=0,
                unknown_probe_remaining=1,
            )

        run_id = f"run_{uuid4().hex}"
        thread_id = f"local_{uuid4().hex}"
        with self.storage.unit_of_work() as transaction:
            if validated_idempotency_key is not None:
                existing = transaction.get_idempotent_run(validated_idempotency_key)
                if existing is not None:
                    record, stored_fingerprint = existing
                    legacy_match = stored_fingerprint in _legacy_request_fingerprints(
                        request, execution_mode
                    )
                    if stored_fingerprint != request_fingerprint and not legacy_match:
                        raise IdempotencyConflictError(
                            "idempotency key was already used for another request"
                        )
                    return _public_run(record)

            transaction.create_run(
                run_id=run_id,
                thread_id=thread_id,
                app_name=request.app_name,
                app_slug=_slugify(request.app_name),
                status="created",
                p1_summary=(
                    {
                        "category": lookup.record.category,
                        "one_liner": lookup.record.one_liner,
                        "auth_methods": lookup.record.auth_methods,
                        "access_model": lookup.record.access_model.kind,
                        "api_type": lookup.record.api_type,
                        "buildability": lookup.record.buildability,
                        "recommended_next_action": lookup.record.recommended_next_action,
                        "verification_status": lookup.record.verification_status,
                        "confidence": lookup.record.confidence,
                        "last_verified": lookup.record.last_verified,
                    }
                    if isinstance(lookup, P1LookupFound)
                    else None
                ),
                operational_research=research_payload,
                route_reason_code=decision.reason_code,
                route_explanation=decision.explanation,
                missing_fields=(
                    _missing_operational_fields(research_payload)
                    if research_payload is not None
                    else ["p1_record", "operational_research"]
                ),
                provider_status={
                    "research": (
                        enrichment_capability.status
                        if enrichment_capability is not None
                        else ("baseline_ready" if research_payload is not None else "not_started")
                    ),
                    "browser": "not_started",
                    "email": "not_started",
                    "validation": "not_started",
                },
                scope_policy=request.requested_scope_policy,
                execution_mode=persisted_execution_mode,
                browser_provider=request.browser_provider,
                credential_creation_policy=request.credential_creation_policy,
                external_actions=False,
                idempotency_key=validated_idempotency_key,
                request_fingerprint=request_fingerprint,
            )
            transaction.append_audit_event(
                run_id=run_id,
                event_type=created_event_type,
                payload={
                    "status": "created",
                    "scope_policy": request.requested_scope_policy,
                    "execution_mode": persisted_execution_mode,
                    "browser_provider": request.browser_provider,
                    "credential_creation_policy": request.credential_creation_policy,
                    "external_actions": False,
                },
            )
            if execution_mode == "execute_when_configured":
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="operational_research_started",
                    payload={"status": "researching", "external_actions": False},
                )

            if isinstance(lookup, P1LookupFound):
                if research_payload is None:  # pragma: no cover - narrowing invariant
                    raise RuntimeError("verified research payload was not built")
                self._record_verified_research(
                    transaction,
                    run_id,
                    lookup,
                    research_payload,
                )
                if reviewed_baseline_version is not None:
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="reviewed_operational_baseline_applied",
                        payload={
                            "status": "baseline_complete",
                            "app_slug": lookup.record.slug,
                            "version": reviewed_baseline_version,
                            "missing_fields": _missing_operational_fields(research_payload),
                            "external_actions": False,
                        },
                    )
                if enrichment_capability is not None:
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="operational_research_enriched",
                        payload={
                            "status": enrichment_capability.status,
                            "source": research_source,
                            "reason_code": enrichment_capability.reason_code,
                            "detail": enrichment_capability.detail,
                            "enrichment_attempts": enrichment_attempts,
                            "documents_fetched": enrichment_documents,
                            "missing_fields": _missing_operational_fields(research_payload),
                            "confidence": research_payload.get("confidence"),
                            # Sanitized provider metrics (counts/latency/provider
                            # name); never query text, page content, or the key.
                            "provider_metrics": enrichment_metrics,
                            "external_actions": False,
                        },
                    )
            else:
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="p1_snapshot_not_found",
                    payload={
                        "status": "not_found",
                        "source": "verified_p1_snapshot",
                        "external_actions": False,
                    },
                )

            routed_status: str = "route_selected" if decision.is_final else "researching"
            decision_event = "route_selected" if decision.is_final else "route_pending"
            persisted_route: AccessRoute = decision.route
            persisted_reason: str = decision.reason_code
            persisted_explanation: str = decision.explanation
            outreach_updates: dict[str, object] = {}
            outreach_event: dict[str, object] | None = None
            persisted_status = routed_status

            capability_report: ComposioCapabilityReport | None = None
            capability_event: dict[str, object] | None = None
            browser_events: list[tuple[str, dict[str, object]]] = []
            observation_status: str | None = None
            # Set when the self-serve browser run is dispatched asynchronously
            # (Option A). Carries the pre-created live session so the background
            # navigate can be started once the creation transaction commits.
            pending_async_navigate: tuple[Any, dict[str, str] | None] | None = None
            # Sanitized autonomous-login bookkeeping: field NAMES and the source
            # only. A credential value never reaches these variables.
            login_remembered_fields: tuple[str, ...] = ()
            injected_login_source: str | None = None
            injected_login_fields: tuple[str, ...] = ()

            if (
                execution_mode == "execute_when_configured"
                and self._workflow is not None
                and isinstance(lookup, P1LookupFound)
            ):
                is_gated = decision.route in _GATED_OUTREACH_ROUTES
                is_self_serve = decision.route == "self_serve"
                needs_capability = is_gated or is_self_serve
                if needs_capability and self._capability_preflight is not None:
                    # Evaluate Composio capability exactly once before any verified
                    # P1 fallback (gated outreach or self-serve browser onboarding).
                    capability_report = self._run_capability_preflight(
                        lookup.record.slug, request.app_name
                    )
                    capability_event = {
                        "capability_state": capability_report.capability_state,
                        "reason_code": capability_report.reason_code,
                        "toolkit_available": capability_report.toolkit_available,
                        "toolkit_slug": capability_report.toolkit_slug,
                        "active_connected_account": capability_report.active_connected_account,
                        "managed_auth_available": capability_report.managed_auth_available,
                        "required_tools_present": capability_report.required_tools_present,
                        "external_actions": False,
                    }

                # The verified P1 fallback (gated outreach or self-serve browser)
                # runs only when Composio cannot already integrate the app.
                fallback_allowed = (
                    capability_report is not None and capability_report.p1_fallback_allowed
                )
                run_provider_action = fallback_allowed
                # Gated outreach fails closed: any non-fallback capability, or an
                # unconfigured/absent preflight, suppresses the send. A self-serve
                # run is suppressed only by a definitive Composio capability
                # (composio_ready/connection_required); an unconfigured or absent
                # preflight preserves plan-only routing with no external action.
                suppress_fallback = (is_gated and not fallback_allowed) or (
                    is_self_serve
                    and capability_report is not None
                    and capability_report.capability_state
                    in {"composio_ready", "connection_required"}
                )

                if suppress_fallback:
                    persisted_status = "configuration_required"
                    decision_event = "configuration_required"
                    persisted_reason = _capability_reason_code(capability_report)
                    outreach_updates = {
                        "provider_status": {
                            "research": "baseline_ready",
                            "browser": "not_started",
                            "email": "not_started",
                            "composio": (
                                capability_report.capability_state
                                if capability_report is not None
                                else "configuration_required"
                            ),
                            "validation": "not_started",
                        },
                    }
                else:
                    # A provider action (gated outreach or self-serve browser) runs
                    # only when the fallback is allowed; unknown/blocked/hybrid
                    # routes run the workflow plan-only (routing only). The workflow
                    # performs the legal internal transitions and this projection
                    # records its truthful result.
                    # Autonomous sign-in credentials (if any) are injected into
                    # Browser Use as secure ``sensitive_data`` placeholders at
                    # session creation, so the agent signs in on its own. The raw
                    # values are passed to the workflow only as a call argument and
                    # never persisted to state, checkpoints, the ledger, or logs.
                    start_sensitive_data: dict[str, str] | None = None
                    # Autonomy: when the owner did not supply credentials for THIS
                    # run, reuse the ones they already authorized for this app.
                    # Without this a second run always stopped at the login form
                    # even though the credentials were known.
                    login_values: Mapping[str, SecretStr] | None = browser_login
                    login_source = "owner_supplied"
                    if not login_values and run_provider_action:
                        remembered = self._reusable_login_values(research.app_slug)
                        if remembered:
                            login_values = remembered
                            login_source = "vault_reuse"
                    if browser_login:
                        remembered_fields = self._remember_reusable_login(
                            app_slug=research.app_slug, values=browser_login
                        )
                        if remembered_fields:
                            login_remembered_fields = remembered_fields
                    if login_values and run_provider_action:
                        injected_login_source = login_source
                        injected_login_fields = tuple(sorted(login_values))
                        start_sensitive_data = self._browser_login_payload(
                            provider=request.browser_provider,
                            # The verified slug and the newly created run id are
                            # already in scope here; the run row is not readable
                            # yet from inside its own creating transaction.
                            app_slug=research.app_slug,
                            # Scope the transient references to THIS run, so the
                            # service will only consume them for the matching run.
                            scope_id=run_id,
                            # The resolved set, which may be the remembered
                            # credentials rather than an owner submission.
                            values=login_values,
                        )
                    selected_worker = self._browser_worker_for(request.browser_provider)
                    trace_available = get_browser_api_trace(research.app_slug) is not None
                    # Trace-only readiness is scoped to the assignment's async
                    # runtime. Conservative/synchronous workflows still load their
                    # own reviewed operational URLs instead of receiving an
                    # incomplete baseline from RunService.
                    browser_research_ready = bool(
                        trace_available
                        and (
                            self._async_browser_enabled
                            or (research.login_url and research.credential_management_url)
                        )
                    )
                    # The pre-created session is attempted first, but a provider
                    # failure must NOT abort run creation. It previously raised
                    # straight out of create_run, which returned an unhandled 500
                    # and persisted NOTHING: the operator saw "the operations API is
                    # unavailable" with no run in the ledger and no way to see why.
                    # A failed start now falls through to the durable workflow, which
                    # records a truthful failure state for a run that really exists.
                    context = None
                    if (
                        self._async_browser_enabled
                        and is_self_serve
                        and run_provider_action
                        and selected_worker is not None
                        and browser_research_ready
                    ):
                        # OPTION A: pre-create the live provider session so the
                        # embedded live view is available immediately, commit the
                        # run at browser_running now, and run the durable navigate
                        # in a background thread. Run creation stays fast (no 504)
                        # and the live stream is available for the entire task.
                        #
                        # The same session metadata the LangGraph browser node
                        # supplies is passed here: without app_slug the service
                        # cannot resolve its host policy, and without secret_scope
                        # it cannot consume this run's one-time login references.
                        worker = selected_worker
                        is_playwright = getattr(worker, "provider_name", "") == "playwright"
                        account_ref: str | None = None
                        if is_playwright:
                            with contextlib.suppress(Exception):
                                account_ref = browser_account_ref(request.company.work_email_ref)
                        try:
                            context = asyncio.run(
                                worker.start(
                                    None,
                                    app_slug=research.app_slug,
                                    account_ref=account_ref,
                                    secret_scope=run_id,
                                    use_storage_state=is_playwright,
                                    live_view_mode=(
                                        "interactive_remote"
                                        if is_playwright
                                        and bool(
                                            getattr(
                                                self._settings,
                                                "browser_interactive_hitl_enabled",
                                                False,
                                            )
                                        )
                                        else "screenshot"
                                    ),
                                )
                            )
                        except (TypeError, AttributeError, AssertionError, NameError):
                            raise  # a programming error must surface, never degrade
                        except Exception as exc:
                            # Sanitized reason only; the durable workflow below now
                            # records the outcome against a persisted run.
                            log_event(
                                "run.dispatch.session_error",
                                level=40,
                                run_id=run_id,
                                thread_id=thread_id,
                                error=type(exc).__name__,
                                reason_code=str(getattr(exc, "reason_code", "") or "unknown"),
                            )
                            context = None
                    if context is not None:
                        pending_async_navigate = (context, start_sensitive_data)
                        workflow_state: OperationsState = {
                            "status": "browser_running",
                            "access_route": "self_serve",
                            "route_reason_code": decision.reason_code,
                            "route_reason": decision.explanation,
                            "browser_session_id": context.session_id,
                        }
                        log_event(
                            "run.dispatch.async_begin",
                            run_id=run_id,
                            thread_id=thread_id,
                            handle=context.session_id,
                            live_view_available=context.live_view_available,
                        )
                    else:
                        # Reached either because Option A does not apply to this run
                        # or because the pre-created session failed above.
                        log_event(
                            "run.dispatch.begin",
                            run_id=run_id,
                            thread_id=thread_id,
                            app_slug=_slugify(request.app_name),
                            route=decision.route,
                            run_provider_action=run_provider_action,
                            has_login=bool(browser_login),
                        )
                        try:
                            workflow_state = self._workflow.start(
                                request.model_copy(update={"dry_run": not run_provider_action}),
                                thread_id=thread_id,
                                sensitive_data=start_sensitive_data,
                                research=research if browser_research_ready else None,
                            )
                        except Exception as exc:
                            log_event(
                                "run.dispatch.error",
                                level=40,
                                run_id=run_id,
                                thread_id=thread_id,
                                error=type(exc).__name__,
                            )
                            raise
                    log_event(
                        "run.dispatch.result",
                        run_id=run_id,
                        thread_id=thread_id,
                        status=str(workflow_state.get("status") or routed_status),
                        access_route=workflow_state.get("access_route"),
                        has_browser_session=bool(workflow_state.get("browser_session_id")),
                        observation_status=(
                            str(workflow_state.get("browser_observation", {}).get("status"))
                            if isinstance(workflow_state.get("browser_observation"), Mapping)
                            else None
                        ),
                    )
                    persisted_status = str(workflow_state.get("status") or routed_status)
                    persisted_route = workflow_state.get("access_route") or decision.route
                    persisted_reason = str(
                        workflow_state.get("route_reason_code") or decision.reason_code
                    )
                    persisted_explanation = str(
                        workflow_state.get("route_reason") or decision.explanation
                    )
                    thread = workflow_state.get("gmail_thread_id")
                    browser_session = workflow_state.get("browser_session_id")
                    observation = workflow_state.get("browser_observation")
                    observation_status = (
                        str(observation.get("status")) if isinstance(observation, Mapping) else None
                    )
                    if pending_async_navigate is not None:
                        # Async browser dispatch: commit browser_running with the
                        # live session; the background navigate advances the run.
                        decision_event = "route_selected"
                        persisted_status = "browser_running"
                        outreach_updates = {
                            "browser_session_id": browser_session,
                            "external_actions": True,
                            "provider_status": {
                                "research": "baseline_ready",
                                "browser": "running",
                                "email": "not_started",
                                "validation": "not_started",
                            },
                        }
                        browser_events = [
                            (
                                "browser_session_started",
                                {
                                    "session_id": browser_session,
                                    "status": "browser_running",
                                    "external_actions": True,
                                },
                            ),
                        ]
                    elif (
                        (
                            persisted_status in {"failed", "blocked"}
                            or (
                                persisted_status == "configuration_required"
                                and observation_status
                                not in {"credential_page_ready", "developer_console_ready"}
                            )
                        )
                        and isinstance(browser_session, str)
                        and browser_session
                    ):
                        # A workflow can retain the session id after navigation
                        # fails. The old projection treated any non-empty id as
                        # success, invented credential_page_ready events, and left
                        # the UI polling a blank/dead browser forever.
                        fallback_reason = {
                            "blocked": "browser_navigation_blocked",
                            "configuration_required": "browser_configuration_required",
                            "failed": "browser_operation_failed",
                        }.get(persisted_status, "browser_operation_failed")
                        persisted_reason = _browser_result_reason(workflow_state, fallback_reason)
                        if persisted_status == "configuration_required":
                            decision_event = "configuration_required"
                        outreach_updates = {
                            "browser_session_id": browser_session,
                            "external_actions": True,
                            "provider_status": {
                                "research": "baseline_ready",
                                "browser": persisted_status,
                                "email": "not_started",
                                "validation": "not_started",
                            },
                        }
                        browser_events = [
                            (
                                "browser_session_started",
                                {
                                    "session_id": browser_session,
                                    "status": "browser_running",
                                    "external_actions": True,
                                },
                            ),
                            (
                                (
                                    "browser_navigation_blocked"
                                    if persisted_status == "blocked"
                                    else "browser_navigation_failed"
                                ),
                                {
                                    "status": persisted_status,
                                    "reason_code": persisted_reason,
                                    "external_actions": True,
                                },
                            ),
                        ]
                    elif isinstance(thread, str) and thread:
                        outreach_updates = {
                            "gmail_session_id": workflow_state.get("gmail_session_id"),
                            "gmail_thread_id": thread,
                            "external_actions": True,
                            "provider_status": {
                                "research": "baseline_ready",
                                "browser": "not_started",
                                "email": "sent",
                                "validation": "not_started",
                            },
                        }
                        # The effect/idempotency key is deterministically
                        # "<run_id>:initial-outreach"; it is not duplicated into the
                        # sanitized payload where the redactor would mask it as noise.
                        outreach_event = {
                            "status": persisted_status,
                            "route": persisted_route,
                            "reason_code": persisted_reason,
                            "intended_recipient": workflow_state.get("intended_recipient"),
                            "actual_recipient": workflow_state.get("actual_recipient"),
                            "outreach_round": workflow_state.get("outreach_round", 0),
                            "gmail_session_id": workflow_state.get("gmail_session_id"),
                            "gmail_thread_id": thread,
                            "provider_outcome": "sent",
                            "external_actions": True,
                        }
                        decision_event = "route_selected"
                    elif isinstance(browser_session, str) and browser_session:
                        # A controlled browser session was started. The effect key
                        # is deterministically "<run_id>:browser-start".
                        decision_event = "route_selected"
                        current_url = workflow_state.get("current_url")
                        outreach_updates = {
                            "browser_session_id": browser_session,
                            "external_actions": True,
                            "provider_status": {
                                "research": "baseline_ready",
                                "browser": observation_status or "running",
                                "email": "not_started",
                                "validation": "not_started",
                            },
                        }
                        if (
                            observation_status == "human_action_required"
                            or persisted_status == "waiting_for_hitl"
                        ):
                            persisted_status = "waiting_for_hitl"
                            hitl = workflow_state.get("hitl_request")
                            required_action: object = None
                            if isinstance(hitl, Mapping):
                                required_action = hitl.get("type") or hitl.get("message")
                            browser_events = [
                                (
                                    "browser_session_started",
                                    {
                                        "session_id": browser_session,
                                        "status": "browser_running",
                                        "external_actions": True,
                                    },
                                ),
                                (
                                    "browser_hitl_required",
                                    {
                                        "status": "waiting_for_hitl",
                                        "current_url": current_url,
                                        "required_human_action": required_action,
                                        "external_actions": True,
                                    },
                                ),
                            ]
                        else:
                            base_browser_events: list[tuple[str, dict[str, object]]] = [
                                (
                                    "browser_session_started",
                                    {
                                        "session_id": browser_session,
                                        "status": "browser_running",
                                        "external_actions": True,
                                    },
                                ),
                                (
                                    "browser_navigation_completed",
                                    {
                                        "current_url": current_url,
                                        "status": "browser_running",
                                        "external_actions": True,
                                    },
                                ),
                                (
                                    "credential_page_ready",
                                    {
                                        "current_url": current_url,
                                        "status": "browser_running",
                                        "external_actions": True,
                                    },
                                ),
                            ]
                            if (
                                self._credential_capturer is not None
                                and self._credential_validator is not None
                            ):
                                # M6: capture -> store -> validate -> bundle. Raw
                                # credentials never leave the adapters/vault; only
                                # vault references and sanitized metadata are stored.
                                credential_outcome = self._run_m6_credentials(research, request)
                                persisted_status = credential_outcome.status
                                persisted_reason = credential_outcome.reason_code
                                decision_event = (
                                    "configuration_required"
                                    if credential_outcome.status == "configuration_required"
                                    else "route_selected"
                                )
                                outreach_updates = {
                                    "browser_session_id": browser_session,
                                    "external_actions": credential_outcome.external_actions,
                                    "provider_status": {
                                        "research": "baseline_ready",
                                        "browser": "credential_page_ready",
                                        "email": "not_started",
                                        "validation": credential_outcome.validation_status
                                        or "configuration_required",
                                    },
                                }
                                if credential_outcome.bundle is not None:
                                    outreach_updates["integrator_bundle"] = (
                                        credential_outcome.bundle
                                    )
                                browser_events = [*base_browser_events, *credential_outcome.events]
                            else:
                                persisted_status = "browser_running"
                                browser_events = base_browser_events
                    elif persisted_status == "configuration_required":
                        decision_event = "configuration_required"
                        # Surface the truthful capability reason (for example a
                        # missing Gmail/browser adapter, verified recipient, or an
                        # ambiguous outcome) rather than the routing reason.
                        capabilities = workflow_state.get("capability_statuses")
                        if (
                            isinstance(capabilities, list)
                            and capabilities
                            and isinstance(capabilities[-1], Mapping)
                        ):
                            persisted_reason = str(
                                capabilities[-1].get("reason_code") or persisted_reason
                            )
                        outreach_updates = {
                            "provider_status": {
                                "research": "baseline_ready",
                                "browser": "not_started",
                                "email": "configuration_required",
                                "validation": "not_started",
                            },
                        }
                    elif persisted_status == "route_selected":
                        decision_event = "route_selected"
                    else:
                        decision_event = "route_pending"
            elif execution_mode == "execute_when_configured" and self._workflow is None:
                # The durable engine is not configured (no encryption key); report
                # the truthful state without performing any provider action.
                persisted_status = "configuration_required"
                decision_event = "configuration_required"

            _validate_created_projection(persisted_status)
            transaction.update_run(
                run_id,
                status=persisted_status,
                access_route=persisted_route,
                route_reason_code=persisted_reason,
                route_explanation=persisted_explanation,
                state_revision=1,
                last_projected_revision=1,
                **outreach_updates,
            )
            if capability_event is not None:
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="composio_capability_evaluated",
                    payload=capability_event,
                )
            transaction.append_audit_event(
                run_id=run_id,
                event_type=decision_event,
                payload={
                    # Route selection is a real completed phase even when this same
                    # transaction immediately dispatches the browser. Recording the
                    # later browser status here erased the route_selected hop from
                    # the evaluator timeline.
                    "status": (
                        "route_selected" if decision_event == "route_selected" else persisted_status
                    ),
                    "route": persisted_route,
                    "reason_code": persisted_reason,
                    "explanation": persisted_explanation,
                    "is_final": decision.is_final,
                    "unknown_probe_attempts": decision.unknown_probe_attempts,
                    "unknown_probe_remaining": decision.unknown_probe_remaining,
                    "external_actions": False,
                },
            )
            if outreach_event is not None:
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="outreach_sent",
                    payload=outreach_event,
                )
            if injected_login_source is not None:
                # Field NAMES and the source only, so the timeline proves the
                # agent signed itself in without recording any credential value.
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="login_credentials_injected",
                    payload={
                        "fields": list(injected_login_fields),
                        "source": injected_login_source,
                        "external_actions": True,
                    },
                )
            if login_remembered_fields:
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="login_credentials_remembered",
                    payload={
                        "fields": list(login_remembered_fields),
                        "external_actions": False,
                    },
                )
            for browser_event_type, browser_payload in browser_events:
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type=browser_event_type,
                    payload=browser_payload,
                )
            created = transaction.get_run(run_id)
            if created is None:  # pragma: no cover - persistence invariant
                raise RuntimeError("created run could not be read")
        # The creation transaction has committed here. Only now start the
        # background browser task, so its own transaction never races the
        # creation write and the run row is already queryable + streamable.
        if pending_async_navigate is not None:
            context, async_sensitive = pending_async_navigate
            self._spawn_async_browser(
                run_id,
                thread_id,
                request,
                research,
                context,
                async_sensitive,
            )
        elif persisted_status in _TERMINAL_BROWSER_STATUSES and not (
            persisted_status == "configuration_required"
            and observation_status in {"credential_page_ready", "developer_console_ready"}
        ):
            # A synchronous workflow may have created a Playwright session and
            # then failed before returning an observation. Release that terminal
            # session now instead of serving its blank frame until the janitor TTL.
            # A verified credential page remains attached for the existing owner
            # handoff even when capture/validation needs configuration.
            self._release_browser_session(
                self._session_context_for(run_id),
                request.browser_provider,
                reason=f"sync_terminal_{persisted_status}",
            )
        return _public_run(created)

    def _spawn_async_browser(
        self,
        run_id: str,
        thread_id: str,
        request: OperationsRequest,
        research: OperationalResearch,
        context: Any,
        sensitive_data: dict[str, str] | None,
    ) -> None:
        """Run the durable browser navigate for a run in a background thread."""

        thread = threading.Thread(
            target=self._run_async_browser,
            args=(run_id, thread_id, request, research, context, sensitive_data),
            name=f"browser-{run_id[:16]}",
            daemon=True,
        )
        self._browser_threads = [t for t in self._browser_threads if t.is_alive()]
        self._browser_threads.append(thread)
        thread.start()

    def _run_async_browser(
        self,
        run_id: str,
        thread_id: str,
        request: OperationsRequest,
        research: OperationalResearch,
        context: Any,
        sensitive_data: dict[str, str] | None,
    ) -> None:
        """Background worker: drive the durable navigate on the pre-created session.

        The session already exists (seeded into the workflow), so ``_browser_start``
        is a no-op and the bounded onboarding task runs against the live session.
        When the task pauses (HITL) or finishes, the terminal state is applied to
        the run so the frontend transitions from browser_running.
        """

        if self._workflow is None:  # pragma: no cover - guarded by caller
            return
        try:
            seed = {
                "browser_profile_id": context.profile_id,
                "browser_session_id": context.session_id,
                "browser_live_view_available": context.live_view_available,
                "browser_session_started_at": context.created_at,
                "browser_session_last_active_at": context.created_at,
                "browser_session_inactivity_expires_at": context.inactivity_expires_at,
                "browser_session_max_expires_at": context.maximum_expires_at,
            }
            workflow_state = self._workflow.start(
                request.model_copy(update={"dry_run": False}),
                thread_id=thread_id,
                sensitive_data=sensitive_data,
                research=research,
                seed=seed,
            )
        except Exception as exc:
            log_event(
                "browser.async.workflow_error",
                level=40,
                run_id=run_id,
                thread_id=thread_id,
                error=type(exc).__name__,
            )
            self._mark_async_browser_failed(run_id)
            # The run is terminal, so its pre-created session must not keep the
            # single Playwright slot until the idle sweep.
            self._release_browser_session(
                context, request.browser_provider, reason="async_workflow_error"
            )
            return
        finally:
            if sensitive_data is not None:
                sensitive_data.clear()
        try:
            self._apply_async_browser_result(run_id, thread_id, request, workflow_state, context)
        except Exception as exc:  # pragma: no cover - defensive
            self._release_browser_session(
                context, request.browser_provider, reason="async_apply_error"
            )
            log_event(
                "browser.async.apply_error",
                level=40,
                run_id=run_id,
                error=type(exc).__name__,
            )

    def _apply_async_browser_result(
        self,
        run_id: str,
        thread_id: str,
        request: OperationsRequest,
        workflow_state: Mapping[str, object],
        context: Any = None,
    ) -> None:
        """Transition a browser_running run based on the completed navigate."""

        observation = workflow_state.get("browser_observation")
        observation_status = (
            str(observation.get("status")) if isinstance(observation, Mapping) else None
        )
        wf_status = str(workflow_state.get("status") or "")
        current_url = workflow_state.get("current_url")
        outcome_fallback = {
            "blocked": "browser_navigation_blocked",
            "configuration_required": "browser_configuration_required",
            "failed": "browser_operation_failed",
        }.get(wf_status, "browser_operation_failed")
        outcome_reason = _browser_result_reason(workflow_state, outcome_fallback)
        try:
            interrupts = self._workflow.get_interrupts(thread_id) if self._workflow else ()
        except Exception:
            interrupts = ()
        waiting = (
            bool(interrupts)
            or observation_status == "human_action_required"
            or wf_status == "waiting_for_hitl"
        )

        lock = self._run_lock(run_id)
        with lock:
            record = self.storage.get_run(run_id)
            if record is None:
                self._release_browser_session(
                    context, request.browser_provider, reason="async_run_missing"
                )
                return
            previous = str(record.get("status") or "browser_running")
            if previous != "browser_running":
                # A resume or another writer already advanced the run; do not
                # clobber its state. If that writer made the run terminal, make
                # teardown idempotently certain here as well.
                log_event("browser.async.apply_skip", run_id=run_id, prev_status=previous)
                if previous in _TERMINAL_BROWSER_STATUSES:
                    self._release_browser_session(
                        context,
                        request.browser_provider,
                        reason=f"async_apply_skip_{previous}",
                    )
                return

            events: list[tuple[str, dict[str, object]]] = []
            extra_updates: dict[str, object] = {}
            hitl_payload: dict[str, object] | None = None
            provider_browser = "running"

            if waiting:
                next_status: RunStatus = "waiting_for_hitl"
                source = interrupts[0] if interrupts else workflow_state.get("hitl_request")
                if isinstance(source, Mapping):
                    hitl_payload = {str(k): v for k, v in source.items()}
                events.append(
                    (
                        "browser_hitl_required",
                        {
                            "status": "waiting_for_hitl",
                            "current_url": current_url,
                            "required_human_action": (
                                hitl_payload.get("type") if hitl_payload else None
                            ),
                            "external_actions": True,
                        },
                    )
                )
            elif wf_status == "blocked":
                next_status = "blocked"
                provider_browser = "blocked"
                events.append(
                    (
                        "browser_navigation_blocked",
                        {
                            "status": "blocked",
                            "reason_code": outcome_reason,
                            "external_actions": True,
                        },
                    )
                )
            elif wf_status == "failed":
                next_status = "failed"
                provider_browser = "failed"
                events.append(
                    (
                        "browser_navigation_failed",
                        {
                            "status": "failed",
                            "reason_code": outcome_reason,
                            "external_actions": True,
                        },
                    )
                )
            elif wf_status == "configuration_required" and observation_status not in {
                "credential_page_ready",
                "developer_console_ready",
            }:
                next_status = "configuration_required"
                provider_browser = "configuration_required"
                events.append(
                    (
                        "browser_navigation_failed",
                        {
                            "status": "configuration_required",
                            "reason_code": outcome_reason,
                            "external_actions": True,
                        },
                    )
                )
            elif observation_status in {"credential_page_ready", "developer_console_ready"}:
                events.append(
                    (
                        "credential_page_ready",
                        {
                            "current_url": current_url,
                            "status": "browser_running",
                            "external_actions": True,
                        },
                    )
                )
                research_obj: OperationalResearch | None = None
                if "operational_research" in workflow_state:
                    try:
                        research_obj = OperationalResearch.model_validate(
                            workflow_state["operational_research"]
                        )
                    except Exception:
                        research_obj = None

                # Hands-off deterministic capture: open a logged-in standalone
                # browser from the session profile and read the API token over
                # CDP (no human copy, no LLM read). Falls back to owner paste.
                captured_refs: dict[str, str] | None = None
                selected_worker = self._browser_worker_for(request.browser_provider)
                auto_capture = getattr(selected_worker, "auto_capture_credentials", None)
                if (
                    research_obj is not None
                    and callable(auto_capture)
                    and self._credential_validator is not None
                    and self._secret_store is not None
                ):
                    handle = str(workflow_state.get("browser_session_id") or "")
                    try:
                        captured_refs = asyncio.run(
                            auto_capture(handle, research_obj.app_slug, self._secret_store)
                        )
                    except Exception as exc:
                        log_event(
                            "browser.async.autocapture_error",
                            level=40,
                            run_id=run_id,
                            error=type(exc).__name__,
                        )
                        captured_refs = None

                if (
                    captured_refs
                    and research_obj is not None
                    and self._credential_validator is not None
                ):
                    outcome = self._finalize_captured_credentials(
                        research_obj, request, captured_refs
                    )
                    next_status = cast(RunStatus, outcome.status)
                    provider_browser = "credential_page_ready"
                    if outcome.bundle is not None:
                        extra_updates["integrator_bundle"] = outcome.bundle
                    events.extend(outcome.events)
                elif (
                    self._credential_capturer is not None
                    and self._credential_validator is not None
                    and research_obj is not None
                ):
                    try:
                        outcome = self._run_m6_credentials(research_obj, request)
                        next_status = cast(RunStatus, outcome.status)
                        provider_browser = "credential_page_ready"
                        if outcome.bundle is not None:
                            extra_updates["integrator_bundle"] = outcome.bundle
                        events.extend(outcome.events)
                    except Exception as exc:  # pragma: no cover - defensive
                        log_event(
                            "browser.async.m6_error",
                            level=40,
                            run_id=run_id,
                            error=type(exc).__name__,
                        )
                        next_status = "browser_running"
                else:
                    next_status = "browser_running"
            else:
                next_status = "browser_running"

            with self.storage.unit_of_work() as transaction:
                rec = transaction.get_run(run_id)
                if rec is None:  # pragma: no cover
                    self._release_browser_session(
                        context, request.browser_provider, reason="async_transaction_run_missing"
                    )
                    return
                revision = int(rec.get("state_revision", 0) or 0) + 1
                if previous != next_status:
                    if next_status == "completed":
                        # Capture and read-only validation completed the two legal
                        # domain hops in this one atomic projection. Validate both;
                        # a direct browser_running -> completed transition is illegal
                        # and previously stranded successful runs during apply.
                        validate_status_transition(
                            cast(RunStatus, previous), "credentials_ready", "browser"
                        )
                        validate_status_transition("credentials_ready", "completed", "browser")
                    else:
                        validate_status_transition(
                            cast(RunStatus, previous), next_status, "browser"
                        )
                changes: dict[str, object] = {
                    "status": next_status,
                    "state_revision": revision,
                    "last_projected_revision": revision,
                    "external_actions": True,
                    "hitl_request": hitl_payload,
                    "provider_status": {
                        "research": "baseline_ready",
                        "browser": provider_browser,
                        "email": "not_started",
                        "validation": "not_started",
                    },
                    **extra_updates,
                }
                transaction.update_run(run_id, **changes)
                for event_type, payload in events:
                    transaction.append_audit_event(
                        run_id=run_id, event_type=event_type, payload=payload
                    )
        preserve_owner_handoff = next_status == "configuration_required" and observation_status in {
            "credential_page_ready",
            "developer_console_ready",
        }
        if not preserve_owner_handoff:
            self._stop_terminal_playwright_session(
                context,
                next_status,
                request.browser_provider,
            )
        log_event("browser.async.applied", run_id=run_id, status=next_status)

    def _stop_terminal_playwright_session(
        self,
        context: Any,
        next_status: RunStatus,
        provider: BrowserProvider,
    ) -> None:
        """Close a self-hosted browser session once the run reaches a terminal state.

        A Playwright session is a real local Chromium process, so leaving it running
        after a terminal outcome leaks memory on a small VPS. Sessions are kept only
        while a run genuinely still needs the browser (``waiting_for_hitl`` for the
        human, or ``browser_running`` while the action loop is active).

        Deliberately Playwright-only: Browser Use has its own cleanup and
        reconciliation semantics (its sessions are intentionally retained for
        inspection), so this branch must never stop them.
        """

        if next_status not in _TERMINAL_BROWSER_STATUSES:
            return
        self._release_browser_session(
            context,
            provider,
            reason=f"async_terminal_{next_status}",
        )

    def _release_browser_session(
        self,
        context: Any,
        provider: BrowserProvider,
        *,
        reason: str,
    ) -> None:
        """Release a self-hosted browser session for a run that is finished.

        Idempotent and never fatal: the browser service's own close is idempotent,
        so a duplicate call is a no-op. Every TERMINAL path must come through here,
        because a Playwright deployment runs a single-session display: a slot left
        held by a finished run makes the NEXT run fail with capacity_exhausted
        until the idle sweep eventually notices.
        """

        worker = self._browser_worker_for(provider)
        if context is None or worker is None:
            return
        if str(getattr(worker, "provider_name", "browser_use")) != "playwright":
            # Browser Use owns its own retention/reconciliation semantics.
            return
        try:
            asyncio.run(worker.stop(context))
        except Exception:
            log_event("browser.session.release_error", level=30, reason=reason)
        else:
            log_event("browser.session.released", reason=reason)

    def _session_context_for(self, run_id: str) -> Any:
        """A minimal session handle for a persisted run, or None.

        Teardown only needs the session id, so this avoids reconstructing worker
        state that no longer exists after a restart.
        """

        record = self.storage.get_run(run_id)
        if record is None:
            return None
        session_id = record.get("browser_session_id")
        if not isinstance(session_id, str) or not session_id:
            return None
        return BrowserSessionContext(
            profile_id=session_id,
            session_id=session_id,
            live_view_available=False,
            allowed_domains=(),
            created_at="",
            inactivity_expires_at="",
            maximum_expires_at="",
        )

    def _mark_async_browser_failed(self, run_id: str) -> None:
        """Best-effort transition of a stuck browser_running run to failed."""

        try:
            lock = self._run_lock(run_id)
            with lock:
                record = self.storage.get_run(run_id)
                if record is None or str(record.get("status")) != "browser_running":
                    return
                with self.storage.unit_of_work() as transaction:
                    rec = transaction.get_run(run_id)
                    if rec is None:
                        return
                    revision = int(rec.get("state_revision", 0) or 0) + 1
                    validate_status_transition("browser_running", "failed", "browser")
                    transaction.update_run(
                        run_id,
                        status="failed",
                        state_revision=revision,
                        last_projected_revision=revision,
                        external_actions=True,
                    )
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="browser_failed",
                        payload={"status": "failed", "external_actions": True},
                    )
        except Exception:  # pragma: no cover - defensive
            pass

    def _run_enrichment_probe(
        self,
        record: P1AppRecord,
        baseline: OperationalResearch,
    ) -> ResearchEnrichmentOutcome:
        """Run the single bounded enrichment probe synchronously.

        ``create_run`` is synchronous and, at the API boundary, is dispatched in
        a worker thread with no running event loop, so ``asyncio.run`` is safe
        and mirrors the durable workflow's async-invocation pattern.
        """

        if self._enricher is None:  # pragma: no cover - guarded by the caller
            raise RuntimeError("no research enricher is configured")
        try:
            return asyncio.run(
                self._enricher.enrich(
                    app_name=baseline.app_name,
                    p1_record=record.model_dump(mode="json"),
                    baseline=baseline,
                )
            )
        except (TypeError, AttributeError, ImportError, ModuleNotFoundError, NameError):
            # A broken integration (wrong kwarg, renamed SDK attribute, missing
            # module) must reach monitoring/tests, not be silently degraded to a
            # provider outage. It may surface as a sanitized HTTP 500 upstream.
            raise
        except Exception:
            # An EXPECTED provider/transport/extraction/validation failure must
            # never turn an otherwise valid run request into an untyped HTTP 500.
            # Preserve the verified P1 baseline and expose only a stable reason.
            return ResearchEnrichmentOutcome(
                research=baseline,
                capability=CapabilityAvailability(
                    capability="operational_research",
                    status="failed",
                    reason_code="official_evidence_provider_failed",
                    detail=(
                        "Official-evidence enrichment did not complete; the verified "
                        "P1 baseline was retained."
                    ),
                ),
                missing_fields=_missing_operational_fields(baseline.model_dump(mode="json")),
                documents_fetched=0,
            )

    def _run_capability_preflight(self, app_slug: str, app_name: str) -> ComposioCapabilityReport:
        """Evaluate Composio capability once, synchronously, with no side effect."""

        if self._capability_preflight is None:  # pragma: no cover - guarded by the caller
            raise RuntimeError("no capability preflight is configured")
        return asyncio.run(
            self._capability_preflight.evaluate(app_name=app_name, app_slug=app_slug)
        )

    def _run_m6_credentials(
        self,
        research: OperationalResearch,
        request: OperationsRequest,
    ) -> _CredentialOutcome:
        """Capture -> store -> validate -> bundle, returning only sanitized metadata.

        Raw credentials exist only inside the injected capture/validation adapters
        and the encrypted vault; this method handles vault references and
        sanitized validation metadata only.
        """

        capturer = self._credential_capturer
        validator = self._credential_validator
        if capturer is None or validator is None:  # pragma: no cover - guarded by caller
            raise RuntimeError("credential adapters are not configured")

        events: list[tuple[str, dict[str, object]]] = [
            (
                "credential_capture_started",
                {"app_slug": research.app_slug, "external_actions": True},
            )
        ]
        try:
            captured = asyncio.run(
                capturer.capture(app_slug=research.app_slug, app_name=research.app_name)
            )
        except ConfigurationRequiredError as exc:
            return _CredentialOutcome(
                status="configuration_required",
                reason_code=exc.reason_code,
                validation_status=None,
                bundle=None,
                external_actions=False,
                events=events,
            )
        references = {kind: validate_vault_reference(ref) for kind, ref in captured.items()}
        events.append(
            (
                "credentials_stored",
                {
                    "kinds": sorted(references),
                    "references": dict(sorted(references.items())),
                    "external_actions": True,
                },
            )
        )
        events.append(
            (
                "credential_validation_started",
                {"app_slug": research.app_slug, "external_actions": True},
            )
        )
        try:
            result = asyncio.run(
                validator.validate(app_slug=research.app_slug, credential_refs=references)
            )
        except ConfigurationRequiredError as exc:
            return _CredentialOutcome(
                status="configuration_required",
                reason_code=exc.reason_code,
                validation_status=None,
                bundle=None,
                external_actions=True,
                events=events,
            )
        events.append(
            (
                "credentials_validated",
                {
                    "validation_status": result.status,
                    "reason_code": result.reason_code,
                    "http_status": result.http_status,
                    "endpoint": result.endpoint,
                    "external_actions": True,
                },
            )
        )
        bundle = build_integrator_bundle(
            research=research,
            company=request.company,
            credential_refs=references,
            validation=result,
            stage="normal",
        )
        events.append(
            (
                "integrator_bundle_generated",
                {
                    "readiness": bundle.readiness,
                    "auth_scheme": bundle.auth_scheme,
                    "scopes": list(bundle.scopes),
                    "credential_ref_count": len(bundle.credential_refs),
                    "external_actions": True,
                },
            )
        )
        if result.status == "valid":
            status = "completed"
            reason_code = result.reason_code
        elif result.status == "invalid":
            status = "configuration_required"
            reason_code = result.reason_code
        else:
            # unavailable / failed: the true credential state is ambiguous. There is
            # no outcome_unknown RunStatus, so the run rests at configuration_required
            # with a truthful reason while the ambiguous validation status is recorded.
            status = "configuration_required"
            reason_code = "validation_outcome_unknown"
        if status == "completed":
            events.extend(
                [
                    (
                        "credentials_ready",
                        {"status": "credentials_ready", "external_actions": True},
                    ),
                    (
                        "run_completed",
                        {"status": "completed", "external_actions": True},
                    ),
                ]
            )
        return _CredentialOutcome(
            status=status,
            reason_code=reason_code,
            validation_status=result.status,
            bundle=bundle.model_dump(mode="json"),
            external_actions=True,
            events=events,
        )

    def _finalize_captured_credentials(
        self,
        research: OperationalResearch,
        request: OperationsRequest,
        captured: Mapping[str, str],
    ) -> _CredentialOutcome:
        """Validate deterministically-captured vault refs and build the bundle.

        The raw credential was read over CDP and vaulted by the browser worker;
        here only the ``vault://`` references, read-only validation metadata, and
        the reference-only bundle are handled — never a raw value.
        """

        validator = self._credential_validator
        if validator is None:  # pragma: no cover - guarded by caller
            raise RuntimeError("credential validator is not configured")
        references = {kind: validate_vault_reference(ref) for kind, ref in captured.items()}
        events: list[tuple[str, dict[str, object]]] = [
            (
                "credentials_stored",
                {
                    "kinds": sorted(references),
                    "references": dict(sorted(references.items())),
                    "external_actions": True,
                },
            ),
            (
                "credential_validation_started",
                {"app_slug": research.app_slug, "external_actions": True},
            ),
        ]
        try:
            result = asyncio.run(
                validator.validate(app_slug=research.app_slug, credential_refs=references)
            )
        except ConfigurationRequiredError as exc:
            return _CredentialOutcome(
                status="configuration_required",
                reason_code=exc.reason_code,
                validation_status=None,
                bundle=None,
                external_actions=True,
                events=events,
            )
        events.append(
            (
                "credentials_validated",
                {
                    "validation_status": result.status,
                    "reason_code": result.reason_code,
                    "http_status": result.http_status,
                    "endpoint": result.endpoint,
                    "external_actions": True,
                },
            )
        )
        bundle = build_integrator_bundle(
            research=research,
            company=request.company,
            credential_refs=references,
            validation=result,
            stage="normal",
        )
        events.append(
            (
                "integrator_bundle_generated",
                {
                    "readiness": bundle.readiness,
                    "auth_scheme": bundle.auth_scheme,
                    "scopes": list(bundle.scopes),
                    "credential_ref_count": len(bundle.credential_refs),
                    "external_actions": True,
                },
            )
        )
        if result.status == "valid":
            status: RunStatus = "completed"
            reason_code = result.reason_code
        elif result.status == "invalid":
            status = "configuration_required"
            reason_code = result.reason_code
        else:
            status = "configuration_required"
            reason_code = "validation_outcome_unknown"
        if status == "completed":
            events.extend(
                [
                    (
                        "credentials_ready",
                        {"status": "credentials_ready", "external_actions": True},
                    ),
                    (
                        "run_completed",
                        {"status": "completed", "external_actions": True},
                    ),
                ]
            )
        return _CredentialOutcome(
            status=status,
            reason_code=reason_code,
            validation_status=result.status,
            bundle=bundle.model_dump(mode="json"),
            external_actions=True,
            events=events,
        )

    def _record_verified_research(
        self,
        transaction: OperationsUnitOfWork,
        run_id: str,
        lookup: P1LookupFound,
        research: Mapping[str, object],
    ) -> None:
        record = lookup.record
        transaction.append_audit_event(
            run_id=run_id,
            event_type="p1_snapshot_loaded",
            payload={
                "status": "found",
                "source": "verified_p1_snapshot",
                "matched_by": lookup.matched_by,
                "api_type": record.api_type,
                "auth_methods": record.auth_methods,
                "access_model": record.access_model.kind,
                "buildability": record.buildability,
                "verification_status": record.verification_status,
                "confidence": record.confidence,
                "evidence_count": len(record.evidence_urls),
                "primary_docs_url": record.primary_docs_url,
                "external_actions": False,
            },
        )
        transaction.append_audit_event(
            run_id=run_id,
            event_type="operational_research_built",
            payload={
                "status": "baseline_complete",
                "source": "verified_p1_snapshot",
                "missing_fields": _missing_operational_fields(research),
                "evidence_count": len(cast(list[object], research.get("evidence_urls", []))),
                "external_actions": False,
            },
        )

    def list_runs(self, *, limit: int = 50, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
        return self._queries.list_runs(limit=limit, offset=offset)

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        return self._queries.get_run(run_id)

    def get_timeline(self, run_id: str) -> list[dict[str, Any]]:
        return self._queries.get_timeline(run_id)

    def get_research(self, run_id: str) -> OperationalResearch | None:
        """Return the persisted sanitized research projection for a run."""

        return self._queries.get_research(run_id)

    def search_apps(self, query: str, *, limit: int = 20) -> list[dict[str, Any]]:
        """Search the verified P1 catalog and return a minimal safe projection."""

        return self._queries.search_apps(query, limit=limit)

    def list_apps(self) -> list[dict[str, Any]]:
        """Return EVERY verified app, so the interface can offer a real choice."""

        return self._queries.list_apps()

    def get_app_research(self, app_slug: str) -> tuple[dict[str, Any], OperationalResearch] | None:
        """Return a verified app summary and its conservative operational baseline."""

        return self._queries.get_app_research(app_slug)

    def get_output(self, run_id: str) -> dict[str, Any] | None:
        return self._queries.get_output(run_id)

    def reveal_credentials(self, run_id: str) -> dict[str, str] | None:
        """Owner-only raw credential reveal resolved live from the encrypted vault."""

        return self._queries.reveal_credentials(run_id)

    def project(
        self,
        run_id: str,
        state: Mapping[str, object],
        revision: int,
        *,
        command: str = "workflow",
    ) -> dict[str, Any]:
        """Idempotently project durable graph state into the sanitized ledger.

        A revision equal to or lower than the last projected revision is a
        no-op: no status is rewritten and no audit event is appended. Every
        status write first passes the single ``validate_status_transition``
        authority. The operations ledger remains a derived projection and never
        overrides the checkpoint.
        """

        with self.storage.unit_of_work() as transaction:
            result = self._apply_projection(transaction, run_id, state, revision, command)
            projected = _public_run(result)
        projected_status = str(result.get("status") or "")
        if projected_status in _TERMINAL_BROWSER_STATUSES:
            self._release_browser_session(
                self._session_context_for(run_id),
                cast(BrowserProvider, result.get("browser_provider", "browser_use")),
                reason=f"project_{projected_status}",
            )
        return projected

    def _apply_projection(
        self,
        transaction: OperationsUnitOfWork,
        run_id: str,
        state: Mapping[str, object],
        revision: int,
        command: str,
    ) -> dict[str, Any]:
        current = transaction.get_run(run_id)
        if current is None:
            raise KeyError("run was not found")
        last_projected = int(current.get("last_projected_revision", 0) or 0)
        if revision <= last_projected:
            return current
        previous_status = cast(RunStatus, current["status"])
        next_status = cast(RunStatus, state.get("status") or previous_status)
        validate_status_transition(previous_status, next_status, command)
        changes: dict[str, object] = {
            "status": next_status,
            "state_revision": revision,
            "last_projected_revision": revision,
        }
        access_route = state.get("access_route")
        if access_route is not None:
            changes["access_route"] = access_route
        route_reason_code = state.get("route_reason_code")
        if route_reason_code is not None:
            changes["route_reason_code"] = route_reason_code
        route_reason = state.get("route_reason")
        if route_reason is not None:
            changes["route_explanation"] = route_reason
        research = state.get("operational_research")
        if isinstance(research, Mapping):
            changes["operational_research"] = dict(research)
        missing = state.get("missing_fields")
        if isinstance(missing, list):
            changes["missing_fields"] = list(missing)
        updated = transaction.update_run(run_id, **changes)
        transaction.append_audit_event(
            run_id=run_id,
            event_type="state_projected",
            payload={
                "status": next_status,
                "revision": revision,
                "external_actions": False,
            },
        )
        return updated

    def _run_lock(self, run_id: str) -> threading.RLock:
        with self._run_locks_guard:
            return self._run_locks.setdefault(run_id, threading.RLock())

    def guarded_status_update(
        self,
        run_id: str,
        *,
        expected_revision: int,
        next_status: RunStatus,
        command: str,
        **changes: object,
    ) -> dict[str, Any]:
        """Apply one mutating command under per-run serialization.

        Competing commands are rejected with ``RunConflictError`` (surfaced as
        HTTP 409) without any partial write or external action. Concurrency is
        guarded by a per-run lock plus an optimistic ``state_revision`` check.
        """

        lock = self._run_lock(run_id)
        if not lock.acquire(blocking=False):
            raise RunConflictError(run_id, command)
        try:
            with self.storage.unit_of_work() as transaction:
                current = transaction.get_run(run_id)
                if current is None:
                    raise KeyError("run was not found")
                if int(current.get("state_revision", 0) or 0) != expected_revision:
                    raise RunConflictError(run_id, command)
                previous_status = cast(RunStatus, current["status"])
                validate_status_transition(previous_status, next_status, command)
                new_revision = expected_revision + 1
                updated = transaction.update_run(
                    run_id,
                    status=next_status,
                    state_revision=new_revision,
                    last_projected_revision=new_revision,
                    **changes,
                )
                projected = _public_run(updated)
                release_provider = cast(
                    BrowserProvider, updated.get("browser_provider", "browser_use")
                )
        finally:
            lock.release()
        if next_status in _TERMINAL_BROWSER_STATUSES:
            self._release_browser_session(
                self._session_context_for(run_id),
                release_provider,
                reason=f"guarded_status_{next_status}",
            )
        return projected

    def get_browser_screenshot(self, run_id: str) -> tuple[bytes, str] | None:
        """Return the newest masked screenshot for a run's browser session."""

        return self._live_view.get_browser_screenshot(run_id)

    def get_browser_interactive_grant(self, run_id: str) -> tuple[str, str, str] | None:
        """Mint an ephemeral Playwright grant only for an active human handoff."""

        return self._live_view.get_browser_interactive_grant(run_id)

    def get_browser_live_url(self, run_id: str) -> str | None:
        """Return the ephemeral signed live-view URL for a run, if one is active."""

        return self._live_view.get_browser_live_url(run_id)

    def _public_no_reply(self, record: Mapping[str, object]) -> dict[str, Any]:
        """Return the current run projection with a no-op reply marker."""

        public = _public_run(record)
        public["latest_reply_class"] = "no_reply"
        public["follow_up_sent"] = False
        return public

    def _company_from_checkpoint(self, thread_id: str) -> CompanyProfile | None:
        """Read the run's company profile from the durable workflow checkpoint.

        Used to give the Gemini reply assistant the real, non-secret company
        facts. Returns None when the checkpoint is unavailable, in which case the
        loop falls back to the deterministic classifier.
        """

        if self._workflow is None or not thread_id:
            return None
        try:
            state = self._workflow.get_state(thread_id)
        except Exception:
            return None
        request_payload = state.get("request")
        if not isinstance(request_payload, Mapping):
            return None
        try:
            return OperationsRequest.model_validate(dict(request_payload)).company
        except Exception:
            return None

    def _email_credentials_bundle_change(
        self,
        record: Mapping[str, object],
        company: CompanyProfile | None,
        credential_refs: dict[str, str],
    ) -> dict[str, object]:
        """Merge emailed credential references into the run's reference-only bundle.

        If a bundle already exists, the new ``vault://`` references are merged in.
        When none exists yet and verified research + company are available, a
        reference-only IntegratorBundle is built so the developer still receives a
        usable handoff. Best-effort: any failure leaves the run completed without a
        bundle rather than breaking the email poll.
        """

        existing_bundle = record.get("integrator_bundle")
        if isinstance(existing_bundle, Mapping):
            merged: dict[str, object] = dict(existing_bundle)
            current_refs = merged.get("credential_refs")
            refs: dict[str, str] = (
                {str(k): str(v) for k, v in current_refs.items()}
                if isinstance(current_refs, Mapping)
                else {}
            )
            refs.update(credential_refs)
            merged["credential_refs"] = refs
            return {"integrator_bundle": merged}
        research_payload = record.get("operational_research")
        if company is None or not isinstance(research_payload, Mapping):
            return {}
        try:
            research = OperationalResearch.model_validate(dict(research_payload))
            bundle = build_integrator_bundle(
                research=research,
                company=company,
                credential_refs=credential_refs,
                validation=None,
                stage="awaiting_provider",
            )
            return {"integrator_bundle": bundle.model_dump(mode="json")}
        except Exception:
            return {}

    def poll_email(self, run_id: str) -> dict[str, Any]:
        """Fetch the outreach thread, classify the latest reply, and advance.

        Closes the gated-outreach loop: reads the Gmail thread by its persisted
        thread id, sanitizes and classifies the latest reply (offline), records a
        sanitized reply event, and moves the run forward. For a "more information
        required" reply it sends one bounded follow-up reply (up to
        ``max_outreach_rounds``) so the back-and-forth continues. Credentials in a
        reply are stored as vault references only; rejections block the run.
        """

        from ops.reply_classifier import ReplyClassifier

        if self._gmail_worker is None:
            raise CredentialSubmissionError("gmail_not_configured")
        settings = self._settings or Settings.from_env()
        lock = self._run_lock(run_id)
        if not lock.acquire(blocking=False):
            raise RunConflictError(run_id, "poll_email")
        try:
            current = self.storage.get_run(run_id)
            if current is None:
                raise KeyError("run was not found")
            if current["status"] not in {"waiting_for_reply", "outreach_sent"}:
                raise CredentialSubmissionError("run_not_awaiting_reply")
            thread_id = current.get("gmail_thread_id")
            if not isinstance(thread_id, str) or not thread_id:
                raise CredentialSubmissionError("gmail_thread_missing")
            app_name = str(current.get("app_name") or "")

            from ops.email_ai import build_email_assistant

            thread = asyncio.run(self._gmail_worker.fetch_thread(thread_id))
            # The vendor (inbound) messages come from the address we correspond
            # with (the controlled recipient); our own outreach/follow-ups do not.
            # Act only on the latest, not-yet-processed inbound reply so repeated
            # background polling is a safe no-op (no timeline spam, no resend).
            counterpart = (settings.outreach_recipient_override or "").casefold()
            inbound = None
            rounds = 0
            for message in thread.messages:
                if counterpart and counterpart in message.sender.casefold():
                    inbound = message
                    rounds += 1
            if inbound is None or self._last_processed_reply.get(run_id) == inbound.message_id:
                return self._public_no_reply(current)
            reply_text = _strip_quoted_reply(inbound.sanitized_body)

            heuristic = asyncio.run(
                ReplyClassifier().classify(app_name=app_name, sanitized_thread=thread)
            )
            cls = heuristic.classification
            ai_reply_body: str | None = None
            classified_by = "heuristic"
            assistant = build_email_assistant(settings)
            company = self._company_from_checkpoint(str(current.get("thread_id") or ""))
            if reply_text and assistant is not None and company is not None:
                try:
                    ai = assistant.analyze_reply(
                        app_name=app_name, company=company, reply_text=reply_text
                    )
                    cls = ai.classification
                    ai_reply_body = (ai.reply_body or "").strip() or None
                    classified_by = "llm"
                except Exception:
                    classified_by = "heuristic"

            next_status: RunStatus = "waiting_for_reply"
            follow_up_sent = False
            credential_refs = {
                f"email_secret_{index + 1}": reference
                for index, reference in enumerate(thread.credential_refs)
            }
            if cls == "credentials_received" and credential_refs:
                next_status = "credentials_ready"
            elif cls == "rejected":
                next_status = "blocked"
            elif cls in {"more_information_required", "meeting_requested"} and (
                rounds <= settings.max_outreach_rounds
            ):
                follow_up_body = ai_reply_body or (
                    "Thank you for the quick response. To help us proceed with the API "
                    "integration, we have shared the requested details above and remain "
                    "available for any further information. Could you confirm the developer "
                    "access and credential issuance steps for production?"
                )
                try:
                    asyncio.run(
                        self._gmail_worker.reply(
                            thread_id,
                            follow_up_body,
                            idempotency_key=f"{run_id}:followup-{inbound.message_id}",
                        )
                    )
                    follow_up_sent = True
                except (ProviderContractError, ProviderOperationError):
                    follow_up_sent = False

            # Mark this inbound reply handled so subsequent polls do not reprocess.
            self._last_processed_reply[run_id] = inbound.message_id

            with self.storage.unit_of_work() as transaction:
                record = transaction.get_run(run_id)
                if record is None:  # pragma: no cover - re-checked under lock
                    raise KeyError("run was not found")
                revision = int(record.get("state_revision", 0) or 0) + 1
                previous_status = cast(RunStatus, record["status"])
                changes: dict[str, object] = {
                    "state_revision": revision,
                    "last_projected_revision": revision,
                    "external_actions": True,
                }
                if next_status == "credentials_ready" and credential_refs:
                    # Credentials arrived by email. Advance through the two legal
                    # hops (-> credentials_ready -> completed) so the gated/email
                    # path terminates instead of dead-ending at credentials_ready
                    # with no forward action (the only other credentials_ready ->
                    # completed edge requires a browser_running submit). The emailed
                    # vault references are merged into the reference-only bundle.
                    validate_status_transition(previous_status, "credentials_ready", "poll_email")
                    validate_status_transition("credentials_ready", "completed", "poll_email")
                    changes["status"] = "completed"
                    changes.update(
                        self._email_credentials_bundle_change(record, company, credential_refs)
                    )
                else:
                    validate_status_transition(previous_status, next_status, "poll_email")
                    changes["status"] = next_status
                updated = transaction.update_run(run_id, **changes)
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="reply_received",
                    payload={
                        "classification": cls,
                        "classified_by": classified_by,
                        "message_count": len(thread.messages),
                        "official_setup_urls": list(heuristic.official_setup_urls),
                        "required_next_action": heuristic.required_next_action,
                        "follow_up_sent": follow_up_sent,
                        "rounds": rounds,
                        "external_actions": True,
                    },
                )
                public = _public_run(updated)
                # Non-persisted, non-secret classification for the caller's receipt.
                public["latest_reply_class"] = cls
                public["follow_up_sent"] = follow_up_sent
                return public
        finally:
            lock.release()

    def resume_run(
        self,
        run_id: str,
        *,
        signal: str = "completed",
        browser_login: Mapping[str, SecretStr] | None = None,
    ) -> dict[str, Any]:
        """Resume a waiting_for_hitl run on the SAME browser session/thread.

        Continues the durable workflow through the existing thread id (no new
        session is created), then projects the resumed state. A repeated
        interrupt keeps the run at waiting_for_hitl with a refreshed instruction;
        a cleared path advances toward the credential page.

        When ``browser_login`` is supplied (owner-only, loopback), its raw values
        are resolved in-memory ONLY for the single ``workflow.resume`` call and
        injected through the selected provider's one-time secret boundary so the
        agent logs in autonomously. The raw values are never written to run state,
        checkpoints, audit events, or logs, and are dropped as soon as resume
        returns; only the non-secret field names are recorded.
        """

        if self._workflow is None:
            raise CredentialSubmissionError("workflow_not_configured")
        lock = self._run_lock(run_id)
        if not lock.acquire(blocking=False):
            raise RunConflictError(run_id, "resume")
        try:
            current = self.storage.get_run(run_id)
            if current is None:
                raise KeyError("run was not found")
            if current["status"] != "waiting_for_hitl":
                raise CredentialSubmissionError("run_not_waiting_for_hitl")
            thread_id = str(current.get("thread_id") or run_id)
            app_slug = str(current.get("app_slug") or "unknown")
            remembered_fields: tuple[str, ...] = ()
            if browser_login:
                # Remember the owner's sign-in credentials so the NEXT resume (or
                # the next run) can authenticate without asking again.
                remembered_fields = self._remember_reusable_login(
                    app_slug=app_slug, values=browser_login
                )
            login_values: Mapping[str, SecretStr] | None = browser_login
            login_source = "owner_supplied"
            if not login_values and signal != "cancelled":
                # Autonomy: a login gate we already hold credentials for must be
                # resolved by the agent, not by asking the human a second time.
                reusable = self._reusable_login_values(app_slug)
                if reusable:
                    login_values = reusable
                    login_source = "vault_reuse"
            injected_login_fields: list[str] = sorted(login_values) if login_values else []
            sensitive_data: dict[str, str] | None = None
            if login_values:
                sensitive_data = self._browser_login_payload(
                    provider=cast(
                        BrowserProvider,
                        current.get("browser_provider", "browser_use"),
                    ),
                    app_slug=app_slug,
                    scope_id=run_id,
                    values=login_values,
                )
            try:
                state = self._workflow.resume(thread_id, signal, sensitive_data=sensitive_data)
            finally:
                # Drop the resolved raw values as soon as resume returns.
                if sensitive_data is not None:
                    sensitive_data.clear()
                    sensitive_data = None
            interrupts = self._workflow.get_interrupts(thread_id)

            observation = state.get("browser_observation")
            observation_status = (
                str(observation.get("status")) if isinstance(observation, Mapping) else None
            )
            current_url = state.get("current_url")
            still_blocked = bool(interrupts) or observation_status == "human_action_required"
            next_status: RunStatus
            capture_events: list[tuple[str, dict[str, object]]] = []
            capture_updates: dict[str, object] = {}
            provider_browser = "running"
            validation_status = "not_started"

            if signal == "cancelled":
                next_status = "blocked"
                provider_browser = "blocked"
            elif still_blocked:
                next_status = "waiting_for_hitl"
            elif observation_status in {"credential_page_ready", "developer_console_ready"}:
                next_status = "browser_running"
                provider_browser = "credential_page_ready"
                capture_events.append(
                    (
                        "credential_page_ready",
                        {
                            "current_url": current_url,
                            "status": "browser_running",
                            "external_actions": True,
                        },
                    )
                )
                research_payload = state.get("operational_research")
                if not isinstance(research_payload, Mapping):
                    research_payload = current.get("operational_research")
                request_payload = state.get("request")
                try:
                    research_obj = OperationalResearch.model_validate(research_payload)
                    request_obj = OperationsRequest.model_validate(request_payload)
                except Exception:
                    research_obj = None
                    request_obj = None

                selected_worker = self._browser_worker_for(
                    cast(BrowserProvider, current.get("browser_provider", "browser_use"))
                )
                auto_capture = getattr(selected_worker, "auto_capture_credentials", None)
                captured_refs: dict[str, str] | None = None
                if (
                    research_obj is not None
                    and request_obj is not None
                    and callable(auto_capture)
                    and self._credential_validator is not None
                    and self._secret_store is not None
                ):
                    capture_events.append(
                        (
                            "credential_capture_started",
                            {
                                "app_slug": research_obj.app_slug,
                                "external_actions": True,
                            },
                        )
                    )
                    handle = str(
                        state.get("browser_session_id") or current.get("browser_session_id") or ""
                    )
                    try:
                        captured_refs = asyncio.run(
                            auto_capture(handle, research_obj.app_slug, self._secret_store)
                        )
                    except Exception as exc:
                        log_event(
                            "browser.resume.autocapture_error",
                            level=40,
                            run_id=run_id,
                            error=type(exc).__name__,
                        )
                        next_status = "configuration_required"
                        validation_status = "configuration_required"
                        capture_updates["route_reason_code"] = "credential_capture_failed"
                        capture_events.append(
                            (
                                "credential_capture_failed",
                                {
                                    "reason_code": "credential_capture_failed",
                                    "external_actions": True,
                                },
                            )
                        )

                if captured_refs and research_obj is not None and request_obj is not None:
                    try:
                        outcome = self._finalize_captured_credentials(
                            research_obj, request_obj, captured_refs
                        )
                    except Exception as exc:
                        log_event(
                            "browser.resume.credential_finalization_error",
                            level=40,
                            run_id=run_id,
                            error=type(exc).__name__,
                        )
                        # Finalization never persisted these refs. Remove the
                        # just-captured entries best-effort so an unexpected
                        # validator/bundle error cannot leave unreachable vault
                        # rows behind.
                        store = self._secret_store
                        if store is not None:
                            for reference in captured_refs.values():
                                with contextlib.suppress(Exception):
                                    store.delete(reference)
                        next_status = "configuration_required"
                        validation_status = "configuration_required"
                        capture_updates["route_reason_code"] = "credential_finalization_failed"
                        capture_events.append(
                            (
                                "credential_finalization_failed",
                                {
                                    "reason_code": "credential_finalization_failed",
                                    "external_actions": True,
                                },
                            )
                        )
                    else:
                        next_status = cast(RunStatus, outcome.status)
                        validation_status = outcome.validation_status or "configuration_required"
                        capture_updates["route_reason_code"] = outcome.reason_code
                        if outcome.bundle is not None:
                            capture_updates["integrator_bundle"] = outcome.bundle
                        capture_events.extend(outcome.events)
            elif observation_status in {"blocked", "failed"}:
                # A resume that ends blocked/failed must say so. Projecting these as
                # ``browser_running`` parked the run permanently: nothing drives a
                # browser_running run (the advancer only sweeps waiting_for_hitl,
                # retry records no action, and the UI offers no resume), so the run
                # held the single browser slot until the next API restart.
                next_status = "blocked" if observation_status == "blocked" else "failed"
                provider_browser = next_status
                capture_updates["route_reason_code"] = _browser_result_reason(
                    state, f"browser_resume_{observation_status}"
                )
                capture_events.append(
                    (
                        "browser_resume_terminal",
                        {
                            "status": next_status,
                            "reason_code": capture_updates["route_reason_code"],
                            "external_actions": True,
                        },
                    )
                )
                # The shared terminal-release block at the end of this method hands
                # the browser session back for these statuses.
            else:
                # "navigating" (or an absent status) is genuinely still in progress.
                next_status = "browser_running"

            with self.storage.unit_of_work() as transaction:
                record = transaction.get_run(run_id)
                if record is None:  # pragma: no cover - re-checked under lock
                    raise KeyError("run was not found")
                revision = int(record.get("state_revision", 0) or 0) + 1
                if next_status == "completed":
                    # Capture completed all three domain phases during this one
                    # atomic resume projection; validate every legal edge even
                    # though only the terminal row is persisted.
                    validate_status_transition("waiting_for_hitl", "browser_running", "resume")
                    validate_status_transition("browser_running", "credentials_ready", "resume")
                    validate_status_transition("credentials_ready", "completed", "resume")
                else:
                    validate_status_transition("waiting_for_hitl", next_status, "resume")
                hitl_payload: dict[str, object] | None = None
                if next_status == "waiting_for_hitl":
                    source = interrupts[0] if interrupts else state.get("hitl_request")
                    if isinstance(source, Mapping):
                        hitl_payload = {str(k): v for k, v in source.items()}
                changes: dict[str, object] = {
                    "status": next_status,
                    "state_revision": revision,
                    "last_projected_revision": revision,
                    "external_actions": True,
                    "hitl_request": hitl_payload,
                    "provider_status": {
                        "research": "baseline_ready",
                        "browser": provider_browser,
                        "email": "not_started",
                        "validation": validation_status,
                    },
                    **capture_updates,
                }
                if isinstance(current_url, str) and current_url:
                    changes["browser_live_url"] = None  # never persist the signed URL
                updated = transaction.update_run(run_id, **changes)
                cancelled = signal == "cancelled"
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="hitl_cancelled" if cancelled else "hitl_resumed",
                    payload={
                        "status": "blocked" if cancelled else "browser_running",
                        "signal": signal,
                        "external_actions": True,
                    },
                )
                if injected_login_fields:
                    # Record ONLY the non-secret field names that were injected;
                    # the values never touch the ledger, state, or logs. The
                    # source distinguishes an owner submission from an autonomous
                    # vault reuse, which is what makes the timeline auditable.
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="login_credentials_injected",
                        payload={
                            "fields": injected_login_fields,
                            "source": login_source,
                            "external_actions": True,
                        },
                    )
                if remembered_fields:
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="login_credentials_remembered",
                        payload={
                            "fields": list(remembered_fields),
                            "external_actions": False,
                        },
                    )
                if next_status == "waiting_for_hitl":
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="browser_hitl_required",
                        payload={
                            "status": "waiting_for_hitl",
                            "current_url": current_url,
                            "required_human_action": (
                                hitl_payload.get("type") if hitl_payload else None
                            ),
                            "external_actions": True,
                        },
                    )
                else:
                    for event_type, payload in capture_events:
                        transaction.append_audit_event(
                            run_id=run_id,
                            event_type=event_type,
                            payload=payload,
                        )
                projected = _public_run(updated)
            if next_status in _TERMINAL_BROWSER_STATUSES:
                # A cancelled (or otherwise terminal) resume ends the run, so the
                # session is released here instead of lingering as a held slot.
                self._release_browser_session(
                    self._session_context_for(run_id),
                    cast(BrowserProvider, current.get("browser_provider", "browser_use")),
                    reason=f"resume_{next_status}",
                )
            return projected
        finally:
            lock.release()

    def submit_owner_credentials(
        self,
        run_id: str,
        *,
        company: CompanyProfile,
        fields: Mapping[str, SecretStr],
    ) -> dict[str, Any]:
        """Owner-only credential submission: vault-write, validate, and bundle.

        Raw values are written straight to the encrypted vault and never enter
        run state, checkpoints, audit events, API output, or logs. Only exact
        ``vault://`` references, sanitized validation metadata, and the reference
        -only IntegratorBundle are persisted. Credentials are supplied explicitly
        by the owner here; they are never scraped from the browser.
        """

        if not fields:
            raise CredentialSubmissionError("no_credential_fields")
        for kind in fields:
            if re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,99}", kind) is None:
                raise CredentialSubmissionError("invalid_credential_field")
        store = self._secret_store
        validator = self._credential_validator
        if store is None or validator is None:
            raise CredentialSubmissionError("credential_boundary_not_configured")

        lock = self._run_lock(run_id)
        if not lock.acquire(blocking=False):
            raise RunConflictError(run_id, "submit_credentials")
        try:
            with self.storage.unit_of_work() as transaction:
                current = transaction.get_run(run_id)
                if current is None:
                    raise KeyError("run was not found")
                if current["status"] != "browser_running":
                    raise CredentialSubmissionError("run_not_awaiting_credentials")
                research_payload = current.get("operational_research")
                if not isinstance(research_payload, Mapping):
                    raise CredentialSubmissionError("verified_research_unavailable")
                research = OperationalResearch.model_validate(dict(research_payload))
                app_slug = research.app_slug

                references: dict[str, str] = {}
                try:
                    for kind, secret in fields.items():
                        cleaned = _clean_credential_value(secret.get_secret_value())
                        if not cleaned:
                            raise CredentialSubmissionError("empty_credential_value")
                        reference = store.put(
                            app_slug=app_slug,
                            kind=kind,
                            value=cleaned,
                        )
                        references[kind] = validate_vault_reference(reference)
                except Exception:
                    for reference in references.values():
                        try:
                            store.delete(reference)
                        except Exception:  # pragma: no cover - best-effort rollback
                            pass
                    raise CredentialSubmissionError("vault_write_failed") from None

                result = asyncio.run(
                    validator.validate(app_slug=app_slug, credential_refs=references)
                )
                bundle = build_integrator_bundle(
                    research=research,
                    company=company,
                    credential_refs=references,
                    validation=result,
                    stage="normal",
                )

                revision = int(current.get("state_revision", 0) or 0) + 1
                if result.status == "valid":
                    validate_status_transition("browser_running", "credentials_ready", "submit")
                    validate_status_transition("credentials_ready", "completed", "submit")
                    final_status: RunStatus = "completed"
                else:
                    validate_status_transition(
                        "browser_running", "configuration_required", "submit"
                    )
                    final_status = "configuration_required"

                updated = transaction.update_run(
                    run_id,
                    status=final_status,
                    state_revision=revision,
                    last_projected_revision=revision,
                    external_actions=True,
                    integrator_bundle=bundle.model_dump(mode="json"),
                    validation={
                        "status": result.status,
                        "reason_code": result.reason_code,
                        "http_status": result.http_status,
                        "endpoint": result.endpoint,
                        "checked_at": result.checked_at,
                        "account_identifier": result.account_identifier,
                    },
                )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="credentials_stored",
                    payload={
                        "kinds": sorted(references),
                        "references": dict(sorted(references.items())),
                        "external_actions": True,
                    },
                )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="credentials_validated",
                    payload={
                        "validation_status": result.status,
                        "reason_code": result.reason_code,
                        "http_status": result.http_status,
                        "endpoint": result.endpoint,
                        "account_identifier": result.account_identifier,
                        "external_actions": True,
                    },
                )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="integrator_bundle_generated",
                    payload={
                        "readiness": bundle.readiness,
                        "auth_scheme": bundle.auth_scheme,
                        "credential_ref_count": len(bundle.credential_refs),
                        "external_actions": True,
                    },
                )
                if final_status == "completed":
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="credentials_ready",
                        payload={"status": "credentials_ready", "external_actions": True},
                    )
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="run_completed",
                        payload={"status": "completed", "external_actions": True},
                    )
                projected = _public_run(updated)
                release_provider = cast(
                    BrowserProvider, current.get("browser_provider", "browser_use")
                )
        finally:
            lock.release()
        self._release_browser_session(
            self._session_context_for(run_id),
            release_provider,
            reason=f"credentials_{final_status}",
        )
        return projected

    def snapshot_provenance(self) -> P1SnapshotProvenance:
        return self._queries.snapshot_provenance()
