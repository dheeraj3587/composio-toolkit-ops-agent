"""Encrypted durable LangGraph workflow with same-thread HITL resume."""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import threading
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Protocol, cast

from pydantic import SecretStr

from ops.browser_api_trace_catalog import get_browser_api_trace
from ops.browser_worker import BrowserObservation, BrowserSessionContext
from ops.config import Settings
from ops.effect_ledger import EffectStore
from ops.gmail_worker import GmailSendResult

# ``ops.graph`` stays the declared import home for the workflow, so the helpers that
# moved into focused modules are re-exported here for run_service and the tests.
from ops.graph_checkpoints import (  # noqa: F401
    _build_saver,
    _config,
    _key_bytes,
    _open_private_checkpoint,
    _resume_signal,
    _run_async,
    _validate_thread_id,
)
from ops.graph_outreach import _outreach_message  # noqa: F401
from ops.graph_state_updates import (  # noqa: F401
    _browser_context,
    _failed_update,
    _load_verified_baseline,
    _missing_research_fields,
    _observation_update,
    _outcome_unknown_update,
    _unavailable_update,
)
from ops.graph_state_updates import browser_account_ref as browser_account_ref
from ops.integrator import BundleStage, build_integrator_bundle
from ops.models import (
    CapabilityAvailability,
    HitlRequest,
    OperationalResearch,
    OperationsRequest,
)
from ops.provider_errors import (
    ConfigurationRequiredError,
    PhaseUnavailableError,
    ProviderOperationError,
)
from ops.routing import decide_access
from ops.state import BrowserProvider, OperationsState

ResearchLoader = Callable[[str], OperationalResearch]


class WorkflowBrowser(Protocol):
    async def start(
        self,
        profile_id: str | None,
        *,
        app_slug: str = ...,
        account_ref: str | None = ...,
        secret_scope: str | None = ...,
        use_storage_state: bool = ...,
        live_view_mode: str = ...,
    ) -> BrowserSessionContext: ...

    async def navigate_onboarding(
        self,
        context: BrowserSessionContext,
        research: OperationalResearch,
        *,
        sensitive_data: Mapping[str, str] | None = None,
        account_creation_requested: bool = False,
        credential_creation_policy: str = "reuse_only",
    ) -> BrowserObservation: ...

    async def resume_after_hitl(
        self,
        context: BrowserSessionContext,
        signal: str,
        research: OperationalResearch | None = None,
        *,
        sensitive_data: Mapping[str, str] | None = None,
        credential_creation_policy: str = "reuse_only",
        provider_session_id: str | None = None,
    ) -> BrowserObservation: ...

    def provider_session_id(self, handle: str) -> str | None: ...


class WorkflowGmail(Protocol):
    async def send_outreach(
        self,
        recipient: str,
        subject: str,
        body: str,
        idempotency_key: str,
    ) -> GmailSendResult: ...


class WorkflowDependencies:
    """Explicit adapters make offline tests deterministic and live calls opt-in."""

    def __init__(
        self,
        *,
        research_loader: ResearchLoader | None = None,
        browser: WorkflowBrowser | None = None,
        browsers: Mapping[BrowserProvider, WorkflowBrowser] | None = None,
        gmail: WorkflowGmail | None = None,
        browser_profile_id: str | None = None,
        effect_store: EffectStore | None = None,
        outreach_recipient: str | None = None,
    ) -> None:
        self.research_loader = research_loader or _load_verified_baseline
        self.browsers: dict[BrowserProvider, WorkflowBrowser] = dict(browsers or {})
        if browser is not None:
            provider = cast(
                BrowserProvider,
                str(getattr(browser, "provider_name", "browser_use")),
            )
            self.browsers.setdefault(provider, browser)
        # Compatibility attribute for older tests/injections. Runtime nodes use
        # the immutable provider stored in each run instead.
        self.browser = browser
        self.gmail = gmail
        self.browser_profile_id = browser_profile_id
        # Reused effect ledger for effectively-once external actions (browser
        # session start). When absent, no reservation is performed.
        self.effect_store = effect_store
        # Controlled fallback outreach recipient (the configured override inbox)
        # used when verified research carries no provider contact address, e.g.
        # gated apps. GmailWorker still redirects every send to the override.
        self.outreach_recipient = outreach_recipient


class DurableOperationsWorkflow:
    """Own a compiled graph, encrypted SQLite saver, and its live connection."""

    def __init__(
        self,
        *,
        checkpoint_path: str | Path,
        encryption_key: str | bytes | SecretStr,
        dependencies: WorkflowDependencies | None = None,
    ) -> None:
        self._path = Path(checkpoint_path)
        self._dependencies = dependencies or WorkflowDependencies()
        self._connection = _open_private_checkpoint(self._path)
        self._database_lock = threading.RLock()
        self._thread_locks: dict[str, threading.RLock] = {}
        self._thread_locks_guard = threading.Lock()
        # In-memory, per-thread login credentials for a single resume() call.
        # Passed to the browser worker as a call argument and cleared immediately
        # afterwards so they never enter OperationsState or the encrypted
        # checkpoint. Guarded by the same per-thread lock resume() holds.
        self._resume_sensitive_data: dict[str, Mapping[str, str]] = {}
        # In-memory, per-thread autonomous sign-in credentials for the first
        # browser task of a start() invoke. Passed to the worker as a call
        # argument and cleared immediately; never enters OperationsState or the
        # encrypted checkpoint.
        self._initial_sensitive_data: dict[str, Mapping[str, str]] = {}
        try:
            self._saver = _build_saver(self._connection, _key_bytes(encryption_key))
            self._graph = self._compile_graph(self._saver)
        except Exception:
            self._connection.close()
            raise

    def start(
        self,
        request: OperationsRequest,
        *,
        thread_id: str | None = None,
        sensitive_data: Mapping[str, str] | None = None,
        research: OperationalResearch | None = None,
        seed: Mapping[str, object] | None = None,
    ) -> OperationsState:
        stable_thread_id = thread_id or str(uuid.uuid4())
        _validate_thread_id(stable_thread_id)
        config = _config(stable_thread_id)
        with self._lock(stable_thread_id), self._database_lock:
            existing = self._graph.get_state(config)
            if existing.values:
                return cast(OperationsState, dict(existing.values))
            # Stash autonomous sign-in credentials for the first browser task in
            # this invoke only. They are read as a call argument by
            # _browser_navigate and never written to graph state or the encrypted
            # checkpoint. Always cleared afterwards.
            if sensitive_data:
                self._initial_sensitive_data[stable_thread_id] = dict(sensitive_data)
            initial: OperationsState = {
                "run_id": stable_thread_id,
                "thread_id": stable_thread_id,
                "app_name": request.app_name,
                "browser_provider": request.browser_provider,
                "credential_creation_policy": request.credential_creation_policy,
                "request": request.model_dump(mode="json"),
                "status": "created",
                "credential_refs": {},
                "hitl_count": 0,
                "browser_attempts": 0,
                "outreach_round": 0,
                "errors": [],
                "audit_events": [],
                "capability_statuses": [],
                "side_effect_keys": {},
            }
            if research is not None:
                initial.update(
                    {
                        "app_slug": research.app_slug,
                        "operational_research": research.model_dump(mode="json"),
                        "evidence_urls": list(research.evidence_urls),
                        "missing_fields": _missing_research_fields(research),
                        "audit_events": [{"event_type": "research_loaded"}],
                    }
                )
            # A caller may seed a pre-created browser session (session id + live
            # view metadata). When present, ``_browser_start`` is a no-op and the
            # bounded onboarding task runs against the already-live session, so the
            # embedded live view is available for the entire task instead of only
            # after it finishes.
            if seed:
                initial.update(cast("OperationsState", dict(seed)))
            try:
                result = self._graph.invoke(initial, config=config, durability="sync")
            finally:
                self._initial_sensitive_data.pop(stable_thread_id, None)
            return cast(OperationsState, dict(result))

    def resume(
        self,
        thread_id: str,
        signal: str,
        *,
        sensitive_data: Mapping[str, str] | None = None,
    ) -> OperationsState:
        _validate_thread_id(thread_id)
        normalized_signal = _resume_signal(signal)
        config = _config(thread_id)
        command_type = importlib.import_module("langgraph.types").Command
        with self._lock(thread_id), self._database_lock:
            snapshot = self._graph.get_state(config)
            if not snapshot.values:
                raise LookupError("workflow thread was not found")
            if not snapshot.interrupts:
                raise RuntimeError("workflow thread is not waiting for human input")
            # Stash login credentials for the single _browser_resume node call in
            # this invoke. They are read as a call argument and never written to
            # graph state or the encrypted checkpoint. Always cleared afterwards.
            if sensitive_data:
                self._resume_sensitive_data[thread_id] = dict(sensitive_data)
            try:
                result = self._graph.invoke(
                    command_type(resume=normalized_signal),
                    config=config,
                    durability="sync",
                )
            finally:
                self._resume_sensitive_data.pop(thread_id, None)
            return cast(OperationsState, dict(result))

    def get_state(self, thread_id: str) -> OperationsState:
        _validate_thread_id(thread_id)
        with self._lock(thread_id), self._database_lock:
            values = self._graph.get_state(_config(thread_id)).values
            if not values:
                raise LookupError("workflow thread was not found")
            return cast(OperationsState, dict(values))

    def get_interrupts(self, thread_id: str) -> tuple[dict[str, object], ...]:
        _validate_thread_id(thread_id)
        with self._lock(thread_id), self._database_lock:
            interrupts = self._graph.get_state(_config(thread_id)).interrupts
        results: list[dict[str, object]] = []
        for value in interrupts:
            payload = getattr(value, "value", None)
            if isinstance(payload, Mapping):
                results.append({str(key): item for key, item in payload.items()})
        return tuple(results)

    def close(self) -> None:
        with self._database_lock:
            self._connection.close()

    def __enter__(self) -> DurableOperationsWorkflow:
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        del exc_type, exc_value, traceback
        self.close()

    def _lock(self, thread_id: str) -> threading.RLock:
        with self._thread_locks_guard:
            return self._thread_locks.setdefault(thread_id, threading.RLock())

    def _compile_graph(self, saver: object) -> Any:
        graph_module = importlib.import_module("langgraph.graph")
        state_graph_type = graph_module.StateGraph
        start = graph_module.START
        end = graph_module.END
        graph = state_graph_type(OperationsState)
        graph.add_node("initialize", self._initialize)
        graph.add_node("research", self._research)
        graph.add_node("route", self._route)
        graph.add_node("browser_start", self._browser_start)
        graph.add_node("browser_navigate", self._browser_navigate)
        graph.add_node("human_interrupt", self._human_interrupt)
        graph.add_node("browser_resume", self._browser_resume)
        graph.add_node("outreach_send", self._outreach_send)
        graph.add_node("finalize", self._finalize)
        graph.add_edge(start, "initialize")
        graph.add_edge("initialize", "research")
        graph.add_edge("research", "route")
        graph.add_conditional_edges(
            "route",
            self._after_route,
            {
                "browser_start": "browser_start",
                "outreach_send": "outreach_send",
                "finalize": "finalize",
            },
        )
        graph.add_edge("browser_start", "browser_navigate")
        graph.add_conditional_edges(
            "browser_navigate",
            self._after_browser,
            {
                "human_interrupt": "human_interrupt",
                "outreach_send": "outreach_send",
                "finalize": "finalize",
            },
        )
        graph.add_edge("human_interrupt", "browser_resume")
        graph.add_conditional_edges(
            "browser_resume",
            self._after_browser,
            {
                "human_interrupt": "human_interrupt",
                "outreach_send": "outreach_send",
                "finalize": "finalize",
            },
        )
        graph.add_edge("outreach_send", "finalize")
        graph.add_edge("finalize", end)
        return graph.compile(checkpointer=saver, name="composio-operations")

    def _initialize(self, state: OperationsState) -> dict[str, object]:
        return {
            "status": "researching",
            "audit_events": [*state.get("audit_events", []), {"event_type": "workflow_started"}],
        }

    def _research(self, state: OperationsState) -> dict[str, object]:
        if state.get("operational_research"):
            return {}
        research = self._dependencies.research_loader(state["app_name"])
        return {
            "app_slug": research.app_slug,
            "operational_research": research.model_dump(mode="json"),
            "evidence_urls": list(research.evidence_urls),
            "missing_fields": _missing_research_fields(research),
            "audit_events": [*state.get("audit_events", []), {"event_type": "research_loaded"}],
        }

    def _route(self, state: OperationsState) -> dict[str, object]:
        """Select the legacy access route without process-global overrides."""

        return self._core_route(state)

    def _core_route(self, state: OperationsState) -> dict[str, object]:
        research = OperationalResearch.model_validate(state["operational_research"])
        decision = decide_access(research)
        browser_route = decision.route in {"self_serve", "hybrid"}
        missing_browser_urls = not research.login_url or not research.credential_management_url
        untraced = get_browser_api_trace(research.app_slug) is None
        if decision.is_final and browser_route and (missing_browser_urls or untraced):
            reason_code = (
                "browser_trace_not_reviewed" if untraced else "verified_browser_urls_missing"
            )
            return {
                "access_route": decision.route,
                "route_reason": decision.explanation,
                "route_reason_code": reason_code,
                "status": "configuration_required",
                "audit_events": [
                    *state.get("audit_events", []),
                    {"event_type": "browser_route_not_ready", "reason_code": reason_code},
                ],
            }
        return {
            "access_route": decision.route,
            "route_reason": decision.explanation,
            "route_reason_code": decision.reason_code,
            "status": "route_selected" if decision.is_final else "researching",
            "audit_events": [*state.get("audit_events", []), {"event_type": "route_selected"}],
        }

    def _after_route(self, state: OperationsState) -> str:
        """Pick the next node in the legacy workflow."""

        return self._core_after_route(state)

    def _core_after_route(self, state: OperationsState) -> str:
        request = OperationsRequest.model_validate(state["request"])
        if (
            request.dry_run
            or state.get("status") == "configuration_required"
            or state.get("access_route") in {"blocked", "unknown"}
        ):
            return "finalize"
        if state.get("access_route") in {"self_serve", "hybrid"}:
            return "browser_start"
        return "outreach_send"

    def _browser_for_state(self, state: OperationsState) -> WorkflowBrowser | None:
        provider = state.get("browser_provider", "browser_use")
        return self._dependencies.browsers.get(provider)

    def _browser_provider_name(self, state: OperationsState) -> str:
        """The effect-ledger provider identity of the wired browser backend.

        Recording a Playwright run as a ``browser_use`` effect would corrupt audit,
        reconciliation, and metrics, so the backend declares its own name and the
        Browser Use worker keeps the historical default.
        """

        return str(getattr(self._browser_for_state(state), "provider_name", "browser_use"))

    def _browser_start(self, state: OperationsState) -> dict[str, object]:
        if state.get("browser_session_id"):
            return {}
        browser = self._browser_for_state(state)
        if browser is None:
            return _unavailable_update(
                state,
                ConfigurationRequiredError(
                    phase=5,
                    capability=f"{state.get('browser_provider', 'browser_use')} browser provider",
                    reason_code="browser_adapter_missing",
                ),
            )
        effect_key = f"{state['run_id']}:browser-start"
        store = self._dependencies.effect_store
        if store is not None:
            reservation = store.reserve(
                provider=self._browser_provider_name(state),
                action="start_session",
                idempotency_key=effect_key,
            )
            if reservation.status == "reconcile_required":
                return _outcome_unknown_update(state, "browser session")
            if reservation.status == "completed":  # pragma: no cover - fresh key per run
                return {}
        try:
            # Supply the app slug, an OPAQUE account reference, the run scope (so
            # one-time login references are consumed only for this run) and the
            # storage-state flag. Both providers accept this signature; Browser Use
            # ignores the extra metadata, so its request is unchanged.
            is_playwright = getattr(browser, "provider_name", "") == "playwright"
            account_ref: str | None = None
            with contextlib.suppress(Exception):
                request = OperationsRequest.model_validate(state["request"])
                account_ref = browser_account_ref(request.company.work_email_ref)
            context = _run_async(
                browser.start(
                    self._dependencies.browser_profile_id,
                    app_slug=str(state.get("app_slug") or ""),
                    account_ref=account_ref,
                    secret_scope=str(state["run_id"]),
                    use_storage_state=is_playwright,
                )
            )
        except PhaseUnavailableError as exc:
            return _unavailable_update(state, exc)
        except ProviderOperationError:
            # Ambiguous session start: the session may or may not exist. Mark the
            # reservation outcome-unknown so no blind retry occurs; reconciliation
            # is required before any further attempt.
            if store is not None:
                store.mark_outcome_unknown(
                    provider=self._browser_provider_name(state),
                    action="start_session",
                    idempotency_key=effect_key,
                )
            return _outcome_unknown_update(state, "browser session")
        if store is not None:
            store.complete(
                provider=self._browser_provider_name(state),
                action="start_session",
                idempotency_key=effect_key,
                receipt={"session_id": context.session_id},
            )
        return {
            "browser_profile_id": context.profile_id,
            "browser_session_id": context.session_id,
            "browser_live_view_available": context.live_view_available,
            "browser_attempts": state.get("browser_attempts", 0) + 1,
            "browser_session_started_at": context.created_at,
            "browser_session_last_active_at": context.created_at,
            "browser_session_inactivity_expires_at": context.inactivity_expires_at,
            "browser_session_max_expires_at": context.maximum_expires_at,
            "status": "browser_running",
            "side_effect_keys": {
                **state.get("side_effect_keys", {}),
                "browser_start": f"{state['run_id']}:browser-start",
            },
            "audit_events": [*state.get("audit_events", []), {"event_type": "browser_started"}],
        }

    def _browser_navigate(self, state: OperationsState) -> dict[str, object]:
        if state.get("status") in {"configuration_required", "failed"}:
            return {}
        browser = self._browser_for_state(state)
        if browser is None:
            return _failed_update(state, "browser onboarding", "browser_adapter_missing")
        research = OperationalResearch.model_validate(state["operational_research"])
        # Autonomous sign-in credentials (if the owner supplied any at create
        # time) are read from the in-memory per-thread stash and injected at
        # session creation, never from graph state.
        thread_id = str(state.get("thread_id") or "")
        sensitive_data = self._initial_sensitive_data.get(thread_id)
        try:
            request = OperationsRequest.model_validate(state["request"])
            if request.account_creation_requested:
                observation = _run_async(
                    browser.navigate_onboarding(
                        _browser_context(state),
                        research,
                        sensitive_data=sensitive_data,
                        account_creation_requested=True,
                        credential_creation_policy=request.credential_creation_policy,
                    )
                )
            else:
                observation = _run_async(
                    browser.navigate_onboarding(
                        _browser_context(state),
                        research,
                        sensitive_data=sensitive_data,
                        credential_creation_policy=request.credential_creation_policy,
                    )
                )
        except PhaseUnavailableError as exc:
            return _unavailable_update(state, exc)
        except ProviderOperationError as exc:
            return _failed_update(state, exc.capability, exc.reason_code)
        return self._attach_session_meta(state, _observation_update(state, observation))

    def _human_interrupt(self, state: OperationsState) -> dict[str, object]:
        observation = BrowserObservation(**cast(dict[str, Any], state["browser_observation"]))
        action_type = observation.human_action_type
        if action_type is None:  # pragma: no cover - observation validation enforces this
            return _failed_update(state, "workflow HITL", "human_action_type_missing")
        request = HitlRequest(
            type=action_type,
            app_name=state["app_name"],
            message=observation.human_instruction or "Complete the action in the live browser.",
            expected_completion_signal="The developer dashboard is visible.",
            live_view_available=state.get("browser_live_view_available", False),
        )
        interrupt = importlib.import_module("langgraph.types").interrupt
        resumed = interrupt(request.model_dump(mode="json"))
        return {
            "hitl_request": None,
            "resume_signal": _resume_signal(resumed),
            "audit_events": [*state.get("audit_events", []), {"event_type": "hitl_resumed"}],
        }

    def _browser_resume(self, state: OperationsState) -> dict[str, object]:
        if state.get("resume_signal") == "cancelled":
            return {"status": "blocked"}
        browser = self._browser_for_state(state)
        if browser is None:
            return _failed_update(state, "browser HITL resume", "browser_adapter_missing")
        # Login credentials (if the owner submitted any for this resume) are read
        # from the in-memory per-thread stash, never from graph state. They reach
        # the worker as a call argument and are cleared by resume() afterwards.
        thread_id = str(state.get("thread_id") or "")
        sensitive_data = self._resume_sensitive_data.get(thread_id)
        research = OperationalResearch.model_validate(state["operational_research"])
        provider_session = state.get("browser_provider_session_id")
        try:
            observation = _run_async(
                browser.resume_after_hitl(
                    _browser_context(state),
                    state.get("resume_signal", "completed"),
                    research,
                    sensitive_data=sensitive_data,
                    credential_creation_policy=OperationsRequest.model_validate(
                        state["request"]
                    ).credential_creation_policy,
                    provider_session_id=(
                        provider_session if isinstance(provider_session, str) else None
                    ),
                )
            )
        except PhaseUnavailableError as exc:
            return _unavailable_update(state, exc)
        except ProviderOperationError as exc:
            return _failed_update(state, exc.capability, exc.reason_code)
        return self._attach_session_meta(state, _observation_update(state, observation))

    def _attach_session_meta(
        self,
        state: OperationsState,
        update: dict[str, object],
    ) -> dict[str, object]:
        """Persist the live provider session id so resume can reconnect later.

        The provider session id is a non-secret identifier (not a token or signed
        URL). Persisting it lets a resume reattach to the same running session
        even after an API restart cleared the worker's in-memory maps. The signed
        live URL itself is never persisted.
        """

        browser = self._browser_for_state(state)
        handle = str(state.get("browser_session_id") or "")
        if browser is None or not handle:
            return update
        getter = getattr(browser, "provider_session_id", None)
        provider_session = getter(handle) if callable(getter) else None
        if isinstance(provider_session, str) and provider_session:
            update["browser_provider_session_id"] = provider_session
        live = getattr(browser, "live_url", None)
        if callable(live):
            update["browser_live_view_available"] = bool(live(handle))
        return update

    def _after_browser(self, state: OperationsState) -> str:
        """Pick the next node after the legacy browser step."""

        return self._core_after_browser(state)

    def _core_after_browser(self, state: OperationsState) -> str:
        observation = state.get("browser_observation")
        if (
            isinstance(observation, Mapping)
            and observation.get("status") == "human_action_required"
        ):
            return "human_interrupt"
        if (
            state.get("access_route") == "hybrid"
            and isinstance(observation, Mapping)
            and observation.get("status") == "credential_page_ready"
        ):
            return "outreach_send"
        return "finalize"

    def _outreach_send(self, state: OperationsState) -> dict[str, object]:
        if state.get("gmail_thread_id"):
            return {}
        if self._dependencies.gmail is None:
            return _unavailable_update(
                state,
                ConfigurationRequiredError(
                    phase=4,
                    capability="Composio Gmail outreach",
                    reason_code="gmail_adapter_missing",
                ),
            )
        research = OperationalResearch.model_validate(state["operational_research"])
        # Prefer the verified provider contact; fall back to the controlled
        # override inbox for gated apps that carry no discovered contact address.
        # Either way GmailWorker redirects the actual send to the override.
        recipient = research.contact_email or self._dependencies.outreach_recipient
        if recipient is None:
            return _unavailable_update(
                state,
                ConfigurationRequiredError(
                    phase=4,
                    capability="Composio Gmail outreach",
                    reason_code="verified_recipient_missing",
                ),
            )
        request = OperationsRequest.model_validate(state["request"])
        subject, body = _outreach_message(request, research)
        key = f"{state['run_id']}:initial-outreach"
        try:
            sent = _run_async(self._dependencies.gmail.send_outreach(recipient, subject, body, key))
        except PhaseUnavailableError as exc:
            return _unavailable_update(state, exc)
        except ProviderOperationError as exc:
            return _failed_update(state, exc.capability, exc.reason_code)
        return {
            "gmail_session_id": sent.session_id,
            "gmail_thread_id": sent.thread_id,
            "intended_recipient": sent.intended_recipient,
            "actual_recipient": sent.actual_recipient,
            "outreach_round": state.get("outreach_round", 0) + 1,
            "status": "waiting_for_reply",
            "side_effect_keys": {**state.get("side_effect_keys", {}), "outreach": key},
            "audit_events": [*state.get("audit_events", []), {"event_type": "outreach_sent"}],
        }

    def _finalize(self, state: OperationsState) -> dict[str, object]:
        request = OperationsRequest.model_validate(state["request"])
        research = OperationalResearch.model_validate(state["operational_research"])
        capabilities = tuple(
            CapabilityAvailability.model_validate(value)
            for value in state.get("capability_statuses", [])
        )
        if request.dry_run:
            return {"status": state.get("status", "route_selected")}
        stage: BundleStage
        if state.get("status") == "waiting_for_reply":
            stage = "awaiting_provider"
        elif state.get("status") == "waiting_for_hitl":
            stage = "human_action_required"
        elif state.get("status") == "blocked":
            stage = "blocked"
        elif state.get("status") == "failed":
            stage = "failed"
        else:
            stage = "normal"
        bundle = build_integrator_bundle(
            research=research,
            company=request.company,
            credential_refs=state.get("credential_refs", {}),
            validation=None,
            capabilities=capabilities,
            stage=stage,
            provider_account_id=state.get("gmail_session_id"),
            developer_app_id=None,
        )
        status = state.get("status", "configuration_required")
        if bundle.readiness == "credentials_ready":
            status = "completed"
        elif bundle.readiness == "configuration_required":
            status = "configuration_required"
        return {
            "integrator_bundle": bundle.model_dump(mode="json"),
            "status": status,
            "audit_events": [*state.get("audit_events", []), {"event_type": "workflow_finalized"}],
        }


def build_graph(
    *,
    checkpoint_path: str | Path | None = None,
    encryption_key: str | bytes | SecretStr | None = None,
    dependencies: WorkflowDependencies | None = None,
) -> DurableOperationsWorkflow:
    """Build the production workflow only when encrypted persistence is configured."""

    settings = Settings.from_env()
    path = checkpoint_path or settings.checkpoint_db_path
    key = encryption_key or settings.langgraph_aes_key
    if key is None:
        raise ConfigurationRequiredError(
            phase=3,
            capability="LangGraph workflow",
            reason_code="langgraph_aes_key_missing",
        )
    return DurableOperationsWorkflow(
        checkpoint_path=path,
        encryption_key=key,
        dependencies=dependencies,
    )


async def start_workflow(
    request: OperationsRequest,
    *,
    workflow: DurableOperationsWorkflow | None = None,
    thread_id: str | None = None,
) -> OperationsState:
    runtime = workflow or build_graph()
    should_close = workflow is None
    try:
        return await asyncio.to_thread(runtime.start, request, thread_id=thread_id)
    finally:
        if should_close:
            runtime.close()


async def resume_workflow(
    thread_id: str,
    signal: str,
    *,
    workflow: DurableOperationsWorkflow | None = None,
) -> OperationsState:
    runtime = workflow or build_graph()
    should_close = workflow is None
    try:
        return await asyncio.to_thread(runtime.resume, thread_id, signal)
    finally:
        if should_close:
            runtime.close()


async def get_workflow_state(
    thread_id: str,
    *,
    workflow: DurableOperationsWorkflow | None = None,
) -> OperationsState:
    runtime = workflow or build_graph()
    should_close = workflow is None
    try:
        return await asyncio.to_thread(runtime.get_state, thread_id)
    finally:
        if should_close:
            runtime.close()


__all__ = [
    "DurableOperationsWorkflow",
    "PhaseUnavailableError",
    "WorkflowDependencies",
    "build_graph",
    "get_workflow_state",
    "resume_workflow",
    "start_workflow",
]
