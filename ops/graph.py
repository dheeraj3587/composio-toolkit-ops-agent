"""Encrypted durable LangGraph workflow with same-thread HITL resume."""

from __future__ import annotations

import asyncio
import importlib
import sqlite3
import threading
import uuid
from collections.abc import Callable, Mapping
from dataclasses import asdict
from pathlib import Path
from typing import Any, Protocol, cast

from pydantic import SecretStr

from ops.browser_worker import BrowserObservation, BrowserSessionContext
from ops.config import Settings
from ops.effect_ledger import EffectStore
from ops.gmail_worker import GmailSendResult
from ops.integrator import BundleStage, build_integrator_bundle
from ops.models import (
    CapabilityAvailability,
    CapabilityStatus,
    HitlRequest,
    OperationalResearch,
    OperationsRequest,
)
from ops.p1_adapter import P1LookupFound, P1OperationalAdapter, to_operational_research
from ops.private_files import finalize_private_database, prepare_private_database
from ops.provider_errors import (
    ConfigurationRequiredError,
    PhaseUnavailableError,
    ProviderContractError,
    ProviderOperationError,
)
from ops.routing import decide_access
from ops.state import OperationsState

ResearchLoader = Callable[[str], OperationalResearch]


class WorkflowBrowser(Protocol):
    async def start(self, profile_id: str | None) -> BrowserSessionContext: ...

    async def navigate_onboarding(
        self,
        context: BrowserSessionContext,
        research: OperationalResearch,
    ) -> BrowserObservation: ...

    async def resume_after_hitl(
        self,
        context: BrowserSessionContext,
        signal: str,
        *,
        sensitive_data: Mapping[str, str] | None = None,
    ) -> BrowserObservation: ...


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
        gmail: WorkflowGmail | None = None,
        browser_profile_id: str | None = None,
        effect_store: EffectStore | None = None,
        outreach_recipient: str | None = None,
    ) -> None:
        self.research_loader = research_loader or _load_verified_baseline
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
        try:
            self._saver = _build_saver(self._connection, _key_bytes(encryption_key))
            self._graph = self._compile_graph(self._saver)
        except Exception:
            self._connection.close()
            raise

    def start(self, request: OperationsRequest, *, thread_id: str | None = None) -> OperationsState:
        stable_thread_id = thread_id or str(uuid.uuid4())
        _validate_thread_id(stable_thread_id)
        config = _config(stable_thread_id)
        with self._lock(stable_thread_id), self._database_lock:
            existing = self._graph.get_state(config)
            if existing.values:
                return cast(OperationsState, dict(existing.values))
            initial: OperationsState = {
                "run_id": stable_thread_id,
                "thread_id": stable_thread_id,
                "app_name": request.app_name,
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
            result = self._graph.invoke(initial, config=config, durability="sync")
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
            {"human_interrupt": "human_interrupt", "finalize": "finalize"},
        )
        graph.add_edge("human_interrupt", "browser_resume")
        graph.add_conditional_edges(
            "browser_resume",
            self._after_browser,
            {"human_interrupt": "human_interrupt", "finalize": "finalize"},
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
        research = OperationalResearch.model_validate(state["operational_research"])
        decision = decide_access(research)
        return {
            "access_route": decision.route,
            "route_reason": decision.explanation,
            "route_reason_code": decision.reason_code,
            "status": "route_selected" if decision.is_final else "researching",
            "audit_events": [*state.get("audit_events", []), {"event_type": "route_selected"}],
        }

    def _after_route(self, state: OperationsState) -> str:
        request = OperationsRequest.model_validate(state["request"])
        if request.dry_run or state.get("access_route") in {"blocked", "unknown"}:
            return "finalize"
        if state.get("access_route") in {"self_serve", "hybrid"}:
            return "browser_start"
        return "outreach_send"

    def _browser_start(self, state: OperationsState) -> dict[str, object]:
        if state.get("browser_session_id"):
            return {}
        if self._dependencies.browser is None:
            return _unavailable_update(
                state,
                ConfigurationRequiredError(
                    phase=5,
                    capability="Browser Use",
                    reason_code="browser_adapter_missing",
                ),
            )
        effect_key = f"{state['run_id']}:browser-start"
        store = self._dependencies.effect_store
        if store is not None:
            reservation = store.reserve(
                provider="browser_use",
                action="start_session",
                idempotency_key=effect_key,
            )
            if reservation.status == "reconcile_required":
                return _outcome_unknown_update(state, "Browser Use session")
            if reservation.status == "completed":  # pragma: no cover - fresh key per run
                return {}
        try:
            context = _run_async(
                self._dependencies.browser.start(self._dependencies.browser_profile_id)
            )
        except PhaseUnavailableError as exc:
            return _unavailable_update(state, exc)
        except ProviderOperationError:
            # Ambiguous session start: the session may or may not exist. Mark the
            # reservation outcome-unknown so no blind retry occurs; reconciliation
            # is required before any further attempt.
            if store is not None:
                store.mark_outcome_unknown(
                    provider="browser_use",
                    action="start_session",
                    idempotency_key=effect_key,
                )
            return _outcome_unknown_update(state, "Browser Use session")
        if store is not None:
            store.complete(
                provider="browser_use",
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
        if self._dependencies.browser is None:
            return _failed_update(state, "browser onboarding", "browser_adapter_missing")
        research = OperationalResearch.model_validate(state["operational_research"])
        try:
            observation = _run_async(
                self._dependencies.browser.navigate_onboarding(
                    _browser_context(state),
                    research,
                )
            )
        except PhaseUnavailableError as exc:
            return _unavailable_update(state, exc)
        except ProviderOperationError as exc:
            return _failed_update(state, exc.capability, exc.reason_code)
        return _observation_update(state, observation)

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
        if self._dependencies.browser is None:
            return _failed_update(state, "browser HITL resume", "browser_adapter_missing")
        # Login credentials (if the owner submitted any for this resume) are read
        # from the in-memory per-thread stash, never from graph state. They reach
        # the worker as a call argument and are cleared by resume() afterwards.
        thread_id = str(state.get("thread_id") or "")
        sensitive_data = self._resume_sensitive_data.get(thread_id)
        try:
            observation = _run_async(
                self._dependencies.browser.resume_after_hitl(
                    _browser_context(state),
                    state.get("resume_signal", "completed"),
                    sensitive_data=sensitive_data,
                )
            )
        except PhaseUnavailableError as exc:
            return _unavailable_update(state, exc)
        except ProviderOperationError as exc:
            return _failed_update(state, exc.capability, exc.reason_code)
        return _observation_update(state, observation)

    def _after_browser(self, state: OperationsState) -> str:
        observation = state.get("browser_observation")
        if (
            isinstance(observation, Mapping)
            and observation.get("status") == "human_action_required"
        ):
            return "human_interrupt"
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


def _open_private_checkpoint(path: Path) -> sqlite3.Connection:
    existed = prepare_private_database(path)
    connection = sqlite3.connect(path, timeout=30, check_same_thread=False)
    try:
        finalize_private_database(path, existed=existed)
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA secure_delete = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection
    except Exception:
        connection.close()
        raise


def _build_saver(connection: sqlite3.Connection, key: bytes) -> object:
    json_module = importlib.import_module("langgraph.checkpoint.serde.jsonplus")
    encrypted_module = importlib.import_module("langgraph.checkpoint.serde.encrypted")
    sqlite_module = importlib.import_module("langgraph.checkpoint.sqlite")
    strict = json_module.JsonPlusSerializer(
        pickle_fallback=False,
        allowed_json_modules=None,
        allowed_msgpack_modules=None,
    )
    encrypted = encrypted_module.EncryptedSerializer.from_pycryptodome_aes(
        serde=strict,
        key=key,
    )
    saver = sqlite_module.SqliteSaver(connection, serde=encrypted)
    saver.setup()
    return saver


def _key_bytes(value: str | bytes | SecretStr) -> bytes:
    if isinstance(value, SecretStr):
        key = value.get_secret_value().encode("utf-8")
    elif isinstance(value, str):
        key = value.encode("utf-8")
    else:
        key = value
    if len(key) not in {16, 24, 32}:
        raise ValueError("LANGGRAPH_AES_KEY must contain exactly 16, 24, or 32 bytes")
    return key


def _config(thread_id: str) -> dict[str, dict[str, str]]:
    return {"configurable": {"thread_id": thread_id}}


def _validate_thread_id(value: str) -> None:
    if not value or len(value) > 200 or any(character in value for character in "\r\n\x00"):
        raise ValueError("thread_id is invalid")


def _resume_signal(value: object) -> str:
    if not isinstance(value, str) or value not in {"completed", "cancelled", "retry"}:
        raise ValueError("resume signal must be completed, cancelled, or retry")
    return value


def _run_async(awaitable: Any) -> Any:
    return asyncio.run(awaitable)


def _load_verified_baseline(app_name: str) -> OperationalResearch:
    lookup = P1OperationalAdapter().lookup(app_name)
    if not isinstance(lookup, P1LookupFound):
        raise LookupError("app is not present in the verified P1 snapshot")
    return to_operational_research(lookup.record)


def _browser_context(state: OperationsState) -> BrowserSessionContext:
    return BrowserSessionContext(
        profile_id=state.get("browser_profile_id", ""),
        session_id=state.get("browser_session_id", ""),
        live_view_available=state.get("browser_live_view_available", False),
        allowed_domains=(),
        created_at=state.get("browser_session_started_at", ""),
        inactivity_expires_at=state.get("browser_session_inactivity_expires_at", ""),
        maximum_expires_at=state.get("browser_session_max_expires_at", ""),
    )


def _observation_update(
    state: OperationsState,
    observation: BrowserObservation,
) -> dict[str, object]:
    status = (
        "waiting_for_hitl" if observation.status == "human_action_required" else "browser_running"
    )
    if observation.status == "blocked":
        status = "blocked"
    elif observation.status == "failed":
        status = "failed"
    request: dict[str, object] | None = None
    hitl_count = state.get("hitl_count", 0)
    if observation.status == "human_action_required":
        hitl_count += 1
        request = {
            "type": observation.human_action_type,
            "message": observation.human_instruction,
            "live_view_available": state.get("browser_live_view_available", False),
        }
    return {
        "browser_observation": asdict(observation),
        "current_url": observation.current_url,
        "hitl_request": request,
        "hitl_count": hitl_count,
        "status": status,
        "audit_events": [
            *state.get("audit_events", []),
            {"event_type": "hitl_requested" if request else "browser_observed"},
        ],
    }


def _unavailable_update(
    state: OperationsState,
    error: PhaseUnavailableError,
) -> dict[str, object]:
    status: CapabilityStatus = (
        "contract_incompatible"
        if isinstance(error, ProviderContractError)
        else "configuration_required"
    )
    capability = CapabilityAvailability(
        capability=error.capability,
        status=status,
        reason_code=error.reason_code,
        detail="The capability did not run; operator configuration or a compatible SDK is required.",
    )
    return {
        "status": "configuration_required",
        "capability_statuses": [
            *state.get("capability_statuses", []),
            capability.model_dump(mode="json"),
        ],
        "errors": [
            *state.get("errors", []),
            {"capability": error.capability, "reason_code": error.reason_code},
        ],
    }


def _failed_update(state: OperationsState, capability: str, reason_code: str) -> dict[str, object]:
    return {
        "status": "failed",
        "errors": [
            *state.get("errors", []),
            {"capability": capability, "reason_code": reason_code},
        ],
    }


def _outcome_unknown_update(state: OperationsState, capability: str) -> dict[str, object]:
    """Record an ambiguous external outcome without claiming success or retrying."""

    capability_state = CapabilityAvailability(
        capability=capability,
        status="configuration_required",
        reason_code="browser_outcome_unknown",
        detail="The provider outcome is ambiguous; reconciliation is required before any retry.",
    )
    return {
        "status": "configuration_required",
        "capability_statuses": [
            *state.get("capability_statuses", []),
            capability_state.model_dump(mode="json"),
        ],
        "errors": [
            *state.get("errors", []),
            {"capability": capability, "reason_code": "browser_outcome_unknown"},
        ],
    }


def _outreach_message(
    request: OperationsRequest,
    research: OperationalResearch,
) -> tuple[str, str]:
    """Build a deterministic outreach from sanitized company and research fields.

    The message contains only non-secret operational facts: provider/app name,
    company legal name and website, a bounded use-case summary, and explicit
    requests for developer access, scopes, approval steps, sandbox availability,
    and the credentials process. It never contains secrets, tokens, vault
    values, browser URLs, prompts, or checkpoint data.
    """

    short_id = research.app_slug[:40]
    subject = f"API access request for {research.app_name} [{short_id}]"
    scopes = (
        ", ".join(scope.name for scope in research.scopes) or "the documented integration scopes"
    )
    use_case = request.company.use_case[:500]
    body = (
        "Hello,\n\n"
        f"{request.company.legal_name} ({request.company.website}) is requesting developer "
        f"and production API access for {research.app_name}.\n\n"
        f"Use case: {use_case}\n\n"
        "To proceed with the integration, we would appreciate confirmation of:\n"
        f"- the developer/API access request process for {research.app_name}\n"
        f"- the required OAuth scopes or permissions ({scopes})\n"
        "- any approval or review steps and their expected timeline\n"
        "- whether a sandbox or test environment is available\n"
        "- the credential issuance process for production access\n\n"
        f"Thank you,\n{request.company.legal_name}"
    )
    return subject, body


def _missing_research_fields(research: OperationalResearch) -> list[str]:
    fields = (
        "api_base_url",
        "authorization_url",
        "token_url",
        "developer_portal_url",
        "signup_url",
        "contact_email",
        "contact_url",
    )
    return [name for name in fields if getattr(research, name) is None]


__all__ = [
    "DurableOperationsWorkflow",
    "PhaseUnavailableError",
    "WorkflowDependencies",
    "build_graph",
    "get_workflow_state",
    "resume_workflow",
    "start_workflow",
]
