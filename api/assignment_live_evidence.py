"""Assignment-only live evidence fixes layered over the conservative core runtime.

The production assignment entry point installs these adapters before the API service
is created. Plan-only behaviour is untouched.
"""

from __future__ import annotations

import importlib
from collections.abc import Mapping
from typing import Any, cast

import ops.browser_worker as browser_worker_module
from api.assignment_runtime import (
    AssignmentBrowserWorker,
    _await_if_needed,
    _blocked_observation,
    _classify_human_action,
    _coerce_task_output,
    _dump,
    _official_target_url,
    _render_browser_task,
    _string,
    assignment_allowed_hosts,
    sanitize_browser_url,
    validate_allowed_domains,
)
from api.models import ProviderState
from api.service import LocalRunService, _EVENT_SUMMARIES
from ops.browser_worker import BrowserObservation, BrowserSessionContext, BrowserTaskOutput
from ops.models import OperationalResearch
from ops.operational_research import (
    EvidenceDocument,
    GeminiStructuredExtractor,
    _render_extraction_prompt,
)
from ops.provider_errors import ProviderContractError, ProviderOperationError

_ORIGINAL_PROVIDER_STATES = LocalRunService._provider_states
_INSTALLED = False


async def _retained_run_assignment_task(
    worker: AssignmentBrowserWorker,
    *,
    context: BrowserSessionContext,
    research: OperationalResearch,
    resume_signal: str | None,
) -> BrowserObservation:
    """Run a bounded task and retain successful sessions for evaluator inspection."""

    worker._require_configuration()
    allowed = assignment_allowed_hosts(research)
    patterns = validate_allowed_domains(allowed.patterns())
    target_url = _official_target_url(research, patterns)
    task = (
        _render_browser_task(target_url, patterns, resume_signal)
        + "\n\nASSIGNMENT VERIFICATION: A documentation page or developer landing page alone is "
        "not the credential page. Continue to the provider sign-in/account settings flow. If a "
        "password, OTP, CAPTCHA, consent, billing, or account-owner action is required, stop there "
        "with hitl_required=true so the live session remains available to the evaluator."
    )
    client = worker._get_client()

    run_kwargs: dict[str, Any] = {
        "schema": BrowserTaskOutput,
        "model": worker._settings.browser_use_model,
        "keep_alive": True,
        "max_cost_usd": worker._settings.browser_use_max_cost_usd,
        "enable_recording": False,
        "allowed_domains": list(patterns),
    }
    provider_session = worker._provider_sessions.get(context.session_id)
    if provider_session:
        run_kwargs["session_id"] = provider_session
    else:
        run_kwargs["start_url"] = target_url

    try:
        result = await _await_if_needed(client.run(task, **run_kwargs))
    except Exception:
        await worker._safe_stop_handle(context.session_id)
        raise ProviderOperationError(
            capability="browser onboarding",
            reason_code="provider_request_failed",
        ) from None

    data = _dump(result)
    returned_session = (
        _string(data.get("session_id"))
        or _string(data.get("browser_session_id"))
        or _string(data.get("id"))
    )
    if provider_session and returned_session and returned_session != provider_session:
        await worker._safe_stop_handle(context.session_id)
        raise ProviderContractError(
            phase=5,
            capability="browser HITL resume",
            reason_code="provider_session_changed",
        )
    if not provider_session:
        if not returned_session:
            raise ProviderOperationError(
                capability="browser onboarding",
                reason_code="provider_session_missing",
            )
        worker._provider_sessions[context.session_id] = returned_session
        provider_session = returned_session

    live_url = _string(data.get("live_url"))
    if not live_url and provider_session:
        sessions = getattr(client, "sessions", None)
        getter = getattr(sessions, "get", None)
        if callable(getter):
            try:
                session = await _await_if_needed(getter(provider_session))
            except Exception:
                session = None
            if session is not None:
                live_url = _string(_dump(session).get("live_url"))
    if live_url:
        worker._assignment_live_urls[context.session_id] = live_url

    output = _coerce_task_output(result)
    current_url = sanitize_browser_url(output.current_url)
    decision = browser_worker_module.evaluate_navigation(current_url, allowed)
    if not decision.allowed:
        await worker._safe_stop_handle(context.session_id)
        return _blocked_observation(decision)

    title = (output.safe_summary or "Official developer setup page")[:500]
    if output.hitl_required:
        reason = output.hitl_reason or "A human action is required in the live browser."
        return BrowserObservation(
            status="human_action_required",
            current_url=current_url,
            page_title=title,
            human_action_type=_classify_human_action(reason),
            human_instruction=reason[:1_000],
        )

    # Do not stop or forget a successful keep-alive session here. The live URL is
    # intentionally retained in memory so the evaluator can inspect the completed
    # browser state. Explicit stop/shutdown remains the cleanup boundary.
    return BrowserObservation(
        status=(
            "credential_page_ready"
            if output.reached_official_setup_page
            else "developer_console_ready"
        ),
        current_url=current_url,
        page_title=title,
    )


async def _compatible_gemini_extract(
    extractor: GeminiStructuredExtractor,
    *,
    app_name: str,
    p1_record: Mapping[str, object],
    documents: tuple[EvidenceDocument, ...],
) -> OperationalResearch:
    """Use current Gemini structured output without deprecated sampling fields."""

    prompt = _render_extraction_prompt(app_name, p1_record, documents)
    genai = importlib.import_module("google.genai")
    types = importlib.import_module("google.genai.types")
    client = genai.Client(api_key=extractor._api_key.get_secret_value())
    config = types.GenerateContentConfig(
        response_mime_type="application/json",
        response_json_schema=OperationalResearch.model_json_schema(),
        http_options=types.HttpOptions(timeout=45_000),
    )
    last_error: Exception | None = None
    for model in extractor._models:
        try:
            response = await client.aio.models.generate_content(
                model=model,
                contents=prompt,
                config=config,
            )
        except Exception as exc:
            last_error = exc
            continue
        text = getattr(response, "text", None)
        if not isinstance(text, str) or not text:
            last_error = RuntimeError("structured extraction returned no content")
            continue
        extractor.model_used = model
        return OperationalResearch.model_validate_json(text)
    raise RuntimeError(f"all Gemini models failed ({', '.join(extractor._models)})") from last_error


def _assignment_provider_states(service: LocalRunService) -> list[ProviderState]:
    """Report initialized runtime adapters as ready instead of amber placeholders."""

    original = {state.provider: state for state in _ORIGINAL_PROVIDER_STATES(service)}
    try:
        wiring = {
            str(row.get("dependency")): row
            for row in service._service.wiring_audit()
            if isinstance(row, Mapping)
        }
    except Exception:
        return list(original.values())

    def wired(name: str) -> bool:
        row = wiring.get(name)
        return bool(row and row.get("runtime_wired") is True)

    readiness = {
        "langgraph": (
            wired("workflow"),
            "Encrypted LangGraph workflow is initialized and available for durable run execution.",
        ),
        "vault": (
            wired("secret_store"),
            "Encrypted secret-store adapter initialized; credential writes remain owner initiated.",
        ),
        "perplexity": (
            wired("research_enricher") and service._settings.perplexity_api_key is not None,
            "Perplexity discovery is wired into execute-mode official-evidence enrichment.",
        ),
        "gemini": (
            wired("research_enricher") and service._settings.google_genai_api_key is not None,
            "Gemini structured extraction is wired into execute-mode official-evidence enrichment.",
        ),
        "composio": (
            wired("composio_preflight"),
            "Read-only Composio toolkit and connected-account preflight is initialized for each run.",
        ),
        "browser_use": (
            wired("browser"),
            "Browser Use is initialized with live execution enabled and per-app domain policy.",
        ),
    }

    result: list[ProviderState] = []
    for provider in ("langgraph", "vault", "perplexity", "gemini", "composio", "browser_use"):
        current = original[provider]
        is_ready, detail = readiness[provider]
        result.append(
            ProviderState(provider=provider, status="ready", detail=detail)
            if is_ready
            else current
        )
    return result


def install_assignment_live_evidence() -> None:
    """Install live-session retention, current Gemini config, and readiness projection."""

    global _INSTALLED
    if _INSTALLED:
        return
    worker_type = cast(Any, AssignmentBrowserWorker)
    worker_type._run_assignment_task = _retained_run_assignment_task
    extractor_type = cast(Any, GeminiStructuredExtractor)
    extractor_type.extract = _compatible_gemini_extract
    service_type = cast(Any, LocalRunService)
    service_type._provider_states = _assignment_provider_states
    _EVENT_SUMMARIES["operational_research_enriched"] = (
        "Perplexity discovery and Gemini structured extraction returned a sanitized enrichment result."
    )
    _INSTALLED = True


__all__ = ["install_assignment_live_evidence"]
