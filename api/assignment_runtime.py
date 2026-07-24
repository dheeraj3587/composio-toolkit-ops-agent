"""Assignment-focused live execution bootstrap for the reviewed 10-app matrix.

This module keeps the existing plan-only path untouched. In
``execute_when_configured`` mode it enables a bounded browser inspection for every
reviewed app that has an official browser surface, while preserving Sherlock's
verified blocked result.

The bootstrap is imported only by ``api.main`` (the production ASGI entry point).
Tests that import ``api.app`` continue to exercise the conservative core runtime.
"""

from __future__ import annotations

import importlib
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import uuid4

import ops.browser_host_policy as browser_policy_module
import ops.browser_worker as browser_worker_module
import ops.composio_capability as composio_module
from ops.browser_api_trace_catalog import get_browser_api_trace
from ops.browser_link_log import log_event, url_host
from ops.browser_host_policy import (
    BrowserAllowedHosts,
    BrowserHostPolicy,
    evaluate_navigation,
)
from ops.browser_worker import (
    BrowserObservation,
    BrowserSessionContext,
    BrowserTaskOutput,
    BrowserWorker,
    _await_if_needed,
    _blocked_observation,
    _classify_human_action,
    _coerce_task_output,
    _dump,
    _isoformat,
    _official_target_url,
    _render_browser_task,
    _string,
    sanitize_browser_url,
    validate_allowed_domains,
)
from ops.composio_capability import (
    ComposioCapabilityPreflight,
    ComposioCapabilityReport,
)
from ops.config import Settings
from ops.models import OperationalResearch, OperationsRequest
from ops.provider_errors import ProviderContractError, ProviderOperationError

_INACTIVITY_WINDOW = timedelta(minutes=15)
_MAXIMUM_WINDOW = timedelta(hours=4)

# Nine apps have a real official browser surface. Sherlock remains blocked by
# verified P1 evidence and is still processed end to end without launching a
# browser session.
_ASSIGNMENT_POLICIES: dict[str, BrowserHostPolicy] = {
    "hubspot": BrowserHostPolicy(
        app_slug="hubspot",
        active=True,
        exact_hosts=("developers.hubspot.com", "app.hubspot.com"),
    ),
    "pipedrive": BrowserHostPolicy(
        app_slug="pipedrive",
        active=True,
        exact_hosts=("developers.pipedrive.com", "app.pipedrive.com", "oauth.pipedrive.com"),
        vendor_wildcard_domains=("pipedrive.com",),
    ),
    "attio": BrowserHostPolicy(
        app_slug="attio",
        active=True,
        exact_hosts=("docs.attio.com", "app.attio.com", "build.attio.com"),
    ),
    "twenty": BrowserHostPolicy(
        app_slug="twenty",
        active=True,
        exact_hosts=("api.twenty.com", "app.twenty.com", "docs.twenty.com"),
        allows_configured_runtime_host=True,
    ),
    "zendesk": BrowserHostPolicy(
        app_slug="zendesk",
        active=True,
        exact_hosts=("developer.zendesk.com", "support.zendesk.com"),
        vendor_wildcard_domains=("zendesk.com",),
    ),
    "google-ads": BrowserHostPolicy(
        app_slug="google-ads",
        active=True,
        exact_hosts=(
            "developers.google.com",
            "ads.google.com",
            "console.cloud.google.com",
            "accounts.google.com",
        ),
    ),
    "whatsapp-business": BrowserHostPolicy(
        app_slug="whatsapp-business",
        active=True,
        exact_hosts=(
            "developers.facebook.com",
            "business.facebook.com",
            "www.facebook.com",
        ),
    ),
    "salesforce": BrowserHostPolicy(
        app_slug="salesforce",
        active=True,
        exact_hosts=(
            "developer.salesforce.com",
            "login.salesforce.com",
            "test.salesforce.com",
        ),
    ),
    "close": BrowserHostPolicy(
        app_slug="close",
        active=True,
        exact_hosts=("app.close.com", "developer.close.com"),
    ),
    # Additive live-demo app. Hubstaff is NOT part of the immutable P1 snapshot;
    # it is seeded only in this production assignment layer so its self-serve
    # sign-in (password-first, with email-OTP fallback) can be demonstrated
    # end to end in the live browser. The P1 files remain untouched.
    "hubstaff": BrowserHostPolicy(
        app_slug="hubstaff",
        active=True,
        exact_hosts=(
            "account.hubstaff.com",
            "app.hubstaff.com",
            "hubstaff.com",
            "developer.hubstaff.com",
        ),
        vendor_wildcard_domains=("hubstaff.com",),
    ),
    "sherlock": BrowserHostPolicy(app_slug="sherlock", active=False),
}


# Reviewed live-matrix apps with no self-serve credential path: even though they
# expose a browser surface, obtaining production API access requires vendor
# approval, so the run sends a single controlled Composio Gmail outreach instead
# of attempting autonomous browser onboarding + credential capture.
_GATED_OUTREACH_APPS: frozenset[str] = frozenset({"google-ads", "whatsapp-business", "close"})


# Additive live-demo app records. These are NOT part of the verified P1
# snapshot and never claim to be: every field is a truthful, hand-authored
# demo seed used only so an additional self-serve app can be onboarded live.
# When the immutable P1 lookup misses one of these apps, the production
# assignment layer supplies this record so the normal self-serve -> browser
# path runs. The P1 files, their hashes, and their provenance are untouched.
_DEMO_APP_RECORDS: dict[str, dict[str, Any]] = {
    "hubstaff": {
        "app": "Hubstaff",
        "category": "Time Tracking & Workforce",
        "one_liner": (
            "Time tracking and workforce management. Live-demo seed (not part of the "
            "verified P1 snapshot)."
        ),
        "auth_methods": ["Email + Password", "Email OTP"],
        "access_model": {
            "kind": "Self-Serve",
            "note": "Public self-serve sign-up and sign-in at account.hubstaff.com.",
        },
        "api_type": "REST",
        "api_breadth": "Moderate",
        "existing_mcp": "None",
        "composio_toolkit": "No",
        "buildability": "Moderate",
        "main_blocker": "None known for the browser onboarding demo.",
        "recommended_next_action": "Build Now",
        "evidence_urls": ["https://account.hubstaff.com/signin"],
        "confidence": 0.5,
        "verification_status": "Auto",
        "slug": "hubstaff",
        "primary_docs_url": "https://developer.hubstaff.com/",
        "rate_limit_note": "Not characterized (live-demo seed).",
        "last_verified": "2026-07-24",
    },
}


def assignment_policy(app_slug: str) -> BrowserHostPolicy | None:
    """Return the assignment matrix policy without mutating global state."""

    return _ASSIGNMENT_POLICIES.get(app_slug)


def _demo_seed_record(normalized_query: str) -> Any | None:
    """Return a synthesized P1 record for an additive live-demo app, if any.

    The lookup key is the same normalized (NFKC + casefolded) app/slug key the
    P1 adapter uses, so either the display name or the slug resolves.
    """

    from ops.p1_adapter import P1AppRecord

    payload = _DEMO_APP_RECORDS.get(normalized_query)
    if payload is None:
        return None
    return P1AppRecord.model_validate(payload)


def assignment_allowed_hosts(research: OperationalResearch) -> BrowserAllowedHosts:
    """Resolve exact reviewed hosts for assignment browser inspection."""

    policy = assignment_policy(research.app_slug)
    if policy is None or not policy.active:
        raise ProviderContractError(
            phase=5,
            capability="assignment browser inspection",
            reason_code="browser_policy_inactive_for_app",
        )
    return BrowserAllowedHosts(
        app_slug=policy.app_slug,
        exact_hosts=policy.exact_hosts,
        vendor_wildcard_domains=policy.vendor_wildcard_domains,
    )


class AssignmentComposioCapabilityPreflight(ComposioCapabilityPreflight):
    """Preserve the read-only preflight while allowing an assignment inspection.

    The returned report is explicit that the normal managed-auth decision was
    overridden only for the assignment browser demonstration. No Composio
    connection is created and no Gmail action is enabled.
    """

    async def evaluate(
        self,
        *,
        app_name: str,
        app_slug: str | None = None,
        required_tools: Sequence[str] = (),
    ) -> ComposioCapabilityReport:
        report = await super().evaluate(
            app_name=app_name,
            app_slug=app_slug,
            required_tools=required_tools,
        )
        if report.capability_state in {
            "custom_auth_or_approval_required",
            "toolkit_unavailable",
        }:
            return report
        return report.model_copy(
            update={
                "capability_state": "custom_auth_or_approval_required",
                "reason_code": "assignment_browser_inspection_enabled",
                "detail": (
                    "Assignment execution mode keeps the read-only Composio result "
                    f"({report.capability_state}) but also performs a bounded official-site "
                    "browser inspection."
                ),
            }
        )


class AssignmentBrowserWorker(BrowserWorker):
    """Launch the real task directly instead of creating an empty session first."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        client: object | None = None,
    ) -> None:
        super().__init__(settings=settings, client=client)
        self._provider_sessions: dict[str, str] = {}
        self._assignment_live_urls: dict[str, str] = {}
        self._assignment_research: dict[str, OperationalResearch] = {}

    async def start(self, profile_id: str | None) -> BrowserSessionContext:
        """Create the real Browser Use session up front and capture its live URL.

        The provider session (and its signed live-view URL) exists the moment the
        session is created, before any task runs. Creating it here, instead of
        deferring to the first ``client.run`` call, means the embedded live view
        and HITL are available for the entire duration of the autonomous task
        rather than only after it finishes. The bounded onboarding task is then
        run against this same ``session_id``.
        """

        self._require_configuration()
        client = self._get_client()
        create_kwargs: dict[str, Any] = {
            "keep_alive": True,
            "enable_recording": False,
            "max_cost_usd": self._settings.browser_use_max_cost_usd,
        }
        if profile_id:
            create_kwargs["profile_id"] = profile_id
        try:
            session = await _await_if_needed(client.sessions.create(**create_kwargs))
        except Exception as exc:
            log_event("browser.session.create_error", level=40, error=type(exc).__name__)
            raise ProviderOperationError(
                capability="Browser Use session",
                reason_code="provider_outcome_unknown",
            ) from None
        data = _dump(session)
        session_id = _string(data.get("id"))
        if not session_id:
            log_event("browser.session.create_no_id", level=40)
            raise ProviderOperationError(
                capability="Browser Use session",
                reason_code="provider_outcome_unknown",
            )
        # The real provider session id is the durable handle from here on.
        self._provider_sessions[session_id] = session_id
        live_url = _string(data.get("live_url"))
        if live_url:
            self._assignment_live_urls[session_id] = live_url
        log_event(
            "browser.session.created",
            handle=session_id,
            live_view_available=bool(live_url),
            live_url_host=url_host(live_url),
        )
        now = datetime.now(UTC)
        return BrowserSessionContext(
            profile_id=profile_id or session_id,
            session_id=session_id,
            live_view_available=bool(live_url),
            allowed_domains=(),
            created_at=_isoformat(now),
            inactivity_expires_at=_isoformat(now + _INACTIVITY_WINDOW),
            maximum_expires_at=_isoformat(now + _MAXIMUM_WINDOW),
        )

    async def navigate_onboarding(
        self,
        context: BrowserSessionContext,
        research: OperationalResearch,
        *,
        sensitive_data: Mapping[str, str] | None = None,
    ) -> BrowserObservation:
        self._assignment_research[context.session_id] = research
        return await self._run_assignment_task(
            context=context,
            research=research,
            resume_signal=None,
            sensitive_data=sensitive_data,
        )

    async def resume_after_hitl(
        self,
        context: BrowserSessionContext,
        signal: str,
        research: OperationalResearch | None = None,
        *,
        sensitive_data: Mapping[str, str] | None = None,
        provider_session_id: str | None = None,
    ) -> BrowserObservation:
        log_event(
            "browser.resume.begin",
            handle=context.session_id,
            signal=signal,
            has_research=bool(research or self._assignment_research.get(context.session_id)),
            provider_session_cached=context.session_id in self._provider_sessions,
            provider_session_supplied=bool(provider_session_id),
        )
        resolved = research or self._assignment_research.get(context.session_id)
        if resolved is None:
            log_event(
                "browser.resume.no_research",
                level=40,
                handle=context.session_id,
            )
            raise ProviderOperationError(
                capability="browser HITL resume",
                reason_code="verified_research_required",
            )
        # Reconnect to the live provider session. The in-memory maps are lost on
        # an API restart, so rebuild them from the durable state the caller
        # supplies (the provider session id and verified research) instead of
        # failing closed. The session itself keeps running on Browser Use.
        self._assignment_research.setdefault(context.session_id, resolved)
        if context.session_id not in self._provider_sessions and provider_session_id:
            self._provider_sessions[context.session_id] = provider_session_id
        if context.session_id not in self._provider_sessions:
            log_event(
                "browser.resume.no_provider_session",
                level=40,
                handle=context.session_id,
            )
            raise ProviderOperationError(
                capability="browser HITL resume",
                reason_code="provider_session_missing",
            )
        return await self._run_assignment_task(
            context=context,
            research=resolved,
            resume_signal=signal,
            sensitive_data=sensitive_data,
        )

    def provider_session_id(self, handle: str) -> str | None:
        """Return the live provider session id bound to a local handle, if any."""

        return self._provider_sessions.get(handle)

    def live_url(self, session_id: str) -> str | None:
        return self._assignment_live_urls.get(session_id)

    async def recover_live_url(self, handle: str, provider_session_id: str) -> str | None:
        """Best-effort refresh of the signed live URL from the running session.

        Used after an API restart cleared the in-memory URL: the provider session
        is still alive, so re-derive its live URL from Browser Use and re-cache
        it. Never persisted; owner-only, ephemeral.
        """

        cached = self._assignment_live_urls.get(handle)
        if cached:
            log_event("browser.recover.cached", handle=handle)
            return cached
        if not provider_session_id:
            log_event("browser.recover.no_provider_session", level=30, handle=handle)
            return None
        self._provider_sessions.setdefault(handle, provider_session_id)
        log_event("browser.recover.fetch", handle=handle)
        try:
            client = self._get_client()
            session = await _await_if_needed(client.sessions.get(provider_session_id))
        except Exception as exc:
            log_event(
                "browser.recover.error", level=30, handle=handle, error=type(exc).__name__
            )
            return None
        live_url = _string(_dump(session).get("live_url"))
        if live_url:
            self._assignment_live_urls[handle] = live_url
            log_event("browser.recover.ok", handle=handle, live_url_host=url_host(live_url))
            return live_url
        log_event("browser.recover.miss", level=30, handle=handle)
        return None

    async def stop(self, context: BrowserSessionContext) -> None:
        await self._safe_stop_handle(context.session_id)

    async def _safe_stop_handle(self, handle: str) -> None:
        provider_session = self._provider_sessions.pop(handle, None)
        self._assignment_live_urls.pop(handle, None)
        self._assignment_research.pop(handle, None)
        if not provider_session:
            return
        client = self._client
        if client is None:
            return
        try:
            await client.sessions.stop(provider_session)
        except Exception:
            pass

    async def _run_assignment_task(
        self,
        *,
        context: BrowserSessionContext,
        research: OperationalResearch,
        resume_signal: str | None,
        sensitive_data: Mapping[str, str] | None = None,
    ) -> BrowserObservation:
        self._require_configuration()
        allowed = assignment_allowed_hosts(research)
        patterns = validate_allowed_domains(allowed.patterns())
        trace = get_browser_api_trace(research.app_slug)
        target_url = _official_target_url(
            research, patterns, preferred_url=trace.start_url if trace is not None else None
        )
        # Owner-submitted login credentials (if any) are injected as Browser Use v3
        # secure ``sensitive_data`` placeholders; only their key names reach the
        # task text, never their values.
        login_fields = tuple(sensitive_data) if sensitive_data else ()
        task = _render_browser_task(target_url, patterns, resume_signal, login_fields, trace=trace)
        client = self._get_client()

        run_kwargs: dict[str, Any] = {
            "output_schema": BrowserTaskOutput,
            "model": self._settings.browser_use_model,
            "keep_alive": True,
            "max_cost_usd": self._settings.browser_use_max_cost_usd,
            "enable_recording": False,
            "allowed_domains": list(patterns),
        }
        if sensitive_data:
            run_kwargs["sensitive_data"] = dict(sensitive_data)
        provider_session = self._provider_sessions.get(context.session_id)
        if provider_session:
            run_kwargs["session_id"] = provider_session
        else:
            run_kwargs["start_url"] = target_url

        try:
            result = await _await_if_needed(client.run(task, **run_kwargs))
        except Exception:
            await self._safe_stop_handle(context.session_id)
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
            await self._safe_stop_handle(context.session_id)
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
            self._provider_sessions[context.session_id] = returned_session

        live_url = _string(data.get("live_url"))
        if live_url:
            self._assignment_live_urls[context.session_id] = live_url

        output = _coerce_task_output(result)
        current_url = sanitize_browser_url(output.current_url)
        decision = evaluate_navigation(current_url, allowed)
        if not decision.allowed:
            await self._safe_stop_handle(context.session_id)
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

        await self._safe_stop_handle(context.session_id)
        return BrowserObservation(
            status=(
                "credential_page_ready"
                if output.reached_official_setup_page
                else "developer_console_ready"
            ),
            current_url=current_url,
            page_title=title,
        )


def _assignment_after_route(
    workflow: object,
    state: Mapping[str, object],
) -> str:
    """Use browser inspection for every runnable app in the 10-app matrix."""

    del workflow
    request = OperationsRequest.model_validate(state["request"])
    if request.dry_run:
        return "finalize"
    if state.get("access_route") in {"blocked", "unknown"}:
        return "finalize"
    slug = str(state.get("app_slug") or "")
    # Gated live-matrix apps go straight to controlled outreach; the human cannot
    # self-serve a credential in the browser, so a vendor email is the honest path.
    if slug in _GATED_OUTREACH_APPS:
        return "outreach_send"
    policy = assignment_policy(slug)
    if policy is not None and policy.active:
        return "browser_start"
    return "outreach_send"


def _install_demo_aware_lookup() -> None:
    """Make the P1 adapter additively resolve live-demo apps on a snapshot miss.

    The immutable snapshot is still loaded and verified first; only when it
    reports ``not_found`` for an allowlisted demo app do we return a synthesized
    ``found`` result. The real snapshot provenance is reused unchanged, and the
    P1 files are never modified.
    """

    p1_module = cast(Any, importlib.import_module("ops.p1_adapter"))
    if getattr(p1_module.P1OperationalAdapter, "_demo_aware_installed", False):
        return
    original_lookup = p1_module.P1OperationalAdapter.lookup
    p1_lookup_found = p1_module.P1LookupFound
    p1_lookup_not_found = p1_module.P1LookupNotFound

    def _demo_aware_lookup(self: Any, app_name_or_slug: str) -> Any:
        result = original_lookup(self, app_name_or_slug)
        if isinstance(result, p1_lookup_not_found):
            seed = _demo_seed_record(result.normalized_query)
            if seed is not None:
                return p1_lookup_found(
                    query=result.query,
                    normalized_query=result.normalized_query,
                    matched_by="slug",
                    record=seed,
                    provenance=result.provenance,
                )
        return result

    p1_module.P1OperationalAdapter.lookup = _demo_aware_lookup
    p1_module.P1OperationalAdapter._demo_aware_installed = True


_INSTALLED = False


def install_assignment_runtime() -> None:
    """Install the production-only assignment execution adapters once."""

    global _INSTALLED
    if _INSTALLED:
        return

    browser_policy_module._BROWSER_POLICIES.update(_ASSIGNMENT_POLICIES)
    _install_demo_aware_lookup()
    browser_worker_module.BrowserWorker = AssignmentBrowserWorker  # type: ignore[misc]
    composio_module.ComposioCapabilityPreflight = (  # type: ignore[misc]
        AssignmentComposioCapabilityPreflight
    )

    # ops.run_service imports these classes directly, so updating only their
    # defining modules does not replace already-bound runtime aliases.
    run_service_module = cast(Any, importlib.import_module("ops.run_service"))
    run_service_module.BrowserWorker = AssignmentBrowserWorker
    run_service_module.ComposioCapabilityPreflight = AssignmentComposioCapabilityPreflight

    graph_module = importlib.import_module("ops.graph")
    workflow_type = cast(Any, graph_module).DurableOperationsWorkflow
    workflow_type._after_route = _assignment_after_route
    _INSTALLED = True


__all__ = [
    "AssignmentBrowserWorker",
    "AssignmentComposioCapabilityPreflight",
    "assignment_allowed_hosts",
    "assignment_policy",
    "install_assignment_runtime",
]
