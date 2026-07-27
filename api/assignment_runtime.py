"""Assignment-focused live execution bootstrap for the verified app catalog.

This module keeps the existing plan-only path untouched. In
``execute_when_configured`` mode it enables a bounded browser inspection for every
app that has an official browser surface: the reviewed matrix below uses its
hand-verified hosts, and every other self-serve app in the P1 snapshot falls back
to an allowlist derived from its own verified research hosts (see
``ops.derived_browser_policy``). Sherlock's verified blocked result is preserved,
and apps with no self-serve credential path keep their outreach route.

The bootstrap is imported only by ``api.main`` (the production ASGI entry point).
Tests that import ``api.app`` continue to exercise the conservative core runtime.
"""

from __future__ import annotations

import asyncio
import importlib
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import uuid4

import httpx

import ops.browser_host_policy as browser_policy_module
import ops.browser_worker as browser_worker_module
import ops.composio_capability as composio_module
from ops.browser_api_trace_catalog import get_browser_api_trace
from ops.browser_host_policy import (
    BrowserAllowedHosts,
    BrowserHostPolicy,
    evaluate_navigation,
)
from ops.browser_link_log import log_event, url_host
from ops.browser_target_selection import derive_account_state, select_browser_target
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
    is_allowed_browser_url,
    sanitize_browser_url,
    to_browser_sensitive_data,
    validate_allowed_domains,
)
from ops.composio_capability import (
    ComposioCapabilityPreflight,
    ComposioCapabilityReport,
)
from ops.config import Settings
from ops.derived_browser_policy import derive_browser_host_policy
from ops.models import OperationalResearch, OperationsRequest
from ops.provider_errors import ProviderContractError, ProviderOperationError
from ops.routing import decide_access

_INACTIVITY_WINDOW = timedelta(minutes=15)
_MAXIMUM_WINDOW = timedelta(hours=4)
# The unpatched core graph nodes this layer wraps. ``api`` must not import
# ``ops.graph`` (the workflow is reached only through the application service), so
# the type is resolved through the module registry instead of an import.
#
# Resolution is cached and MUST happen before the node is replaced: resolving a
# node after patching would return this module's own wrapper and recurse forever.
# ``install_assignment_runtime`` therefore primes the cache before it assigns, and
# a direct call before installation still resolves the genuine core node.
_CORE_NODES: dict[str, Any] = {}


def _core_workflow_type() -> Any:
    return cast(Any, importlib.import_module("ops.graph")).DurableOperationsWorkflow


def _core_node(name: str) -> Any:
    """Return the original core graph node, resolved once on first use."""

    if name not in _CORE_NODES:
        _CORE_NODES[name] = getattr(_core_workflow_type(), name)
    return _CORE_NODES[name]


# Routes that cannot yield a self-serve credential on their own: the browser
# inspection still runs (it is what a human would do first) and the controlled
# vendor outreach is sent afterwards.
_GATED_ROUTES: frozenset[str] = frozenset({"approval_required", "partner_gated"})

# Reviewed apps with a real official browser surface, keyed by canonical slug.
# The first block is the original live matrix; the self-serve batch below it was
# activated for autonomous navigation (Level A). Sherlock remains blocked by
# verified P1 evidence and is still processed end to end without launching a
# browser session.
_ASSIGNMENT_POLICIES: dict[str, BrowserHostPolicy] = {
    "hubspot": BrowserHostPolicy(
        app_slug="hubspot",
        active=True,
        exact_hosts=("developers.hubspot.com", "app.hubspot.com"),
        # Sign-in and regional app subdomains (app-na2, app-eu1, ...) plus the
        # emailed one-time sign-in link all live under *.hubspot.com.
        vendor_wildcard_domains=("hubspot.com",),
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
    # --- Self-serve batch activated for autonomous navigation (Level A) ---
    # These nine apps already ship verified STRICT APP TRACE steering (see
    # ops/browser_api_traces.json) and are classified self_serve by verified P1
    # evidence. Hosts below were confirmed on 2026-07-24 by following each app's
    # live sign-in -> developer/API-settings -> credential-page redirect chain.
    # The agent navigates to the credential page and the owner submits the value;
    # hands-off capture (Level B) is added per app only after a live token-format
    # verification (see credential_capture_specs.py).
    "podio": BrowserHostPolicy(
        app_slug="podio",
        active=True,
        # Sign-in and the API-client page both live on podio.com/settings/api;
        # orgs are path-based, so no per-tenant subdomain.
        exact_hosts=("podio.com", "developers.podio.com"),
    ),
    "zoho-crm": BrowserHostPolicy(
        app_slug="zoho-crm",
        active=True,
        # US data center. Zoho is multi-DC (accounts/api-console.zoho.{eu,in,
        # com.au,jp,...} and zohocloud.ca for Canada); non-US accounts need their
        # DC host added. Self Client OAuth credentials at api-console.zoho.com.
        exact_hosts=("accounts.zoho.com", "api-console.zoho.com"),
    ),
    "intercom": BrowserHostPolicy(
        app_slug="intercom",
        active=True,
        # Access token issued per app in the Developer Hub at app.intercom.com;
        # app.eu/app.au are the fixed regional data-hosting variants.
        exact_hosts=(
            "app.intercom.com",
            "app.eu.intercom.com",
            "app.au.intercom.com",
            "developers.intercom.com",
        ),
    ),
    "pylon": BrowserHostPolicy(
        app_slug="pylon",
        active=True,
        # Direct token generation at app.usepylon.com/settings/api-tokens.
        exact_hosts=("app.usepylon.com", "docs.usepylon.com"),
    ),
    "liveagent": BrowserHostPolicy(
        app_slug="liveagent",
        active=True,
        # Accounts are per-tenant <account>.ladesk.com; the API v3 key lives in
        # the tenant admin panel. www.liveagent.com is the login launcher.
        exact_hosts=("www.liveagent.com", "support.liveagent.com"),
        vendor_wildcard_domains=("ladesk.com",),
    ),
    "slack": BrowserHostPolicy(
        app_slug="slack",
        active=True,
        # Tokens live on api.slack.com/apps (app creation required). Workspaces
        # are <workspace>.slack.com and Enterprise Grid <org>.enterprise.slack.com,
        # all covered by the vendor wildcard; slack.com root serves sign-in.
        exact_hosts=("slack.com",),
        vendor_wildcard_domains=("slack.com",),
    ),
    "twilio": BrowserHostPolicy(
        app_slug="twilio",
        active=True,
        # Login form on www.twilio.com/login; Account SID + Auth Token and API
        # keys on console.twilio.com. login.twilio.com is Twilio's unified login.
        exact_hosts=(
            "console.twilio.com",
            "www.twilio.com",
            "login.twilio.com",
            "twilio.com",
        ),
    ),
    "zoho-cliq": BrowserHostPolicy(
        app_slug="zoho-cliq",
        active=True,
        # Same Zoho OAuth surface as CRM (US DC; multi-DC caveat applies).
        exact_hosts=("accounts.zoho.com", "api-console.zoho.com"),
    ),
    "pumble": BrowserHostPolicy(
        app_slug="pumble",
        active=True,
        # Pumble is a CAKE.com product: sign-in federates through
        # account.cake.com, the API add-on is installed via marketplace.cake.com,
        # and keys are generated inside the app at app.pumble.com.
        exact_hosts=(
            "app.pumble.com",
            "pumble.com",
            "account.cake.com",
            "marketplace.cake.com",
        ),
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


def resolved_browser_policy(research: OperationalResearch) -> BrowserHostPolicy | None:
    """Return the reviewed policy for an app, else one derived from its research.

    Precedence is deliberate:

    1. An ACTIVE reviewed policy always wins — the hand-verified hosts and any
       app-specific quirks (regional data centres, tenant wildcards) stay exactly
       as reviewed.
    2. An explicitly INACTIVE reviewed policy is a reviewed "no" (Sherlock) and
       blocks derivation entirely.
    3. Otherwise the allowlist is derived from the app's own verified research
       hosts, so the remaining apps in the P1 snapshot can actually execute
       instead of dead-ending at ``configuration_required``.

    ``None`` means no browser session may be launched for this app.
    """

    policy = assignment_policy(research.app_slug)
    if policy is not None:
        return policy if policy.active else None
    return derive_browser_host_policy(research)


def assignment_allowed_hosts(research: OperationalResearch) -> BrowserAllowedHosts:
    """Resolve the reviewed (or research-derived) hosts for browser inspection."""

    policy = resolved_browser_policy(research)
    if policy is None:
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


def assignment_browser_ready(research: OperationalResearch) -> bool:
    """True when a browser run for this app has both an allowlist and a target.

    Checked BEFORE the graph commits to a browser route so an app with no usable
    entry URL falls back to outreach instead of starting a paid session that would
    immediately fail with ``official_target_url_unavailable``. The account state is
    irrelevant here: it only reorders the same candidate set.
    """

    try:
        allowed = assignment_allowed_hosts(research)
        patterns = validate_allowed_domains(allowed.patterns())
        target = select_browser_target(
            research=research,
            trace=get_browser_api_trace(research.app_slug),
            allowed_domains=patterns,
            account_state="unknown",
            is_allowed_url=is_allowed_browser_url,
            fallback_mode="browser_use",
        )
    except (ProviderContractError, ValueError):
        return False
    return target is not None


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
        # handle -> Browser Use profile id (carries the persisted login state).
        self._profile_ids: dict[str, str] = {}

    def _get_client(self) -> Any:
        """Return a Browser Use client bound to the CURRENT event loop.

        The SDK's async HTTP client is bound to the event loop it was created in.
        Session creation, navigation, and HITL resume each run in their own
        ``asyncio.run`` loop (one per graph node / worker call), so a cached
        client would be reused across loops and raise a RuntimeError on the next
        request. Reuse only an explicitly injected client (offline tests); in
        production create a fresh client for each call. The live provider session
        is server-side and is referenced across clients by its ``session_id``.
        """

        if self._client is not None:
            return self._client
        self._require_configuration()
        api_key = self._settings.browser_use_api_key
        assert api_key is not None  # guaranteed by _require_configuration above
        module = importlib.import_module("browser_use_sdk.v3")
        return module.AsyncBrowserUse(
            api_key=api_key.get_secret_value(),
            timeout=120.0,
        )

    async def _close_if_owned(self, client: Any) -> None:
        """Close a per-call temporary client to release its HTTP connections.

        An injected client (offline tests, ``self._client`` set) is owned by the
        caller and left open; only a client this worker created is closed.
        """

        if self._client is None and callable(getattr(client, "close", None)):
            try:
                await client.close()
            except Exception:
                pass

    async def start(
        self,
        profile_id: str | None,
        *,
        app_slug: str = "",
        account_ref: str | None = None,
        secret_scope: str | None = None,
        use_storage_state: bool = False,
        live_view_mode: str = "screenshot",
    ) -> BrowserSessionContext:
        """Create the real Browser Use session up front and capture its live URL.

        The provider session (and its signed live-view URL) exists the moment the
        session is created, before any task runs. Creating it here, instead of
        deferring to the first ``client.run`` call, means the embedded live view
        and HITL are available for the entire duration of the autonomous task
        rather than only after it finishes. The bounded onboarding task is then
        run against this same ``session_id``.

        The Playwright-specific metadata is accepted and IGNORED so the graph has a
        single call site; Browser Use's session-creation request is unchanged.
        """

        del app_slug, account_ref, secret_scope, use_storage_state, live_view_mode
        self._require_configuration()
        client = self._get_client()
        # Attach a fresh Browser Use profile so the autonomous login state
        # (cookies/localStorage) persists. After sign-in, a standalone browser
        # opened from this profile is already logged in, which lets a
        # deterministic Playwright/CDP read capture the API token with no human
        # copy and without the LLM ever reading the secret.
        if not profile_id:
            try:
                profile = await _await_if_needed(
                    client.profiles.create(name=f"ops-{uuid4().hex[:12]}")
                )
                profile_id = _string(_dump(profile).get("id")) or None
            except Exception as exc:
                log_event("browser.profile.create_error", level=30, error=type(exc).__name__)
                profile_id = None
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
        if profile_id:
            self._profile_ids[session_id] = profile_id
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
        account_creation_requested: bool = False,
        credential_creation_policy: str = "reuse_only",
    ) -> BrowserObservation:
        self._assignment_research[context.session_id] = research
        return await self._run_assignment_task(
            context=context,
            research=research,
            resume_signal=None,
            sensitive_data=sensitive_data,
            account_creation_requested=account_creation_requested,
            credential_creation_policy=credential_creation_policy,
        )

    async def resume_after_hitl(
        self,
        context: BrowserSessionContext,
        signal: str,
        research: OperationalResearch | None = None,
        *,
        sensitive_data: Mapping[str, str] | None = None,
        credential_creation_policy: str = "reuse_only",
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
            credential_creation_policy=credential_creation_policy,
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
            log_event("browser.recover.error", level=30, handle=handle, error=type(exc).__name__)
            return None
        live_url = _string(_dump(session).get("live_url"))
        if live_url:
            self._assignment_live_urls[handle] = live_url
            log_event("browser.recover.ok", handle=handle, live_url_host=url_host(live_url))
            return live_url
        log_event("browser.recover.miss", level=30, handle=handle)
        return None

    async def auto_capture_credentials(
        self, handle: str, app_slug: str, secret_store: Any
    ) -> dict[str, str] | None:
        """Deterministically read the app's API credential over CDP and vault it.

        Opens a standalone browser from the session's logged-in profile, goes to
        the app's token settings page, reads the credential value by strict
        pattern (never via the LLM), writes it to the encrypted vault, and
        returns only the ``vault://`` reference. Returns None when capture is not
        possible so the caller can fall back to owner submission.
        """

        import importlib
        import re
        from urllib.parse import urlsplit

        from ops.credential_capture_specs import get_capture_spec

        spec = get_capture_spec(app_slug)
        if spec is None:
            log_event("capture.no_spec", handle=handle, app_slug=app_slug)
            return None
        profile_id = self._profile_ids.get(handle)
        if not profile_id or secret_store is None:
            log_event("capture.no_profile", level=30, handle=handle, app_slug=app_slug)
            return None

        client = self._get_client()
        try:
            browser = await _await_if_needed(client.browsers.create(profile_id=profile_id))
        except Exception as exc:
            log_event(
                "capture.browser_create_error", level=40, handle=handle, error=type(exc).__name__
            )
            return None
        bdata = _dump(browser)
        cdp_url = _string(bdata.get("cdp_url"))
        browser_id = _string(bdata.get("id"))
        if not cdp_url:
            log_event("capture.no_cdp_url", level=40, handle=handle)
            await self._stop_standalone_browser(client, browser_id)
            return None

        pattern = re.compile(spec.value_pattern)
        log_event("capture.begin", handle=handle, app_slug=app_slug, target_host=url_host(spec.url))
        try:
            pw_module = importlib.import_module("playwright.async_api")
            async with pw_module.async_playwright() as pw:
                pw_browser = await pw.chromium.connect_over_cdp(cdp_url, timeout=30_000)
                try:
                    context = (
                        pw_browser.contexts[0]
                        if pw_browser.contexts
                        else await pw_browser.new_context()
                    )
                    page = context.pages[0] if context.pages else await context.new_page()
                    await page.goto(spec.url, wait_until="domcontentloaded", timeout=45_000)
                    await page.wait_for_timeout(2_500)
                    host = urlsplit(page.url).hostname or ""
                    if not (host == spec.vendor_domain or host.endswith("." + spec.vendor_domain)):
                        log_event("capture.off_domain", level=40, handle=handle, current_host=host)
                        return None
                    inputs = page.locator("input")
                    total = await inputs.count()
                    token: str | None = None
                    for index in range(min(total, 60)):
                        try:
                            value = await inputs.nth(index).input_value(timeout=2_000)
                        except Exception:
                            continue
                        candidate = value.strip() if isinstance(value, str) else ""
                        if candidate and pattern.match(candidate):
                            token = candidate
                            break
                    if token is None:
                        log_event("capture.value_not_found", level=30, handle=handle, inputs=total)
                        return None
                    reference = secret_store.put(
                        app_slug=app_slug, kind=spec.field_kind, value=token
                    )
                    del token
                    log_event("capture.stored", handle=handle, app_slug=app_slug)
                    return {spec.field_kind: reference}
                finally:
                    try:
                        await pw_browser.close()
                    except Exception:
                        pass
        except Exception as exc:
            log_event("capture.error", level=40, handle=handle, error=type(exc).__name__)
            return None
        finally:
            await self._stop_standalone_browser(client, browser_id)

    async def _stop_standalone_browser(self, client: Any, browser_id: str | None) -> None:
        if not browser_id:
            return
        try:
            await _await_if_needed(client.browsers.stop(browser_id))
        except Exception:
            pass

    async def stop(self, context: BrowserSessionContext) -> None:
        await self._safe_stop_handle(context.session_id)

    async def _safe_stop_handle(self, handle: str) -> None:
        provider_session = self._provider_sessions.pop(handle, None)
        self._assignment_live_urls.pop(handle, None)
        self._assignment_research.pop(handle, None)
        profile_id = self._profile_ids.pop(handle, None)
        if not provider_session and not profile_id:
            return
        try:
            client = self._get_client()
        except Exception:
            return
        try:
            if provider_session:
                try:
                    await client.sessions.stop(provider_session)
                except Exception:
                    pass
            # Delete the per-run profile so accumulated login state cannot exhaust
            # the provider profile quota over repeated runs.
            if profile_id:
                try:
                    await client.profiles.delete(profile_id)
                except Exception:
                    pass
        finally:
            await self._close_if_owned(client)

    async def _run_assignment_task(
        self,
        *,
        context: BrowserSessionContext,
        research: OperationalResearch,
        resume_signal: str | None,
        sensitive_data: Mapping[str, str] | None = None,
        account_creation_requested: bool = False,
        credential_creation_policy: str = "reuse_only",
    ) -> BrowserObservation:
        del credential_creation_policy
        self._require_configuration()
        allowed = assignment_allowed_hosts(research)
        patterns = validate_allowed_domains(allowed.patterns())
        trace = get_browser_api_trace(research.app_slug)
        target_url = _official_target_url(
            research,
            patterns,
            trace=trace,
            account_state=derive_account_state(
                sensitive_data=sensitive_data,
                account_creation_requested=account_creation_requested,
            ),
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
            # DETECTION, NOT PROVIDER ENFORCEMENT. Browser Use v3 has no domain
            # allowlist field (neither RunTaskRequest nor CreateBrowserSessionRequest
            # declares one); this passes through the SDK's **extra and may be ignored
            # server-side. Real host restriction is the post-task evaluate_navigation
            # check below plus the STRICT APP TRACE + global hard stops in the task.
            # test_browser_use_contract.py guards this SDK reality against drift.
            "allowed_domains": list(patterns),
        }
        browser_secrets = to_browser_sensitive_data(sensitive_data)
        if browser_secrets:
            run_kwargs["sensitive_data"] = browser_secrets
        provider_session = self._provider_sessions.get(context.session_id)
        if provider_session:
            run_kwargs["session_id"] = provider_session
        else:
            run_kwargs["start_url"] = target_url

        try:
            result = await asyncio.wait_for(
                _await_if_needed(client.run(task, **run_kwargs)),
                timeout=self._settings.browser_use_task_timeout_seconds,
            )
        except TimeoutError:
            # This is our explicit wall-clock bound, not an ambiguous SDK socket
            # timeout. The provider session id is known, so stop it and its
            # temporary profile rather than leaving paid work running remotely.
            log_event(
                "browser.run.deadline_exceeded",
                level=40,
                handle=context.session_id,
            )
            await self._safe_stop_handle(context.session_id)
            raise ProviderOperationError(
                capability="browser onboarding",
                reason_code="provider_timeout",
            ) from None
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            # Ambiguous: a read/connect timeout means the remote agent MAY still be
            # running. Do NOT stop the session or record a clean failure — preserve
            # the session so a caller can reconcile it by id before any retry
            # re-executes a side effect. (Fixes: timeouts recorded as clean fails.)
            log_event(
                "browser.run.outcome_unknown",
                level=40,
                handle=context.session_id,
                error=type(exc).__name__,
            )
            raise ProviderOperationError(
                capability="browser onboarding",
                reason_code="provider_outcome_unknown",
            ) from None
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


def _assignment_route(
    workflow: Any,
    state: Mapping[str, object],
) -> dict[str, object]:
    """Let an executable assignment run proceed without weakening the core gate.

    The core route refuses a browser route whenever the verified research has no
    reviewed login/credential URL pair (``verified_browser_urls_missing``) or no
    hand-authored navigation trace (``browser_trace_not_reviewed``). Both are true
    for most of the P1 snapshot, which left those runs finalizing at
    ``configuration_required`` without ever executing. Here the run is allowed to
    continue only when this layer can prove it is actually executable: a resolved
    host allowlist AND a validated entry target. Every other core refusal, and
    every non-browser route, is returned untouched.
    """

    result = cast("dict[str, object]", _core_node("_route")(workflow, state))
    if result.get("route_reason_code") not in {
        "verified_browser_urls_missing",
        "browser_trace_not_reviewed",
    }:
        return result

    request = OperationsRequest.model_validate(state["request"])
    if request.dry_run:
        return result

    research = OperationalResearch.model_validate(state["operational_research"])
    decision = decide_access(research)
    if (
        not decision.is_final
        or decision.route not in {"self_serve", "hybrid"}
        or not assignment_browser_ready(research)
    ):
        return result

    audit_events = state.get("audit_events")
    audit_history = list(audit_events) if isinstance(audit_events, list) else []
    # A reviewed trace's start_url is validated when the catalog loads; a derived
    # target comes from the app's own verified research. Either way the worker
    # re-checks the target against this app's allowlist before navigating.
    return {
        "access_route": decision.route,
        "route_reason": decision.explanation,
        "route_reason_code": decision.reason_code,
        "status": "route_selected",
        "audit_events": [*audit_history, {"event_type": "route_selected"}],
    }


def _assignment_after_route(
    workflow: object,
    state: Mapping[str, object],
) -> str:
    """Use browser inspection for every app this layer can actually execute."""

    del workflow
    request = OperationsRequest.model_validate(state["request"])
    if request.dry_run:
        return "finalize"
    route = state.get("access_route")
    if route in {"blocked", "unknown"}:
        return "finalize"
    slug = str(state.get("app_slug") or "")
    # Gated live-matrix apps go straight to controlled outreach; the human cannot
    # self-serve a credential in the browser, so a vendor email is the honest path.
    if slug in _GATED_OUTREACH_APPS:
        return "outreach_send"
    policy = assignment_policy(slug)
    if policy is not None and policy.active:
        return "browser_start"
    # No reviewed policy: the app can still be driven in the browser using hosts
    # derived from its own verified research. This is the same treatment the
    # reviewed matrix already gives gated apps such as Salesforce and Zendesk; a
    # gated route additionally sends its vendor outreach after the inspection
    # (see ``_assignment_after_browser``).
    raw_research = state.get("operational_research")
    if isinstance(raw_research, Mapping):
        research = OperationalResearch.model_validate(raw_research)
        if assignment_browser_ready(research):
            log_event(
                "route.browser_from_derived_policy",
                app_slug=slug,
                access_route=str(route),
            )
            return "browser_start"
    return "outreach_send"


def _assignment_after_browser(
    workflow: Any,
    state: Mapping[str, object],
) -> str:
    """Keep the vendor outreach for gated apps that were browser-inspected first.

    The core rule sends only a ``hybrid`` run from a reached credential page to
    outreach. Approval- and partner-gated apps now reach the browser too, and for
    them the inspection alone is not an outcome: production access still needs the
    vendor, so the controlled Gmail outreach is still sent once.
    """

    node = cast("str", _core_node("_after_browser")(workflow, state))
    if node != "finalize" or state.get("gmail_thread_id"):
        return node
    if state.get("access_route") not in _GATED_ROUTES:
        return node
    observation = state.get("browser_observation")
    if not isinstance(observation, Mapping):
        return node
    if observation.get("status") not in {"credential_page_ready", "developer_console_ready"}:
        return node
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


def install_assignment_browser_policies() -> None:
    """Install the reviewed assignment host matrix in the current process.

    The API and isolated Playwright service are separate processes. Installing
    the matrix only from ``api.main`` left the browser service on the conservative
    core defaults, where HubSpot is intentionally inactive, so Chromium opened a
    blank page and then refused the first navigation. Keep this installer narrow:
    it changes only host-policy metadata and does not install Browser Use adapters
    or workflow monkey patches in the Playwright process.
    """

    browser_policy_module._BROWSER_POLICIES.update(_ASSIGNMENT_POLICIES)


def install_assignment_runtime() -> None:
    """Install the production-only assignment execution adapters once."""

    global _INSTALLED
    if _INSTALLED:
        return

    install_assignment_browser_policies()
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

    workflow_type = _core_workflow_type()
    # Capture the originals BEFORE replacing them, so the wrappers can never
    # resolve themselves and recurse.
    _core_node("_route")
    _core_node("_after_browser")
    workflow_type._route = _assignment_route
    workflow_type._after_route = _assignment_after_route
    workflow_type._after_browser = _assignment_after_browser
    _INSTALLED = True


__all__ = [
    "AssignmentBrowserWorker",
    "AssignmentComposioCapabilityPreflight",
    "assignment_allowed_hosts",
    "assignment_browser_ready",
    "assignment_policy",
    "install_assignment_browser_policies",
    "install_assignment_runtime",
    "resolved_browser_policy",
]
