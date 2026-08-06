"""One provider-aware projection of what the browser UI may actually do.

The interface previously derived its permissions from ``run.status`` alone, which
is wrong in both directions: a ``browser_running`` run is not necessarily on a
credential page, and Playwright interaction is available only during an explicit,
configuration-gated HITL pause. Only the backend can see provider capability,
trusted recorded events, and the policy opt-ins that gate each mutation endpoint,
so the decision is made here, once, and shipped to the client as explicit booleans.

Every capability defaults to False and becomes True only on positive evidence.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping

from api.models import (
    BrowserLifecycle,
    BrowserUiState,
    HitlRequestView,
    LiveViewMode,
)
from ops.browser.readiness import browser_configuration_state
from ops.core.config import Settings
from ops.core.state import BrowserProvider

# A credential may be submitted only after THIS trusted event was recorded. A
# running session proves nothing about having reached the credential page.
CREDENTIAL_PAGE_EVENT = "credential_page_ready"

# Recorded reconciliation reasons that mean the live session is genuinely gone.
SESSION_LOST_REASONS = frozenset(
    {
        "playwright_session_lost_on_restart",
        "browser_service_session_lost",
    }
)

# HITL action types an owner can actually clear by supplying sign-in credentials.
# A CAPTCHA, OTP, passkey, billing or consent gate is NOT one of them, so the
# login form must never be offered for those.
# Only a missing-login gate requires another email/password submission.
# Provider verification and account selection are completed directly
# through the interactive browser.
LOGIN_HITL_ACTIONS = frozenset({"login_required"})

# Terminal run statuses: no browser mutation is legal from any of them.
TERMINAL_RUN_STATUSES = frozenset({"completed", "blocked", "failed"})

# ``ResumeRequest.browser_verification`` carries a one-time code or reviewed HTTPS
# magic link through the transient browser boundary. It remains owner-policy gated.
OTP_SUBMISSION_SUPPORTED = True


def resolve_provider(
    settings: Settings,
    provider: BrowserProvider | None = None,
) -> BrowserProvider:
    """Resolve the backend this run's browser surface describes.

    A historical run row may still carry the retired ``browser_use`` value. It is
    reported back as recorded — the row is what happened — but Playwright is the
    only backend anything can run on now, so an absent value resolves to it.
    """

    del settings  # the deployment no longer chooses; there is one backend
    return provider or "playwright"


def session_lost_recorded(events: Collection[Mapping[str, object]]) -> bool:
    """Whether reconciliation recorded that this run's live session was lost."""

    for event in events:
        if str(event.get("event_type")) != "run_reconciled_on_startup":
            continue
        payload = event.get("payload")
        reason = str(payload.get("reason")) if isinstance(payload, Mapping) else ""
        if reason in SESSION_LOST_REASONS:
            return True
    return False


def project_browser_ui(
    *,
    settings: Settings,
    browser_provider: BrowserProvider | None = None,
    run_status: str,
    event_types: Collection[str],
    browser_session_id: str | None = None,
    hitl: HitlRequestView | None = None,
    screenshot_present: bool = False,
    session_lost: bool = False,
    plan_only: bool = False,
    owner_submission_ready: bool = False,
) -> BrowserUiState:
    """Project the browser capabilities for one run.

    ``event_types`` are the run's recorded audit event types (the trusted progress
    record). ``screenshot_present`` must be a real "a current frame exists" answer
    from the worker, never an assumption from the provider or the run status.
    """

    provider = resolve_provider(settings, browser_provider)
    configured = browser_configuration_state(settings, provider)
    credential_page_verified = CREDENTIAL_PAGE_EVENT in event_types
    session_started = bool(browser_session_id) or "browser_session_started" in event_types
    terminal = run_status in TERMINAL_RUN_STATUSES

    lifecycle, reason_code = _lifecycle(
        run_status=run_status,
        event_types=event_types,
        session_started=session_started,
        session_lost=session_lost,
        configured=configured,
        plan_only=plan_only,
        credential_page_verified=credential_page_verified,
    )

    # A live session is the precondition for any view at all.
    session_live = lifecycle in {"running", "waiting_for_hitl", "credential_page_ready"}
    live_view_mode = _live_view_mode(
        lifecycle=lifecycle,
        session_live=session_live,
        screenshot_present=screenshot_present,
        interactive_enabled=bool(getattr(settings, "browser_interactive_hitl_enabled", False)),
    )
    # Rule 9: interactivity is a capability, not a run state. Only a real
    # interactive remote during a human gate can be driven; a masked frame never
    # can be. The "or a hosted provider view" term went with the hosted backend.
    interaction_available = (
        live_view_mode == "interactive_remote" and lifecycle == "waiting_for_hitl"
    )

    # Rules 10 and 11: a lost session or a terminal run permits no mutation.
    mutations_allowed = session_live and not session_lost and not terminal

    can_resume = bool(mutations_allowed and lifecycle == "waiting_for_hitl" and _resumable(hitl))
    action_type = hitl.action_type if hitl is not None else ""
    can_submit_otp = bool(
        can_resume
        and action_type == "email_otp"
        and OTP_SUBMISSION_SUPPORTED
        and bool(getattr(settings, "allow_local_credential_submission", False))
    )
    # Rule 7: an explicit backend requirement — a reviewed HITL gate the owner can
    # clear with credentials — plus the owner-action policy the endpoint enforces.
    can_submit_login = bool(
        can_resume
        and action_type in LOGIN_HITL_ACTIONS
        and bool(getattr(settings, "allow_local_credential_submission", False))
    )
    # Rules 3 and 4: never "the session is running"; the credential page must have
    # been verified, and the owner-only submission endpoint must be enabled.
    can_submit_credential = bool(
        mutations_allowed
        and (credential_page_verified or owner_submission_ready)
        and bool(getattr(settings, "allow_local_credential_submission", False))
    )

    return BrowserUiState(
        provider=provider,
        lifecycle=lifecycle,
        live_view_mode=live_view_mode,
        live_view_available=live_view_mode != "unavailable",
        interaction_available=interaction_available,
        # Rule 8: an actual current frame, nothing weaker.
        screenshot_available=bool(screenshot_present),
        credential_page_verified=credential_page_verified,
        can_submit_login=can_submit_login,
        can_submit_otp=can_submit_otp,
        can_resume=can_resume,
        can_submit_credential=can_submit_credential,
        reason_code=reason_code,
    )


def _resumable(hitl: HitlRequestView | None) -> bool:
    return hitl is not None and hitl.resumable is True


def _lifecycle(
    *,
    run_status: str,
    event_types: Collection[str],
    session_started: bool,
    session_lost: bool,
    configured: bool,
    plan_only: bool,
    credential_page_verified: bool,
) -> tuple[BrowserLifecycle, str | None]:
    """Resolve the lifecycle and a sanitized reason, most specific first."""

    if session_lost:
        return "session_lost", "browser_session_lost"
    if plan_only:
        return "not_started", "plan_only_run"
    if not configured:
        return "unavailable", "browser_not_configured"
    if run_status == "failed" or "browser_failed" in event_types:
        return "failed", "browser_attempt_failed"
    if run_status in TERMINAL_RUN_STATUSES:
        # A completed or blocked run holds no live session, so it can offer no
        # view — even though its recorded credential-page progress remains true.
        return "unavailable", "no_live_browser_session"
    if run_status == "waiting_for_hitl":
        return "waiting_for_hitl", "human_action_required"
    if run_status == "browser_running":
        # A verified credential page is the more specific truth for a live session.
        if credential_page_verified:
            return "credential_page_ready", "credential_page_verified"
        return "running", "browser_session_running"
    if credential_page_verified:
        return "credential_page_ready", "credential_page_verified"
    if run_status in TERMINAL_RUN_STATUSES or session_started:
        # The run either finished or had a session that is no longer live.
        return "unavailable", "no_live_browser_session"
    return "not_started", "browser_not_started"


def _live_view_mode(
    *,
    lifecycle: BrowserLifecycle,
    session_live: bool,
    screenshot_present: bool,
    interactive_enabled: bool,
) -> LiveViewMode:
    """The view that can actually be served right now.

    This used to branch on the provider and hand a non-Playwright run
    ``hosted_url``, which made the frame drivable. That branch is gone with the
    backend it described: a legacy row still *reports* ``browser_use`` as its
    recorded provider, but there is no hosted session behind it, and offering an
    interactive view for a session nothing can serve is worse than offering none.
    The one backend uses a continuous remote surface while autonomous work runs
    and while a human gate is active. Capability is separate from transport:
    running is server-enforced view-only; HITL may receive a control grant.
    """

    if not session_live:
        return "unavailable"
    if lifecycle == "credential_page_ready":
        return "unavailable"
    if interactive_enabled:
        return "interactive_remote"
    return "screenshot" if screenshot_present else "unavailable"


__all__ = [
    "CREDENTIAL_PAGE_EVENT",
    "LOGIN_HITL_ACTIONS",
    "OTP_SUBMISSION_SUPPORTED",
    "SESSION_LOST_REASONS",
    "TERMINAL_RUN_STATUSES",
    "project_browser_ui",
    "resolve_provider",
    "session_lost_recorded",
]
