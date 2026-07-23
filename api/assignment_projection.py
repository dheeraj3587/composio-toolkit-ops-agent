"""Run-specific phase projection for the assignment execution runtime."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from api.models import PhaseState
from api.service import LocalRunService
from ops.browser_host_policy import get_browser_policy
from ops.models import OperationalResearch

_ORIGINAL_PHASES = LocalRunService._phases
_INSTALLED = False


def _event_types(service: LocalRunService, record: Mapping[str, object]) -> set[str]:
    run_id = record.get("run_id")
    if not isinstance(run_id, str):
        return set()
    try:
        timeline = service._service.get_timeline(run_id)
    except Exception:
        return set()
    return {str(event.get("event_type")) for event in timeline}


def _browser_is_wired(service: LocalRunService) -> bool:
    try:
        rows = service._service.wiring_audit()
    except Exception:
        return False
    return any(
        row.get("dependency") == "browser" and row.get("runtime_wired") is True for row in rows
    )


def _assignment_phases(
    service: LocalRunService,
    research: OperationalResearch | None,
    record: dict[str, object],
) -> list[PhaseState]:
    phases = _ORIGINAL_PHASES(service, research, record)
    if record.get("execution_mode") != "operations":
        return phases

    events = _event_types(service, record)
    run_status = str(record.get("status") or "")
    provider_status = record.get("provider_status")
    browser_provider = (
        str(provider_status.get("browser"))
        if isinstance(provider_status, Mapping) and provider_status.get("browser") is not None
        else "not_started"
    )
    policy = get_browser_policy(research.app_slug) if research is not None else None
    browser_configured = bool(
        service._settings.browser_use_api_key is not None
        and service._settings.allow_live_browser
        and service._settings.langgraph_aes_key is not None
        and _browser_is_wired(service)
    )

    if policy is None or not policy.active:
        browser = PhaseState(
            key="browser",
            name="Browser",
            phase="5/6",
            status="unavailable",
            detail="No active reviewed browser policy exists for this app.",
            available=False,
        )
    elif not browser_configured:
        browser = PhaseState(
            key="browser",
            name="Browser",
            phase="5/6",
            status="configuration_required",
            detail=(
                "Browser Use, ALLOW_LIVE_BROWSER, and encrypted workflow configuration "
                "are required."
            ),
            available=False,
        )
    elif run_status == "waiting_for_hitl" or "browser_hitl_required" in events:
        browser = PhaseState(
            key="browser",
            name="Browser",
            phase="5/6",
            status="waiting",
            detail="The browser is paused on the same session for a human action.",
            available=True,
        )
    elif "credential_page_ready" in events:
        browser = PhaseState(
            key="browser",
            name="Browser",
            phase="5/6",
            status="complete",
            detail="The agent reached the official developer or credential setup page.",
            available=True,
        )
    elif run_status == "failed" or browser_provider in {"failed", "blocked"}:
        browser = PhaseState(
            key="browser",
            name="Browser",
            phase="5/6",
            status="failed",
            detail="The recorded browser attempt ended with a sanitized failure.",
            available=False,
        )
    elif "browser_session_started" in events or record.get("browser_session_id"):
        browser = PhaseState(
            key="browser",
            name="Browser",
            phase="5/6",
            status="running",
            detail="A policy-gated Browser Use execution was recorded for this run.",
            available=True,
        )
    else:
        browser = PhaseState(
            key="browser",
            name="Browser",
            phase="5/6",
            status="not_started",
            detail="Browser execution has not started for this run.",
            available=True,
        )

    if run_status == "waiting_for_hitl":
        hitl = PhaseState(
            key="hitl",
            name="HITL",
            phase="3",
            status="waiting",
            detail="A human must complete the requested action in the live browser.",
            available=True,
        )
    elif "hitl_resumed" in events:
        hitl = PhaseState(
            key="hitl",
            name="HITL",
            phase="3",
            status="complete",
            detail="The human action was completed and the same browser session resumed.",
            available=True,
        )
    else:
        hitl = PhaseState(
            key="hitl",
            name="HITL",
            phase="3",
            status="not_started",
            detail="No human action has been requested for this run.",
            available=True,
        )

    projected: list[PhaseState] = []
    for phase in phases:
        if phase.key == "browser":
            projected.append(browser)
        elif phase.key == "hitl":
            projected.append(hitl)
        elif phase.key == "email" and "outreach_sent" not in events:
            projected.append(
                PhaseState(
                    key="email",
                    name="Email",
                    phase="4",
                    status="not_started",
                    detail="Email was not part of this browser-inspection run.",
                    available=False,
                )
            )
        else:
            projected.append(phase)
    return projected


def install_assignment_projection() -> None:
    """Install the run-specific projection once."""

    global _INSTALLED
    if _INSTALLED:
        return
    service_type = cast(Any, LocalRunService)
    service_type._phases = _assignment_phases
    _INSTALLED = True


__all__ = ["install_assignment_projection"]
