"""How a node reports what happened: the sanitized state updates.

Every graph node returns one of these shapes instead of writing status text inline,
which is what keeps a run's outcome truthful and auditable.

The important distinction is between the three failure kinds, and it is preserved here
exactly. An UNAVAILABLE capability means the dependency was not configured, so the run
records configuration_required and keeps the verified baseline rather than pretending to
have tried. A FAILED capability means the provider was reached and refused. An
OUTCOME-UNKNOWN capability means the provider may have acted but we cannot prove it,
which must never be collapsed into either of the other two: for an outreach that
distinction is the difference between safely retrying and emailing a vendor twice.

Observations carry only sanitized, bounded fields (status, URL, typed reason code), never
page text or a credential, so a state update is always safe to persist and log.
"""

from __future__ import annotations

from dataclasses import asdict

from ops.browser_worker import BrowserObservation, BrowserSessionContext
from ops.models import CapabilityAvailability, CapabilityStatus, OperationalResearch
from ops.operational_baselines import apply_reviewed_operational_baseline
from ops.p1_adapter import P1LookupFound, P1OperationalAdapter, to_operational_research
from ops.provider_errors import PhaseUnavailableError, ProviderContractError
from ops.state import OperationsState


def browser_account_ref(work_email_ref: str) -> str:
    """A stable, OPAQUE account reference for storage-state binding.

    Hashes the (already non-raw) work-email vault REFERENCE so a real email address
    never becomes a filename component or crosses to the browser service, while the
    same account still maps to the same saved-state binding across runs.
    """

    import hashlib

    return hashlib.sha256(work_email_ref.encode("utf-8")).hexdigest()[:32]


def _load_verified_baseline(app_name: str) -> OperationalResearch:
    lookup = P1OperationalAdapter().lookup(app_name)
    if not isinstance(lookup, P1LookupFound):
        raise LookupError("app is not present in the verified P1 snapshot")
    research, _baseline_version = apply_reviewed_operational_baseline(
        to_operational_research(lookup.record)
    )
    return research


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
