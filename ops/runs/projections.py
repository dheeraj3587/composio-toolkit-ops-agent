"""Pure projection and value-normalization helpers for the run service.

Every function here is deterministic and free of run-service state: it takes a
verified record, a stored row, or a raw value and returns the sanitized shape the
public boundary is allowed to expose. Keeping them in one leaf module means the
sanitization rules can be read (and reasoned about) without the surrounding
orchestration, and no caller can quietly grow a second, divergent projection.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Literal, cast

from ops.core.redaction import redact_data, redact_text
from ops.core.secret_store import parse_vault_reference
from ops.onboarding.phase import ONBOARDING_PHASES, ONBOARDING_REASON_CODES
from ops.providers.composio_capability import ComposioCapabilityReport
from ops.research.p1_adapter import P1AppRecord, to_operational_research

# Gated routes that may proceed to a single controlled outreach in
# execute_when_configured. self_serve/hybrid use the browser path (later
# milestones) and unknown/blocked never contact a provider.
_TERMINAL_BROWSER_STATUSES: frozenset[str] = frozenset(
    {"completed", "failed", "blocked", "configuration_required"}
)

# Persisted reason codes for a gated run whose outreach the Composio capability
# preflight suppressed (or could not evaluate).
_CAPABILITY_SUPPRESSION_REASONS = {
    "composio_ready": "composio_ready",
    "connection_required": "composio_connection_required",
}

# The public RunService boundary exposes logical execution modes, while storage
# keeps its existing persisted tokens (no migration of existing rows).
_PERSISTED_EXECUTION_MODE = {
    "plan_only": "local_dry_run",
    "execute_when_configured": "operations",
}
_LOGICAL_EXECUTION_MODE = {value: key for key, value in _PERSISTED_EXECUTION_MODE.items()}

_PUBLIC_RUN_FIELDS = (
    "run_id",
    "thread_id",
    "app_name",
    "app_slug",
    "status",
    "access_route",
    "created_at",
    "updated_at",
    "browser_provider",
    "credential_creation_policy",
    "recipe_version",
    "route_kind",
    "readiness_tier",
    "attempt",
    "phase",
    "reason_code",
    "state_engine",
    # The pinned model and reasoning effort, which the run really does execute
    # on: ops/workflow/canonical_runtime.py reads the raw storage row and hands
    # the pin to the worker. They were missing here, so the projection that
    # feeds GET /api/runs/{id}/timeline returned None for both and the console
    # rendered the literal "Deployment default" for every run — including one
    # pinned to mercury:mercury-2 at effort high. An operator could not tell a
    # pinned run from an unpinned one, which is the exact confusion the
    # refuse-do-not-substitute design in api/service.py exists to prevent.
    # Both are _safe_text-bounded on write in ops/core/storage.py and are
    # validated against the model catalog before they are stored, so neither
    # can carry secret or free-form material.
    "decision_model",
    "decision_effort",
)


def _app_projection(record: P1AppRecord) -> dict[str, Any]:
    """The ONE minimal, non-secret projection of a verified P1 record.

    Shared by catalog search and the full listing so the two can never drift into
    exposing different fields for the same record.
    """

    return {
        "app_name": record.app,
        "app_slug": record.slug,
        "category": record.category,
        "api_type": record.api_type,
        "auth_methods": list(record.auth_methods),
        "access_route": to_operational_research(record).access_route,
        "buildability": record.buildability,
        "verification_status": record.verification_status,
        "confidence": record.confidence,
    }


def _sanitized_app_list(items: list[dict[str, Any]], *, capability: str) -> list[dict[str, Any]]:
    """Redact a catalog projection, refusing to return an unexpected shape."""

    sanitized = redact_data(items)
    if not isinstance(sanitized, list):  # pragma: no cover - fixed list invariant
        raise RuntimeError(f"{capability} response could not be sanitized")
    return cast("list[dict[str, Any]]", sanitized)


def _capability_reason_code(report: ComposioCapabilityReport | None) -> str:
    if report is None:
        return "composio_preflight_unavailable"
    return _CAPABILITY_SUPPRESSION_REASONS.get(report.capability_state, report.reason_code)


def _slugify(app_name: str) -> str:
    # Sanitize before transforming. Lower-casing or replacing separators first
    # can otherwise make a provider credential stop matching its redaction
    # signature while leaving a recognizable fragment in the public slug.
    safe_name = redact_text(app_name)
    slug = re.sub(r"[^a-z0-9]+", "-", safe_name.strip().lower()).strip("-")
    return slug or "app"


def _clean_credential_value(value: str) -> str:
    """Strip surrounding whitespace and invisible formatting characters.

    Credentials copied or read from a rendered page can pick up zero-width or
    directional Unicode marks (e.g. U+200E LEFT-TO-RIGHT MARK, U+200B ZERO WIDTH
    SPACE, U+FEFF BYTE ORDER MARK). These corrupt the stored token and break
    ASCII encoding when the read-only validator sends it in an HTTP header. They
    are never part of a real API key, so they are removed before storage.
    """

    without_format = "".join(ch for ch in value if unicodedata.category(ch) != "Cf")
    return without_format.strip()


def _parse_timestamp(value: object) -> datetime | None:
    """Parse a stored ISO-8601 timestamp into an aware UTC datetime, or ``None``.

    A value that cannot be parsed returns ``None`` so callers skip the row rather
    than treating an unreadable timestamp as "infinitely idle" and tearing down a
    run that may still be working.
    """

    if not isinstance(value, str) or not value:
        return None
    candidate = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _browser_result_reason(state: Mapping[str, object], default: str) -> str:
    """Return one typed browser reason without exposing page or exception text."""

    observation = state.get("browser_observation")
    candidates: list[object] = [observation]
    for field_name in ("errors", "capability_statuses"):
        values = state.get(field_name)
        if isinstance(values, list) and values:
            candidates.append(values[-1])
    for candidate in candidates:
        if not isinstance(candidate, Mapping):
            continue
        reason = candidate.get("reason_code")
        if (
            isinstance(reason, str)
            and len(reason) <= 100
            and re.fullmatch(r"[a-z0-9_:-]+", reason) is not None
        ):
            return reason
    return default


def _strip_quoted_reply(body: str) -> str:
    """Keep only the new reply text, dropping quoted history ('On ... wrote:')."""

    trimmed = re.split(r"(?im)^\s*On .*wrote:\s*$", body)[0]
    lines = [line for line in trimmed.splitlines() if not line.lstrip().startswith(">")]
    return "\n".join(lines).strip()


def _public_run(record: Mapping[str, object]) -> dict[str, Any]:
    public = {
        field: record.get(field) for field in _PUBLIC_RUN_FIELDS if record.get(field) is not None
    }
    stored_request = record.get("request")
    if isinstance(stored_request, Mapping):
        account_mode = stored_request.get("account_mode")
        if account_mode in {"existing_account", "create_account"}:
            public["account_mode"] = account_mode
    persisted_execution_mode = str(record.get("execution_mode") or "local_dry_run")
    public["execution_mode"] = _LOGICAL_EXECUTION_MODE.get(persisted_execution_mode, "plan_only")
    public["external_actions"] = bool(record.get("external_actions", False))
    sanitized = redact_data(public)
    if not isinstance(sanitized, dict):  # pragma: no cover - fixed mapping invariant
        raise RuntimeError("run response could not be sanitized")
    return cast(dict[str, Any], sanitized)


def _missing_operational_fields(research: Mapping[str, object]) -> list[str]:
    candidates = (
        "api_base_url",
        "authorization_url",
        "token_url",
        "credential_fields",
        "credential_creation_instructions",
        "scopes",
        "developer_portal_url",
        "signup_url",
        "login_url",
        "credential_management_url",
        "production_approval_required",
    )
    missing: list[str] = []
    for name in candidates:
        value = research.get(name)
        if value is None or value == "" or value == [] or value == ():
            missing.append(name)
    # A provider may intentionally expose a support form instead of publishing an
    # email address. Either reviewed channel is operationally complete; requiring
    # both forced unnecessary live enrichment on an otherwise deterministic run.
    if not research.get("contact_email") and not research.get("contact_url"):
        missing.append("contact_channel")
    return missing


def decode_stored_payload(value: object) -> dict[str, Any]:
    """Decode only sanitized audit payloads returned by ``OperationsStorage``."""

    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str):
        decoded = json.loads(value)
        return dict(decoded) if isinstance(decoded, Mapping) else {}
    return {}


# ---------------------------------------------------------------------------
# Onboarding timeline projection (design LL-7, LL-6.1)
# ---------------------------------------------------------------------------

# The projector reads DURABLE ROWS ONLY. An audit row's sanitized payload is
# never a source: the summary comes from the API's static allow-list and every
# field below is read from a typed durable column (phase history, onboarding run
# state, or the run row). A mistakenly-rich audit payload therefore cannot reach
# the timeline (Requirements 17.1, 17.11).

TimelineEventStatus = Literal["recorded", "completed", "blocked", "failed"]

_ONBOARDING_PHASES: Final[frozenset[str]] = frozenset(ONBOARDING_PHASES)
_ONBOARDING_REASON_CODES: Final[frozenset[str]] = frozenset(ONBOARDING_REASON_CODES)

# Mirrors ``api.models.BoundedIdentifier`` / ``Sha256Digest``. Applied here so a
# durable value that could not be projected is dropped at the projection boundary
# instead of failing response validation with the whole timeline.
_BOUNDED_IDENTIFIER = re.compile(r"^[A-Za-z0-9._-]{1,200}$")
_PROFILE_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_ATTEMPT = 1_000

# Durable column aliases: phase history names the committed phase ``to_phase``,
# and the run row names the browser session ``provider_session_id``.
_PHASE_COLUMNS: Final[tuple[str, ...]] = ("onboarding_phase", "phase", "to_phase")
_SESSION_COLUMNS: Final[tuple[str, ...]] = ("browser_session_id", "provider_session_id")
_VAULT_REFERENCE_COLUMNS: Final[tuple[str, ...]] = (
    "vault_reference",
    "credential_reference",
    "account_ref",
)

# The LL-7 per-event detail allow-list. An event type may carry only the closed
# detail fields its row of the LL-7 table names, so a durable column that is
# irrelevant to the event cannot ride along on it (Requirement 17.11).
_ONBOARDING_EVENT_DETAIL_FIELDS: Final[dict[str, tuple[str, ...]]] = {
    "onboarding_research_started": ("adapters_engaged",),
    "onboarding_official_domain_found": ("registrable_domain", "evidence_count"),
    "onboarding_research_inconclusive": ("evidence_count",),
    "onboarding_vault_checked": ("credentials_present",),
    "onboarding_credentials_missing": ("credentials_present",),
    "onboarding_admission_requested": (),
    "onboarding_operator_approved_signup": ("decision", "decided_by"),
    "onboarding_signup_started": ("host",),
    "onboarding_verification_email_received": ("sender_domain", "verification_kind"),
    "onboarding_verification_completed": (),
    "onboarding_authenticated": (),
    "onboarding_developer_app_created": ("developer_app_id",),
    "onboarding_credentials_generated": ("credential_kind",),
    "onboarding_stored_in_vault": ("credential_kind",),
    "onboarding_credentials_validated": (
        "validation_endpoint",
        "validation_http_status",
        "checked_at",
    ),
    "onboarding_completed": ("duration_seconds", "verdict"),
    "onboarding_captcha_detected": ("host",),
    "onboarding_captcha_resolved": (),
    "onboarding_verification_unresolved": (),
    "onboarding_validation_failed": ("validation_endpoint", "validation_http_status"),
    "onboarding_run_paused": (),
    "onboarding_run_cancelled": (),
    "onboarding_run_reset": (),
    "onboarding_step_retried": (),
}

# The python type each detail field is stored as. A durable column holding
# anything else is dropped rather than coerced.
_BOOL_DETAIL_FIELDS: Final[frozenset[str]] = frozenset({"credentials_present"})
_INT_DETAIL_FIELDS: Final[frozenset[str]] = frozenset(
    {"evidence_count", "validation_http_status", "duration_seconds"}
)
_LIST_DETAIL_FIELDS: Final[frozenset[str]] = frozenset({"adapters_engaged"})


@dataclass(frozen=True, slots=True)
class ProjectedTimelineEvent:
    """One timeline event as the durable rows describe it, minus the summary.

    The summary is deliberately absent: it belongs to the API's static allow-list
    keyed by ``event_type``, so no projection can substitute run data for it
    (Requirement 17.4).
    """

    event_id: int
    event_type: str
    created_at: str
    status: TimelineEventStatus
    correlation: dict[str, Any] | None
    detail: dict[str, Any] | None


def _durable_identifier(value: object, *, limit: int = 200) -> str | None:
    if not isinstance(value, str):
        return None
    return value if len(value) <= limit and _BOUNDED_IDENTIFIER.fullmatch(value) else None


def _durable_column(
    row: Mapping[str, object],
    fallback: Mapping[str, object] | None,
    names: tuple[str, ...],
) -> object:
    """Read the first present, non-null durable column, row before fallback."""

    for source in (row, fallback):
        if source is None:
            continue
        for name in names:
            value = source.get(name)
            if value is not None:
                return value
    return None


def _durable_attempt(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value <= _MAX_ATTEMPT else None


def _vault_reference_id(value: object) -> str | None:
    """The reference's ``id`` segment, which is independent of the secret.

    ``parse_vault_reference`` yields the random identifier minted at write time,
    so nothing derived from the credential's content reaches the timeline
    (Requirement 17.13).
    """

    if not isinstance(value, str) or not value:
        return None
    try:
        parts = parse_vault_reference(value)
    except ValueError:
        return None
    return _durable_identifier(parts.identifier)


def onboarding_timeline_correlation(
    row: Mapping[str, object],
    *,
    fallback: Mapping[str, object] | None = None,
) -> dict[str, Any] | None:
    """Project the correlation set for one durable onboarding row.

    Returns ``None`` when the row does not carry the full correlation set — a
    legacy (non-onboarding) event, or an onboarding row whose durable columns are
    not yet joined onto it. That degrades the event to an uncorrelated one rather
    than inventing an attribution for it.
    """

    run_id = _durable_identifier(_durable_column(row, fallback, ("run_id",)))
    correlation_id = _durable_identifier(
        _durable_column(row, fallback, ("correlation_id",)), limit=64
    )
    phase = _durable_column(row, fallback, _PHASE_COLUMNS)
    digest = _durable_column(row, fallback, ("profile_digest",))
    reason_code = _durable_column(row, fallback, ("reason_code",))
    attempt = _durable_attempt(_durable_column(row, fallback, ("attempt",)))
    if (
        run_id is None
        or correlation_id is None
        or attempt is None
        or not isinstance(phase, str)
        or phase not in _ONBOARDING_PHASES
        or not isinstance(digest, str)
        or _PROFILE_DIGEST.fullmatch(digest) is None
        or not isinstance(reason_code, str)
        or reason_code not in _ONBOARDING_REASON_CODES
    ):
        return None

    correlation: dict[str, Any] = {
        "run_id": run_id,
        "correlation_id": correlation_id,
        "onboarding_phase": phase,
        "profile_digest": digest,
        "attempt": attempt,
        "reason_code": reason_code,
    }
    session_id = _durable_identifier(_durable_column(row, fallback, _SESSION_COLUMNS), limit=64)
    if session_id is not None:
        correlation["browser_session_id"] = session_id
    reference_id = _vault_reference_id(_durable_column(row, fallback, _VAULT_REFERENCE_COLUMNS))
    if reference_id is not None:
        correlation["vault_reference_id"] = reference_id
    return correlation


def onboarding_timeline_detail(
    event_type: str,
    row: Mapping[str, object],
    *,
    fallback: Mapping[str, object] | None = None,
) -> dict[str, Any] | None:
    """Project the closed detail object LL-7 allows for ``event_type``.

    Only the fields that event's LL-7 row names are read, and only from durable
    columns. ``None`` means the event carries no detail.
    """

    allowed = _ONBOARDING_EVENT_DETAIL_FIELDS.get(event_type, ())
    detail: dict[str, Any] = {}
    for field_name in allowed:
        value = _durable_column(row, fallback, (field_name,))
        if value is None:
            continue
        if field_name in _BOOL_DETAIL_FIELDS:
            if isinstance(value, bool):
                detail[field_name] = value
        elif field_name in _INT_DETAIL_FIELDS:
            if isinstance(value, int) and not isinstance(value, bool):
                detail[field_name] = value
        elif field_name in _LIST_DETAIL_FIELDS:
            if isinstance(value, list | tuple) and all(isinstance(item, str) for item in value):
                detail[field_name] = [str(item) for item in value]
        elif isinstance(value, str):
            detail[field_name] = value
    return detail or None


def onboarding_timeline_event(
    row: Mapping[str, object],
    *,
    durable: Mapping[str, object] | None = None,
) -> ProjectedTimelineEvent:
    """Project one durable audit row onto the timeline event's non-summary fields.

    ``durable`` is the run's own durable projection (its phase, attempt, reason
    code, session id, and profile digest); it supplies the correlation columns a
    per-event row does not carry itself. The audit row's sanitized payload is not
    read at all.
    """

    event_type = str(row.get("event_type") or "")
    return ProjectedTimelineEvent(
        event_id=int(cast(int, row.get("id") or 0)),
        event_type=event_type,
        created_at=str(row.get("created_at") or "unknown"),
        status="recorded",
        correlation=onboarding_timeline_correlation(row, fallback=durable),
        detail=onboarding_timeline_detail(event_type, row, fallback=durable),
    )


__all__ = [
    "ProjectedTimelineEvent",
    "TimelineEventStatus",
    "decode_stored_payload",
    "onboarding_timeline_correlation",
    "onboarding_timeline_detail",
    "onboarding_timeline_event",
]
