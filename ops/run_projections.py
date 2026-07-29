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
from datetime import UTC, datetime
from typing import Any, cast

from ops.composio_capability import ComposioCapabilityReport
from ops.p1_adapter import P1AppRecord, to_operational_research
from ops.redaction import redact_data, redact_text

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


__all__ = [
    "decode_stored_payload",
]
