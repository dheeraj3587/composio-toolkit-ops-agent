"""Application service for durable, sanitized operations-ledger runs.

This module is the single application boundary shared by HTTP, CLI, LangGraph,
and internal debugging surfaces. Creating a run is intentionally side-effect
free: it verifies the immutable P1 snapshot, builds a conservative research
baseline, records the deterministic route, and leaves provider execution to
explicit retry/resume actions guarded by runtime policy.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from ops.models import IntegratorBundle, OperationalResearch, OperationsRequest
from ops.p1_adapter import (
    DEFAULT_P1_ROOT,
    P1LookupFound,
    P1OperationalAdapter,
    P1SnapshotProvenance,
    load_verified_snapshot,
    to_operational_research,
)
from ops.redaction import redact_data, redact_text
from ops.routing import RoutingDecision, decide_access
from ops.storage import OperationsStorage, OperationsUnitOfWork

IDEMPOTENCY_KEY_PATTERN = re.compile(r"^idem_[0-9a-f]{32}$")

_PUBLIC_RUN_FIELDS = (
    "run_id",
    "thread_id",
    "app_name",
    "app_slug",
    "status",
    "access_route",
    "created_at",
    "updated_at",
)


class InvalidIdempotencyKeyError(ValueError):
    """Raised without echoing a malformed or credential-shaped key."""


class IdempotencyConflictError(ValueError):
    """Raised when a key is reused for a different canonical request."""


def validate_idempotency_key(value: str | None) -> str | None:
    """Validate a short opaque replay key without accepting secret material."""

    if value is None:
        return None
    if IDEMPOTENCY_KEY_PATTERN.fullmatch(value) is None or redact_text(value) != value:
        raise InvalidIdempotencyKeyError("idempotency key is invalid")
    return value


def _request_fingerprint(request: OperationsRequest) -> str:
    canonical = json.dumps(
        request.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _slugify(app_name: str) -> str:
    # Sanitize before transforming. Lower-casing or replacing separators first
    # can otherwise make a provider credential stop matching its redaction
    # signature while leaving a recognizable fragment in the public slug.
    safe_name = redact_text(app_name)
    slug = re.sub(r"[^a-z0-9]+", "-", safe_name.strip().lower()).strip("-")
    return slug or "app"


def _public_run(record: Mapping[str, object]) -> dict[str, Any]:
    public = {
        field: record.get(field) for field in _PUBLIC_RUN_FIELDS if record.get(field) is not None
    }
    public["execution_mode"] = record.get("execution_mode") or "local_dry_run"
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
        "scopes",
        "developer_portal_url",
        "signup_url",
        "production_approval_required",
        "contact_email",
        "contact_url",
    )
    missing: list[str] = []
    for name in candidates:
        value = research.get(name)
        if value is None or value == "" or value == []:
            missing.append(name)
    return missing


class RunService:
    """Coordinate verified P1 lookup, routing, and sanitized persistence."""

    def __init__(
        self,
        *,
        storage: OperationsStorage,
        p1_adapter: P1OperationalAdapter | None = None,
    ) -> None:
        self.storage = storage
        self.p1_adapter = p1_adapter or P1OperationalAdapter()

    @classmethod
    def from_paths(
        cls,
        *,
        db_path: str | Path,
        snapshot_root: str | Path = DEFAULT_P1_ROOT,
    ) -> RunService:
        return cls(
            storage=OperationsStorage(db_path),
            p1_adapter=P1OperationalAdapter(snapshot_root),
        )

    def initialize(self) -> None:
        """Validate application-owned storage and the pinned snapshot."""

        self.storage.initialize()
        load_verified_snapshot(self.p1_adapter.snapshot_root)

    def create_run(
        self,
        request: OperationsRequest,
        *,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Create and route one run without invoking an external provider."""

        if not request.dry_run:
            raise ValueError("Phase 2 accepts dry-run requests only")
        validated_idempotency_key = validate_idempotency_key(idempotency_key)
        request_fingerprint = (
            _request_fingerprint(request) if validated_idempotency_key is not None else None
        )

        # Verify all immutable inputs before writing any run state.
        lookup = self.p1_adapter.lookup(request.app_name)
        research_payload: Mapping[str, object] | None = None
        if isinstance(lookup, P1LookupFound):
            research = to_operational_research(lookup.record)
            decision = decide_access(research)
            research_payload = research.model_dump(mode="json")
        else:
            decision = RoutingDecision(
                route="unknown",
                reason_code="insufficient_evidence_probe_available",
                explanation=(
                    "The app is not present in the verified P1 snapshot. One bounded enrichment "
                    "probe remains available, but no external provider was invoked."
                ),
                is_final=False,
                unknown_probe_attempts=0,
                unknown_probe_remaining=1,
            )

        run_id = f"run_{uuid4().hex}"
        thread_id = f"local_{uuid4().hex}"
        with self.storage.unit_of_work() as transaction:
            if validated_idempotency_key is not None:
                existing = transaction.get_idempotent_run(validated_idempotency_key)
                if existing is not None:
                    record, stored_fingerprint = existing
                    if stored_fingerprint != request_fingerprint:
                        raise IdempotencyConflictError(
                            "idempotency key was already used for another request"
                        )
                    return _public_run(record)

            transaction.create_run(
                run_id=run_id,
                thread_id=thread_id,
                app_name=request.app_name,
                app_slug=_slugify(request.app_name),
                status="created",
                p1_summary=(
                    {
                        "category": lookup.record.category,
                        "one_liner": lookup.record.one_liner,
                        "auth_methods": lookup.record.auth_methods,
                        "access_model": lookup.record.access_model.kind,
                        "api_type": lookup.record.api_type,
                        "buildability": lookup.record.buildability,
                        "recommended_next_action": lookup.record.recommended_next_action,
                        "verification_status": lookup.record.verification_status,
                        "confidence": lookup.record.confidence,
                        "last_verified": lookup.record.last_verified,
                    }
                    if isinstance(lookup, P1LookupFound)
                    else None
                ),
                operational_research=research_payload,
                route_reason_code=decision.reason_code,
                route_explanation=decision.explanation,
                missing_fields=(
                    _missing_operational_fields(research_payload)
                    if research_payload is not None
                    else ["p1_record", "operational_research"]
                ),
                provider_status={
                    "research": "baseline_ready" if research_payload is not None else "not_started",
                    "browser": "not_started",
                    "email": "not_started",
                    "validation": "not_started",
                },
                scope_policy=request.requested_scope_policy,
                execution_mode="local_dry_run",
                external_actions=False,
                idempotency_key=validated_idempotency_key,
                request_fingerprint=request_fingerprint,
            )
            transaction.append_audit_event(
                run_id=run_id,
                event_type="dry_run_created",
                payload={
                    "status": "created",
                    "scope_policy": request.requested_scope_policy,
                    "execution_mode": "local_dry_run",
                    "external_actions": False,
                },
            )

            if isinstance(lookup, P1LookupFound):
                if research_payload is None:  # pragma: no cover - narrowing invariant
                    raise RuntimeError("verified research payload was not built")
                self._record_verified_research(
                    transaction,
                    run_id,
                    lookup,
                    research_payload,
                )
            else:
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="p1_snapshot_not_found",
                    payload={
                        "status": "not_found",
                        "source": "verified_p1_snapshot",
                        "external_actions": False,
                    },
                )

            persisted_status = "route_selected" if decision.is_final else "researching"
            decision_event = "route_selected" if decision.is_final else "route_pending"
            transaction.update_run(
                run_id,
                status=persisted_status,
                access_route=decision.route,
                route_reason_code=decision.reason_code,
                route_explanation=decision.explanation,
            )
            transaction.append_audit_event(
                run_id=run_id,
                event_type=decision_event,
                payload={
                    "status": persisted_status,
                    "route": decision.route,
                    "reason_code": decision.reason_code,
                    "explanation": decision.explanation,
                    "is_final": decision.is_final,
                    "unknown_probe_attempts": decision.unknown_probe_attempts,
                    "unknown_probe_remaining": decision.unknown_probe_remaining,
                    "external_actions": False,
                },
            )
            created = transaction.get_run(run_id)
            if created is None:  # pragma: no cover - persistence invariant
                raise RuntimeError("created run could not be read")
            return _public_run(created)

    def _record_verified_research(
        self,
        transaction: OperationsUnitOfWork,
        run_id: str,
        lookup: P1LookupFound,
        research: Mapping[str, object],
    ) -> None:
        record = lookup.record
        transaction.append_audit_event(
            run_id=run_id,
            event_type="p1_snapshot_loaded",
            payload={
                "status": "found",
                "source": "verified_p1_snapshot",
                "matched_by": lookup.matched_by,
                "api_type": record.api_type,
                "auth_methods": record.auth_methods,
                "access_model": record.access_model.kind,
                "buildability": record.buildability,
                "verification_status": record.verification_status,
                "confidence": record.confidence,
                "evidence_count": len(record.evidence_urls),
                "primary_docs_url": record.primary_docs_url,
                "external_actions": False,
            },
        )
        transaction.append_audit_event(
            run_id=run_id,
            event_type="operational_research_built",
            payload={
                "status": "baseline_complete",
                "source": "verified_p1_snapshot",
                "missing_fields": _missing_operational_fields(research),
                "evidence_count": len(cast(list[object], research.get("evidence_urls", []))),
                "external_actions": False,
            },
        )

    def list_runs(self, *, limit: int = 50, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
        records = self.storage.list_runs(limit=limit, offset=offset)
        return ([_public_run(record) for record in records], self.storage.count_runs())

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        record = self.storage.get_run(run_id)
        return _public_run(record) if record is not None else None

    def get_timeline(self, run_id: str) -> list[dict[str, Any]]:
        if self.storage.get_run(run_id) is None:
            return []
        return self.storage.list_audit_events(run_id)

    def get_research(self, run_id: str) -> OperationalResearch | None:
        """Return the persisted sanitized research projection for a run."""

        record = self.storage.get_run(run_id)
        if record is None:
            return None
        persisted = record.get("operational_research")
        if isinstance(persisted, Mapping):
            return OperationalResearch.model_validate(persisted)
        return None

    def search_apps(self, query: str, *, limit: int = 20) -> list[dict[str, Any]]:
        """Search the verified P1 catalog and return a minimal safe projection."""

        if limit < 1 or limit > 100:
            raise ValueError("limit must be between 1 and 100")
        normalized = " ".join(query.casefold().split())
        snapshot = load_verified_snapshot(self.p1_adapter.snapshot_root)
        matches: list[dict[str, Any]] = []
        for record in snapshot.records:
            haystack = " ".join((record.app, record.slug, record.category)).casefold()
            if normalized and normalized not in haystack:
                continue
            matches.append(
                {
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
            )
            if len(matches) >= limit:
                break
        sanitized = redact_data(matches)
        if not isinstance(sanitized, list):  # pragma: no cover - fixed list invariant
            raise RuntimeError("app search response could not be sanitized")
        return cast(list[dict[str, Any]], sanitized)

    def get_app_research(self, app_slug: str) -> tuple[dict[str, Any], OperationalResearch] | None:
        """Return a verified app summary and its conservative operational baseline."""

        lookup = self.p1_adapter.lookup(app_slug)
        if not isinstance(lookup, P1LookupFound):
            return None
        record = lookup.record
        summary = {
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
        return summary, to_operational_research(record)

    def get_output(self, run_id: str) -> dict[str, Any] | None:
        record = self.storage.get_run(run_id)
        if record is None:
            return None
        bundle = record.get("integrator_bundle")
        if bundle is None:
            return {}
        validated = IntegratorBundle.model_validate(bundle)
        sanitized = redact_data(validated.model_dump(mode="json"))
        if not isinstance(sanitized, dict):  # pragma: no cover - model invariant
            raise RuntimeError("output response could not be sanitized")
        return cast(dict[str, Any], sanitized)

    def snapshot_provenance(self) -> P1SnapshotProvenance:
        return load_verified_snapshot(self.p1_adapter.snapshot_root).provenance


def decode_stored_payload(value: object) -> dict[str, Any]:
    """Decode only sanitized audit payloads returned by ``OperationsStorage``."""

    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str):
        decoded = json.loads(value)
        return dict(decoded) if isinstance(decoded, Mapping) else {}
    return {}
