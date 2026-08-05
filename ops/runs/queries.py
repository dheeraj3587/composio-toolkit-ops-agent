"""Read-only run, catalog, and reference-only output queries.

Every operation here answers a question about already-persisted state or about the
immutable verified snapshot. None of them advance a run, contact a provider, or
mutate anything.

The collaborator holds a reference to the run service rather than copies of its
dependencies, and reads ``storage`` and ``p1_adapter`` through
that reference on every call. That is required, not incidental: tests and scripts
replace adapters after construction, so a cached copy could silently be stale.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, cast

from ops.core.models import IntegratorBundle, OperationalResearch
from ops.core.redaction import redact_data
from ops.core.storage import OperationsStorage
from ops.recipes.app_recipes import load_app_recipe_catalog
from ops.research.operational_baselines import apply_reviewed_operational_baseline
from ops.research.p1_adapter import (
    P1LookupFound,
    P1OperationalAdapter,
    P1SnapshotProvenance,
    load_verified_snapshot,
    to_operational_research,
)
from ops.runs.projections import _app_projection, _public_run, _sanitized_app_list


class RunQueryContext(Protocol):
    """The run-service state these read-only queries need.

    Declared as a protocol so this module never imports the service it serves,
    which keeps the dependency one-directional.
    """

    storage: OperationsStorage
    p1_adapter: P1OperationalAdapter


class RunQueryService:
    """Answer read-only questions about runs and the verified app catalog."""

    def __init__(self, context: RunQueryContext) -> None:
        self._context = context

    @property
    def storage(self) -> OperationsStorage:
        return self._context.storage

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

    def get_progress_events(self, run_id: str, *, limit: int) -> list[dict[str, Any]]:
        """The run's loop progress events, newest first (Requirement 4.2)."""

        if self.storage.get_run(run_id) is None:
            return []
        return self.storage.list_progress_events(run_id, limit=limit)

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
        """Search the reviewed runnable catalog and return a minimal safe projection."""

        if limit < 1 or limit > 100:
            raise ValueError("limit must be between 1 and 100")
        normalized = " ".join(query.casefold().split())
        snapshot = load_verified_snapshot(self._context.p1_adapter.snapshot_root)
        runnable_slugs = {recipe.app_slug for recipe in load_app_recipe_catalog().apps}
        matches: list[dict[str, Any]] = []
        for record in snapshot.records:
            if record.slug not in runnable_slugs:
                continue
            haystack = " ".join((record.app, record.slug, record.category)).casefold()
            if normalized and normalized not in haystack:
                continue
            matches.append(_app_projection(record))
            if len(matches) >= limit:
                break
        return _sanitized_app_list(matches, capability="app search")

    def list_apps(self) -> list[dict[str, Any]]:
        """Return every reviewed runnable app, so the interface offers real choices.

        Search alone required the operator to already know an app's name. This
        Returns the recipe-bound subset of the verified snapshot (ordered by
        display name). Snapshot-only records are evidence, not runnable product
        capabilities, so exposing them here would let an operator select a run
        that the create boundary must reject.

        Same minimal projection and sanitization as ``search_apps``; the response
        is derived only from the provenance-verified snapshot.
        """

        snapshot = load_verified_snapshot(self._context.p1_adapter.snapshot_root)
        runnable_slugs = {recipe.app_slug for recipe in load_app_recipe_catalog().apps}
        ordered = sorted(
            (record for record in snapshot.records if record.slug in runnable_slugs),
            key=lambda record: record.app.casefold(),
        )
        return _sanitized_app_list(
            [_app_projection(record) for record in ordered], capability="app catalog"
        )

    def get_app_research(self, app_slug: str) -> tuple[dict[str, Any], OperationalResearch] | None:
        """Return a verified app summary and its reviewed operational baseline.

        This stays a pure read of persisted state. Resolving a signup route is
        the signup research agent's job and happens when a run starts, not while
        the console is rendering a capability check — a live probe here would put
        a network call in the request path of an otherwise offline query.
        """

        lookup = self._context.p1_adapter.lookup(app_slug)
        if not isinstance(lookup, P1LookupFound):
            return None
        record = lookup.record
        research, _baseline_version = apply_reviewed_operational_baseline(
            to_operational_research(record)
        )
        summary = {
            "app_name": record.app,
            "app_slug": record.slug,
            "category": record.category,
            "api_type": record.api_type,
            "auth_methods": list(record.auth_methods),
            "access_route": research.access_route,
            "buildability": record.buildability,
            "verification_status": record.verification_status,
            "confidence": record.confidence,
        }
        return summary, research

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
        return load_verified_snapshot(self._context.p1_adapter.snapshot_root).provenance


__all__ = [
    "RunQueryContext",
    "RunQueryService",
]
