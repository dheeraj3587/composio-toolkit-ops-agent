"""Immutable recipe snapshots for canonical SQLite runs.

The checked-in catalog is consulted exactly once, during run creation. Every
later operation re-validates this durable snapshot and refuses to call a
provider when the snapshot is absent, malformed, or inconsistent with the
run's immutable public identity fields.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from ops.recipes.app_recipes import AppRecipe

_SNAPSHOT_SCHEMA = "app-recipe-snapshot-v1"


class RecipeSnapshotError(ValueError):
    """A canonical run cannot safely recover its creation-time recipe."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def build_recipe_snapshot(recipe: AppRecipe, recipe_version: str) -> dict[str, object]:
    """Return the sanitized, version-bound payload persisted at run creation."""

    if not recipe_version:
        raise ValueError("recipe version is required")
    return {
        "snapshot_schema": _SNAPSHOT_SCHEMA,
        "recipe_version": recipe_version,
        "recipe": recipe.model_dump(mode="json"),
    }


def recipe_from_run(record: Mapping[str, Any]) -> AppRecipe:
    """Load and identity-check the immutable recipe for one canonical run.

    Existing canonical rows created before snapshots were introduced are not
    silently rebound to today's catalog. They fail closed instead. Legacy rows
    are handled by their read-only adapter and are rejected here as well.
    """

    if record.get("state_engine") != "canonical_v1":
        raise RecipeSnapshotError("legacy_run_is_read_only")
    snapshot = record.get("recipe_snapshot")
    if not isinstance(snapshot, Mapping):
        raise RecipeSnapshotError("immutable_recipe_snapshot_missing")
    if snapshot.get("snapshot_schema") != _SNAPSHOT_SCHEMA:
        raise RecipeSnapshotError("immutable_recipe_snapshot_invalid")
    public_version = record.get("recipe_version")
    if (
        not isinstance(public_version, str)
        or not public_version
        or snapshot.get("recipe_version") != public_version
    ):
        raise RecipeSnapshotError("immutable_recipe_snapshot_mismatch")
    payload = snapshot.get("recipe")
    if not isinstance(payload, Mapping):
        raise RecipeSnapshotError("immutable_recipe_snapshot_invalid")
    try:
        recipe = AppRecipe.model_validate(dict(payload))
    except ValidationError:
        raise RecipeSnapshotError("immutable_recipe_snapshot_invalid") from None

    identity = {
        "app_slug": recipe.app_slug,
        "app_name": recipe.app_name,
        "route_kind": recipe.route_kind,
        "readiness_tier": recipe.readiness_tier,
    }
    if any(record.get(field) != value for field, value in identity.items()):
        raise RecipeSnapshotError("immutable_recipe_snapshot_mismatch")
    return recipe


__all__ = [
    "RecipeSnapshotError",
    "build_recipe_snapshot",
    "recipe_from_run",
]
