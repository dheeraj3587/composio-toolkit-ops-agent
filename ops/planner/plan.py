"""Run_Plan value types and the canonical form every planned surface is stored in."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Final, Literal, get_args
from urllib.parse import urlsplit

from ops.core.storage import MAX_PLAN_SURFACES, MAX_SURFACE_HOST_LENGTH, MAX_SURFACE_PATH_LENGTH

# The key-identity folding is already reviewed in one place; a second implementation
# here would let a plan surface and an operation key disagree about one URL.
from ops.onboarding.effects import _canonical
from ops.providers.profile import ProviderProfile
from ops.recipes.app_recipes import AppRecipe, SuccessPredicate, load_app_recipe_catalog

SurfacePurpose = Literal["entry", "login", "signup", "verification", "developer_app", "credential"]
PlanSource = Literal["planner", "recipe", "profile"]

PROFILE_CATALOG_ID: Final = "provider-profile-v1"

SURFACE_PURPOSES: Final[tuple[SurfacePurpose, ...]] = get_args(SurfacePurpose)
PLAN_SOURCES: Final[tuple[PlanSource, ...]] = get_args(PlanSource)
_FORBIDDEN_HOST_CHARACTERS: Final = "/?#:@ "
_FORBIDDEN_PATH_CHARACTERS: Final = "?# "


@dataclass(frozen=True, slots=True)
class PlannedSurface:
    """One navigable surface: an exact host and an absolute path, nothing else."""

    host: str
    path: str
    purpose: SurfacePurpose

    def __post_init__(self) -> None:
        if (
            not self.host
            or len(self.host) > MAX_SURFACE_HOST_LENGTH
            or self.host != self.host.casefold()
            or not self.host.isascii()
            or any(character in self.host for character in _FORBIDDEN_HOST_CHARACTERS)
        ):
            raise ValueError("a planned surface host must be a bounded lower-case ascii host")
        if (
            not self.path.startswith("/")
            or len(self.path) > MAX_SURFACE_PATH_LENGTH
            or not self.path.isascii()
            or any(character in self.path for character in _FORBIDDEN_PATH_CHARACTERS)
        ):
            raise ValueError("a planned surface path must be a bounded absolute ascii path")
        if self.purpose not in SURFACE_PURPOSES:
            raise ValueError("a planned surface purpose is outside the closed vocabulary")

    def as_row(self) -> dict[str, str]:
        """The exact shape ``OperationsStorage.record_run_plan`` accepts."""

        return {"host": self.host, "path": self.path, "purpose": self.purpose}


@dataclass(frozen=True, slots=True)
class RunPlan:
    """The ordered route a run may drive, bound to one reviewed recipe revision."""

    app_slug: str
    catalog_id: str
    recipe_version: str
    revision: int
    source: PlanSource
    surfaces: tuple[PlannedSurface, ...]
    credential_surface: PlannedSurface
    success_digest: str

    def __post_init__(self) -> None:
        if not 1 <= len(self.surfaces) <= MAX_PLAN_SURFACES:
            raise ValueError(f"a run plan names 1..{MAX_PLAN_SURFACES} surfaces")
        if self.revision < 1:
            raise ValueError("a run plan revision is 1-based")
        if self.source not in PLAN_SOURCES:
            raise ValueError("a run plan source is outside the closed vocabulary")

    def surface_for_step(self, step_index: int) -> PlannedSurface | None:
        """The surface the plan expects at ``step_index``, or ``None`` if it names none."""

        if 0 <= step_index < len(self.surfaces):
            return self.surfaces[step_index]
        return None

    def as_surface_rows(self) -> list[dict[str, str]]:
        return [surface.as_row() for surface in self.surfaces]


def canonical_surface(url: str, *, purpose: SurfacePurpose) -> PlannedSurface:
    """Fold one URL into a planned surface: https only, no userinfo, no port.

    Query and fragment are dropped rather than filtered, and the path is folded
    exactly as :func:`ops.onboarding.effects._canonical` folds it, so the folding is
    idempotent and one URL yields one surface.
    """

    folded = urlsplit(_canonical(url))
    if folded.scheme != "https":
        raise ValueError("a planned surface must be an https URL")
    return PlannedSurface(host=folded.hostname or "", path=folded.path or "/", purpose=purpose)


def success_digest(success: SuccessPredicate, *, catalog_id: str, recipe_version: str) -> str:
    """Digest the recipe's own success predicate together with its catalog binding.

    The predicate is checked-in catalog content, so a digest is enough to detect a
    plan made against a different recipe without re-copying clause text.
    """

    payload = {
        "catalog_id": catalog_id,
        "recipe_version": recipe_version,
        "success": success.model_dump(mode="json"),
    }
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def catalog_binding(recipe: AppRecipe) -> tuple[str, str]:
    """The catalog id and the recipe version identifier one plan row carries."""

    catalog = load_app_recipe_catalog()
    return catalog.catalog_id, f"{catalog.schema_version}.{recipe.evidence_verified_at}"


def profile_binding(profile: ProviderProfile) -> tuple[str, str]:
    """Bind a plan to exactly one immutable committed provider profile."""

    if not profile.profile_digest:
        raise ValueError("a profile-authorized plan requires a committed profile digest")
    return PROFILE_CATALOG_ID, profile.profile_digest


def profile_success_digest(profile: ProviderProfile) -> str:
    """Digest the exact profile-owned URL vocabulary the plan may select from."""

    payload = {
        "app_slug": profile.app_slug,
        "profile_digest": profile.profile_digest,
        "operational_urls": list(profile.operational_urls()),
    }
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


__all__ = [
    "PLAN_SOURCES",
    "PROFILE_CATALOG_ID",
    "SURFACE_PURPOSES",
    "PlanSource",
    "PlannedSurface",
    "RunPlan",
    "SurfacePurpose",
    "canonical_surface",
    "catalog_binding",
    "profile_binding",
    "profile_success_digest",
    "success_digest",
]
