"""Plan_Validator: every planned surface must be declared by the run's own recipe.

The refusal is a value carrying the failing ordinal as closed data and never the
offending string, and it is produced before any browser session exists.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

from ops.browser.host_policy import (
    BrowserAllowedHosts,
    BrowserPolicyInactiveError,
    evaluate_navigation,
)
from ops.onboarding.phase import OnboardingReasonCode
from ops.planner.plan import (
    PROFILE_CATALOG_ID,
    PlannedSurface,
    RunPlan,
    canonical_surface,
    profile_success_digest,
)
from ops.providers.profile import ProviderProfile
from ops.recipes.app_recipes import AppRecipe

PLAN_REFUSAL_REASON_CODE: Final[OnboardingReasonCode] = "plan_surface_not_in_catalog"

# Why one ordinal failed, as closed data an operator can read without the string.
PlanRefusalDetail = Literal[
    "recipe_route_not_browser",
    "app_slug_mismatch",
    "surface_count_exceeds_recipe",
    "surface_count_exceeds_profile",
    "host_not_in_recipe",
    "host_not_in_profile",
    "navigation_denied",
    "path_not_declared",
    "credential_surface_unprovable",
    "profile_binding_mismatch",
]

# The credential surface is reported at ordinal 0: it is not one of the ordered
# surfaces, so it cannot borrow one of their positions.
CREDENTIAL_SURFACE_ORDINAL: Final = 0


@dataclass(frozen=True, slots=True)
class PlanRefusal:
    """A plan the catalog does not declare; no session is created for it."""

    reason_code: OnboardingReasonCode
    detail: PlanRefusalDetail
    ordinal: int

    def __post_init__(self) -> None:
        if self.ordinal < 0:
            raise ValueError("a plan refusal ordinal is 0-based on the credential surface")


@dataclass(frozen=True, slots=True)
class DeclaredPaths:
    """The recipe's own paths, split by how a planned path may match them."""

    exact: frozenset[str]
    prefixes: tuple[str, ...]
    contains: tuple[str, ...]

    def admits(self, path: str) -> bool:
        if path in self.exact:
            return True
        for raw in self.prefixes:
            prefix = raw.rstrip("/") or "/"
            if path == prefix or (prefix != "/" and path.startswith(f"{prefix}/")):
                return True
        return any(fragment in path for fragment in self.contains)


def _path_of(url: str | None) -> str | None:
    if url is None:
        return None
    try:
        return canonical_surface(url, purpose="entry").path
    except ValueError:
        return None


def declared_paths(recipe: AppRecipe) -> DeclaredPaths:
    """Every path the recipe declares, by match kind — the validator's whole vocabulary."""

    browser = recipe.browser
    if browser is None:
        return DeclaredPaths(exact=frozenset(), prefixes=(), contains=())
    urls = (
        recipe.urls.login,
        recipe.urls.signup,
        recipe.urls.developer_portal,
        recipe.urls.credential_management,
        *(step.target_url for step in browser.steps),
    )
    exact = {path for path in (_path_of(url) for url in urls) if path is not None}
    contains: list[str] = list(browser.success.url_path_contains)
    for step in browser.steps:
        contains.extend(step.completion.url_path_contains)
    prefixes = browser.signup.entry_path_prefixes if browser.signup is not None else ()
    return DeclaredPaths(
        exact=frozenset(exact),
        prefixes=tuple(prefixes),
        contains=tuple(dict.fromkeys(contains)),
    )


def declared_surface_paths(recipe: AppRecipe) -> tuple[str, ...]:
    """The exact paths a decision may select from, ordered as the recipe declares them."""

    browser = recipe.browser
    if browser is None:
        return ()
    ordered = [
        _path_of(url)
        for url in (
            recipe.urls.login,
            recipe.urls.signup,
            *(step.target_url for step in browser.steps),
            recipe.urls.developer_portal,
            recipe.urls.credential_management,
        )
    ]
    return tuple(dict.fromkeys(path for path in ordered if path is not None))


def _refuse(detail: PlanRefusalDetail, ordinal: int) -> PlanRefusal:
    return PlanRefusal(reason_code=PLAN_REFUSAL_REASON_CODE, detail=detail, ordinal=ordinal)


def _check_surface(
    surface: PlannedSurface,
    ordinal: int,
    *,
    recipe: AppRecipe,
    allowed: BrowserAllowedHosts,
    paths: DeclaredPaths,
) -> PlanRefusal | None:
    browser = recipe.browser
    if browser is None or surface.host not in browser.exact_hosts:
        # Exact membership deliberately, not evaluate_navigation: a wildcard the
        # run's allow-list may carry must never admit a *planned* surface.
        return _refuse("host_not_in_recipe", ordinal)
    if not evaluate_navigation(f"https://{surface.host}{surface.path}", allowed).allowed:
        return _refuse("navigation_denied", ordinal)
    if not paths.admits(surface.path):
        return _refuse("path_not_declared", ordinal)
    return None


def _validate_recipe_plan(plan: RunPlan, *, recipe: AppRecipe) -> PlanRefusal | None:
    """``None`` when every surface is catalog-declared; a refusal otherwise."""

    browser = recipe.browser
    if recipe.route_kind != "playwright" or browser is None:
        return _refuse("recipe_route_not_browser", CREDENTIAL_SURFACE_ORDINAL)
    if plan.app_slug != recipe.app_slug:
        return _refuse("app_slug_mismatch", CREDENTIAL_SURFACE_ORDINAL)
    if len(plan.surfaces) > len(browser.steps):
        return _refuse("surface_count_exceeds_recipe", len(browser.steps) + 1)

    allowed = BrowserAllowedHosts(
        app_slug=recipe.app_slug,
        exact_hosts=browser.exact_hosts,
        vendor_wildcard_domains=(),
    )
    paths = declared_paths(recipe)
    for ordinal, surface in enumerate(plan.surfaces, start=1):
        refusal = _check_surface(surface, ordinal, recipe=recipe, allowed=allowed, paths=paths)
        if refusal is not None:
            return refusal

    credential = plan.credential_surface
    if browser.scope == "credential_surface":
        if not browser.success.proves_credential_surface():
            return _refuse("credential_surface_unprovable", CREDENTIAL_SURFACE_ORDINAL)
        credential_paths = DeclaredPaths(
            exact=frozenset(), prefixes=(), contains=browser.success.url_path_contains
        )
    else:
        declared = _path_of(recipe.urls.credential_management)
        if declared is None:
            return _refuse("credential_surface_unprovable", CREDENTIAL_SURFACE_ORDINAL)
        credential_paths = DeclaredPaths(exact=frozenset({declared}), prefixes=(), contains=())
    refusal = _check_surface(
        credential,
        CREDENTIAL_SURFACE_ORDINAL,
        recipe=recipe,
        allowed=allowed,
        paths=credential_paths,
    )
    return refusal


def _profile_surface_keys(profile: ProviderProfile) -> frozenset[tuple[str, str]]:
    declared: set[tuple[str, str]] = set()
    for url in profile.operational_urls():
        try:
            surface = canonical_surface(url, purpose="entry")
        except ValueError:
            continue
        declared.add((surface.host, surface.path))
    return frozenset(declared)


def validate_profile_plan(plan: RunPlan, *, profile: ProviderProfile) -> PlanRefusal | None:
    """Validate every surface against one committed profile and its digest."""

    if plan.app_slug != profile.app_slug:
        return _refuse("app_slug_mismatch", CREDENTIAL_SURFACE_ORDINAL)
    if (
        plan.catalog_id != PROFILE_CATALOG_ID
        or plan.recipe_version != profile.profile_digest
        or plan.success_digest != profile_success_digest(profile)
    ):
        return _refuse("profile_binding_mismatch", CREDENTIAL_SURFACE_ORDINAL)
    declared = _profile_surface_keys(profile)
    if not declared:
        return _refuse("credential_surface_unprovable", CREDENTIAL_SURFACE_ORDINAL)
    if len(plan.surfaces) > len(declared):
        return _refuse("surface_count_exceeds_profile", len(declared) + 1)
    try:
        allowed = profile.allowed_hosts()
    except BrowserPolicyInactiveError:
        return _refuse("navigation_denied", CREDENTIAL_SURFACE_ORDINAL)

    def check(surface: PlannedSurface, ordinal: int) -> PlanRefusal | None:
        if (surface.host, surface.path) not in declared:
            return _refuse("host_not_in_profile", ordinal)
        if not evaluate_navigation(f"https://{surface.host}{surface.path}", allowed).allowed:
            return _refuse("navigation_denied", ordinal)
        return None

    for ordinal, surface in enumerate(plan.surfaces, start=1):
        refusal = check(surface, ordinal)
        if refusal is not None:
            return refusal
    return check(plan.credential_surface, CREDENTIAL_SURFACE_ORDINAL)


def validate_plan(
    plan: RunPlan,
    *,
    recipe: AppRecipe | None = None,
    profile: ProviderProfile | None = None,
) -> PlanRefusal | None:
    """Validate against exactly one immutable route authority."""

    if (recipe is None) == (profile is None):
        raise ValueError("plan validation requires exactly one route authority")
    if profile is not None:
        return validate_profile_plan(plan, profile=profile)
    assert recipe is not None
    return _validate_recipe_plan(plan, recipe=recipe)


__all__ = [
    "CREDENTIAL_SURFACE_ORDINAL",
    "PLAN_REFUSAL_REASON_CODE",
    "DeclaredPaths",
    "PlanRefusal",
    "PlanRefusalDetail",
    "declared_paths",
    "declared_surface_paths",
    "validate_plan",
    "validate_profile_plan",
]
