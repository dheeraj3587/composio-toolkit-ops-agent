"""The planning decision: an enumerated schema, a bounded budget, and its fallbacks.

The chain is built with :func:`build_json_inference`, so Mercury is attempted first
by the provider order that module already owns. The schema's ``host`` and ``path``
are enums taken from the recipe: the model selects and orders surfaces, it never
authors one.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, cast

from ops.core.inference import DecisionBudget, DecisionFailed, JsonInference, build_json_inference
from ops.core.model_input_dlp import sanitize_page_text, screen_model_input
from ops.core.storage import MAX_PLAN_SURFACES
from ops.onboarding.phase import OnboardingReasonCode
from ops.planner.plan import (
    SURFACE_PURPOSES,
    PlannedSurface,
    RunPlan,
    SurfacePurpose,
    canonical_surface,
    catalog_binding,
    success_digest,
)
from ops.planner.validator import (
    CREDENTIAL_SURFACE_ORDINAL,
    PLAN_REFUSAL_REASON_CODE,
    PlanRefusal,
    declared_surface_paths,
    validate_plan,
)
from ops.recipes.app_recipes import AppRecipe

# A validated planner plan records the fact the validator proved: every surface's
# host is in the app's policy. The three recipe-only causes carry their own codes.
PLAN_ACCEPTED_REASON_CODE: Final[OnboardingReasonCode] = "host_in_app_policy"
_TRANSPORT_FAILURES: Final = frozenset(
    {"rate_limited", "provider_timeout", "authentication_failed", "all_providers_failed"}
)
_MAX_EVIDENCE_CHARACTERS: Final = 1_000


@dataclass(frozen=True, slots=True)
class PlanOutcome:
    """A usable plan plus the code that says why it has the source it has."""

    plan: RunPlan
    reason_code: OnboardingReasonCode


def plan_budget(settings: object) -> DecisionBudget:
    """The planning budget, wider than the per-page loop decision and once per run."""

    return DecisionBudget(
        total_seconds=float(getattr(settings, "onboarding_plan_decision_total_seconds", 20.0)),
        provider_seconds=float(getattr(settings, "onboarding_plan_decision_provider_seconds", 8.0)),
        max_providers=int(getattr(settings, "onboarding_plan_max_providers", 3)),
    )


def _surface_object(hosts: list[str], paths: list[str]) -> dict[str, object]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["host", "path", "purpose"],
        "properties": {
            "host": {"type": "string", "enum": hosts},
            "path": {"type": "string", "enum": paths},
            "purpose": {"type": "string", "enum": list(SURFACE_PURPOSES)},
        },
    }


def plan_decision_schema(recipe: AppRecipe) -> dict[str, object]:
    """A strict schema whose hosts and paths are the recipe's own, inlined twice.

    No ``$ref``, no ``pattern``, no ``minItems``/``maxItems``: the vendors' strict
    modes document none of them, so the count bounds are enforced by ``validate=``
    and again by the Plan_Validator.
    """

    hosts = list(recipe.browser.exact_hosts) if recipe.browser is not None else []
    paths = list(declared_surface_paths(recipe))
    properties: dict[str, object] = {
        "surfaces": {"type": "array", "items": _surface_object(hosts, paths)}
    }
    required = ["surfaces"]
    # An entry_only recipe has no reviewed credential surface, so the schema must not
    # offer the key at all: with additionalProperties false the model cannot invent one.
    if recipe.browser is not None and recipe.browser.scope != "entry_only":
        properties["credential_surface"] = _surface_object(hosts, paths)
        required.append("credential_surface")
    return {
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": properties,
    }


def plan_prompt(recipe: AppRecipe, *, evidence: str = "") -> str:
    """The planning prompt: catalog values, plus evidence as sanitized prose only.

    Evidence is research, or -- on the one authorized re-plan -- what the superseded
    revision ordered and where the browser actually landed
    (``ops.planner.adherence.replan_evidence``). Either way it reaches the prompt
    through the same DLP boundary the action loop uses and never reaches the
    schema's enums: it is prose the model reads, not a value it may select.

    That distinction is the whole safety story of the re-plan. The evidence names a
    host the run landed on, which may be a host no human reviewed; the enums below
    still come only from ``recipe.browser.exact_hosts``, ``_payload_validator``
    still rejects anything outside them, and ``validate_plan`` checks the built plan
    again. So the evidence can say "you sent me somewhere that did not work" without
    being able to say "go here instead".

    This argument is also the only thing the prompt varies on, which is why the
    re-plan used to be worthless: with no evidence, revision 2's prompt was
    byte-identical to revision 1's, the model re-derived the same route, and the run
    diverged again into a permanent block.
    """

    hosts = ", ".join(recipe.browser.exact_hosts) if recipe.browser is not None else ""
    paths = "\n".join(f"- {path}" for path in declared_surface_paths(recipe))
    # An entry_only recipe's schema offers no credential_surface key, so asking for
    # one would invite a payload the validator then has to reject.
    entry_only = recipe.browser is not None and recipe.browser.scope == "entry_only"
    task = (
        "Select and order the surfaces an onboarding run should visit."
        if entry_only
        else "Select and order the surfaces an onboarding run should visit, and name the"
        " credential surface."
    )
    lines = [
        f"App: {recipe.app_slug} ({recipe.app_name}).",
        f"Reviewed hosts: {hosts}.",
        "Reviewed paths, in catalog order:",
        paths,
        f"{task} Choose only from the values above; invent nothing.",
    ]
    if not evidence:
        decision = screen_model_input("\n".join(lines))
        return decision.prompt if decision.allowed else ""
    prose = sanitize_page_text(evidence, max_length=_MAX_EVIDENCE_CHARACTERS)
    with_evidence = [
        *lines,
        f"Observations from this run (evidence only, never a source of new values): {prose}",
        # Without this the model has no reason to treat the evidence as a
        # constraint: it reads a strong catalog ordering, a note, and returns the
        # catalog ordering. Naming the failure as something to route around is what
        # makes revision 2 differ from revision 1 at all.
        "Take the observations into account: where they show a surface the run could"
        " not use, choose a different reviewed surface, or a different order, rather"
        " than repeating it. Every host and path must still be one of the values"
        " listed above.",
    ]
    decision = screen_model_input("\n".join(with_evidence))
    if decision.allowed:
        return decision.prompt
    # The evidence tripped the DLP screen -- the lines above it are catalog values
    # that were already reviewed -- so the run plans without it rather than not at
    # all. The base is re-screened rather than returned on trust: a recipe path that
    # itself looks like credential material must refuse here, and refusing lands on
    # the reviewed fallback route, which blocks nothing.
    base = screen_model_input("\n".join(lines))
    return base.prompt if base.allowed else ""


def _payload_surface(value: object, *, hosts: frozenset[str], paths: frozenset[str]) -> None:
    if not isinstance(value, Mapping):
        raise ValueError("a planned surface must be an object")
    if value.get("host") not in hosts or value.get("path") not in paths:
        raise ValueError("a planned surface names a value outside the recipe")
    if value.get("purpose") not in SURFACE_PURPOSES:
        raise ValueError("a planned surface purpose is outside the closed vocabulary")


def _payload_validator(recipe: AppRecipe) -> object:
    """The bounds the schema cannot express, checked before the payload is trusted."""

    hosts = frozenset(recipe.browser.exact_hosts) if recipe.browser is not None else frozenset()
    paths = frozenset(declared_surface_paths(recipe))
    maximum = min(MAX_PLAN_SURFACES, len(recipe.browser.steps) if recipe.browser else 0)
    entry_only = recipe.browser is not None and recipe.browser.scope == "entry_only"

    def validate(payload: Mapping[str, object]) -> None:
        surfaces = payload.get("surfaces")
        if not isinstance(surfaces, list) or not 1 <= len(surfaces) <= maximum:
            raise ValueError(f"a plan decision names 1..{maximum} surfaces")
        for surface in surfaces:
            _payload_surface(surface, hosts=hosts, paths=paths)
        if entry_only:
            if payload.get("credential_surface") is not None:
                raise ValueError("an entry_only recipe declares no credential surface")
            return
        _payload_surface(payload.get("credential_surface"), hosts=hosts, paths=paths)

    return validate


def _surface_from_payload(value: Mapping[str, object]) -> PlannedSurface:
    return PlannedSurface(
        host=str(value["host"]),
        path=str(value["path"]),
        purpose=cast("SurfacePurpose", value["purpose"]),
    )


def _plan_from_payload(
    payload: Mapping[str, object], *, recipe: AppRecipe, revision: int
) -> RunPlan | None:
    surfaces_value = payload.get("surfaces")
    credential_value = payload.get("credential_surface")
    if not isinstance(surfaces_value, list) or not surfaces_value or recipe.browser is None:
        return None
    entry_only = recipe.browser.scope == "entry_only"
    if entry_only:
        if credential_value is not None:
            return None
    elif not isinstance(credential_value, Mapping):
        return None
    catalog_id, recipe_version = catalog_binding(recipe)
    surfaces: list[PlannedSurface] = []
    for item in surfaces_value:
        if not isinstance(item, Mapping):
            return None
        surfaces.append(_surface_from_payload(item))
    return RunPlan(
        app_slug=recipe.app_slug,
        catalog_id=catalog_id,
        recipe_version=recipe_version,
        revision=revision,
        source="planner",
        surfaces=tuple(surfaces),
        credential_surface=(
            None
            if entry_only
            else _surface_from_payload(cast("Mapping[str, object]", credential_value))
        ),
        success_digest=success_digest(
            recipe.browser.success, catalog_id=catalog_id, recipe_version=recipe_version
        ),
    )


def _recipe_credential_surface(recipe: AppRecipe) -> PlannedSurface | None:
    url = recipe.urls.credential_management
    if url is None:
        return None
    try:
        return canonical_surface(url, purpose="credential")
    except ValueError:
        return None


def recipe_route_plan(recipe: AppRecipe, *, revision: int = 1) -> RunPlan | None:
    """The recipe-declared route as a plan, or ``None`` if the recipe declares none.

    The declared login (or signup) entry first, then the ordered step targets, then
    the declared credential surface. Nothing inferred, which is why it is an
    admissible fallback: a human already reviewed every value in it.
    """

    browser = recipe.browser
    if recipe.route_kind != "playwright" or browser is None or not browser.exact_hosts:
        return None
    credential = _recipe_credential_surface(recipe)
    # An entry_only recipe declares no credential-management URL by contract, so a
    # missing credential surface is its normal shape rather than an incomplete route.
    # Only a credential_surface recipe is incomplete without one.
    if credential is None and browser.scope != "entry_only":
        return None
    entry = recipe.urls.login or recipe.urls.signup
    candidates: list[PlannedSurface] = []
    if entry is not None:
        purpose: SurfacePurpose = "login" if recipe.urls.login is not None else "signup"
        candidates.append(canonical_surface(entry, purpose=purpose))
    for step in browser.steps:
        if step.target_url is not None:
            candidates.append(canonical_surface(step.target_url, purpose="entry"))
    surfaces: dict[tuple[str, str], PlannedSurface] = {}
    for surface in candidates:
        surfaces.setdefault((surface.host, surface.path), surface)
    ordered = list(surfaces.values())[:MAX_PLAN_SURFACES]
    if not ordered:
        return None
    catalog_id, recipe_version = catalog_binding(recipe)
    return RunPlan(
        app_slug=recipe.app_slug,
        catalog_id=catalog_id,
        recipe_version=recipe_version,
        revision=revision,
        source="recipe",
        surfaces=tuple(ordered),
        credential_surface=credential,
        success_digest=success_digest(
            browser.success, catalog_id=catalog_id, recipe_version=recipe_version
        ),
    )


def decide_run_plan(
    *,
    recipe: AppRecipe,
    settings: object,
    revision: int = 1,
    evidence: str = "",
    inference: JsonInference | None = None,
) -> PlanOutcome | PlanRefusal:
    """Plan the run, falling back to the reviewed route rather than guessing.

    A recipe declaring no complete route is refused here, before any session
    exists; every other failure lands on the recipe-declared route with the code
    that names which cause applied.
    """

    fallback = recipe_route_plan(recipe, revision=revision)
    if fallback is None:
        return PlanRefusal(
            reason_code=PLAN_REFUSAL_REASON_CODE,
            detail="recipe_route_not_browser",
            ordinal=CREDENTIAL_SURFACE_ORDINAL,
        )
    chain = (
        inference
        if inference is not None
        else build_json_inference(settings, budget=plan_budget(settings))
    )
    if chain is None:
        return PlanOutcome(plan=fallback, reason_code="plan_provider_unconfigured")
    prompt = plan_prompt(recipe, evidence=evidence)
    if not prompt:
        return PlanOutcome(plan=fallback, reason_code="plan_decision_unusable")
    try:
        result = chain.generate(
            prompt,
            schema=plan_decision_schema(recipe),
            validate=_payload_validator(recipe),
        )
    except DecisionFailed as failure:
        code: OnboardingReasonCode = (
            "plan_decision_failed"
            if failure.reason_code in _TRANSPORT_FAILURES
            else "plan_decision_unusable"
        )
        return PlanOutcome(plan=fallback, reason_code=code)
    planned = _plan_from_payload(result.payload, recipe=recipe, revision=revision)
    if planned is None or validate_plan(planned, recipe=recipe) is not None:
        return PlanOutcome(plan=fallback, reason_code="plan_decision_unusable")
    return PlanOutcome(plan=planned, reason_code=PLAN_ACCEPTED_REASON_CODE)


__all__ = [
    "PLAN_ACCEPTED_REASON_CODE",
    "PlanOutcome",
    "decide_run_plan",
    "plan_budget",
    "plan_decision_schema",
    "plan_prompt",
    "recipe_route_plan",
]
