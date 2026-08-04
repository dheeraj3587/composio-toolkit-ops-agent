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
from ops.core.models import OperationalResearch
from ops.core.storage import MAX_PLAN_SURFACES
from ops.onboarding.phase import OnboardingReasonCode
from ops.planner.plan import (
    SURFACE_PURPOSES,
    PlannedSurface,
    RunPlan,
    SurfacePurpose,
    canonical_surface,
    catalog_binding,
    profile_binding,
    profile_success_digest,
    success_digest,
)
from ops.planner.validator import (
    CREDENTIAL_SURFACE_ORDINAL,
    PLAN_REFUSAL_REASON_CODE,
    PlanRefusal,
    declared_surface_paths,
    validate_plan,
    validate_profile_plan,
)
from ops.providers.profile import ProviderProfile
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


class InferenceUnset:
    """Sentinel distinguishing "no chain supplied" from an explicit ``None``.

    ``inference=None`` used to mean "build one", which left no way to ask for
    planning *without* a model — an offline deployment, or a test that must not
    reach a provider, had no way to say so. Planning with no model is a
    first-class outcome (the deterministic route plus
    ``plan_provider_unconfigured``), so it needs to be expressible.
    """

    __slots__ = ()


UNSET_INFERENCE: Final = InferenceUnset()


def _resolved_chain(
    inference: JsonInference | None | InferenceUnset, settings: object
) -> JsonInference | None:
    """The chain to plan with: build only when nothing at all was supplied."""

    if isinstance(inference, InferenceUnset):
        return build_json_inference(settings, budget=plan_budget(settings))
    return inference


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
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["surfaces", "credential_surface"],
        "properties": {
            "surfaces": {"type": "array", "items": _surface_object(hosts, paths)},
            "credential_surface": _surface_object(hosts, paths),
        },
    }


def plan_prompt(recipe: AppRecipe, *, evidence: str = "") -> str:
    """The planning prompt: catalog values, plus research as sanitized prose only.

    Research is evidence, so it reaches the prompt through the same DLP boundary the
    action loop uses and never reaches the schema's enums.
    """

    hosts = ", ".join(recipe.browser.exact_hosts) if recipe.browser is not None else ""
    paths = "\n".join(f"- {path}" for path in declared_surface_paths(recipe))
    lines = [
        f"App: {recipe.app_slug} ({recipe.app_name}).",
        f"Reviewed hosts: {hosts}.",
        "Reviewed paths, in catalog order:",
        paths,
        "Select and order the surfaces an onboarding run should visit, and name the",
        "credential surface. Choose only from the values above; invent nothing.",
    ]
    if evidence:
        prose = sanitize_page_text(evidence, max_length=_MAX_EVIDENCE_CHARACTERS)
        lines.append(f"Research notes (evidence only): {prose}")
    decision = screen_model_input("\n".join(lines))
    if decision.allowed:
        return decision.prompt
    return "\n".join(lines[:-1]) if evidence else ""


def research_evidence(research: OperationalResearch) -> str:
    """Render live research as bounded prose for a planning prompt.

    Evidence, never authority: the strings here are only ever appended to a prompt
    behind ``sanitize_page_text``/``screen_model_input``, and the schema's enums
    still come from the recipe or the committed profile. So a research field that
    disagrees with the route authority cannot introduce a surface — it can only
    inform the order the model selects among surfaces that already exist.
    """

    parts = [f"access route: {research.access_route}"]
    for label, url in (
        ("signup", research.signup_url),
        ("login", research.login_url),
        ("credential management", research.credential_management_url),
        ("developer portal", research.developer_portal_url),
    ):
        if url:
            parts.append(f"{label} observed at {url}")
    # The instructions are the one genuinely prose-shaped research output, and the
    # part most likely to name which surface a credential is actually minted on.
    for instruction in research.credential_creation_instructions[:4]:
        parts.append(str(instruction))
    return "; ".join(parts)


def profile_research_evidence(profile: ProviderProfile) -> str:
    """Render a committed profile's own corroborated evidence as prose.

    The mounted path has no ``OperationalResearch``; what it has is the field
    evidence the profile was built from, which is the same live discovery output
    one corroboration step later. Values are already proven to lie on the
    profile's registrable domain, so this adds no reach.
    """

    parts: list[str] = []
    for item in profile.evidence:
        if item.field not in ("signup_url", "login_url", "developer_portal_url"):
            continue
        parts.append(f"{item.field} {item.value} ({item.corroborations} sources)")
    return "; ".join(parts)


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

    def validate(payload: Mapping[str, object]) -> None:
        surfaces = payload.get("surfaces")
        if not isinstance(surfaces, list) or not 1 <= len(surfaces) <= maximum:
            raise ValueError(f"a plan decision names 1..{maximum} surfaces")
        for surface in surfaces:
            _payload_surface(surface, hosts=hosts, paths=paths)
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
    if not isinstance(surfaces_value, list) or not surfaces_value:
        return None
    if not isinstance(credential_value, Mapping) or recipe.browser is None:
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
        credential_surface=_surface_from_payload(credential_value),
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
    if credential is None:
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


def _profile_declared_surfaces(profile: ProviderProfile) -> tuple[PlannedSurface, ...]:
    """Canonical profile-owned surfaces in onboarding order, de-duplicated."""

    candidates: list[tuple[str | None, SurfacePurpose]] = [
        (profile.signup_url, "signup"),
        (profile.login_url, "login"),
        (profile.developer_portal_url, "developer_app"),
    ]
    for flow in profile.flows():
        purpose: SurfacePurpose = "developer_app" if flow.kind == "developer_app" else "credential"
        candidates.append((flow.entry_url, purpose))
    candidates.append((profile.developer_docs_url, "entry"))
    surfaces: dict[tuple[str, str], PlannedSurface] = {}
    for url, purpose in candidates:
        if url is None:
            continue
        surface = canonical_surface(url, purpose=purpose)
        surfaces.setdefault((surface.host, surface.path), surface)
    return tuple(surfaces.values())


def _profile_credential_surface(profile: ProviderProfile) -> PlannedSurface | None:
    for flow in profile.flows():
        if flow.supported and flow.entry_url is not None:
            return canonical_surface(flow.entry_url, purpose="credential")
    fallback = profile.developer_portal_url or profile.login_url or profile.signup_url
    return None if fallback is None else canonical_surface(fallback, purpose="credential")


def profile_route_plan(profile: ProviderProfile, *, revision: int = 1) -> RunPlan | None:
    """Deterministic fallback containing only committed-profile canonical URLs."""

    surfaces = _profile_declared_surfaces(profile)[:MAX_PLAN_SURFACES]
    credential = _profile_credential_surface(profile)
    if not surfaces or credential is None:
        return None
    catalog_id, profile_digest = profile_binding(profile)
    return RunPlan(
        app_slug=profile.app_slug,
        catalog_id=catalog_id,
        recipe_version=profile_digest,
        revision=revision,
        source="profile",
        surfaces=surfaces,
        credential_surface=credential,
        success_digest=profile_success_digest(profile),
    )


def profile_plan_decision_schema(profile: ProviderProfile) -> dict[str, object]:
    declared = _profile_declared_surfaces(profile)
    hosts = list(dict.fromkeys(surface.host for surface in declared))
    paths = list(dict.fromkeys(surface.path for surface in declared))
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["surfaces", "credential_surface"],
        "properties": {
            "surfaces": {"type": "array", "items": _surface_object(hosts, paths)},
            "credential_surface": _surface_object(hosts, paths),
        },
    }


def profile_plan_prompt(profile: ProviderProfile, *, evidence: str = "") -> str:
    """The profile planning prompt: committed URLs, plus research as prose only.

    ``evidence`` reaches the model through the same DLP boundary the recipe prompt
    and the action loop use, and never reaches the schema's enums — the committed
    profile remains the only authority over which hosts and paths exist.
    """

    declared = _profile_declared_surfaces(profile)
    lines = [
        f"App: {profile.app_slug} ({profile.provider_name}).",
        f"Committed profile digest: {profile.profile_digest}.",
        "Select and order only these corroborated canonical surfaces:",
        *(f"- {surface.purpose}: https://{surface.host}{surface.path}" for surface in declared),
        "Name the credential surface using only the same host/path vocabulary. Invent nothing.",
    ]
    if evidence:
        prose = sanitize_page_text(evidence, max_length=_MAX_EVIDENCE_CHARACTERS)
        lines.append(f"Research notes (evidence only): {prose}")
    decision = screen_model_input("\n".join(lines))
    if decision.allowed:
        return decision.prompt
    # A screened-out prompt loses only the evidence line; the corroborated
    # surfaces are catalog-equivalent values and are safe to plan from alone.
    return "\n".join(lines[:-1]) if evidence else ""


def _profile_payload_validator(profile: ProviderProfile) -> object:
    declared = _profile_declared_surfaces(profile)
    pairs = frozenset((surface.host, surface.path) for surface in declared)
    hosts = frozenset(surface.host for surface in declared)
    paths = frozenset(surface.path for surface in declared)

    def validate(payload: Mapping[str, object]) -> None:
        surfaces = payload.get("surfaces")
        if not isinstance(surfaces, list) or not 1 <= len(surfaces) <= min(
            MAX_PLAN_SURFACES, len(pairs)
        ):
            raise ValueError("a profile plan decision has an invalid surface count")
        for value in (*surfaces, payload.get("credential_surface")):
            _payload_surface(value, hosts=hosts, paths=paths)
            assert isinstance(value, Mapping)
            if (value.get("host"), value.get("path")) not in pairs:
                raise ValueError("a profile plan combined values from different canonical URLs")

    return validate


def _profile_plan_from_payload(
    payload: Mapping[str, object], *, profile: ProviderProfile, revision: int
) -> RunPlan | None:
    surfaces_value = payload.get("surfaces")
    credential_value = payload.get("credential_surface")
    if not isinstance(surfaces_value, list) or not surfaces_value:
        return None
    if not isinstance(credential_value, Mapping):
        return None
    surfaces: list[PlannedSurface] = []
    for item in surfaces_value:
        if not isinstance(item, Mapping):
            return None
        surfaces.append(_surface_from_payload(item))
    catalog_id, profile_digest = profile_binding(profile)
    return RunPlan(
        app_slug=profile.app_slug,
        catalog_id=catalog_id,
        recipe_version=profile_digest,
        revision=revision,
        source="planner",
        surfaces=tuple(surfaces),
        credential_surface=_surface_from_payload(credential_value),
        success_digest=profile_success_digest(profile),
    )


def decide_profile_plan(
    *,
    profile: ProviderProfile,
    settings: object,
    revision: int = 1,
    evidence: str = "",
    inference: JsonInference | None | InferenceUnset = UNSET_INFERENCE,
) -> PlanOutcome | PlanRefusal:
    """Let the model order profile-owned URLs; fall back without inventing any."""

    fallback = profile_route_plan(profile, revision=revision)
    if fallback is None:
        return PlanRefusal(
            reason_code=PLAN_REFUSAL_REASON_CODE,
            detail="credential_surface_unprovable",
            ordinal=CREDENTIAL_SURFACE_ORDINAL,
        )
    chain = _resolved_chain(inference, settings)
    if chain is None:
        return PlanOutcome(plan=fallback, reason_code="plan_provider_unconfigured")
    prompt = profile_plan_prompt(profile, evidence=evidence)
    if not prompt:
        return PlanOutcome(plan=fallback, reason_code="plan_decision_unusable")
    try:
        result = chain.generate(
            prompt,
            schema=profile_plan_decision_schema(profile),
            validate=_profile_payload_validator(profile),
        )
    except DecisionFailed as failure:
        code: OnboardingReasonCode = (
            "plan_decision_failed"
            if failure.reason_code in _TRANSPORT_FAILURES
            else "plan_decision_unusable"
        )
        return PlanOutcome(plan=fallback, reason_code=code)
    planned = _profile_plan_from_payload(result.payload, profile=profile, revision=revision)
    if planned is None or validate_profile_plan(planned, profile=profile) is not None:
        return PlanOutcome(plan=fallback, reason_code="plan_decision_unusable")
    return PlanOutcome(plan=planned, reason_code=PLAN_ACCEPTED_REASON_CODE)


def decide_run_plan(
    *,
    recipe: AppRecipe,
    settings: object,
    revision: int = 1,
    evidence: str = "",
    inference: JsonInference | None | InferenceUnset = UNSET_INFERENCE,
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
    chain = _resolved_chain(inference, settings)
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
    "UNSET_INFERENCE",
    "InferenceUnset",
    "PlanOutcome",
    "decide_profile_plan",
    "decide_run_plan",
    "plan_budget",
    "plan_decision_schema",
    "plan_prompt",
    "profile_plan_decision_schema",
    "profile_plan_prompt",
    "profile_research_evidence",
    "profile_route_plan",
    "recipe_route_plan",
    "research_evidence",
]
