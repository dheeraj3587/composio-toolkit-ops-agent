"""Deterministic IntegratorBundle construction from sanitized workflow facts."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from ops.credential_validator import CredentialValidationResult
from ops.models import (
    CapabilityAvailability,
    CompanyProfile,
    IntegratorBundle,
    OperationalResearch,
    validate_vault_reference,
)

BundleStage = Literal[
    "normal",
    "awaiting_provider",
    "human_action_required",
    "blocked",
    "failed",
]


def build_integrator_bundle(
    *,
    research: OperationalResearch,
    company: CompanyProfile,
    credential_refs: dict[str, str],
    validation: CredentialValidationResult | None,
    capabilities: tuple[CapabilityAvailability, ...] = (),
    stage: BundleStage = "normal",
    provider_account_id: str | None = None,
    developer_app_id: str | None = None,
    operational_notes: tuple[str, ...] = (),
) -> IntegratorBundle:
    """Build a strict reference-only handoff without guessing readiness."""

    refs = {
        name: validate_vault_reference(reference)
        for name, reference in credential_refs.items()
    }
    readiness = _readiness(
        route=research.access_route,
        refs_present=bool(refs),
        validation=validation,
        capabilities=capabilities,
        stage=stage,
    )
    notes = list(operational_notes)
    if validation is not None:
        notes.append(f"Credential validation status: {validation.status}.")
    if readiness == "configuration_required":
        notes.append("One or more external capabilities require operator configuration.")
    return IntegratorBundle(
        app_name=research.app_name,
        app_slug=research.app_slug,
        readiness=readiness,
        api_type=research.api_type,
        api_base_url=research.api_base_url,
        auth_scheme=_auth_scheme(research.auth_methods),
        authorization_url=research.authorization_url,
        token_url=research.token_url,
        scopes=[scope.name for scope in research.scopes],
        callback_urls=list(company.callback_urls),
        credential_refs=refs,
        access_route=research.access_route,
        provider_account_id=provider_account_id,
        developer_app_id=developer_app_id,
        evidence_urls=list(research.evidence_urls),
        operational_notes=notes,
        created_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    )


def _readiness(
    *,
    route: str,
    refs_present: bool,
    validation: CredentialValidationResult | None,
    capabilities: tuple[CapabilityAvailability, ...],
    stage: BundleStage,
) -> Literal[
    "credentials_ready",
    "awaiting_provider",
    "human_action_required",
    "configuration_required",
    "blocked",
    "failed",
]:
    if stage == "failed":
        return "failed"
    if stage == "blocked" or route == "blocked":
        return "blocked"
    if stage == "human_action_required":
        return "human_action_required"
    if refs_present:
        if validation is None:
            return "configuration_required"
        if validation.status == "valid":
            return "credentials_ready"
        if validation.status == "unavailable":
            return "configuration_required"
        return "failed"
    if any(capability.status in {"configuration_required", "contract_incompatible"} for capability in capabilities):
        return "configuration_required"
    if stage == "awaiting_provider" or route in {"approval_required", "partner_gated", "hybrid"}:
        return "awaiting_provider"
    return "configuration_required"


def _auth_scheme(methods: list[str]) -> str:
    normalized = " ".join(methods).casefold()
    if "oauth" in normalized:
        return "oauth2"
    if "api key" in normalized or "apikey" in normalized:
        return "api_key"
    if "basic" in normalized:
        return "basic"
    return "unknown"

