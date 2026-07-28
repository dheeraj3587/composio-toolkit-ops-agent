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
    "managed_connection_ready",
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
        name: validate_vault_reference(reference) for name, reference in credential_refs.items()
    }
    readiness = _readiness(
        route=research.access_route,
        refs_present=bool(refs),
        provider_account_ready=bool(provider_account_id),
        validation=validation,
        capabilities=capabilities,
        stage=stage,
    )
    notes = list(operational_notes)
    if validation is not None:
        notes.append(f"Credential validation status: {validation.status}.")
    if readiness == "configuration_required":
        notes.append("One or more external capabilities require operator configuration.")
    auth_scheme = _auth_scheme(research.auth_methods, refs)
    oauth_selected = auth_scheme == "oauth2"
    return IntegratorBundle(
        app_name=research.app_name,
        app_slug=research.app_slug,
        readiness=readiness,
        api_type=research.api_type,
        api_base_url=research.api_base_url,
        auth_scheme=auth_scheme,
        authorization_url=research.authorization_url if oauth_selected else None,
        token_url=research.token_url if oauth_selected else None,
        scopes=[scope.name for scope in research.scopes] if oauth_selected else [],
        callback_urls=list(company.callback_urls) if oauth_selected else [],
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
    provider_account_ready: bool,
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
    if stage == "managed_connection_ready":
        return "credentials_ready" if provider_account_ready else "configuration_required"
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
    if any(
        capability.status in {"configuration_required", "contract_incompatible"}
        for capability in capabilities
    ):
        return "configuration_required"
    if stage == "awaiting_provider" or route in {"approval_required", "partner_gated", "hybrid"}:
        return "awaiting_provider"
    return "configuration_required"


def _auth_scheme(methods: list[str], credential_refs: dict[str, str]) -> str:
    # Concrete captured fields are stronger evidence than a provider's list of all
    # supported methods. Pipedrive advertises OAuth and personal API tokens; when
    # this run actually captured ``api_token``, calling the handoff OAuth2 is false.
    normalized_fields = {field.casefold().replace("-", "_") for field in credential_refs}
    if normalized_fields & {"api_key", "apikey", "api_token"}:
        return "api_key"

    normalized = " ".join(methods).casefold()
    if "oauth" in normalized:
        return "oauth2"
    if "api key" in normalized or "apikey" in normalized:
        return "api_key"
    if "basic" in normalized:
        return "basic"
    return "unknown"
