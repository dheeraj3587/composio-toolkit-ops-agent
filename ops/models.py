"""Strict public contracts for the operations pipeline."""

from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ops.state import AccessRoute

VAULT_REFERENCE_PATTERN = re.compile(r"^vault://[a-z0-9-]+/[a-z0-9_-]+/[A-Za-z0-9_-]+$")
VaultReference = Annotated[str, Field(min_length=12, max_length=512)]


def validate_vault_reference(value: str) -> str:
    """Accept only exact opaque vault references, never credential values."""

    if VAULT_REFERENCE_PATTERN.fullmatch(value) is None:
        raise ValueError("credential values must be exact vault:// references")
    return value


class StrictModel(BaseModel):
    """Base contract that rejects drift and hides rejected values in errors."""

    model_config = ConfigDict(
        extra="forbid",
        hide_input_in_errors=True,
        str_strip_whitespace=True,
    )


class CompanyProfile(StrictModel):
    legal_name: str
    website: str
    work_email_ref: VaultReference
    use_case: str
    expected_volume: str | None = None
    callback_urls: list[str] = Field(default_factory=list)

    _validate_work_email_ref = field_validator("work_email_ref")(validate_vault_reference)


class OperationsRequest(StrictModel):
    app_name: str
    company: CompanyProfile
    requested_scope_policy: Literal["minimum", "recommended", "maximum"] = "maximum"
    dry_run: bool = True
    outreach_recipient_override: str | None = None


class ScopeRequirement(StrictModel):
    name: str
    description: str | None = None
    required: bool | None = None
    source_url: str


class OperationalResearch(StrictModel):
    app_name: str
    app_slug: str
    api_available: bool | None
    api_type: str
    api_base_url: str | None
    auth_methods: list[str]
    authorization_url: str | None
    token_url: str | None
    credential_fields: list[str]
    scopes: list[ScopeRequirement]
    developer_portal_url: str | None
    signup_url: str | None
    access_route: AccessRoute
    production_approval_required: bool | None
    contact_email: str | None
    contact_url: str | None
    evidence_urls: list[str]
    confidence: float = Field(ge=0.0, le=1.0)


class IntegratorBundle(StrictModel):
    app_name: str
    app_slug: str
    readiness: Literal[
        "credentials_ready",
        "awaiting_provider",
        "human_action_required",
        "blocked",
        "failed",
    ]
    api_type: str
    api_base_url: str | None
    auth_scheme: str
    authorization_url: str | None
    token_url: str | None
    scopes: list[str]
    callback_urls: list[str]
    credential_refs: dict[str, VaultReference]
    access_route: AccessRoute
    provider_account_id: str | None
    developer_app_id: str | None
    evidence_urls: list[str]
    operational_notes: list[str]
    created_at: str

    @field_validator("credential_refs")
    @classmethod
    def validate_credential_refs(cls, credential_refs: dict[str, str]) -> dict[str, str]:
        return {
            name: validate_vault_reference(reference) for name, reference in credential_refs.items()
        }
