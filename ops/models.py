"""Strict public contracts for the operations pipeline."""

from __future__ import annotations

import re
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ops.state import AccessRoute

VAULT_REFERENCE_PATTERN = re.compile(r"^vault://[a-z0-9-]+/[a-z0-9_-]+/[A-Za-z0-9_-]+$")
VaultReference = Annotated[str, Field(min_length=12, max_length=512)]
CapabilityStatus = Literal[
    "ready",
    "configuration_required",
    "contract_incompatible",
    "disabled",
    "failed",
]


def validate_vault_reference(value: str) -> str:
    """Accept only exact opaque vault references, never credential values."""

    if VAULT_REFERENCE_PATTERN.fullmatch(value) is None:
        raise ValueError("credential values must be exact vault:// references")
    return value


def validate_https_url(value: str) -> str:
    """Validate a bounded HTTPS URL without performing network I/O.

    Network-facing boundaries perform DNS and redirect validation as well.  The
    model validator prevents credentials, relative URLs, and non-HTTPS schemes
    from ever becoming durable workflow data.
    """

    if len(value) > 2_048:
        raise ValueError("URL exceeds the supported length")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("an absolute HTTPS URL is required")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing user information are not allowed")
    return value


class StrictModel(BaseModel):
    """Base contract that rejects drift and hides rejected values in errors."""

    model_config = ConfigDict(
        extra="forbid",
        hide_input_in_errors=True,
        str_strip_whitespace=True,
    )


class CompanyProfile(StrictModel):
    legal_name: str = Field(min_length=1, max_length=200)
    website: str
    work_email_ref: VaultReference
    use_case: str = Field(min_length=1, max_length=2_000)
    expected_volume: str | None = Field(default=None, max_length=200)
    callback_urls: list[str] = Field(default_factory=list)

    _validate_work_email_ref = field_validator("work_email_ref")(validate_vault_reference)
    _validate_website = field_validator("website")(validate_https_url)
    _validate_callback_urls = field_validator("callback_urls")(
        lambda values: [validate_https_url(value) for value in values]
    )


class OperationsRequest(StrictModel):
    app_name: str = Field(min_length=1, max_length=200)
    company: CompanyProfile
    requested_scope_policy: Literal["minimum", "recommended", "maximum"] = "maximum"
    dry_run: bool = True
    outreach_recipient_override: str | None = Field(default=None, max_length=320)


class ScopeRequirement(StrictModel):
    name: str = Field(min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=2_000)
    required: bool | None = None
    source_url: str

    _validate_source_url = field_validator("source_url")(validate_https_url)


class OperationalResearch(StrictModel):
    app_name: str = Field(min_length=1, max_length=200)
    app_slug: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", max_length=120)
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
    evidence_urls: list[str] = Field(max_length=50)
    confidence: float = Field(ge=0.0, le=1.0)

    @field_validator(
        "api_base_url",
        "authorization_url",
        "token_url",
        "developer_portal_url",
        "signup_url",
        "contact_url",
    )
    @classmethod
    def validate_optional_urls(cls, value: str | None) -> str | None:
        return validate_https_url(value) if value is not None else None

    _validate_evidence_urls = field_validator("evidence_urls")(
        lambda values: [validate_https_url(value) for value in values]
    )


class CapabilityAvailability(StrictModel):
    """Sanitized capability state suitable for API and workflow persistence."""

    capability: str = Field(min_length=1, max_length=100)
    status: CapabilityStatus
    reason_code: str = Field(min_length=1, max_length=100)
    detail: str = Field(min_length=1, max_length=500)


class HitlRequest(StrictModel):
    """A bounded human-action request containing no credential material."""

    type: Literal[
        "captcha",
        "email_otp",
        "phone_otp",
        "passkey",
        "security_key",
        "device_approval",
        "provider_verification",
        "legal_acceptance",
        "billing",
        "account_selection",
    ]
    app_name: str = Field(min_length=1, max_length=200)
    message: str = Field(min_length=1, max_length=500)
    expected_completion_signal: str = Field(min_length=1, max_length=500)
    live_view_available: bool = False


class IntegratorBundle(StrictModel):
    app_name: str
    app_slug: str
    readiness: Literal[
        "credentials_ready",
        "awaiting_provider",
        "human_action_required",
        "configuration_required",
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
