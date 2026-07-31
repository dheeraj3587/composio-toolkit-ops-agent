"""Strict public contracts for the operations pipeline."""

from __future__ import annotations

import re
from typing import Annotated, Literal
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ops.browser.setup_values import normalize_provider_setup_fields
from ops.core.state import AccessRoute, BrowserProvider, CredentialCreationPolicy

VAULT_REFERENCE_PATTERN = re.compile(r"^vault://[a-z0-9-]+/[a-z0-9_-]+/[A-Za-z0-9_-]+$")
VaultReference = Annotated[str, Field(min_length=12, max_length=512)]
AccountMode = Literal["existing_account", "create_account"]
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


# Query PARAMETER NAMES that indicate a session/credential artifact rather than
# a stable entry point. Matched against parsed parameter NAMES only — never as a
# substring of the whole URL, so ``?zipcode=123`` (contains "code") and
# ``?monkey=true`` (contains "key") are accepted while ``?code=...`` /
# ``?api_key=...`` are rejected.
_SENSITIVE_QUERY_PARAM_NAMES = frozenset(
    {"access_token", "api_key", "code", "key", "password", "secret", "token"}
)


def validate_operational_url(value: str | None) -> str | None:
    """Validate an operational (not merely evidence-citation) HTTPS URL.

    Beyond ``validate_https_url``, this rejects any URL whose parsed query
    parameter NAMES include a session/credential artifact (an access token, API
    key, auth code, password, or secret), and rejects any URL carrying a
    fragment. Operational fields must hold a stable, documented ENTRY POINT
    (a login page, a credential-management page), never a live, single-use
    session artifact. Parameter-name parsing (not substring matching) means an
    innocuous ``?zipcode=`` or ``?monkey=`` is not falsely rejected.
    """

    if value is None:
        return None
    validated = validate_https_url(value)
    parsed = urlsplit(validated)
    query_names = {name.casefold() for name, _v in parse_qsl(parsed.query, keep_blank_values=True)}
    if query_names & _SENSITIVE_QUERY_PARAM_NAMES:
        raise ValueError("operational URL carries sensitive query data")
    if parsed.fragment:
        raise ValueError("operational entry URLs must not contain fragments")
    return validated


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
    # The durable account-intent contract. ``account_creation_requested`` is
    # retained as the browser-worker compatibility projection and is derived
    # from this field for all new requests.
    account_mode: AccountMode
    requested_scope_policy: Literal["minimum", "recommended", "maximum"] = "maximum"
    # Immutable execution-engine choice. Older callers and checkpoints default to
    # Browser Use; the website sends its explicit operator selection.
    browser_provider: BrowserProvider = "browser_use"
    # Immutable authorization boundary for developer-app/key creation. Legacy
    # API/CLI callers remain read-only unless they opt in explicitly.
    credential_creation_policy: CredentialCreationPolicy = "reuse_only"
    # Immutable, explicitly reviewed provider setup values (names, callback URL,
    # region, expiry, etc.). Secret material is categorically not accepted here.
    provider_setup: dict[str, str] = Field(default_factory=dict, max_length=20)
    dry_run: bool = True
    # Explicit local intent only. It is never inferred from research, a browser
    # page, or an LLM, and is forwarded only to the browser target selector.
    account_creation_requested: bool = False

    @field_validator("provider_setup")
    @classmethod
    def validate_provider_setup(cls, value: dict[str, str]) -> dict[str, str]:
        return normalize_provider_setup_fields(value)

    @model_validator(mode="before")
    @classmethod
    def normalize_account_intent(cls, value: object) -> object:
        """Keep historical checkpoints readable while making mode canonical.

        Older serialized requests only contain ``account_creation_requested``.
        They are upgraded in memory without rewriting the ledger. New callers
        provide ``account_mode`` and the worker-facing boolean is filled in
        deterministically. Conflicting values are rejected instead of allowing
        the API and browser to disagree about whether signup was authorized.
        """

        if not isinstance(value, dict):
            return value
        payload = dict(value)
        # Historical checkpoints may contain the former per-run outreach sink.
        # Ignore it on read; routing is governed exclusively by the deployment's
        # OUTREACH_RECIPIENT_OVERRIDE.
        payload.pop("outreach_recipient_override", None)
        account_mode = payload.get("account_mode")
        creation_requested = payload.get("account_creation_requested")
        if account_mode is None:
            payload["account_mode"] = (
                "create_account" if creation_requested is True else "existing_account"
            )
            return payload
        expected = account_mode == "create_account"
        if creation_requested is None:
            payload["account_creation_requested"] = expected
        elif creation_requested is not expected:
            raise ValueError("account mode conflicts with account creation intent")
        return payload


class ScopeRequirement(StrictModel):
    name: str = Field(min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=2_000)
    required: bool | None = None
    source_url: str

    _validate_source_url = field_validator("source_url")(validate_https_url)


# Operational URL fields that must be backed by field-level evidence when the
# extractor supplies a NEW value (one that does not exactly reaffirm the
# verified P1 baseline).
OperationalUrlField = Literal[
    "api_base_url",
    "authorization_url",
    "token_url",
    "developer_portal_url",
    "signup_url",
    "login_url",
    "credential_management_url",
    "contact_url",
]


class OperationalUrlClaim(StrictModel):
    """A model-supplied assertion that ``url`` (for ``field``) is documented on
    the fetched evidence page ``source_url``.

    Validation elsewhere (``_validate_operational_urls``) requires the claim's
    ``url`` to literally appear in that specific source document's text, that
    ``source_url`` be a page we actually fetched, and that ``url`` pass the
    trusted host policy — so a claim cannot launder an invented URL.
    """

    field: OperationalUrlField
    url: str
    source_url: str

    _validate_url = field_validator("url")(validate_operational_url)
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
    # Bounded, non-secret prose describing HOW to create the credential (e.g.
    # "Open Settings > Private apps > Create app"). Never a rendered credential
    # value, never long research prose, never a browser-generated session URL.
    credential_creation_instructions: tuple[Annotated[str, Field(max_length=500)], ...] = Field(
        default=(), max_length=20
    )
    scopes: list[ScopeRequirement]
    developer_portal_url: str | None
    signup_url: str | None
    # A stable, documented sign-in entry point — distinct from the developer
    # portal or signup page, which may not be where an EXISTING user logs in.
    login_url: str | None = None
    # The stable page where API keys/tokens are viewed or created — distinct
    # from developer_portal_url, which may be a docs/marketing landing page
    # rather than the actual in-app settings screen.
    credential_management_url: str | None = None
    access_route: AccessRoute
    production_approval_required: bool | None
    contact_email: str | None
    contact_url: str | None
    evidence_urls: list[str] = Field(max_length=50)
    # Field-level evidence for NEW operational URLs (see OperationalUrlClaim).
    # Backward-compatible: defaults empty, so existing callers/serialized rows
    # without it remain valid.
    operational_url_claims: tuple[OperationalUrlClaim, ...] = Field(default=(), max_length=32)
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

    @field_validator("login_url", "credential_management_url")
    @classmethod
    def validate_operational_entry_urls(cls, value: str | None) -> str | None:
        return validate_operational_url(value)

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

    # Mirrors ops.browser.worker.HumanActionType, which cannot be imported here
    # (browser_worker imports this module). ops.workflow.graph passes an observation's gate
    # type straight in, so a member missing from this list is a validation failure
    # at the interrupt boundary; tests assert the two stay identical.
    type: Literal[
        "login_required",
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
        "signup_authorization",
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
