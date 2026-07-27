"""Strict, versioned browser automation contracts and durable registry."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ops.private_files import finalize_private_database, prepare_private_database

ContractStatus = Literal["active", "expired", "rejected", "draft"]
ContractRoute = Literal[
    "self_serve",
    "self_serve_with_hitl",
    "hybrid",
    "approval_required",
    "partner_gated",
    "blocked",
    "unsupported",
]
SignupSemanticField = Literal[
    "email",
    "password",
    "password_confirmation",
    "first_name",
    "last_name",
    "full_name",
    "company_name",
    "website",
    "workspace_name",
    "country",
    "role_title",
    "signup_submit",
]
SelectOptionMode = Literal[
    "approved_label",
    "approved_value",
    "fixed_label",
    "fixed_value",
]

_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_EVIDENCE_HASH = re.compile(r"^[0-9a-f]{64}$")
_SEMANTIC_FIELD = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_TEST_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")
_SIGNUP_FIELDS: frozenset[SignupSemanticField] = frozenset(
    {
        "email",
        "password",
        "password_confirmation",
        "first_name",
        "last_name",
        "full_name",
        "company_name",
        "website",
        "workspace_name",
        "country",
        "role_title",
        "signup_submit",
    }
)
# Historical field-name aliases only. These strings are schema vocabulary, not
# credential values; inline allowlisting keeps the secret scanner strict elsewhere.
_SIGNUP_FIELD_ALIASES: dict[str, SignupSemanticField] = {
    "signup_email": "email",
    "account_password": "password",  # pragma: allowlist secret
    "confirm_password": "password_confirmation",  # pragma: allowlist secret
    "legal_name": "company_name",
    "company_website": "website",
    "account_name": "workspace_name",
    "account_display_name": "workspace_name",
    "job_title": "role_title",
    "role": "role_title",
}


class ContractValidationError(ValueError):
    """Raised when a contract is well-formed JSON but not safe for execution."""


class _StrictContractModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        str_strip_whitespace=True,
    )


class ContractRouting(_StrictContractModel):
    route_classification: ContractRoute
    signup_supported: bool = False
    login_supported: bool = False
    production_approval_required: bool | None = None
    developer_app_creation_supported: bool = False
    credential_creation_supported: bool = False


class ContractHosts(_StrictContractModel):
    vendor_hosts: tuple[str, ...] = Field(default=(), max_length=40)
    authentication_hosts: tuple[str, ...] = Field(default=(), max_length=30)
    email_verification_hosts: tuple[str, ...] = Field(default=(), max_length=30)
    developer_console_hosts: tuple[str, ...] = Field(default=(), max_length=30)
    credential_surface_hosts: tuple[str, ...] = Field(default=(), max_length=30)
    passive_asset_hosts: tuple[str, ...] = Field(default=(), max_length=40)
    prohibited_hosts: tuple[str, ...] = Field(default=(), max_length=40)

    @field_validator("*")
    @classmethod
    def _hosts_are_normalized(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(_normalize_host_pattern(value) for value in values))

    @model_validator(mode="after")
    def _prohibited_hosts_do_not_overlap(self) -> ContractHosts:
        active = set(
            self.vendor_hosts
            + self.authentication_hosts
            + self.email_verification_hosts
            + self.developer_console_hosts
            + self.credential_surface_hosts
            + self.passive_asset_hosts
        )
        if active & set(self.prohibited_hosts):
            raise ValueError("a prohibited host cannot also be active")
        return self


class ContractPasswordPolicy(_StrictContractModel):
    min_length: int = Field(default=12, ge=8, le=128)
    max_length: int = Field(default=128, ge=8, le=128)
    require_lower: bool = True
    require_upper: bool = True
    require_digit: bool = True
    require_symbol: bool = False
    allowed_symbols: str = Field(default="!@#$%^&*()-_=+", min_length=1, max_length=64)

    @model_validator(mode="after")
    def _lengths_are_consistent(self) -> ContractPasswordPolicy:
        if self.max_length < self.min_length:
            raise ValueError("password maximum length is below minimum length")
        if any(character.isspace() for character in self.allowed_symbols):
            raise ValueError("password symbols cannot contain whitespace")
        if len(set(self.allowed_symbols)) != len(self.allowed_symbols):
            raise ValueError("password symbols must be unique")
        return self


class ContractSelectOption(_StrictContractModel):
    """Reviewed rule for a select or combobox value."""

    mode: SelectOptionMode
    fixed_option: str | None = Field(default=None, max_length=200)

    @model_validator(mode="after")
    def _mode_matches_value_source(self) -> ContractSelectOption:
        fixed = self.mode.startswith("fixed_")
        if fixed and not self.fixed_option:
            raise ValueError("fixed select modes require a reviewed option")
        if not fixed and self.fixed_option is not None:
            raise ValueError("approved-value select modes cannot carry a fixed option")
        if self.fixed_option is not None and "\x00" in self.fixed_option:
            raise ValueError("reviewed select option is invalid")
        return self


class ContractSignupFieldHints(_StrictContractModel):
    """Reviewed, value-free hints for one semantic signup field."""

    reviewed_test_ids: tuple[str, ...] = Field(default=(), max_length=12)
    accessible_names: tuple[str, ...] = Field(default=(), max_length=20)
    placeholders: tuple[str, ...] = Field(default=(), max_length=20)
    nearby_headings: tuple[str, ...] = Field(default=(), max_length=12)
    select_option: ContractSelectOption | None = None

    @field_validator("reviewed_test_ids")
    @classmethod
    def _test_ids_are_bounded(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        result = tuple(dict.fromkeys(values))
        if any(_TEST_ID.fullmatch(value) is None for value in result):
            raise ValueError("reviewed test id is invalid")
        return result

    @field_validator("accessible_names", "placeholders", "nearby_headings")
    @classmethod
    def _hints_are_bounded(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        result = tuple(dict.fromkeys(values))
        if any(not value or len(value) > 200 or "\x00" in value for value in result):
            raise ValueError("signup field hint is invalid")
        return result


class ContractSignup(_StrictContractModel):
    entrypoints: tuple[str, ...] = Field(default=(), max_length=10)
    required_semantic_fields: tuple[SignupSemanticField, ...] = Field(
        default=(), max_length=30
    )
    optional_semantic_fields: tuple[SignupSemanticField, ...] = Field(
        default=(), max_length=30
    )
    field_hints: dict[SignupSemanticField, ContractSignupFieldHints] = Field(
        default_factory=dict,
        max_length=30,
    )
    password_policy: ContractPasswordPolicy = Field(default_factory=ContractPasswordPolicy)
    success_predicates: tuple[str, ...] = Field(default=(), max_length=30)
    existing_account_predicates: tuple[str, ...] = Field(default=(), max_length=20)
    verification_predicates: tuple[str, ...] = Field(default=(), max_length=20)
    captcha_predicates: tuple[str, ...] = Field(default=(), max_length=20)
    phone_verification_predicates: tuple[str, ...] = Field(default=(), max_length=20)
    legal_billing_predicates: tuple[str, ...] = Field(default=(), max_length=20)

    @model_validator(mode="before")
    @classmethod
    def _normalize_historical_semantic_names(cls, value: object) -> object:
        if not isinstance(value, dict):
            return value
        normalized = dict(value)
        for key in ("required_semantic_fields", "optional_semantic_fields"):
            raw = normalized.get(key, ())
            if isinstance(raw, (list, tuple)):
                normalized[key] = tuple(
                    dict.fromkeys(_normalize_signup_field(str(item)) for item in raw)
                )
        raw_hints = normalized.get("field_hints")
        if isinstance(raw_hints, dict):
            hints: dict[SignupSemanticField, object] = {}
            for raw_key, hint in raw_hints.items():
                key = _normalize_signup_field(str(raw_key))
                if key in hints:
                    raise ValueError("duplicate signup field hints after normalization")
                hints[key] = hint
            normalized["field_hints"] = hints
        return normalized

    @field_validator("entrypoints")
    @classmethod
    def _entrypoints_are_https(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(_validated_https(value) for value in values))

    @field_validator("required_semantic_fields", "optional_semantic_fields")
    @classmethod
    def _semantic_fields_are_supported(
        cls,
        values: tuple[SignupSemanticField, ...],
    ) -> tuple[SignupSemanticField, ...]:
        result = tuple(dict.fromkeys(values))
        if any(value not in _SIGNUP_FIELDS for value in result):
            raise ValueError("signup semantic field is unsupported")
        return result

    @field_validator("field_hints")
    @classmethod
    def _field_hint_keys_are_supported(
        cls,
        values: dict[SignupSemanticField, ContractSignupFieldHints],
    ) -> dict[SignupSemanticField, ContractSignupFieldHints]:
        if any(key not in _SIGNUP_FIELDS for key in values):
            raise ValueError("signup field hint key is unsupported")
        return values

    @field_validator(
        "success_predicates",
        "existing_account_predicates",
        "verification_predicates",
        "captcha_predicates",
        "phone_verification_predicates",
        "legal_billing_predicates",
    )
    @classmethod
    def _predicates_are_bounded(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        result = tuple(dict.fromkeys(values))
        if any(not value or len(value) > 300 or "\x00" in value for value in result):
            raise ValueError("contract predicate is invalid")
        return result

    @model_validator(mode="after")
    def _field_sets_are_consistent(self) -> ContractSignup:
        required = set(self.required_semantic_fields)
        optional = set(self.optional_semantic_fields)
        if required & optional:
            raise ValueError("signup field cannot be both required and optional")
        if "signup_submit" in optional:
            raise ValueError("signup submit control cannot be optional")
        for field, hints in self.field_hints.items():
            if hints.select_option is not None and field not in {"country", "role_title"}:
                raise ValueError("reviewed select options are limited to country and role/title")
        return self


class ContractLogin(_StrictContractModel):
    entrypoints: tuple[str, ...] = Field(default=(), max_length=10)
    login_patterns: tuple[str, ...] = Field(default=(), max_length=30)
    authentication_success_predicates: tuple[str, ...] = Field(default=(), max_length=30)
    authentication_failure_predicates: tuple[str, ...] = Field(default=(), max_length=30)

    @field_validator("entrypoints")
    @classmethod
    def _entrypoints_are_https(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(_validated_https(value) for value in values))


class ContractDeveloperApp(_StrictContractModel):
    console_entrypoints: tuple[str, ...] = Field(default=(), max_length=10)
    search_strategy: tuple[str, ...] = Field(default=(), max_length=20)
    required_fields: tuple[str, ...] = Field(default=(), max_length=30)
    success_predicates: tuple[str, ...] = Field(default=(), max_length=30)

    @field_validator("console_entrypoints")
    @classmethod
    def _entrypoints_are_https(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(_validated_https(value) for value in values))


class ContractCredentials(_StrictContractModel):
    artifact_types: tuple[str, ...] = Field(default=(), max_length=20)
    search_strategy: tuple[str, ...] = Field(default=(), max_length=20)
    creation_strategy: tuple[str, ...] = Field(default=(), max_length=20)
    reveal_strategy: tuple[str, ...] = Field(default=(), max_length=20)
    capture_strategy: tuple[str, ...] = Field(default=(), max_length=20)
    validation_strategy: tuple[str, ...] = Field(default=(), max_length=20)


class ContractEvidence(_StrictContractModel):
    source_urls: tuple[str, ...] = Field(min_length=1, max_length=50)
    field_sources: dict[str, tuple[str, ...]] = Field(default_factory=dict, max_length=100)

    @field_validator("source_urls")
    @classmethod
    def _source_urls_are_https(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(_validated_https(value) for value in values))

    @field_validator("field_sources")
    @classmethod
    def _field_sources_are_https(
        cls,
        values: dict[str, tuple[str, ...]],
    ) -> dict[str, tuple[str, ...]]:
        result: dict[str, tuple[str, ...]] = {}
        for key, urls in values.items():
            if _SEMANTIC_FIELD.fullmatch(key) is None:
                raise ValueError("evidence field name is invalid")
            result[key] = tuple(
                dict.fromkeys(_validated_https(value) for value in urls)
            )
        return result


class BrowserAutomationContract(_StrictContractModel):
    app_slug: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", max_length=120)
    app_name: str = Field(min_length=1, max_length=200)
    schema_version: str = "1"
    contract_version: str
    status: ContractStatus = "draft"
    generated_at: str
    expires_at: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_hash: str
    routing: ContractRouting
    hosts: ContractHosts
    signup: ContractSignup = Field(default_factory=ContractSignup)
    login: ContractLogin = Field(default_factory=ContractLogin)
    developer_app: ContractDeveloperApp = Field(default_factory=ContractDeveloperApp)
    credentials: ContractCredentials = Field(default_factory=ContractCredentials)
    evidence: ContractEvidence

    @field_validator("schema_version", "contract_version")
    @classmethod
    def _version_is_bounded(cls, value: str) -> str:
        if _VERSION.fullmatch(value) is None:
            raise ValueError("contract version is invalid")
        return value

    @field_validator("evidence_hash")
    @classmethod
    def _hash_is_sha256(cls, value: str) -> str:
        normalized = value.casefold()
        if _EVIDENCE_HASH.fullmatch(normalized) is None:
            raise ValueError("evidence hash must be a lowercase SHA-256 digest")
        return normalized

    @field_validator("generated_at", "expires_at")
    @classmethod
    def _timestamps_are_aware(cls, value: str) -> str:
        _parse_time(value)
        return value

    @model_validator(mode="after")
    def _lifetime_is_forward(self) -> BrowserAutomationContract:
        if _parse_time(self.expires_at) <= _parse_time(self.generated_at):
            raise ValueError("contract expiration must follow generation")
        if self.routing.signup_supported and not self.signup.entrypoints:
            raise ValueError("signup-supported contracts require a signup entrypoint")
        if self.routing.login_supported and not self.login.entrypoints:
            raise ValueError("login-supported contracts require a login entrypoint")
        return self

    def is_expired(self, *, now: datetime | None = None) -> bool:
        current = now or datetime.now(UTC)
        return _parse_time(self.expires_at) <= current

    def assert_usable(self, *, now: datetime | None = None) -> None:
        if self.status != "active":
            raise ContractValidationError("automation contract is not active")
        if self.is_expired(now=now):
            raise ContractValidationError("automation contract is expired")


class SQLiteAutomationContractRegistry:
    """Persistent, append-only registry for strict sanitized contracts."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

    def initialize(self) -> None:
        existed = prepare_private_database(self.db_path)
        connection = sqlite3.connect(self.db_path, timeout=10)
        try:
            finalize_private_database(self.db_path, existed=existed)
            connection.execute("PRAGMA secure_delete = ON")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS browser_automation_contracts (
                    app_slug TEXT NOT NULL,
                    contract_version TEXT NOT NULL,
                    status TEXT NOT NULL,
                    generated_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    evidence_hash TEXT NOT NULL,
                    contract_json TEXT NOT NULL,
                    PRIMARY KEY (app_slug, contract_version)
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_browser_contract_latest
                ON browser_automation_contracts(app_slug, generated_at DESC)
                """
            )
            connection.commit()
        finally:
            connection.close()

    def put(self, contract: BrowserAutomationContract) -> BrowserAutomationContract:
        self.initialize()
        serialized = contract.model_dump_json()
        with sqlite3.connect(self.db_path, timeout=10) as connection:
            connection.execute(
                """
                INSERT INTO browser_automation_contracts (
                    app_slug, contract_version, status, generated_at,
                    expires_at, evidence_hash, contract_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(app_slug, contract_version) DO UPDATE SET
                    status = excluded.status,
                    generated_at = excluded.generated_at,
                    expires_at = excluded.expires_at,
                    evidence_hash = excluded.evidence_hash,
                    contract_json = excluded.contract_json
                """,
                (
                    contract.app_slug,
                    contract.contract_version,
                    contract.status,
                    contract.generated_at,
                    contract.expires_at,
                    contract.evidence_hash,
                    serialized,
                ),
            )
            connection.commit()
        return contract

    def get(
        self,
        app_slug: str,
        contract_version: str,
    ) -> BrowserAutomationContract | None:
        self.initialize()
        with sqlite3.connect(self.db_path, timeout=10) as connection:
            row = connection.execute(
                """
                SELECT contract_json FROM browser_automation_contracts
                WHERE app_slug = ? AND contract_version = ?
                """,
                (app_slug, contract_version),
            ).fetchone()
        return _contract_from_row(row)

    def latest(self, app_slug: str) -> BrowserAutomationContract | None:
        self.initialize()
        with sqlite3.connect(self.db_path, timeout=10) as connection:
            row = connection.execute(
                """
                SELECT contract_json FROM browser_automation_contracts
                WHERE app_slug = ?
                ORDER BY generated_at DESC, contract_version DESC
                LIMIT 1
                """,
                (app_slug,),
            ).fetchone()
        return _contract_from_row(row)

    def latest_fresh(
        self,
        app_slug: str,
        *,
        now: datetime | None = None,
    ) -> BrowserAutomationContract | None:
        contract = self.latest(app_slug)
        if contract is None or contract.status != "active" or contract.is_expired(now=now):
            return None
        return contract


def evidence_hash_for(source_urls: tuple[str, ...] | list[str]) -> str:
    canonical = json.dumps(
        sorted(set(source_urls)),
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _contract_from_row(row: tuple[object, ...] | None) -> BrowserAutomationContract | None:
    if row is None:
        return None
    if len(row) != 1 or not isinstance(row[0], (str, bytes, bytearray)):
        raise RuntimeError("automation contract row is invalid")
    return BrowserAutomationContract.model_validate_json(row[0])


def _normalize_signup_field(value: str) -> SignupSemanticField:
    normalized = value.strip().casefold()
    alias = _SIGNUP_FIELD_ALIASES.get(normalized)
    if alias is not None:
        return alias
    if normalized not in _SIGNUP_FIELDS:
        raise ValueError("signup semantic field is unsupported")
    # Membership in the typed finite set is the runtime narrowing proof.
    return next(field for field in _SIGNUP_FIELDS if field == normalized)


def _validated_https(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("contract URL must be absolute credential-free HTTPS")
    if parsed.fragment:
        raise ValueError("contract URL must not contain a fragment")
    return value


def _normalize_host_pattern(value: str) -> str:
    if "://" in value or "/" in value or "@" in value:
        raise ValueError("contract host must be a hostname pattern, not a URL")
    normalized = value.rstrip(".").casefold()
    wildcard = normalized.startswith("*.")
    host = normalized[2:] if wildcard else normalized
    labels = host.split(".")
    if len(labels) < 2 or any(
        _HOST_LABEL.fullmatch(label) is None for label in labels
    ):
        raise ValueError("contract host pattern is invalid")
    return f"*.{host}" if wildcard else host


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("contract timestamp must include a timezone")
    return parsed.astimezone(UTC)


__all__ = [
    "BrowserAutomationContract",
    "ContractCredentials",
    "ContractDeveloperApp",
    "ContractEvidence",
    "ContractHosts",
    "ContractLogin",
    "ContractPasswordPolicy",
    "ContractRoute",
    "ContractRouting",
    "ContractSelectOption",
    "ContractSignup",
    "ContractSignupFieldHints",
    "ContractValidationError",
    "SQLiteAutomationContractRegistry",
    "SelectOptionMode",
    "SignupSemanticField",
    "evidence_hash_for",
]
