"""Environment-backed settings with conservative, dry-run defaults."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from ops.models import validate_vault_reference


def _optional(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _secret(value: str | None) -> SecretStr | None:
    normalized = _optional(value)
    return SecretStr(normalized) if normalized is not None else None


def _boolean(value: str | None, *, default: bool) -> bool:
    normalized = _optional(value)
    if normalized is None:
        return default
    lowered = normalized.casefold()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    raise ValueError("boolean environment values must be true or false")


def _integer(value: str | None, *, default: int) -> int:
    normalized = _optional(value)
    if normalized is None:
        return default
    try:
        return int(normalized)
    except ValueError:
        raise ValueError("integer environment value is invalid") from None


def _csv(value: str | None) -> tuple[str, ...]:
    normalized = _optional(value)
    if normalized is None:
        return ()
    return tuple(item.strip() for item in normalized.split(",") if item.strip())


class Settings(BaseModel):
    """Runtime configuration; raw secret values never appear in ``repr``."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
    )

    perplexity_api_key: SecretStr | None = Field(default=None, repr=False)
    google_genai_api_key: SecretStr | None = Field(default=None, repr=False)
    composio_api_key: SecretStr | None = Field(default=None, repr=False)
    browser_use_api_key: SecretStr | None = Field(default=None, repr=False)
    langgraph_aes_key: SecretStr | None = Field(default=None, repr=False)
    secret_vault_key: SecretStr | None = Field(default=None, repr=False)

    langgraph_strict_msgpack: bool = True
    composio_user_id: str = "ops-assignment-user"
    composio_gmail_connected_account_id: str | None = None

    company_legal_name: str | None = None
    company_website: str | None = None
    company_work_email_ref: str | None = None
    company_use_case: str | None = None
    company_expected_volume: str | None = None
    oauth_callback_urls: tuple[str, ...] = ()

    outreach_recipient_override: str | None = None
    allow_live_vendor_email: bool = False
    allow_live_browser: bool = False
    max_outreach_rounds: int = Field(default=5, ge=1)
    max_unclear_retries: int = Field(default=1, ge=0)
    max_browser_attempts: int = Field(default=2, ge=1)
    max_hitl_count: int = Field(default=3, ge=0)

    ops_db_path: Path = Path("./private/ops.db")
    checkpoint_db_path: Path = Path("./private/checkpoints.db")
    secret_vault_db_path: Path = Path("./private/secret_vault.db")
    provider_effects_db_path: Path = Path("./private/provider_effects.db")

    @field_validator("company_work_email_ref")
    @classmethod
    def validate_company_work_email_ref(cls, value: str | None) -> str | None:
        return validate_vault_reference(value) if value is not None else None

    @classmethod
    def from_env(
        cls,
        *,
        env: Mapping[str, str] | None = None,
        dotenv_path: str | Path | None = ".env",
    ) -> Settings:
        """Build settings from a supplied mapping or the process environment."""

        if env is None:
            if dotenv_path is not None:
                load_dotenv(dotenv_path=dotenv_path, override=False)
            source: Mapping[str, str] = os.environ
        else:
            source = env

        values: dict[str, Any] = {
            "perplexity_api_key": _secret(source.get("PERPLEXITY_API_KEY")),
            "google_genai_api_key": _secret(source.get("GOOGLE_GENAI_API_KEY")),
            "composio_api_key": _secret(source.get("COMPOSIO_API_KEY")),
            "browser_use_api_key": _secret(source.get("BROWSER_USE_API_KEY")),
            "langgraph_aes_key": _secret(source.get("LANGGRAPH_AES_KEY")),
            "secret_vault_key": _secret(source.get("SECRET_VAULT_KEY")),
            "langgraph_strict_msgpack": _boolean(
                source.get("LANGGRAPH_STRICT_MSGPACK"), default=True
            ),
            "composio_user_id": _optional(source.get("COMPOSIO_USER_ID")) or "ops-assignment-user",
            "composio_gmail_connected_account_id": _optional(
                source.get("COMPOSIO_GMAIL_CONNECTED_ACCOUNT_ID")
            ),
            "company_legal_name": _optional(source.get("COMPANY_LEGAL_NAME")),
            "company_website": _optional(source.get("COMPANY_WEBSITE")),
            "company_work_email_ref": _optional(source.get("COMPANY_WORK_EMAIL_REF")),
            "company_use_case": _optional(source.get("COMPANY_USE_CASE")),
            "company_expected_volume": _optional(source.get("COMPANY_EXPECTED_VOLUME")),
            "oauth_callback_urls": _csv(source.get("OAUTH_CALLBACK_URLS")),
            "outreach_recipient_override": _optional(source.get("OUTREACH_RECIPIENT_OVERRIDE")),
            "allow_live_vendor_email": _boolean(
                source.get("ALLOW_LIVE_VENDOR_EMAIL"), default=False
            ),
            "allow_live_browser": _boolean(source.get("ALLOW_LIVE_BROWSER"), default=False),
            "max_outreach_rounds": _integer(source.get("MAX_OUTREACH_ROUNDS"), default=5),
            "max_unclear_retries": _integer(source.get("MAX_UNCLEAR_RETRIES"), default=1),
            "max_browser_attempts": _integer(source.get("MAX_BROWSER_ATTEMPTS"), default=2),
            "max_hitl_count": _integer(source.get("MAX_HITL_COUNT"), default=3),
            "ops_db_path": Path(source.get("OPS_DB_PATH", "./private/ops.db")),
            "checkpoint_db_path": Path(
                source.get("CHECKPOINT_DB_PATH", "./private/checkpoints.db")
            ),
            "secret_vault_db_path": Path(
                source.get("SECRET_VAULT_DB_PATH", "./private/secret_vault.db")
            ),
            "provider_effects_db_path": Path(
                source.get("PROVIDER_EFFECTS_DB_PATH", "./private/provider_effects.db")
            ),
        }
        return cls.model_validate(values)


def load_settings(
    *,
    env: Mapping[str, str] | None = None,
    dotenv_path: str | Path | None = ".env",
) -> Settings:
    """Public convenience wrapper used by CLI and Streamlit entrypoints."""

    return Settings.from_env(env=env, dotenv_path=dotenv_path)
