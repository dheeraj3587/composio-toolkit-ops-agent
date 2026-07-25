"""Environment-backed settings with conservative, dry-run defaults."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

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


def _float(value: str | None, *, default: float) -> float:
    normalized = _optional(value)
    if normalized is None:
        return default
    try:
        return float(normalized)
    except ValueError:
        raise ValueError("float environment value is invalid") from None


def _choice(value: str | None, allowed: tuple[str, ...], *, default: str) -> str:
    """Return a normalized enum value.

    An ABSENT value uses ``default``, but a present-and-invalid value raises: a typo
    like ``BROWSER_PROVIDER=playwrite`` must not silently select a different backend
    than the operator intended.
    """

    normalized = _optional(value)
    if normalized is None:
        return default
    lowered = normalized.casefold()
    if lowered not in allowed:
        raise ValueError(f"value must be one of {', '.join(allowed)}")
    return lowered


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
    you_api_key: SecretStr | None = Field(default=None, repr=False)
    google_genai_api_key: SecretStr | None = Field(default=None, repr=False)
    openrouter_api_key: SecretStr | None = Field(default=None, repr=False)
    groq_api_key: SecretStr | None = Field(default=None, repr=False)
    cerebras_api_key: SecretStr | None = Field(default=None, repr=False)
    composio_api_key: SecretStr | None = Field(default=None, repr=False)
    browser_use_api_key: SecretStr | None = Field(default=None, repr=False)
    langgraph_aes_key: SecretStr | None = Field(default=None, repr=False)
    secret_vault_key: SecretStr | None = Field(default=None, repr=False)
    ops_internal_api_token: SecretStr | None = Field(default=None, repr=False)

    langgraph_strict_msgpack: bool = True
    composio_user_id: str = "ops-assignment-user"
    composio_gmail_connected_account_id: str | None = None

    # Gemini production model is pinned to a specific stable id by default; a
    # hot-swapped ``*-latest`` alias is intentionally not the default. The
    # fallback chain is tried in order when a model is unavailable/overloaded.
    gemini_model: str = "gemini-3.6-flash"

    @property
    def gemini_model_chain(self) -> tuple[str, ...]:
        """Ordered, de-duplicated Gemini model fallback chain."""

        ordered = [self.gemini_model, "gemini-3.6-flash", "gemini-3.5-flash", "gemini-2.5-flash"]
        return tuple(dict.fromkeys(model for model in ordered if model))

    # OpenRouter is the primary LLM for the email loop (compose/classify/reply);
    # Gemini is the fallback. The model is a free OpenRouter model by default.
    openrouter_model: str = "nvidia/nemotron-3-ultra-550b-a55b:free"

    # Free-tier browser-decision models. Both providers are OpenAI-compatible but
    # differ: strict json_schema requires a gpt-oss model, and Groq prefixes it
    # with "openai/" while Cerebras does not (verified against both vendors' docs).
    groq_model: str = "openai/gpt-oss-120b"
    cerebras_model: str = "gpt-oss-120b"

    # Session count is the real quota (not dollars), so use the most capable
    # Browser Use model for reliable multi-step onboarding navigation. The latest
    # Opus available on Browser Use Cloud is claude-opus-4.7 (there is no 4.8).
    browser_use_model: str = "claude-opus-4.7"
    # Per-session cost cap set high so a run never stops mid-task on the cap.
    browser_use_max_cost_usd: float = Field(default=50.0, gt=0)
    # Which browser automation backend a run uses. Default is the paid Browser Use
    # cloud (prod-proven); "playwright" selects the self-hosted harness. This is the
    # single switch behind the gradual migration — the default keeps prod unchanged.
    browser_provider: Literal["browser_use", "playwright"] = "browser_use"
    # Self-hosted Playwright limits. Each session is a real Chromium process, so the
    # cap is sized for a small VPS. --no-sandbox is opt-in (see _launch_args).
    playwright_max_sessions: int = Field(default=2, ge=1, le=10)
    playwright_disable_sandbox: bool = False
    # The isolated browser service (Chromium in its own container). When the provider
    # is "playwright" this is the NORMAL path: the API speaks authenticated RPC and
    # never launches Chromium itself, which is what makes a session survive an API
    # restart.
    browser_service_url: str | None = None
    browser_service_token: SecretStr | None = Field(default=None, repr=False)
    browser_service_owner: str = "ops-assignment-user"
    # Running Chromium INSIDE the API process is for isolated tests and local
    # debugging only, so it must be requested explicitly rather than being a silent
    # fallback whenever the service happens to be unconfigured.
    playwright_in_process_sandbox: bool = False
    # Owner-only local credential submission is opt-in and loopback-only.
    allow_local_credential_submission: bool = False

    # You.com is a RESEARCH/RETRIEVAL provider only (official-document discovery
    # and extraction). It never operates a browser, never receives credentials,
    # and never controls the default browser provider above. Every flag here
    # requires ``you_api_key`` to be configured (see the ``*_configured``
    # properties below).
    #
    # SAFE DEFAULT: all three capabilities default to DISABLED. A configured
    # API key alone must never start spending credits — an operator opts into
    # each capability explicitly (staged rollout: Search, then Contents, then
    # the expensive Research fallback). ``.env`` may enable them deliberately.
    you_search_enabled: bool = False
    you_contents_enabled: bool = False
    you_research_enabled: bool = False

    you_search_count: int = Field(default=5, ge=1, le=10)
    you_search_timeout_seconds: float = Field(default=20.0, ge=2.0, le=60.0)
    you_contents_timeout_seconds: float = Field(default=30.0, ge=2.0, le=60.0)
    # Sent to You.com Contents as ``max_age`` (the SDK supports it in 2.5.0):
    # cached content older than this forces a fresh crawl. Also used as the
    # local Contents cache TTL, so the two agree.
    you_contents_max_age_seconds: int = Field(default=86_400, ge=0)
    you_research_timeout_seconds: float = Field(default=60.0, ge=10.0, le=180.0)

    you_max_search_calls_per_enrichment: int = Field(default=2, ge=1, le=4)
    you_max_contents_pages_per_enrichment: int = Field(default=8, ge=1, le=10)
    you_max_research_calls_per_enrichment: int = Field(default=1, ge=0, le=1)

    # Persistent research cache (SQLite). Shared by Search/Contents/Research so
    # identical app research does not re-spend credits. Never stores secrets.
    research_cache_db_path: Path = Path("./private/research_cache.db")

    @property
    def you_search_configured(self) -> bool:
        return self.you_api_key is not None and self.you_search_enabled

    @property
    def you_contents_configured(self) -> bool:
        return self.you_api_key is not None and self.you_contents_enabled

    @property
    def you_research_configured(self) -> bool:
        # A zero per-enrichment budget disables Research even when the flag and
        # key are present — the budget is the hard ceiling, not just the flag.
        return (
            self.you_api_key is not None
            and self.you_research_enabled
            and self.you_max_research_calls_per_enrichment > 0
        )

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
    # Autonomous email poller cadence (seconds). The agent checks every
    # waiting_for_reply run for new provider replies on this interval.
    email_poll_interval_seconds: int = Field(default=45, ge=10)
    max_unclear_retries: int = Field(default=1, ge=0)
    max_browser_attempts: int = Field(default=2, ge=1)
    max_hitl_count: int = Field(default=3, ge=0)
    # Bounded retry for transient Composio Gmail READ failures only (sends are
    # guarded by the effect ledger and never retried here). The per-attempt delay
    # grows exponentially from the base; set the base to 0 to disable waiting.
    gmail_retry_max_attempts: int = Field(default=3, ge=1, le=6)
    gmail_retry_base_delay_seconds: float = Field(default=0.5, ge=0.0, le=10.0)

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
            "you_api_key": _secret(source.get("YDC_API_KEY")),
            "google_genai_api_key": _secret(source.get("GOOGLE_GENAI_API_KEY")),
            "openrouter_api_key": _secret(source.get("OPENROUTER_API_KEY")),
            "groq_api_key": _secret(source.get("GROQ_API_KEY")),
            "cerebras_api_key": _secret(source.get("CEREBRAS_API_KEY")),
            "groq_model": _optional(source.get("GROQ_MODEL")) or "openai/gpt-oss-120b",
            "cerebras_model": _optional(source.get("CEREBRAS_MODEL")) or "gpt-oss-120b",
            "openrouter_model": _optional(source.get("OPENROUTER_MODEL"))
            or "nvidia/nemotron-3-ultra-550b-a55b:free",
            "composio_api_key": _secret(source.get("COMPOSIO_API_KEY")),
            "browser_use_api_key": _secret(source.get("BROWSER_USE_API_KEY")),
            "langgraph_aes_key": _secret(source.get("LANGGRAPH_AES_KEY")),
            "secret_vault_key": _secret(source.get("SECRET_VAULT_KEY")),
            "ops_internal_api_token": _secret(source.get("OPS_INTERNAL_API_TOKEN")),
            "langgraph_strict_msgpack": _boolean(
                source.get("LANGGRAPH_STRICT_MSGPACK"), default=True
            ),
            "composio_user_id": _optional(source.get("COMPOSIO_USER_ID")) or "ops-assignment-user",
            "composio_gmail_connected_account_id": _optional(
                source.get("COMPOSIO_GMAIL_CONNECTED_ACCOUNT_ID")
            ),
            "gemini_model": _optional(source.get("GEMINI_MODEL")) or "gemini-3.5-flash",
            "browser_use_model": _optional(source.get("BROWSER_USE_MODEL")) or "claude-opus-4.7",
            "browser_use_max_cost_usd": _float(
                source.get("BROWSER_USE_MAX_COST_USD"), default=50.0
            ),
            "browser_provider": _choice(
                source.get("BROWSER_PROVIDER"),
                ("browser_use", "playwright"),
                default="browser_use",
            ),
            "playwright_max_sessions": _integer(source.get("PLAYWRIGHT_MAX_SESSIONS"), default=2),
            "playwright_disable_sandbox": _boolean(
                source.get("PLAYWRIGHT_DISABLE_SANDBOX"), default=False
            ),
            "browser_service_url": _optional(source.get("BROWSER_SERVICE_URL")),
            "browser_service_token": _secret(source.get("BROWSER_SERVICE_TOKEN")),
            "browser_service_owner": (
                _optional(source.get("BROWSER_SERVICE_OWNER")) or "ops-assignment-user"
            ),
            "playwright_in_process_sandbox": _boolean(
                source.get("PLAYWRIGHT_IN_PROCESS_SANDBOX"), default=False
            ),
            "allow_local_credential_submission": _boolean(
                source.get("ALLOW_LOCAL_CREDENTIAL_SUBMISSION"), default=False
            ),
            "you_search_enabled": _boolean(source.get("YOU_SEARCH_ENABLED"), default=False),
            "you_contents_enabled": _boolean(source.get("YOU_CONTENTS_ENABLED"), default=False),
            "you_research_enabled": _boolean(source.get("YOU_RESEARCH_ENABLED"), default=False),
            "you_search_count": _integer(source.get("YOU_SEARCH_COUNT"), default=5),
            "you_search_timeout_seconds": _float(
                source.get("YOU_SEARCH_TIMEOUT_SECONDS"), default=20.0
            ),
            "you_contents_timeout_seconds": _float(
                source.get("YOU_CONTENTS_TIMEOUT_SECONDS"), default=30.0
            ),
            "you_contents_max_age_seconds": _integer(
                source.get("YOU_CONTENTS_MAX_AGE_SECONDS"), default=86_400
            ),
            "you_research_timeout_seconds": _float(
                source.get("YOU_RESEARCH_TIMEOUT_SECONDS"), default=60.0
            ),
            "you_max_search_calls_per_enrichment": _integer(
                source.get("YOU_MAX_SEARCH_CALLS_PER_ENRICHMENT"), default=2
            ),
            "you_max_contents_pages_per_enrichment": _integer(
                source.get("YOU_MAX_CONTENTS_PAGES_PER_ENRICHMENT"), default=8
            ),
            "you_max_research_calls_per_enrichment": _integer(
                source.get("YOU_MAX_RESEARCH_CALLS_PER_ENRICHMENT"), default=1
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
            "email_poll_interval_seconds": _integer(
                source.get("EMAIL_POLL_INTERVAL_SECONDS"), default=45
            ),
            "max_unclear_retries": _integer(source.get("MAX_UNCLEAR_RETRIES"), default=1),
            "max_browser_attempts": _integer(source.get("MAX_BROWSER_ATTEMPTS"), default=2),
            "max_hitl_count": _integer(source.get("MAX_HITL_COUNT"), default=3),
            "gmail_retry_max_attempts": _integer(source.get("GMAIL_RETRY_MAX_ATTEMPTS"), default=3),
            "gmail_retry_base_delay_seconds": _float(
                source.get("GMAIL_RETRY_BASE_DELAY_SECONDS"), default=0.5
            ),
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
            "research_cache_db_path": Path(
                source.get("RESEARCH_CACHE_DB_PATH", "./private/research_cache.db")
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
