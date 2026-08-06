"""Environment-backed settings with conservative, dry-run defaults."""

from __future__ import annotations

import hmac
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from ops.browser.session_capability import (
    BrowserSessionCapabilityError,
    validate_capability_owner,
)
from ops.core.inference import DecisionBudget
from ops.core.models import validate_vault_reference


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


# --- Autonomous onboarding credential ladder: the two budgets nothing named -----
#
# Requirements 10.15 through 10.19 describe a retry -> supersede -> pause ladder that
# terminates on "the configured budget", and neither the design nor the code named a
# number. Without these two the ladder has no stopping point: a provider answering
# `unavailable` forever would be retried forever, and a provider rejecting its own
# freshly minted credential would be re-minted forever. Both are recorded here rather
# than only on the field so the choice is reviewable next to its justification.
#
# ``credential_validation_attempt_budget`` = 3, bounded 1..10
#   Terminates Requirement 10.15 (retry while the attempt count is below the budget,
#   reason code `credential_invalid_retryable`) and Requirement 10.16 (at the budget,
#   pause `credential_invalid_terminal` and leave the reference unpublished). 3 matches
#   the verification attempt budget of Requirement 7.27, and the 1..10 bound matches
#   ``gmail_verification_max_attempts``, so the two retry ladders read alike.
#
# ``credential_generation_budget`` = 2, bounded 1..5
#   Terminates Requirement 10.17 (mark superseded, advance the generation counter, and
#   re-mint while the generation count is below the budget) and Requirement 10.19 (at
#   the budget, mark the reference unusable and pause `credential_invalid_terminal`).
#   2 permits exactly one supersede after the first mint: a credential the provider
#   itself calls `invalid` twice is a provider-side problem an operator must see, and
#   every additional generation leaves another real credential behind on the provider's
#   developer application. The 1..5 ceiling keeps that residue small.


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
    # Inception's Mercury diffusion models. First in the browser-decision chain
    # because the action loop is latency bound: every page state costs one
    # decision, and a faster first token shortens the whole run.
    mercury_api_key: SecretStr | None = Field(default=None, repr=False)
    groq_api_key: SecretStr | None = Field(default=None, repr=False)
    cerebras_api_key: SecretStr | None = Field(default=None, repr=False)
    composio_api_key: SecretStr | None = Field(default=None, repr=False)
    # Gmail can belong to a different Composio project than managed-auth/toolkit
    # discovery. It falls back to COMPOSIO_API_KEY for existing deployments.
    composio_gmail_api_key: SecretStr | None = Field(default=None, repr=False)
    langgraph_aes_key: SecretStr | None = Field(default=None, repr=False)
    secret_vault_key: SecretStr | None = Field(default=None, repr=False)
    ops_internal_api_token: SecretStr | None = Field(default=None, repr=False)
    browser_secret_broker_token: SecretStr | None = Field(default=None, repr=False)

    langgraph_strict_msgpack: bool = True
    composio_user_id: str = "ops-owner"
    # Gmail connections may live under a different Composio project and external
    # user than the managed-auth/toolkit runtime. It falls back to the generic
    # user id so existing single-project deployments continue to work.
    composio_gmail_user_id: str = "ops-owner"
    composio_gmail_connected_account_id: str | None = None
    # Exact mailbox address used when a run creates a vendor account. The
    # connected-account id selects the Gmail connection; it does not reliably
    # expose the mailbox address to the browser workflow, so the address is an
    # explicit private deployment input and is never requested in the UI.
    gmail_signup_address: SecretStr | None = Field(default=None, repr=False)
    # The one identity provider the agent may hand registration to when a vendor
    # refuses the email path for the configured address -- Apify rejects every
    # ``@gmail.com`` address and offers only "Continue with Google", so without
    # this the signup is unreachable rather than merely gated. Unset means the
    # original behavior: such a route stops for a human. The accepted cost is
    # that the run completes as whichever account the provider signs in.
    signup_identity_handoff_provider: str | None = None
    # Public, same-origin return location for managed OAuth. The adapter validates
    # it as a stable HTTPS URL and never persists the provider redirect URL.
    managed_auth_callback_base_url: str | None = None

    # Gemini production model is pinned to a specific stable id by default; a
    # hot-swapped ``*-latest`` alias is intentionally not the default. The
    # fallback chain is tried in order when a model is unavailable/overloaded.
    gemini_model: str = "gemini-3.6-flash"

    @property
    def gemini_model_chain(self) -> tuple[str, ...]:
        """Ordered, de-duplicated Gemini model fallback chain."""

        ordered = [self.gemini_model, "gemini-3.6-flash", "gemini-3.5-flash", "gemini-2.5-flash"]
        return tuple(dict.fromkeys(model for model in ordered if model))

    # OpenRouter is the email loop's (compose/classify/reply) second choice, not
    # its first: ``ops.email.ai.build_email_assistant`` puts Mercury in front of
    # it and Gemini behind it, the same order ``build_json_inference`` uses. This
    # comment still said "primary" from when the chain was OpenRouter then Gemini.
    # The model is a free OpenRouter model by default.
    openrouter_model: str = "nvidia/nemotron-3-ultra-550b-a55b:free"

    # Free-tier browser-decision models. Both providers are OpenAI-compatible but
    # differ: strict json_schema requires a gpt-oss model, and Groq prefixes it
    # with "openai/" while Cerebras does not (verified against both vendors' docs).
    groq_model: str = "openai/gpt-oss-120b"
    cerebras_model: str = "gpt-oss-120b"
    # Mercury 2 is Inception's chat model and supports strict json_schema.
    mercury_model: str = "mercury-2"
    # Inception exposes a reasoning dial: "instant", "low", "medium", "high" —
    # there is no level above "high", so that is what "maximum effort" means here.
    #
    # This used to default to "low", arguing the loop wants latency over
    # deliberation on a page it can already see. That argument holds for a page
    # the loop reads correctly the first time and is exactly wrong for the pages
    # that end runs: a stacked federated button above an email form, a "Next" that
    # is a div, a consent gate that looks like a signup. Those cost a whole run
    # when misread and a few seconds of tokens when deliberated over.
    mercury_reasoning_effort: str = "high"

    # The self-hosted Playwright harness is the only browser backend. The paid
    # Browser Use cloud adapter was removed: it could not run the reviewed
    # credential ladder (its own docstring notes the SDK exposes no
    # ``allowed_domains`` control), so host safety was reconstructed after the fact
    # from a returned URL rather than enforced at the network layer the way
    # ``make_egress_route_handler`` does. One backend also means one code path to
    # audit for the rule that a credential is only ever typed on a reviewed origin.
    browser_provider: Literal["playwright"] = "playwright"
    # Self-hosted Playwright limits. Each session is a real Chromium process, so the
    # cap is sized for a small VPS. --no-sandbox is opt-in (see _launch_args).
    #
    # This is also the onboarding browser pool capacity (default 2, ceiling 10) that
    # Requirement 21.3 bounds: browser_service.BrowserServiceSettings.max_sessions
    # reads the same PLAYWRIGHT_MAX_SESSIONS value, so capacity has one source of
    # truth and is deliberately NOT re-declared under an onboarding-specific name.
    playwright_max_sessions: int = Field(default=2, ge=1, le=10)
    playwright_disable_sandbox: bool = False
    # The isolated browser service (Chromium in its own container). When the provider
    # is "playwright" this is the NORMAL path: the API speaks authenticated RPC and
    # never launches Chromium itself, which is what makes a session survive an API
    # restart.
    browser_service_url: str | None = None
    browser_service_token: SecretStr | None = Field(default=None, repr=False)
    # API-only master key used to derive a distinct browser-session capability for
    # each run. The derived value crosses the private RPC; this master key never does.
    browser_session_capability_key: SecretStr | None = Field(default=None, repr=False)
    # Stable tenant/storage namespace. This is deliberately NOT run authorization:
    # encrypted storage state is reused across runs for the same app/account.
    browser_service_owner: str = "ops-owner"
    browser_service_client_timeout_seconds: float = Field(default=315.0, ge=5.0, le=600.0)
    # Explicit capability switch for the one-session headed/noVNC assignment path.
    # The browser service independently enforces max_sessions=1 when this is true.
    browser_interactive_hitl_enabled: bool = False
    # Allow an app with no checked-in recipe to browse the single registrable
    # domain its own verified URLs agree on. Off by default: with it disabled the
    # browser still refuses every app that lacks a reviewed host list.
    browser_domain_discovery_enabled: bool = False
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
    # Sent to You.com Contents as ``max_age`` (supported by the pinned SDK; see
    # requirements-providers.txt): cached content older than this forces a fresh
    # crawl. Also used as the local Contents cache TTL, so the two agree.
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
    def any_you_feature_configured(self) -> bool:
        """Whether ANY You.com capability is actually usable.

        Runtime wiring must branch on this, not on the mere presence of a key: a
        configured ``YDC_API_KEY`` with every flag off means You.com is disabled
        and the original Perplexity + guarded-HTTP path must be built unchanged.
        """

        return bool(
            self.you_search_configured
            or self.you_contents_configured
            or self.you_research_configured
        )

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
    # Startup must be observational by default. When enabled, startup creates
    # delayed maintenance threads but performs no provider call in the startup
    # call path. Production uses a grace period so the API can become healthy
    # before reconciliation or Gmail reads begin.
    ops_startup_automation_enabled: bool = False
    ops_automation_start_delay_seconds: float = Field(default=30.0, ge=1.0, le=300.0)
    # Autonomous startup also requires a deploy-owned marker matching BOTH this
    # immutable revision and a fresh per-deploy nonce. The delay is only load
    # smoothing; this marker is the release-acceptance authority.
    app_revision: str = "local-uncommitted"
    ops_deploy_acceptance_nonce: SecretStr | None = Field(default=None, repr=False)
    ops_deploy_acceptance_marker_path: Path = Path("./private/deploy-acceptance.json")
    max_outreach_rounds: int = Field(default=5, ge=1)
    # Autonomous email poller cadence (seconds). The agent checks every
    # waiting_for_reply run for new provider replies on this interval.
    email_poll_interval_seconds: int = Field(default=45, ge=10, le=900)
    # Bound shared-mailbox work per cycle so one large backlog cannot starve the
    # API or monopolize the connected Gmail account.
    email_poll_max_runs_per_cycle: int = Field(default=25, ge=1, le=100)
    max_unclear_retries: int = Field(default=1, ge=0)
    max_browser_attempts: int = Field(default=2, ge=1)
    max_hitl_count: int = Field(default=3, ge=0)
    # Autonomous sign-in: remember the owner's app login credentials in the
    # encrypted vault so a LATER run (or an automatic resume) can authenticate
    # itself instead of stopping for a human every time. Every other login path
    # is one-time and run-scoped, which is precisely why autonomy was impossible.
    # Opt-out with BROWSER_LOGIN_CREDENTIAL_REUSE=false.
    browser_login_credential_reuse: bool = True
    # How many times a run may be auto-advanced past a machine-resolvable human
    # gate (e.g. a login form we hold credentials for) before it truly waits for
    # a human. Bounded so a persistently failing login can never loop forever.
    max_autonomous_advances: int = Field(default=2, ge=0, le=10)
    # Cadence of the autonomous advancement sweep, in seconds.
    autonomous_advance_interval_seconds: int = Field(default=20, ge=5)
    # Bounded retry for transient Composio Gmail READ failures only (sends are
    # guarded by the effect ledger and never retried here). The per-attempt delay
    # grows exponentially from the base; set the base to 0 to disable waiting.
    gmail_retry_max_attempts: int = Field(default=3, ge=1, le=6)
    gmail_retry_base_delay_seconds: float = Field(default=0.5, ge=0.0, le=10.0)
    gmail_signup_preflight_timeout_seconds: float = Field(default=10.0, ge=1.0, le=30.0)
    # Emailed verification (signup confirmation / login code or magic link). The
    # freshness window is enforced in code against each message's own receive
    # timestamp because Gmail's relative age operators have no hour unit, so a
    # short-lived one-time secret cannot be bounded by the search query alone.
    gmail_verification_max_age_seconds: int = Field(default=900, ge=60, le=3_600)
    # How many times a single run may poll the inbox for one verification before it
    # settles into a truthful human gate. Bounded so a provider that never sends
    # cannot spin forever.
    gmail_verification_max_attempts: int = Field(default=3, ge=1, le=10)
    gmail_verification_poll_seconds: float = Field(default=5.0, ge=0.0, le=60.0)
    # When true, a verification secret may be consumed ONLY when the message can be
    # bound to this run's exact signup/login recipient and a reviewed sender. The
    # Production defaults fail closed: a message without an exact run recipient
    # binding is never injected into a browser. Legacy deployments can opt out
    # explicitly while migrating their stored login identities.
    gmail_verification_require_binding: bool = True
    # A reviewed From domain is not proof of sender identity. Production accepts
    # an OTP/link only when Gmail supplies aligned DMARC, DKIM, or SPF evidence
    # in Authentication-Results (or a validated ARC chain).
    gmail_verification_require_authenticated_sender: bool = True

    # --- Autonomous provider onboarding budgets --------------------------------
    # Every bound the onboarding phase driver needs is configuration, not a literal
    # buried in a loop, so a deployment can tighten a budget without a code change
    # and so each bound has exactly one source of truth. These are separate from the
    # gmail_* settings above on purpose: those configure the Gmail adapter, while
    # these configure the provider-agnostic onboarding services (the verification
    # service resolves mail through the VerificationProvider port and never names
    # Gmail).
    #
    # Loop budgets (Requirements 4.10, 5.10). Sourced by
    # ops/onboarding/action_loop.py::LoopBudget; each bound returns its own
    # exhausted/denied-fatal reason code rather than a generic failure.
    onboarding_loop_max_actions: int = Field(default=60, ge=1, le=200)
    onboarding_loop_max_model_calls: int = Field(default=80, ge=1, le=300)
    onboarding_loop_max_no_progress: int = Field(default=6, ge=1, le=20)
    onboarding_loop_max_wallclock_seconds: int = Field(default=900, ge=30, le=3_600)
    onboarding_loop_max_navigation_denials: int = Field(default=10, ge=1, le=50)
    # CAPTCHA is the only mid-flight operator prompt, so its budget is what stops a
    # provider that re-challenges forever from prompting forever (Requirement 11.10:
    # 3 pauses per run, then `captcha_attempt_budget_exhausted`).
    onboarding_captcha_pause_budget: int = Field(default=3, ge=1, le=10)
    # Email verification (Requirements 7.11, 7.26, 7.27). The base delay feeds the
    # bounded backoff (base * 2**attempt, capped at 30 s, jittered); the attempt
    # budget is where the run pauses with `verification_unresolved`; the maximum
    # message age is the freshness floor a candidate message must clear, which
    # Requirement 7.11 bounds at 3600 seconds.
    onboarding_verification_base_delay_seconds: float = Field(default=5.0, ge=0.0, le=60.0)
    onboarding_verification_attempt_budget: int = Field(default=3, ge=1, le=10)
    onboarding_verification_max_message_age_seconds: int = Field(default=3_600, ge=60, le=3_600)
    # Lease mechanics (Requirements 16.4, 16.5). The pair is checked against each
    # other by a model validator rather than merely documented, because a renewal
    # cadence wider than a third of the TTL turns one slow store call into a
    # fenced-out worker instead of a tolerated retry.
    onboarding_lease_ttl_seconds: int = Field(default=60, ge=15, le=600)
    onboarding_lease_renew_interval_seconds: int = Field(default=20, ge=5, le=200)
    # Autonomous takeover after a human clears a human-only gate (Requirement 1.1).
    #
    # This one defaults ON, unlike every live-capability flag in this file, and the
    # difference is deliberate: the watcher only OBSERVES a page a human is already
    # looking at. It spends nothing, opens no session, and starts no provider work,
    # so defaulting it off would ship the reported freeze — "after a human enters the
    # captcha the agent doesn't take over" — unfixed. It stays gated by
    # `ops_startup_automation_enabled` and by deployment acceptance, exactly like the
    # existing sweeps. ALLOW_LIVE_BROWSER and ALLOW_LIVE_VENDOR_EMAIL are untouched
    # and stay disabled.
    onboarding_takeover_enabled: bool = True
    # 5 s is "immediately" at human scale, and one read-only clearance probe per
    # paused run is cheap.
    onboarding_takeover_interval_seconds: int = Field(default=5, ge=1, le=30)
    # A probe must never outlive its own interval: a slow probe is reported as
    # `probe_failed` and the run keeps waiting, so this stays under the tightest
    # interval rather than queueing behind it.
    onboarding_takeover_probe_timeout_seconds: float = Field(default=5.0, ge=1.0, le=15.0)
    # Progress liveness (Requirements 4.2, 4.9). The staleness window sits above the
    # slowest single step (act 40 s plus verify 20 s) with room for one retry, and far
    # below the loop wall clock of 900 s, so a working-but-slow run is not marked
    # stalled. The window is the bound on the timeline's progress query.
    onboarding_progress_stale_seconds: int = Field(default=180, ge=30, le=1_800)
    onboarding_progress_window: int = Field(default=50, ge=1, le=200)
    # One deadline per step of one browser operation (Requirement 4.7). The set is
    # checked against `browser_service_client_timeout_seconds` by
    # `browser_step_deadlines_fit_inside_the_client_budget` below rather than merely
    # documented, because a set that sums past the outer budget turns a per-step
    # timeout into a client-side abort that names no step at all. The defaults sum to
    # 100 s, under the browser service's own 120 s operation ceiling and far under the
    # 315 s client budget.
    onboarding_step_observe_timeout_seconds: int = Field(default=20, ge=5, le=60)
    onboarding_step_decide_timeout_seconds: int = Field(default=20, ge=5, le=60)
    onboarding_step_act_timeout_seconds: int = Field(default=40, ge=5, le=90)
    onboarding_step_verify_timeout_seconds: int = Field(default=20, ge=5, le=60)
    # Pre-flight planning (Requirement 5.3). Paid once per run, before any browser
    # session exists, so the total is wider than one action decision while each
    # provider attempt stays short and how much of the chain one plan may consume
    # stays bounded.
    onboarding_plan_decision_total_seconds: float = Field(default=20.0, ge=5.0, le=60.0)
    onboarding_plan_decision_provider_seconds: float = Field(default=8.0, ge=2.0, le=30.0)
    onboarding_plan_max_providers: int = Field(default=3, ge=1, le=5)
    # The two budgets that terminate the credential ladder. See the module-level
    # comment above `Settings` for why these numbers were chosen and which
    # acceptance criteria each one terminates.
    credential_validation_attempt_budget: int = Field(default=3, ge=1, le=10)
    credential_generation_budget: int = Field(default=2, ge=1, le=5)
    # Onboarding research adapters (Requirement 2.2). Every discovery adapter the
    # profile builder may engage is its own opt-in flag, so enabling one provider
    # never enables another and a new adapter arrives as a new flag plus a port
    # implementation rather than an edit to the orchestrator. Registration is
    # `ops/providers/profile_builder.py::research_adapters`, which raises rather
    # than degrading when a flag is on and its credential is absent.
    #
    # These are separate from the `you_*` flags above and from
    # `perplexity_api_key` on purpose: those configure the reviewed-catalog
    # enrichment path, which starts from a P1 record's official host list. Profile
    # research starts from a provider name and no host list at all, so which
    # adapter may run there is a distinct decision — and, like every capability
    # flag in this file, defaults to off so a configured key alone never spends.
    onboarding_research_perplexity_enabled: bool = False
    # Requirement 2.5: the per-adapter attempt cap. Discovery retries only an
    # adapter that RAISED — an adapter returning no candidate has answered, and
    # asking it again would just re-spend. 2 keeps one transient failure
    # survivable while bounding a permanently unreachable adapter to a single
    # retry, so it cannot extend discovery without bound.
    onboarding_research_adapter_attempts: int = Field(default=2, ge=1, le=4)

    @property
    def onboarding_research_perplexity_configured(self) -> bool:
        """Whether the Perplexity discovery adapter is both opted into and keyed."""

        return self.onboarding_research_perplexity_enabled and self.perplexity_api_key is not None

    ops_db_path: Path = Path("./private/ops.db")
    checkpoint_db_path: Path = Path("./private/checkpoints.db")
    secret_vault_db_path: Path = Path("./private/secret_vault.db")
    provider_effects_db_path: Path = Path("./private/provider_effects.db")

    @field_validator("company_work_email_ref")
    @classmethod
    def validate_company_work_email_ref(cls, value: str | None) -> str | None:
        return validate_vault_reference(value) if value is not None else None

    @field_validator("gmail_signup_address")
    @classmethod
    def validate_gmail_signup_address(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        address = value.get_secret_value()
        if (
            len(address) > 320
            or address.count("@") != 1
            or any(character.isspace() for character in address)
            or any(character in address for character in "<>,;\r\n")
        ):
            raise ValueError("GMAIL_SIGNUP_ADDRESS must be one email address")
        local_part, domain = address.rsplit("@", 1)
        if not local_part or "." not in domain or domain.startswith(".") or domain.endswith("."):
            raise ValueError("GMAIL_SIGNUP_ADDRESS must be one email address")
        return value

    @field_validator("signup_identity_handoff_provider")
    @classmethod
    def validate_signup_identity_handoff_provider(cls, value: str | None) -> str | None:
        if value is None:
            return None
        provider = value.strip().lower()
        if not provider:
            return None
        # Kept as a literal rather than imported from ops.browser.signup so the
        # settings module stays free of the browser stack. The driver checks the
        # name again against its own table and ignores anything it does not
        # recognize, so a name that slips past here still cannot click anything.
        if provider not in {"google", "github", "gitlab", "microsoft", "apple"}:
            raise ValueError(
                "SIGNUP_IDENTITY_HANDOFF_PROVIDER must be one of "
                "google, github, gitlab, microsoft, apple"
            )
        return provider

    @field_validator("browser_session_capability_key")
    @classmethod
    def validate_browser_session_capability_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        secret = value.get_secret_value()
        if len(secret) < 32:
            raise ValueError("BROWSER_SESSION_CAPABILITY_KEY must be at least 32 characters")
        lowered = secret.casefold()
        if any(marker in lowered for marker in ("replace-with", "change-me", "example")):
            raise ValueError("BROWSER_SESSION_CAPABILITY_KEY contains a placeholder")
        return value

    @field_validator("ops_internal_api_token")
    @classmethod
    def validate_ops_internal_api_token(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        token = value.get_secret_value()
        if len(token) < 32:
            raise ValueError("OPS_INTERNAL_API_TOKEN must be at least 32 characters")
        if any(marker in token.casefold() for marker in ("replace-with", "change-me", "example")):
            raise ValueError("OPS_INTERNAL_API_TOKEN contains a placeholder")
        return value

    @field_validator("browser_secret_broker_token")
    @classmethod
    def validate_browser_secret_broker_token(
        cls,
        value: SecretStr | None,
    ) -> SecretStr | None:
        if value is None:
            return None
        token = value.get_secret_value()
        if len(token) < 32:
            raise ValueError("BROWSER_SECRET_BROKER_TOKEN must be at least 32 characters")
        if any(marker in token.casefold() for marker in ("replace-with", "change-me", "example")):
            raise ValueError("BROWSER_SECRET_BROKER_TOKEN contains a placeholder")
        return value

    @field_validator("browser_service_token")
    @classmethod
    def validate_browser_service_token(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        token = value.get_secret_value()
        if len(token) < 32:
            raise ValueError("BROWSER_SERVICE_TOKEN must be at least 32 characters")
        if any(marker in token.casefold() for marker in ("replace-with", "change-me", "example")):
            raise ValueError("BROWSER_SERVICE_TOKEN contains a placeholder")
        return value

    @field_validator("browser_service_owner")
    @classmethod
    def validate_browser_service_owner(cls, value: str) -> str:
        try:
            return validate_capability_owner(value)
        except BrowserSessionCapabilityError:
            raise ValueError(
                "BROWSER_SERVICE_OWNER must be an HTTP-safe ASCII identifier"
            ) from None

    @model_validator(mode="after")
    def onboarding_lease_renewal_fits_inside_the_lease(self) -> Settings:
        """Keep the renew interval at or below one third of the lease duration.

        Requirement 16.5 states the cadence, and Requirement 16.7 depends on it: two
        consecutive renewals may fail while the deadline is still in the future only
        while the interval is at most a third of the TTL. A mis-set pair is rejected
        at startup rather than discovered as a fenced-out worker mid-run.
        """

        if self.onboarding_lease_renew_interval_seconds * 3 > self.onboarding_lease_ttl_seconds:
            raise ValueError(
                "ONBOARDING_LEASE_RENEW_INTERVAL_SECONDS must be at most one third of "
                "ONBOARDING_LEASE_TTL_SECONDS"
            )
        return self

    @model_validator(mode="after")
    def browser_step_deadlines_fit_inside_the_client_budget(self) -> Settings:
        """Keep the four per-step deadlines inside the outer browser-operation budget.

        Requirement 4.7 declares one deadline per step of one browser operation, and
        Requirement 4.8 makes a set that does not fit a configuration error naming the
        rejected values. A set summing to the client budget or beyond turns a per-step
        timeout into a client-side abort, which reports no step at all — exactly the
        diagnosis this feature exists to make possible. The decide deadline is floored
        separately at the decision budget, because a decide step shorter than the chain
        it waits on would cancel a decision the chain was still allowed to make.
        """

        deadlines = (
            ("observe", self.onboarding_step_observe_timeout_seconds),
            ("decide", self.onboarding_step_decide_timeout_seconds),
            ("act", self.onboarding_step_act_timeout_seconds),
            ("verify", self.onboarding_step_verify_timeout_seconds),
        )
        total = sum(seconds for _, seconds in deadlines)
        if total >= self.browser_service_client_timeout_seconds:
            named = ", ".join(f"{name}={seconds}" for name, seconds in deadlines)
            raise ValueError(
                f"the per-step deadlines ({named}) sum to {total} which is not below "
                "BROWSER_SERVICE_CLIENT_TIMEOUT_SECONDS="
                f"{self.browser_service_client_timeout_seconds}"
            )
        decision_budget_seconds = DecisionBudget().total_seconds
        if self.onboarding_step_decide_timeout_seconds < decision_budget_seconds:
            raise ValueError(
                "ONBOARDING_STEP_DECIDE_TIMEOUT_SECONDS="
                f"{self.onboarding_step_decide_timeout_seconds} must be at least the "
                f"decision budget of {decision_budget_seconds}s"
            )
        return self

    @model_validator(mode="after")
    def control_plane_tokens_are_independent(self) -> Settings:
        configured = [
            (name, value.get_secret_value())
            for name, value in (
                ("OPS_INTERNAL_API_TOKEN", self.ops_internal_api_token),
                ("BROWSER_SERVICE_TOKEN", self.browser_service_token),
                ("BROWSER_SESSION_CAPABILITY_KEY", self.browser_session_capability_key),
                ("BROWSER_SECRET_BROKER_TOKEN", self.browser_secret_broker_token),
            )
            if value is not None
        ]
        for index, (left_name, left_value) in enumerate(configured):
            for right_name, right_value in configured[index + 1 :]:
                if hmac.compare_digest(left_value, right_value):
                    raise ValueError(f"{left_name} must differ from {right_name}")
        return self

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
            # YDC_API_KEY is canonical. Accept the two historical spellings used
            # by existing deployments without ever copying or logging the value.
            "you_api_key": _secret(
                source.get("YDC_API_KEY") or source.get("YOU_API_KEY") or source.get("You_API_KEY")
            ),
            "google_genai_api_key": _secret(source.get("GOOGLE_GENAI_API_KEY")),
            "openrouter_api_key": _secret(source.get("OPENROUTER_API_KEY")),
            "groq_api_key": _secret(source.get("GROQ_API_KEY")),
            "cerebras_api_key": _secret(source.get("CEREBRAS_API_KEY")),
            # MERCURY_API_KEY is canonical. INCEPTION_API_KEY is accepted because
            # that is the name Inception's own documentation exports.
            "mercury_api_key": _secret(
                source.get("MERCURY_API_KEY") or source.get("INCEPTION_API_KEY")
            ),
            "groq_model": _optional(source.get("GROQ_MODEL")) or "openai/gpt-oss-120b",
            "cerebras_model": _optional(source.get("CEREBRAS_MODEL")) or "gpt-oss-120b",
            "mercury_model": _optional(source.get("MERCURY_MODEL")) or "mercury-2",
            "mercury_reasoning_effort": _choice(
                source.get("MERCURY_REASONING_EFFORT"),
                ("instant", "low", "medium", "high"),
                default="high",
            ),
            "openrouter_model": _optional(source.get("OPENROUTER_MODEL"))
            or "nvidia/nemotron-3-ultra-550b-a55b:free",
            "composio_api_key": _secret(source.get("COMPOSIO_API_KEY")),
            "composio_gmail_api_key": _secret(
                source.get("COMPOSIO_GMAIL_API_KEY") or source.get("COMPOSIO_API_KEY")
            ),
            "langgraph_aes_key": _secret(source.get("LANGGRAPH_AES_KEY")),
            "secret_vault_key": _secret(source.get("SECRET_VAULT_KEY")),
            "ops_internal_api_token": _secret(source.get("OPS_INTERNAL_API_TOKEN")),
            "browser_secret_broker_token": _secret(source.get("BROWSER_SECRET_BROKER_TOKEN")),
            "langgraph_strict_msgpack": _boolean(
                source.get("LANGGRAPH_STRICT_MSGPACK"), default=True
            ),
            "composio_user_id": _optional(source.get("COMPOSIO_USER_ID")) or "ops-owner",
            "composio_gmail_user_id": _optional(source.get("COMPOSIO_GMAIL_USER_ID"))
            or _optional(source.get("COMPOSIO_USER_ID"))
            or "ops-owner",
            "composio_gmail_connected_account_id": _optional(
                source.get("COMPOSIO_GMAIL_SIGNUP_CONNECTED_ACCOUNT_ID")
                or source.get("COMPOSIO_GMAIL_CONNECTED_ACCOUNT_ID")
            ),
            "gmail_signup_address": _secret(source.get("GMAIL_SIGNUP_ADDRESS")),
            "signup_identity_handoff_provider": _optional(
                source.get("SIGNUP_IDENTITY_HANDOFF_PROVIDER")
            ),
            "managed_auth_callback_base_url": _optional(
                source.get("MANAGED_AUTH_CALLBACK_BASE_URL")
            ),
            "gemini_model": _optional(source.get("GEMINI_MODEL")) or "gemini-3.6-flash",
            # BROWSER_PROVIDER is still read so a deployment that still sets it does
            # not fail to start, but "playwright" is the only accepted value and the
            # only backend that exists.
            "browser_provider": _choice(
                source.get("BROWSER_PROVIDER"),
                ("playwright",),
                default="playwright",
            ),
            "playwright_max_sessions": _integer(source.get("PLAYWRIGHT_MAX_SESSIONS"), default=2),
            "playwright_disable_sandbox": _boolean(
                source.get("PLAYWRIGHT_DISABLE_SANDBOX"), default=False
            ),
            "browser_service_url": _optional(source.get("BROWSER_SERVICE_URL")),
            "browser_service_token": _secret(source.get("BROWSER_SERVICE_TOKEN")),
            "browser_session_capability_key": _secret(source.get("BROWSER_SESSION_CAPABILITY_KEY")),
            "browser_service_owner": (
                _optional(source.get("BROWSER_SERVICE_OWNER")) or "ops-owner"
            ),
            "browser_service_client_timeout_seconds": _float(
                source.get("BROWSER_SERVICE_CLIENT_TIMEOUT_SECONDS"), default=315.0
            ),
            "browser_interactive_hitl_enabled": _boolean(
                source.get("BROWSER_INTERACTIVE_HITL_ENABLED"), default=False
            ),
            "browser_domain_discovery_enabled": _boolean(
                source.get("BROWSER_DOMAIN_DISCOVERY_ENABLED"), default=False
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
            "ops_startup_automation_enabled": _boolean(
                source.get("OPS_STARTUP_AUTOMATION_ENABLED"), default=False
            ),
            "ops_automation_start_delay_seconds": _float(
                source.get("OPS_AUTOMATION_START_DELAY_SECONDS"), default=30.0
            ),
            "app_revision": _optional(source.get("APP_REVISION")) or "local-uncommitted",
            "ops_deploy_acceptance_nonce": _secret(source.get("OPS_DEPLOY_ACCEPTANCE_NONCE")),
            "ops_deploy_acceptance_marker_path": Path(
                source.get(
                    "OPS_DEPLOY_ACCEPTANCE_MARKER_PATH",
                    "./private/deploy-acceptance.json",
                )
            ),
            "max_outreach_rounds": _integer(source.get("MAX_OUTREACH_ROUNDS"), default=5),
            "email_poll_interval_seconds": _integer(
                source.get("EMAIL_POLL_INTERVAL_SECONDS"), default=45
            ),
            "email_poll_max_runs_per_cycle": _integer(
                source.get("EMAIL_POLL_MAX_RUNS_PER_CYCLE"), default=25
            ),
            "max_unclear_retries": _integer(source.get("MAX_UNCLEAR_RETRIES"), default=1),
            "browser_login_credential_reuse": _boolean(
                source.get("BROWSER_LOGIN_CREDENTIAL_REUSE"), default=True
            ),
            "max_autonomous_advances": _integer(source.get("MAX_AUTONOMOUS_ADVANCES"), default=2),
            "autonomous_advance_interval_seconds": _integer(
                source.get("AUTONOMOUS_ADVANCE_INTERVAL_SECONDS"), default=20
            ),
            "max_browser_attempts": _integer(source.get("MAX_BROWSER_ATTEMPTS"), default=2),
            "max_hitl_count": _integer(source.get("MAX_HITL_COUNT"), default=3),
            "gmail_retry_max_attempts": _integer(source.get("GMAIL_RETRY_MAX_ATTEMPTS"), default=3),
            "gmail_retry_base_delay_seconds": _float(
                source.get("GMAIL_RETRY_BASE_DELAY_SECONDS"), default=0.5
            ),
            "gmail_signup_preflight_timeout_seconds": _float(
                source.get("GMAIL_SIGNUP_PREFLIGHT_TIMEOUT_SECONDS"), default=10.0
            ),
            "gmail_verification_max_age_seconds": _integer(
                source.get("GMAIL_VERIFICATION_MAX_AGE_SECONDS"), default=900
            ),
            "gmail_verification_max_attempts": _integer(
                source.get("GMAIL_VERIFICATION_MAX_ATTEMPTS"), default=3
            ),
            "gmail_verification_poll_seconds": _float(
                source.get("GMAIL_VERIFICATION_POLL_SECONDS"), default=5.0
            ),
            "gmail_verification_require_binding": _boolean(
                source.get("GMAIL_VERIFICATION_REQUIRE_BINDING"), default=True
            ),
            "gmail_verification_require_authenticated_sender": _boolean(
                source.get("GMAIL_VERIFICATION_REQUIRE_AUTHENTICATED_SENDER"),
                default=True,
            ),
            "onboarding_loop_max_actions": _integer(
                source.get("ONBOARDING_LOOP_MAX_ACTIONS"), default=60
            ),
            "onboarding_loop_max_model_calls": _integer(
                source.get("ONBOARDING_LOOP_MAX_MODEL_CALLS"), default=80
            ),
            "onboarding_loop_max_no_progress": _integer(
                source.get("ONBOARDING_LOOP_MAX_NO_PROGRESS"), default=6
            ),
            "onboarding_loop_max_wallclock_seconds": _integer(
                source.get("ONBOARDING_LOOP_MAX_WALLCLOCK_SECONDS"), default=900
            ),
            "onboarding_loop_max_navigation_denials": _integer(
                source.get("ONBOARDING_LOOP_MAX_NAVIGATION_DENIALS"), default=10
            ),
            "onboarding_captcha_pause_budget": _integer(
                source.get("ONBOARDING_CAPTCHA_PAUSE_BUDGET"), default=3
            ),
            "onboarding_verification_base_delay_seconds": _float(
                source.get("ONBOARDING_VERIFICATION_BASE_DELAY_SECONDS"), default=5.0
            ),
            "onboarding_verification_attempt_budget": _integer(
                source.get("ONBOARDING_VERIFICATION_ATTEMPT_BUDGET"), default=3
            ),
            "onboarding_verification_max_message_age_seconds": _integer(
                source.get("ONBOARDING_VERIFICATION_MAX_MESSAGE_AGE_SECONDS"), default=3_600
            ),
            "onboarding_lease_ttl_seconds": _integer(
                source.get("ONBOARDING_LEASE_TTL_SECONDS"), default=60
            ),
            "onboarding_lease_renew_interval_seconds": _integer(
                source.get("ONBOARDING_LEASE_RENEW_INTERVAL_SECONDS"), default=20
            ),
            "onboarding_takeover_enabled": _boolean(
                source.get("ONBOARDING_TAKEOVER_ENABLED"), default=True
            ),
            "onboarding_takeover_interval_seconds": _integer(
                source.get("ONBOARDING_TAKEOVER_INTERVAL_SECONDS"), default=5
            ),
            "onboarding_takeover_probe_timeout_seconds": _float(
                source.get("ONBOARDING_TAKEOVER_PROBE_TIMEOUT_SECONDS"), default=5.0
            ),
            "onboarding_progress_stale_seconds": _integer(
                source.get("ONBOARDING_PROGRESS_STALE_SECONDS"), default=180
            ),
            "onboarding_progress_window": _integer(
                source.get("ONBOARDING_PROGRESS_WINDOW"), default=50
            ),
            "onboarding_step_observe_timeout_seconds": _integer(
                source.get("ONBOARDING_STEP_OBSERVE_TIMEOUT_SECONDS"), default=20
            ),
            "onboarding_step_decide_timeout_seconds": _integer(
                source.get("ONBOARDING_STEP_DECIDE_TIMEOUT_SECONDS"), default=20
            ),
            "onboarding_step_act_timeout_seconds": _integer(
                source.get("ONBOARDING_STEP_ACT_TIMEOUT_SECONDS"), default=40
            ),
            "onboarding_step_verify_timeout_seconds": _integer(
                source.get("ONBOARDING_STEP_VERIFY_TIMEOUT_SECONDS"), default=20
            ),
            "onboarding_plan_decision_total_seconds": _float(
                source.get("ONBOARDING_PLAN_DECISION_TOTAL_SECONDS"), default=20.0
            ),
            "onboarding_plan_decision_provider_seconds": _float(
                source.get("ONBOARDING_PLAN_DECISION_PROVIDER_SECONDS"), default=8.0
            ),
            "onboarding_plan_max_providers": _integer(
                source.get("ONBOARDING_PLAN_MAX_PROVIDERS"), default=3
            ),
            "credential_validation_attempt_budget": _integer(
                source.get("CREDENTIAL_VALIDATION_ATTEMPT_BUDGET"), default=3
            ),
            "credential_generation_budget": _integer(
                source.get("CREDENTIAL_GENERATION_BUDGET"), default=2
            ),
            "onboarding_research_perplexity_enabled": _boolean(
                source.get("ONBOARDING_RESEARCH_PERPLEXITY_ENABLED"), default=False
            ),
            "onboarding_research_adapter_attempts": _integer(
                source.get("ONBOARDING_RESEARCH_ADAPTER_ATTEMPTS"), default=2
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
