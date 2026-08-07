"""Versioned, reviewed onboarding recipes for the approved 50-app matrix."""

from __future__ import annotations

import json
import re
from datetime import date
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, Literal, Self
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from ops.browser.setup_values import APPROVED_BROWSER_VALUE_REFS

if TYPE_CHECKING:
    from ops.browser.api_trace_catalog import BrowserApiTrace, CheckpointPredicate
    from ops.core.models import OperationalResearch
    from ops.credentials.capture_specs import CredentialCaptureSpec
    from ops.credentials.validator import CredentialValidationPolicy

RouteKind = Literal["managed_auth", "playwright", "gated"]
ReadinessTier = Literal[
    "managed_auth_ready",
    "browser_ready",
    "owner_submit_ready",
    "outreach_ready",
    "outreach_review_required",
]
AuthStyle = Literal[
    "oauth2",
    "api_key",
    "bearer_token",
    "basic_auth",
    "bot_token",
    "personal_access_token",
    "service_account",
]
CredentialFieldKind = Literal[
    "api_key",
    "bearer_token",
    "bot_token",
    "personal_access_token",
    "username",
    "password",
    "client_id",
    "client_secret",
]
CaptureMode = Literal["managed_connection", "automatic", "owner_submit", "none"]
CaptureSource = Literal["input_value", "text"]
BrowserRecipeScope = Literal["entry_only", "credential_surface"]
# What one reviewed browser step is FOR. The first three move the page; the last
# three do not, and that distinction is now load-bearing rather than descriptive.
#
# Until these existed the recipe language could only say "go somewhere", so a flow
# whose next move happens on the page already loaded — telegram issuing a token
# through a chat, a settings panel that opens a dialog — had no way to be written
# down. The step still cannot name a selector or a value: ``click_control`` and
# ``await_control`` point at ``control_names``, ``fill_field`` points at
# ``allowed_value_refs``, and both of those are reviewed allow-lists the model
# chooses from by id. What an in-page verb actually buys is the REMOVAL of the
# reviewed navigation candidate, so a step that means "act here" can no longer be
# satisfied by walking away from the page.
BrowserAction = Literal[
    "navigate",
    "authenticate_then_navigate",
    "capture_boundary",
    "click_control",
    "fill_field",
    "await_control",
]
# The subset that may carry a ``target_url`` and be offered a ``goto`` candidate.
NAVIGATING_BROWSER_ACTIONS: Final[frozenset[str]] = frozenset(
    {"navigate", "authenticate_then_navigate", "capture_boundary"}
)
# ``email_first`` is a reviewer's claim: a human confirmed the route asks for an
# email alone and only then for a password. ``dom_detected`` is what a researched
# route may claim instead -- the entry paths and submit labels are evidence-backed,
# but nobody reviewed the step ordering, so the driver reads the form shape off the
# live page. It authorizes no new surface: either shape must still be the single
# unambiguous reviewed form, under the same host allowlist and human gates.
SignupFlow = Literal["email_first", "dom_detected"]
HitlGate = Literal[
    "captcha",
    "mfa",
    "account_selection",
    "device_approval",
    "email_verification",
    "legal_consent",
    "billing",
]
ValidationAuthScheme = Literal["bearer", "api_key_header", "basic_auth"]
SendingPolicy = Literal["controlled_sink_only"]

MANAGED_AUTH_SLUGS = (
    "salesforce",
    "hubspot",
    "attio",
    "zendesk",
    "intercom",
    "gorgias",
    "slack",
    "discord",
    "google-ads",
    "mailchimp",
    "gumroad",
    "github",
    "supabase",
    "sentry",
    "notion",
    "airtable",
    "linear",
    "jira",
    "asana",
    "monday",
    "clickup",
    "harvest",
    "stripe",
    "quickbooks",
    "fathom",
)
PLAYWRIGHT_SLUGS = (
    "pipedrive",
    "telegram",
    "klaviyo",
    "shopify",
    "dataforseo",
    "apify",
    "firecrawl",
    "bright-data",
    "vercel",
    "cloudflare",
    "neo4j",
    "datadog",
    "coda",
    "xero",
)
GATED_SLUGS = (
    "close",
    "freshdesk",
    "plain",
    "help-scout",
    "meta-ads",
    "linkedin-ads",
    "sendgrid",
    "ahrefs",
    "snowflake",
    "brex",
    "ramp",
)

_CATALOG_PATH = Path(__file__).with_name("app_recipes.json")
_HOST_PATTERN = re.compile(
    r"^(?:\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_SENSITIVE_QUERY_NAMES = frozenset(
    {"access_token", "api_key", "code", "key", "password", "secret", "token"}
)
# The characters a reviewed URL fragment may use: RFC 3986 unreserved and
# sub-delims plus "/", "?" and "%", which is every character a hash route needs.
# Deliberately absent are ":" and "#", so a fragment can never spell a second
# absolute URL ("https://evil.example") for anything downstream to peel off and
# follow, and control characters and whitespace, which only ever arrive from a
# mangled paste. The 256 cap is well above any real route and keeps a fragment
# from being used as a payload channel inside a reviewed catalog entry.
_FRAGMENT_PATTERN = re.compile(r"[A-Za-z0-9\-._~!$&'()*+,;=@/?%]{1,256}")


class AppRecipeCatalogError(ValueError):
    """The checked-in recipe catalog is malformed or over-claims readiness."""


class _RecipeModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        str_strip_whitespace=True,
    )


def _https_url(value: str, label: str) -> str:
    """Return ``value`` unchanged once it is usable as a reviewed recipe URL.

    PRE: ``value`` is catalog text, not a URL read off a live page.
    POST: the result is https, carries a host, no userinfo, no sensitive query
    name, and at most one bounded fragment; otherwise ``ValueError``.

    A fragment is allowed because the client never puts it on the wire: it is a
    routing artifact the browser keeps to itself, so refusing one buys no
    security while making real destinations unrepresentable -- neo4j Aura hides
    its API-key page behind ``#/``, and every SPA hash route reads the same way.
    Nothing that guards navigation looks at it either: host confinement reads
    ``urlsplit(...).hostname`` and path matching reads ``.path``, both of which
    ``urlsplit`` splits the fragment off before returning.
    """

    parsed = urlsplit(value)
    # The RAW fragment, not ``parsed.fragment``: ``urlsplit`` silently deletes
    # ASCII tab and newline anywhere in the URL, so the parsed fragment of
    # "...#a<TAB>b" is a clean "ab" while the tab stays in the value we return.
    # Reading the text after the first "#" ourselves is what makes the "no
    # control characters, no whitespace" half of the contract true, and it also
    # puts any second "#" inside the checked span.
    _before, _hash, raw_fragment = value.partition("#")
    if (
        not value
        or len(value) > 2_048
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or (raw_fragment and _FRAGMENT_PATTERN.fullmatch(raw_fragment) is None)
    ):
        raise ValueError(f"{label} must be a stable HTTPS URL")
    query_names = {
        name.casefold() for name, _value in parse_qsl(parsed.query, keep_blank_values=True)
    }
    if query_names & _SENSITIVE_QUERY_NAMES:
        raise ValueError(f"{label} contains sensitive query data")
    return value


def _without_fragment(value: str | None) -> str | None:
    """Return ``value`` with any fragment removed, for boundaries that ban one.

    PRE: ``value`` is a reviewed recipe URL (or ``None``).
    POST: the result is the same URL up to, but not including, the first ``#``.

    Splitting on the literal ``#`` rather than re-joining ``urlsplit`` parts keeps
    the surviving text byte-identical, so a URL that never had a fragment is
    returned unchanged and no percent-encoding is silently rewritten.
    """

    if value is None:
        return None
    head, _, _fragment = value.partition("#")
    return head


def _unique(values: tuple[str, ...], label: str, maximum: int = 30) -> tuple[str, ...]:
    if len(values) > maximum or any(not item or len(item) > 2_000 for item in values):
        raise ValueError(f"{label} is invalid")
    if len(values) != len(set(values)):
        raise ValueError(f"{label} contains duplicates")
    return values


def _host(value: str, label: str, *, wildcard: bool) -> str:
    if value != value.casefold() or _HOST_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be a normalized host pattern")
    if value.startswith("*.") and not wildcard:
        raise ValueError(f"{label} must be an exact host")
    return value


class VerifiedUrls(_RecipeModel):
    login: str | None = None
    signup: str | None = None
    developer_portal: str | None = None
    credential_management: str | None = None
    contact: str | None = None

    @field_validator("login", "signup", "developer_portal", "credential_management", "contact")
    @classmethod
    def validate_url(cls, value: str | None) -> str | None:
        return None if value is None else _https_url(value, "operational URL")


class SuccessPredicate(_RecipeModel):
    url_path_contains: tuple[str, ...] = ()
    title_contains: tuple[str, ...] = ()
    visible_text_contains: tuple[str, ...] = ()
    required_accessible_names: tuple[str, ...] = ()
    forbidden_text: tuple[str, ...] = ()

    @field_validator(
        "url_path_contains",
        "title_contains",
        "visible_text_contains",
        "required_accessible_names",
        "forbidden_text",
    )
    @classmethod
    def validate_clauses(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique(value, "predicate clauses", 20)

    def has_positive_condition(self) -> bool:
        return bool(
            self.url_path_contains
            or self.title_contains
            or self.visible_text_contains
            or self.required_accessible_names
        )

    def proves_credential_surface(self) -> bool:
        return bool(self.url_path_contains) and bool(
            self.title_contains or self.visible_text_contains or self.required_accessible_names
        )


class BrowserStep(_RecipeModel):
    order: int = Field(ge=1, le=20)
    action: BrowserAction
    target_url: str | None
    instruction: str = Field(min_length=1, max_length=2_000)
    completion: SuccessPredicate
    hitl_gates: tuple[HitlGate, ...] = Field(default=(), max_length=10)
    # Exact non-secret references this step may place into provider controls.
    # Values are resolved only from immutable run input; page text and model
    # output can never become a form value.
    allowed_value_refs: tuple[str, ...] = Field(default=(), max_length=20)
    # Exact accessible names of reviewed Create/Generate/Save controls. Merely
    # setting create_if_missing on a run is insufficient: both the run and this
    # recipe-owned allowlist must authorize the control.
    credential_creation_controls: tuple[str, ...] = Field(default=(), max_length=20)
    # Reviewed accessible names of controls the agent may CONSIDER on this step.
    #
    # `completion` answers "is this step done"; it is folded into the checkpoint's
    # expected_signals, which `generate_candidates` uses as a relevance filter over
    # element names. Those two jobs pull apart: the Pipedrive step is complete when
    # the page says "API token", but the control that gets there is named "Generate
    # new token" -- which matches neither the path nor the completion text, so the
    # filter dropped the only useful element and the run stopped for a human on a
    # page it could have finished itself. Naming the controls here restores them as
    # candidates WITHOUT asserting they must be present for the step to count as
    # complete (a created token's button may well disappear).
    control_names: tuple[str, ...] = Field(default=(), max_length=20)

    @field_validator("target_url")
    @classmethod
    def validate_target(cls, value: str | None) -> str | None:
        return None if value is None else _https_url(value, "browser step target")

    @field_validator("allowed_value_refs")
    @classmethod
    def validate_value_refs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        refs = _unique(value, "browser step value references", 20)
        if set(refs) - APPROVED_BROWSER_VALUE_REFS:
            raise ValueError("browser step contains an unapproved value reference")
        return refs

    @field_validator("credential_creation_controls")
    @classmethod
    def validate_creation_controls(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique(value, "browser step creation controls", 20)

    @field_validator("control_names")
    @classmethod
    def validate_control_names(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique(value, "browser step control names", 20)

    @model_validator(mode="after")
    def validate_step(self) -> Self:
        if not self.completion.has_positive_condition():
            raise ValueError("browser step needs a positive predicate")
        if len(self.hitl_gates) != len(set(self.hitl_gates)):
            raise ValueError("HITL gates contain duplicates")
        # ``click_control`` joins ``capture_boundary`` here because it is the verb
        # for exactly this act — pressing a reviewed "Create API key" on a page the
        # run is already on. Every other verb either moves the page or does not
        # press anything, so authorizing creation on one would be a control the
        # step can never reach.
        if self.credential_creation_controls and self.action not in {
            "capture_boundary",
            "click_control",
        }:
            raise ValueError("credential creation controls require a capture or click step")
        # Authorizing a control the candidate filter can never surface is a silent
        # no-op that reads like a working configuration. Require the reviewer to
        # declare it in both places, so the two lists cannot drift apart.
        if set(self.credential_creation_controls) - set(self.control_names):
            raise ValueError("credential creation control is missing from control names")
        # An in-page step must say what it acts ON, or it authorizes nothing and
        # merely removes the navigation candidate — a step that can only stall.
        # The requirement is per verb because the two allow-lists are different
        # authorities: control_names widens what may be CLICKED, allowed_value_refs
        # names the reviewed non-secret values that may be TYPED.
        if self.action not in NAVIGATING_BROWSER_ACTIONS:
            if self.target_url is not None:
                raise ValueError("an in-page browser step cannot carry a target url")
            if self.action == "fill_field" and not self.allowed_value_refs:
                raise ValueError("fill_field needs at least one allowed value reference")
            if self.action in {"click_control", "await_control"} and not self.control_names:
                raise ValueError(f"{self.action} needs at least one reviewed control name")
        return self


class SignupPolicy(_RecipeModel):
    """Reviewed deterministic signup behavior for one browser recipe.

    Signup policy is deliberately narrower than the general browser trace.  It
    authorizes only a specific initial form shape and exact submit label; it never
    grants the model authority to infer a registration flow from page prose.
    """

    flow: SignupFlow
    entry_path_prefixes: tuple[str, ...] = Field(min_length=1, max_length=10)
    entry_submit_labels: tuple[str, ...] = Field(min_length=1, max_length=10)
    entry_submit_implies_legal_acceptance: bool

    @field_validator("entry_path_prefixes")
    @classmethod
    def validate_entry_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        paths = _unique(value, "signup entry paths", 10)
        if any(
            not item.startswith("/")
            or "?" in item
            or "#" in item
            or "//" in item
            or len(item) > 300
            for item in paths
        ):
            raise ValueError("signup entry path must be an absolute path prefix")
        return paths

    @field_validator("entry_submit_labels")
    @classmethod
    def validate_submit_labels(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        labels = _unique(value, "signup submit labels", 10)
        if any(len(item) > 120 for item in labels):
            raise ValueError("signup submit label is too long")
        return labels


class BrowserRecipe(_RecipeModel):
    scope: BrowserRecipeScope
    exact_hosts: tuple[str, ...] = Field(min_length=1, max_length=30)
    identity_provider_hosts: tuple[str, ...] = Field(default=(), max_length=30)
    # Reviewed hosts that only exist on the far side of a successful sign-in: the
    # console the vendor lands you on, or the hosted-auth callback host it bounces
    # through (``*.auth0.com``-style tenants, ``clerk.<vendor>``, a separate
    # ``app.`` origin that the marketing site never links to).
    #
    # A fourth host list rather than more ``exact_hosts`` entries, because
    # ``exact_hosts`` is read by five callers as the answer to "which hosts does
    # this vendor own for PUBLIC research purposes" -- research-result acceptance
    # (ops/you/host_policy.py:117), signup-route scanning
    # (ops/research/signup_agent.py:283), the planner's surface validator
    # (ops/planner/validator.py:133), verification-link acceptance
    # (ops/runs/verification.py:447) and the signup overlay
    # (ops/recipes/signup_overlay.py:120). A post-login console is a place the run
    # goes, not a place a search result may claim to be, and folding the two would
    # quietly widen all five.
    #
    # Exact hosts only (``wildcard=False``): unlike ``static_resource_hosts``, an
    # entry here becomes a TOP-LEVEL navigation destination via
    # ``ops/browser/host_policy.py``, and a wildcard destination is a subdomain
    # takeover away from being an open redirect target.
    post_auth_hosts: tuple[str, ...] = Field(default=(), max_length=30)
    static_resource_hosts: tuple[str, ...] = Field(default=(), max_length=30)
    # Email is a separate trust boundary from browser navigation. Sender domains
    # and magic-link hosts must be reviewed explicitly rather than guessed from
    # the browser allowlist or collapsed into one overly broad pattern set.
    verification_sender_domains: tuple[str, ...] = Field(default=(), max_length=20)
    verification_link_hosts: tuple[str, ...] = Field(default=(), max_length=20)
    sensitive_selectors: tuple[str, ...] = Field(min_length=1, max_length=30)
    signup: SignupPolicy | None = None
    steps: tuple[BrowserStep, ...] = Field(min_length=1, max_length=12)
    success: SuccessPredicate

    @field_validator("exact_hosts")
    @classmethod
    def validate_exact_hosts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            _host(item, "browser host", wildcard=False) for item in _unique(value, "hosts")
        )

    @field_validator("identity_provider_hosts")
    @classmethod
    def validate_idp_hosts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            _host(item, "identity-provider host", wildcard=False)
            for item in _unique(value, "hosts")
        )

    @field_validator("post_auth_hosts")
    @classmethod
    def validate_post_auth_hosts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            _host(item, "post-authentication host", wildcard=False)
            for item in _unique(value, "hosts")
        )

    @field_validator("static_resource_hosts")
    @classmethod
    def validate_static_hosts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            _host(item, "static-resource host", wildcard=True) for item in _unique(value, "hosts")
        )

    @field_validator("verification_sender_domains", "verification_link_hosts")
    @classmethod
    def validate_verification_hosts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            _host(item, "verification host", wildcard=True)
            for item in _unique(value, "verification hosts", 20)
        )

    @field_validator("sensitive_selectors")
    @classmethod
    def validate_selectors(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique(value, "sensitive selectors")

    @model_validator(mode="after")
    def validate_browser(self) -> Self:
        if tuple(step.order for step in self.steps) != tuple(range(1, len(self.steps) + 1)):
            raise ValueError("browser step order must be contiguous")
        if self.scope == "credential_surface" and not self.success.proves_credential_surface():
            raise ValueError("browser success must combine a path and structural label")
        if self.scope == "entry_only" and not self.success.has_positive_condition():
            raise ValueError("entry-only browser success is unprovable")
        # A host may be declared once and in one role. Listing the same host as
        # both a vendor host and a post-auth host is not additive -- it is a
        # reviewer saying two different things about it, and the reader that
        # matters (``exact_hosts`` means "the vendor owns this publicly") would
        # silently win. Refuse it at review time instead of resolving it at
        # runtime.
        overlap = set(self.post_auth_hosts) & (
            set(self.exact_hosts) | set(self.identity_provider_hosts)
        )
        if overlap:
            raise ValueError("post-authentication host is already declared in another host role")
        # The three navigation host lists are unioned into ONE flat pattern list by
        # ``ops/browser/host_policy.py``, and that list is serialized across the
        # browser-service RPC, where both the request model
        # (browser_service/models.py) and the rebuild
        # (``allowed_hosts_from_patterns``) refuse anything longer than
        # ``MAX_ALLOWED_HOST_PATTERNS``. Each field's own ``max_length`` of 30 was
        # a sufficient bound while only ``exact_hosts`` reached navigation; the
        # union is not, so a recipe that validates here could still be refused at
        # session creation with a 422 that names the wire, not the recipe. Counted
        # after de-duplication because the rebuild counts unique patterns too.
        # Imported inside the call: host_policy imports THIS module at its top.
        from ops.browser.host_policy import MAX_ALLOWED_HOST_PATTERNS

        navigation_hosts = {*self.exact_hosts, *self.identity_provider_hosts, *self.post_auth_hosts}
        if len(navigation_hosts) > MAX_ALLOWED_HOST_PATTERNS:
            raise ValueError("browser navigation hosts exceed the serialized allow-list bound")
        # The navigation destinations a step may name. ``post_auth_hosts`` counts
        # because ``ops/browser/host_policy.py`` now unions it into the run's
        # navigation allow-list: a step whose target the boundary permits but the
        # schema refuses would make the field undeclarable for the one flow it
        # exists for (step 2 = "open the console you were redirected into").
        step_target_hosts = frozenset((*self.exact_hosts, *self.post_auth_hosts))
        for step in self.steps:
            if step.target_url is not None:
                host = (urlsplit(step.target_url).hostname or "").casefold()
                if host not in step_target_hosts:
                    raise ValueError("browser step target is outside exact navigation hosts")
        return self


class CredentialField(_RecipeModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{0,99}$")
    label: str = Field(min_length=1, max_length=120)
    kind: CredentialFieldKind
    secret: bool


class CaptureFieldSpec(_RecipeModel):
    """One exact field read by the trusted capture boundary."""

    field_name: str = Field(pattern=r"^[a-z][a-z0-9_]{0,99}$")
    selectors: tuple[str, ...] = Field(min_length=1, max_length=20)
    value_pattern: str = Field(min_length=1, max_length=500)
    source: CaptureSource = "input_value"
    reveal_selector: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def validate_field(self) -> Self:
        _unique(self.selectors, "capture field selectors", 20)
        try:
            re.compile(self.value_pattern)
        except re.error as exc:
            raise ValueError("capture pattern is invalid") from exc
        return self


class CaptureSpec(_RecipeModel):
    mode: CaptureMode
    # Legacy single-field representation. It remains readable for checked-in
    # snapshots while new recipes use ``fields`` for one or more values.
    field_name: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{0,99}$")
    selectors: tuple[str, ...] = Field(default=(), max_length=20)
    value_pattern: str | None = Field(default=None, max_length=500)
    reveal_selector: str | None = Field(default=None, max_length=500)
    fields: tuple[CaptureFieldSpec, ...] = Field(default=(), max_length=20)
    expected_path_prefix: str | None = Field(default=None, max_length=300)
    expected_heading: str | None = Field(default=None, max_length=200)

    @property
    def capture_fields(self) -> tuple[CaptureFieldSpec, ...]:
        if self.fields:
            return self.fields
        if self.field_name and self.selectors and self.value_pattern:
            return (
                CaptureFieldSpec(
                    field_name=self.field_name,
                    selectors=self.selectors,
                    value_pattern=self.value_pattern,
                    reveal_selector=self.reveal_selector,
                ),
            )
        return ()

    @model_validator(mode="after")
    def validate_capture(self) -> Self:
        _unique(self.selectors, "capture selectors", 20)
        legacy = (self.field_name, self.selectors, self.value_pattern, self.reveal_selector)
        common = (self.expected_path_prefix, self.expected_heading)
        if self.mode != "automatic":
            if self.fields or any(legacy) or any(common):
                raise ValueError("non-automatic capture has extra fields")
            return self
        if not all(common):
            raise ValueError("automatic capture page contract is incomplete")
        if self.fields and any(legacy):
            raise ValueError("automatic capture cannot mix legacy and multi-field shapes")
        if not self.fields and not all(legacy[:3]):
            raise ValueError("automatic capture spec is incomplete")
        names = tuple(field.field_name for field in self.capture_fields)
        if len(names) != len(set(names)):
            raise ValueError("automatic capture field names contain duplicates")
        return self


class ValidationPolicy(_RecipeModel):
    endpoint: str
    method: Literal["GET"]
    auth_scheme: ValidationAuthScheme
    credential_field: str = Field(pattern=r"^[a-z][a-z0-9_]{0,99}$")
    header_name: str = Field(min_length=1, max_length=100)
    account_identifier_paths: tuple[str, ...] = Field(default=(), max_length=20)
    # Literal text before the secret for providers whose scheme is neither bare
    # nor ``Bearer`` (for example Klaviyo's ``Klaviyo-API-Key <key>``).
    header_value_prefix: str = Field(default="", max_length=100)
    # Static, non-secret headers a provider requires (for example a revision pin).
    extra_headers: tuple[tuple[str, str], ...] = Field(default=(), max_length=10)
    # The non-secret username field for ``basic_auth`` credential pairs.
    username_field: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{0,99}$")

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        return _https_url(value, "validation endpoint")

    @model_validator(mode="after")
    def validate_policy(self) -> Self:
        for text in (self.header_name, self.header_value_prefix):
            if "\r" in text or "\n" in text:
                raise ValueError("validation header is invalid")
        _unique(self.account_identifier_paths, "account identifier paths", 20)
        if self.auth_scheme == "basic_auth":
            if self.username_field is None:
                raise ValueError("basic validation requires a username field")
            if self.username_field == self.credential_field:
                raise ValueError("basic validation needs distinct username and secret fields")
        elif self.username_field is not None:
            raise ValueError("username field is only valid for basic validation")
        if self.auth_scheme != "api_key_header" and self.header_value_prefix:
            raise ValueError("header value prefix is only valid for api-key validation")
        names = {self.header_name.casefold()}
        for name, value in self.extra_headers:
            if not name or "\r" in name or "\n" in name or "\r" in value or "\n" in value:
                raise ValueError("static validation header is invalid")
            if name.casefold() in names:
                raise ValueError("static validation header collides with the credential header")
            names.add(name.casefold())
        return self


class OutreachSpec(_RecipeModel):
    contact_url: str | None
    contact_email: str | None
    approval_reason: str = Field(min_length=1, max_length=1_000)
    template_id: str = Field(min_length=1, max_length=100)
    sending_policy: SendingPolicy

    @field_validator("contact_url")
    @classmethod
    def validate_contact_url(cls, value: str | None) -> str | None:
        return None if value is None else _https_url(value, "contact URL")

    @field_validator("contact_email")
    @classmethod
    def validate_email(cls, value: str | None) -> str | None:
        if value is not None and ("@" not in value or "\r" in value or "\n" in value):
            raise ValueError("contact email is invalid")
        return value


class AppRecipe(_RecipeModel):
    app_slug: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", max_length=120)
    app_name: str = Field(min_length=1, max_length=200)
    route_kind: RouteKind
    toolkit_slug: str = Field(pattern=r"^[a-z0-9_]+$", max_length=120)
    readiness_tier: ReadinessTier
    evidence_verified_at: str
    evidence_urls: tuple[str, ...] = Field(min_length=1, max_length=20)
    auth_styles: tuple[AuthStyle, ...] = Field(min_length=1, max_length=10)
    urls: VerifiedUrls = Field(default_factory=VerifiedUrls)
    browser: BrowserRecipe | None = None
    credential_fields: tuple[CredentialField, ...] = Field(default=(), max_length=12)
    capture: CaptureSpec
    validation: ValidationPolicy | None = None
    outreach: OutreachSpec | None = None

    @field_validator("evidence_verified_at")
    @classmethod
    def validate_date(cls, value: str) -> str:
        try:
            date.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("evidence date is invalid") from exc
        return value

    @field_validator("evidence_urls")
    @classmethod
    def validate_evidence(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique(tuple(_https_url(item, "evidence URL") for item in value), "evidence URLs")

    @model_validator(mode="after")
    def validate_recipe(self) -> Self:
        if len(self.auth_styles) != len(set(self.auth_styles)):
            raise ValueError("auth styles contain duplicates")
        if len({field.name for field in self.credential_fields}) != len(self.credential_fields):
            raise ValueError("credential field names must be unique")
        if self.route_kind == "managed_auth":
            if (
                self.readiness_tier != "managed_auth_ready"
                or self.capture.mode != "managed_connection"
                or "oauth2" not in self.auth_styles
                or self.browser is not None
                or self.credential_fields
                or self.validation is not None
                or self.outreach is not None
            ):
                raise ValueError("managed-auth contract is invalid")
            return self
        if self.route_kind == "playwright":
            return self._validate_playwright()
        if (
            self.readiness_tier not in {"outreach_ready", "outreach_review_required"}
            or self.capture.mode != "none"
            or self.browser is not None
            or self.credential_fields
            or self.validation is not None
            or self.outreach is None
        ):
            raise ValueError("gated route contract is invalid")
        if self.readiness_tier == "outreach_ready" and not (
            self.outreach.contact_url or self.outreach.contact_email
        ):
            raise ValueError("outreach-ready route needs a contact")
        return self

    def _validate_playwright(self) -> Self:
        if not self.credential_fields or not any(field.secret for field in self.credential_fields):
            raise ValueError("Playwright route needs an owner credential schema")
        if self.outreach is not None or self.urls.login is None or self.browser is None:
            raise ValueError("Playwright route needs a reviewed browser entry")
        login_host = (urlsplit(self.urls.login).hostname or "").casefold()
        first = self.browser.steps[0]
        if login_host not in self.browser.exact_hosts:
            raise ValueError("login URL is outside exact navigation hosts")
        if first.action != "navigate" or first.target_url != self.urls.login:
            raise ValueError("first Playwright step must open the reviewed login URL")
        if self.browser.signup is not None:
            if self.urls.signup is None:
                raise ValueError("signup policy requires a reviewed signup URL")
            signup_url = urlsplit(self.urls.signup)
            signup_host = (signup_url.hostname or "").casefold()
            if signup_host not in self.browser.exact_hosts:
                raise ValueError("signup URL is outside exact navigation hosts")
            matches_entry = False
            for raw_prefix in self.browser.signup.entry_path_prefixes:
                prefix = raw_prefix.rstrip("/") or "/"
                if signup_url.path == prefix or (
                    prefix != "/" and signup_url.path.startswith(f"{prefix}/")
                ):
                    matches_entry = True
                    break
            if not matches_entry:
                raise ValueError("signup URL does not match the reviewed entry path")
        elif self.urls.signup is not None:
            raise ValueError("signup URL requires a reviewed signup policy")
        if self.readiness_tier == "owner_submit_ready":
            if self.capture.mode != "owner_submit" or self.browser.scope != "entry_only":
                raise ValueError("owner-submit route needs a reviewed entry-only policy")
            if self.validation is not None or self.urls.credential_management is not None:
                raise ValueError("owner-submit route must not claim credential automation")
            return self
        if self.readiness_tier != "browser_ready":
            raise ValueError("Playwright readiness is invalid")
        if (
            self.browser.scope != "credential_surface"
            or self.capture.mode != "automatic"
            or self.validation is None
            or self.urls.credential_management is None
        ):
            raise ValueError("browser-ready contract is incomplete")
        field_names = {field.name for field in self.credential_fields}
        capture_fields = self.capture.capture_fields
        captured_names = {field.field_name for field in capture_fields}
        validation_fields = {self.validation.credential_field}
        if self.validation.username_field is not None:
            validation_fields.add(self.validation.username_field)
        capture_selectors = {selector for field in capture_fields for selector in field.selectors}
        if (
            not capture_fields
            or not captured_names <= field_names
            or not validation_fields <= captured_names
            or not capture_selectors <= set(self.browser.sensitive_selectors)
        ):
            raise ValueError("secret boundary is inconsistent")
        return self

    @property
    def browser_ready(self) -> bool:
        return self.readiness_tier == "browser_ready" and self.browser is not None


class AppRecipeCatalog(_RecipeModel):
    schema_version: str
    catalog_id: str = Field(min_length=1, max_length=200)
    selection_source: str = Field(min_length=1, max_length=300)
    # The catalog may grow up to the size of the locked P1 research snapshot (100
    # apps). The exact membership and route of every app is still pinned by the
    # slug tuples below, so growth remains an explicit, reviewed change rather
    # than something a malformed catalog can do implicitly.
    apps: tuple[AppRecipe, ...] = Field(min_length=50, max_length=100)

    @model_validator(mode="after")
    def validate_matrix(self) -> Self:
        if self.schema_version != "1.0":
            raise ValueError("unsupported app recipe schema version")
        slugs = tuple(recipe.app_slug for recipe in self.apps)
        expected = (*MANAGED_AUTH_SLUGS, *PLAYWRIGHT_SLUGS, *GATED_SLUGS)
        if slugs != expected:
            raise ValueError("app recipe catalog does not match the approved matrix")
        expected_routes = {
            **{slug: "managed_auth" for slug in MANAGED_AUTH_SLUGS},
            **{slug: "playwright" for slug in PLAYWRIGHT_SLUGS},
            **{slug: "gated" for slug in GATED_SLUGS},
        }
        if any(recipe.route_kind != expected_routes[recipe.app_slug] for recipe in self.apps):
            raise ValueError("an app is assigned to the wrong approved route")
        return self


def parse_app_recipe_catalog(value: object) -> AppRecipeCatalog:
    """Strictly parse a catalog value without provider I/O."""

    try:
        return AppRecipeCatalog.model_validate(value)
    except ValidationError as exc:
        errors = exc.errors(include_url=False, include_input=False)
        raise AppRecipeCatalogError(str(errors[0].get("msg", "invalid catalog"))) from exc


@lru_cache(maxsize=1)
def load_app_recipe_catalog() -> AppRecipeCatalog:
    """Load the repository-owned recipe catalog."""

    try:
        raw: object = json.loads(_CATALOG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AppRecipeCatalogError("app recipe catalog is unavailable") from exc
    return parse_app_recipe_catalog(raw)


@lru_cache(maxsize=1)
def _recipes_by_slug() -> MappingProxyType[str, AppRecipe]:
    return MappingProxyType({recipe.app_slug: recipe for recipe in load_app_recipe_catalog().apps})


@lru_cache(maxsize=1)
def _recipes_by_name() -> MappingProxyType[str, AppRecipe]:
    return MappingProxyType(
        {recipe.app_name.strip().casefold(): recipe for recipe in load_app_recipe_catalog().apps}
    )


def get_app_recipe(app_slug: str) -> AppRecipe | None:
    """Resolve one canonical app slug, reviewed catalog first.

    A researched signup overlay is consulted only when one has been installed
    for this app, and an overlay is only ever the reviewed recipe with a signup
    route filled in — see :mod:`ops.recipes.signup_overlay` for what it may and
    may not change. Resolving it HERE rather than at each call site is
    deliberate: the planner validator, the host policy, the signup policy and
    the driver all read the recipe through this function, so they cannot
    disagree about which one is in force.

    Imported inside the call because the overlay module imports this one.
    """

    reviewed = _recipes_by_slug().get(app_slug.strip().casefold())
    if reviewed is None:
        return None
    from ops.recipes.signup_overlay import shared_signup_overlays

    return shared_signup_overlays().overlay_for(reviewed) or reviewed


def get_app_recipe_for_name(app_name: str) -> AppRecipe | None:
    """Resolve the catalog's reviewed display name without inventing a slug.

    This matters for names such as ``Monday.com`` whose punctuation is not part
    of the approved canonical slug (``monday``).

    The name lookup only finds which reviewed recipe is meant; the recipe itself
    is returned by :func:`get_app_recipe` so a researched signup overlay applies
    here too. Callers reach the catalog by whichever identifier they hold —
    ``CanonicalRuntime.recipe_for_request`` tries the display name first — and a
    recipe that carried a signup route under one identifier but not the other
    would make the run's signup readiness depend on how the app was named.
    """

    reviewed = _recipes_by_name().get(app_name.strip().casefold())
    if reviewed is None:
        return None
    return get_app_recipe(reviewed.app_slug)


def recipes_for_route(route_kind: RouteKind) -> tuple[AppRecipe, ...]:
    """Return recipes for one canonical route."""

    if route_kind not in {"managed_auth", "playwright", "gated"}:
        raise ValueError("unknown app recipe route")
    return tuple(
        recipe for recipe in load_app_recipe_catalog().apps if recipe.route_kind == route_kind
    )


def recipe_to_operational_research(
    recipe: AppRecipe,
    app_name: str | None = None,
) -> OperationalResearch:
    """Project a recipe onto the existing locked-P1 research boundary."""

    from ops.core.models import OperationalResearch
    from ops.research.p1_adapter import P1LookupNotFound, lookup_p1_record, to_operational_research

    lookup = lookup_p1_record(recipe.app_slug)
    if isinstance(lookup, P1LookupNotFound):
        raise AppRecipeCatalogError(f"{recipe.app_slug} is absent from the locked P1 snapshot")
    base = to_operational_research(lookup.record)
    if recipe.route_kind in {"managed_auth", "playwright"}:
        access_route = "self_serve"
    elif recipe.outreach is not None and (
        recipe.outreach.contact_url or recipe.outreach.contact_email
    ):
        access_route = "partner_gated"
    else:
        access_route = "approval_required"
    contact_url = recipe.urls.contact
    contact_email: str | None = None
    if recipe.outreach is not None:
        contact_url = recipe.outreach.contact_url or contact_url
        contact_email = recipe.outreach.contact_email
    # The research boundary refuses a fragment on an operational URL
    # (``ops/core/models.validate_operational_url``), and a recipe may now carry
    # one. The fragment is exactly the part the server never sees, so dropping it
    # here loses nothing the research record is for -- it names an entry POINT --
    # while the recipe itself keeps the hash route the browser actually needs.
    reviewed_urls: dict[str, str | None] = {
        "developer_portal_url": _without_fragment(recipe.urls.developer_portal),
        "signup_url": _without_fragment(recipe.urls.signup),
        "login_url": _without_fragment(recipe.urls.login),
        "credential_management_url": _without_fragment(recipe.urls.credential_management),
        "contact_url": _without_fragment(contact_url),
    }
    operational_url_claims = [
        {"field": field, "url": url, "source_url": url}
        for field, url in reviewed_urls.items()
        if url is not None
    ]
    payload = base.model_dump(mode="python")
    payload.update(
        {
            "app_name": app_name or recipe.app_name,
            "credential_fields": [field.name for field in recipe.credential_fields],
            "developer_portal_url": reviewed_urls["developer_portal_url"],
            "signup_url": reviewed_urls["signup_url"],
            "login_url": reviewed_urls["login_url"],
            "credential_management_url": reviewed_urls["credential_management_url"],
            "operational_url_claims": operational_url_claims,
            "access_route": access_route,
            "production_approval_required": recipe.route_kind == "gated",
            "contact_email": contact_email,
            "contact_url": reviewed_urls["contact_url"],
            "evidence_urls": list(dict.fromkeys([*base.evidence_urls, *recipe.evidence_urls])),
        }
    )
    return OperationalResearch.model_validate(payload)


def get_app_browser_trace(app_slug: str) -> BrowserApiTrace | None:
    """Project the reviewed browser portion of one recipe for the worker loop.

    ``BrowserApiTrace`` remains a narrow execution DTO while ``AppRecipe`` is the
    only policy source for new runs.  The credential target is the trace goal for
    a fully reviewed recipe; entry-only recipes stop at their public login URL.
    """

    recipe = get_app_recipe(app_slug)
    return recipe_to_browser_trace(recipe) if recipe is not None else None


def recipe_predicate(value: SuccessPredicate) -> CheckpointPredicate:
    """Convert one reviewed recipe predicate into the execution DTO's predicate."""

    from ops.browser.api_trace_catalog import CheckpointPredicate

    return CheckpointPredicate(
        url_path_contains=value.url_path_contains,
        title_contains=value.title_contains,
        visible_text_contains=value.visible_text_contains,
        required_accessible_names=value.required_accessible_names,
        forbidden_text=value.forbidden_text,
    )


def recipe_to_browser_trace(recipe: AppRecipe) -> BrowserApiTrace | None:
    """Project one already-bound recipe without consulting the live catalog."""

    from ops.browser.api_trace_catalog import BrowserApiTrace, BrowserApiTraceStep

    if recipe.route_kind != "playwright" or recipe.browser is None:
        return None

    browser = recipe.browser
    start_url = (
        recipe.urls.credential_management
        if browser.scope == "credential_surface"
        else recipe.urls.login
    )
    if start_url is None:  # guarded by AppRecipe validation
        return None

    predicate = recipe_predicate
    relevant_steps = browser.steps[1:] if browser.scope == "credential_surface" else browser.steps
    checkpoints = tuple(
        BrowserApiTraceStep(
            order=index,
            instruction=step.instruction,
            expected_signals=tuple(
                dict.fromkeys(
                    (
                        *step.completion.url_path_contains,
                        *step.completion.title_contains,
                        *step.completion.visible_text_contains,
                        *step.completion.required_accessible_names,
                        # Reviewed control labels widen the candidate filter only;
                        # they are absent from `completion` above, so they never
                        # become a condition for the step being finished.
                        *step.control_names,
                    )
                )
            )
            or (step.instruction,),
            completion=predicate(step.completion),
            allowed_value_refs=step.allowed_value_refs,
            credential_creation_controls=step.credential_creation_controls,
            # The step's reviewed destination, which used to stop here. Every
            # three-step recipe already names its API-settings page on step 2 and
            # the executing loop never saw it, so the one page the run exists to
            # reach was not among the places it was allowed to go. The host was
            # checked against ``exact_hosts`` when the recipe was validated, and
            # ``navigation_allowed`` checks it again before and after the move.
            target_url=step.target_url,
            navigates=step.action in NAVIGATING_BROWSER_ACTIONS,
            # Recipe HITL gates describe conditions that trigger a pause; they are
            # not unconditional manual checkpoints. The deterministic gate detector
            # enforces them when they are actually present on the page.
            requires_hitl=False,
        )
        for index, step in enumerate(relevant_steps, start=1)
    )
    success = predicate(browser.success)
    success_signals = tuple(
        dict.fromkeys(
            (
                *browser.success.url_path_contains,
                *browser.success.title_contains,
                *browser.success.visible_text_contains,
                *browser.success.required_accessible_names,
            )
        )
    )
    return BrowserApiTrace(
        position=PLAYWRIGHT_SLUGS.index(recipe.app_slug) + 1,
        app_slug=recipe.app_slug,
        app_name=recipe.app_name,
        access_model="self_serve",
        start_url=start_url,
        evidence_url=recipe.evidence_urls[0],
        credential_goal=browser.steps[-1].instruction,
        checkpoints=checkpoints,
        success_signals=success_signals or ("reviewed route predicate",),
        success=success,
    )


def get_app_capture_spec(app_slug: str) -> CredentialCaptureSpec | None:
    """Return an automatic capture DTO only when the recipe authorizes it."""

    recipe = get_app_recipe(app_slug)
    return recipe_to_capture_spec(recipe) if recipe is not None else None


def recipe_to_capture_spec(recipe: AppRecipe) -> CredentialCaptureSpec | None:
    """Project the immutable recipe into a code-owned capture contract."""

    from ops.credentials.capture_specs import (
        CredentialCaptureFieldSpec,
        CredentialCaptureSpec,
    )

    fields = recipe.capture.capture_fields
    if (
        recipe.route_kind != "playwright"
        or recipe.capture.mode != "automatic"
        or recipe.urls.credential_management is None
        or not fields
    ):
        return None
    hostname = (urlsplit(recipe.urls.credential_management).hostname or "").casefold()
    if not hostname:  # guarded by URL validation
        return None
    projected = tuple(
        CredentialCaptureFieldSpec(
            field_kind=field.field_name,
            value_pattern=field.value_pattern,
            selectors=field.selectors,
            source=field.source,
            reveal_selector=field.reveal_selector,
        )
        for field in fields
    )
    # Populate the legacy properties only for a single field so old direct
    # callers remain source-compatible. Execution consumes ``capture_fields``.
    only = projected[0] if len(projected) == 1 else None
    return CredentialCaptureSpec(
        app_slug=recipe.app_slug,
        url=recipe.urls.credential_management,
        vendor_domain=hostname,
        field_kind=(only.field_kind if only is not None else None),
        value_pattern=(only.value_pattern if only is not None else None),
        selectors=(only.selectors if only is not None else ()),
        expected_path_prefix=recipe.capture.expected_path_prefix,
        expected_heading=recipe.capture.expected_heading,
        reveal_selector=(only.reveal_selector if only is not None else None),
        fields=projected,
    )


def get_app_validation_policy(app_slug: str) -> CredentialValidationPolicy | None:
    """Return the recipe-owned read-only validation policy for one app."""

    recipe = get_app_recipe(app_slug)
    return recipe_to_validation_policy(recipe) if recipe is not None else None


def recipe_to_validation_policy(recipe: AppRecipe) -> CredentialValidationPolicy | None:
    """Project read-only validation policy from an immutable run recipe."""

    from ops.credentials.validator import CredentialValidationPolicy

    if recipe.validation is None:
        return None
    validation = recipe.validation
    return CredentialValidationPolicy(
        app_slug=recipe.app_slug,
        allowed_endpoints=(validation.endpoint,),
        auth_scheme=validation.auth_scheme,
        credential_field=validation.credential_field,
        header_name=validation.header_name,
        account_identifier_paths=validation.account_identifier_paths,
        header_value_prefix=validation.header_value_prefix,
        extra_headers=validation.extra_headers,
        username_field=validation.username_field,
    )


__all__ = [
    "AppRecipe",
    "AppRecipeCatalog",
    "AppRecipeCatalogError",
    "AuthStyle",
    "BrowserRecipe",
    "BrowserRecipeScope",
    "BrowserStep",
    "CaptureMode",
    "CaptureSource",
    "CaptureFieldSpec",
    "CaptureSpec",
    "CredentialField",
    "CredentialFieldKind",
    "GATED_SLUGS",
    "MANAGED_AUTH_SLUGS",
    "NAVIGATING_BROWSER_ACTIONS",
    "OutreachSpec",
    "PLAYWRIGHT_SLUGS",
    "ReadinessTier",
    "RouteKind",
    "SuccessPredicate",
    "ValidationPolicy",
    "VerifiedUrls",
    "get_app_recipe",
    "get_app_recipe_for_name",
    "get_app_browser_trace",
    "get_app_capture_spec",
    "get_app_validation_policy",
    "load_app_recipe_catalog",
    "parse_app_recipe_catalog",
    "recipe_predicate",
    "recipe_to_browser_trace",
    "recipe_to_capture_spec",
    "recipe_to_operational_research",
    "recipe_to_validation_policy",
    "recipes_for_route",
]
