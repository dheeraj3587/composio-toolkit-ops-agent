"""The per-run immutable provider profile: a runtime analogue of a reviewed recipe.

A provider the repo has never seen has no checked-in ``AppRecipe``, so nothing
declares which host its signup page lives on or which flow mints a credential.
``ProviderProfile`` is the runtime stand-in. It is built once per run from
corroborated research, content-addressed, and then never mutated, so every later
decision in the run is attributable to one immutable artifact rather than to
whatever a page happened to say at the time.

The load-bearing invariant is domain confinement, and it is enforced at
construction rather than at every call site: a profile refuses any URL that is
not HTTPS or whose host resolves to a registrable domain other than the single
primary domain the profile declares. ``ops.browser.host_policy.registrable_domain``
is the only authority consulted for that, so this module and the reviewed browser
policy can never disagree about what a vendor owns. A consumer holding a
``ProviderProfile`` therefore never has to re-check where its URLs point.

Auxiliary hosts are additive and typed (identity provider, static assets, email
link host). They are deliberately not a second primary domain: the profile
declares exactly one, and an auxiliary entry that restates it is refused.

``allowed_hosts()`` closes the loop: it is a projection rather than a stored
field, and it invokes the browser host-policy module's explicit committed-profile
authority so the resulting wildcard is exactly the single corroborated domain.
It never merges those hosts with the app's static recipe policy.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from typing import Literal, get_args
from urllib.parse import urlsplit, urlunsplit

# Aliased on import because ``ProviderProfile`` has a field of the same name, and
# because the provenance matters: this is the same helper the reviewed browser
# host policy uses, including its conservative handling of ``co.uk``-style public
# suffixes. Deriving the profile's domain rule from a second implementation would
# let the two boundaries drift apart.
from ops.browser.host_policy import (
    BrowserAllowedHosts,
    BrowserPolicyInactiveError,
    build_browser_allowed_hosts,
    evaluate_navigation,
)
from ops.browser.host_policy import registrable_domain as resolve_registrable_domain
from ops.core.models import OperationalResearch, validate_https_url

# The access routes for which a browser session may exist at all. Onboarding is
# self-serve by definition — the run signs itself up — so that is the default;
# ``hybrid`` is admitted for a provider whose self-serve path exists alongside a
# sales-assisted one. Every other ``AccessRoute`` member is refused by
# ``build_browser_allowed_hosts`` before any policy is resolved.
BrowserAccessRoute = Literal["self_serve", "hybrid"]

ProfileField = Literal[
    "registrable_domain",
    "developer_portal_url",
    "signup_url",
    "login_url",
    "developer_docs_url",
    "developer_app_flow",
    "oauth_flow",
    "api_key_flow",
    "pat_flow",
    "approval_requirement",
    "billing_requirement",
]

ApprovalRequirement = Literal["none", "manual_review", "invite_only", "unknown"]
BillingRequirement = Literal["none", "card_required", "paid_plan_required", "unknown"]
FlowKind = Literal["developer_app", "oauth", "api_key", "pat", "client_credentials"]
AuxiliaryHostKind = Literal["identity_provider", "static_assets", "email_link_host"]

CredentialKind = Literal[
    "oauth_client_id",
    "oauth_client_secret",
    "api_key",
    "personal_access_token",
    "client_credentials_pair",
]

# Runtime vocabularies derived from the Literal aliases above rather than
# restated, so a member added to one is never missing from the other. Research
# output is untrusted input, so these values are checked at construction even
# though the annotations already constrain in-repo callers.
APPROVAL_REQUIREMENTS: frozenset[str] = frozenset(get_args(ApprovalRequirement))
BILLING_REQUIREMENTS: frozenset[str] = frozenset(get_args(BillingRequirement))
AUXILIARY_HOST_KINDS: frozenset[str] = frozenset(get_args(AuxiliaryHostKind))

# A SHA-256 hex digest of the cited excerpt: fixed width, so a claim cannot cite
# a truncated or invented digest.
SOURCE_DIGEST_LENGTH = 64
MAX_FLOW_STEPS = 8
MAX_FLOW_STEP_CHARACTERS = 200

_APP_SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


@dataclass(frozen=True, slots=True)
class FieldEvidence:
    """Why one profile field is believed, and how strongly.

    ``source_url`` must be a document the builder actually fetched, and
    ``source_digest`` is the sha256 of that document's bounded excerpt, so a claim
    cannot cite a page that was never read.
    """

    field: ProfileField
    value: str  # the claimed URL / domain / enum value
    source_url: str  # https, from EvidenceDocument.source_url
    source_digest: str  # sha256 hex of EvidenceDocument.relevant_text
    adapters: tuple[str, ...]  # discovery adapters that surfaced source_url
    corroborations: int  # distinct source_digests supporting `value`
    confidence: float  # 0.0 .. 1.0
    extracted_at: str  # ISO-8601 UTC; excluded from the digest

    def __post_init__(self) -> None:
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("field evidence confidence is out of range")
        if self.corroborations < 1:
            raise ValueError("field evidence requires at least one corroboration")
        if len(self.source_digest) != SOURCE_DIGEST_LENGTH:
            raise ValueError("field evidence requires a sha256 source digest")


@dataclass(frozen=True, slots=True)
class AuxiliaryHost:
    """An additive, typed non-primary host. Never a second primary domain."""

    host: str
    kind: AuxiliaryHostKind
    source_digest: str


@dataclass(frozen=True, slots=True)
class FlowSpec:
    """One credential-producing path through the provider's own site."""

    kind: FlowKind
    supported: bool
    entry_url: str | None  # https, inside registrable_domain
    steps: tuple[str, ...] = ()  # <= 8 items, <= 200 chars, non-secret
    produces: tuple[CredentialKind, ...] = ()
    requires_approval: bool = False
    requires_billing: bool = False
    evidence: tuple[FieldEvidence, ...] = ()

    def __post_init__(self) -> None:
        if self.supported and not self.entry_url:
            raise ValueError("a supported flow requires an entry url")
        if len(self.steps) > MAX_FLOW_STEPS or any(
            len(step) > MAX_FLOW_STEP_CHARACTERS for step in self.steps
        ):
            raise ValueError("flow steps exceed their bound")


@dataclass(frozen=True, slots=True)
class ProviderProfile:
    """The runtime analogue of a reviewed recipe: immutable, digested, per-run.

    INVARIANT: every https URL on this object resolves to ``registrable_domain``
    via ``ops.browser.host_policy.registrable_domain``. Construction enforces it,
    so no consumer has to re-check.
    """

    run_id: str
    provider_name: str
    app_slug: str  # ^[a-z0-9]+(?:-[a-z0-9]+)*$
    registrable_domain: str
    auxiliary_hosts: tuple[AuxiliaryHost, ...]
    developer_portal_url: str | None
    signup_url: str | None
    login_url: str | None
    developer_docs_url: str | None
    developer_app_flow: FlowSpec
    oauth_flow: FlowSpec
    api_key_flow: FlowSpec
    pat_flow: FlowSpec
    approval_requirement: ApprovalRequirement
    billing_requirement: BillingRequirement
    evidence: tuple[FieldEvidence, ...]
    confidence: float  # min() over required-field evidence
    adapters_engaged: tuple[str, ...]  # excluded from the digest
    built_at: str  # excluded from the digest
    profile_digest: str = ""  # set by build; 64 hex

    def __post_init__(self) -> None:
        if _APP_SLUG.fullmatch(self.app_slug) is None:
            raise ValueError("provider profile requires a canonical app slug")
        # Exactly one primary registrable domain: the stored value must already BE
        # the registrable form of itself. That refuses a host masquerading as a
        # domain (``app.provider.com``) and an unnormalized one (``Provider.com.``),
        # either of which would make "the profile's domain" mean two things.
        if resolve_registrable_domain(self.registrable_domain) != self.registrable_domain:
            raise ValueError("provider profile requires exactly one canonical registrable domain")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("provider profile confidence is out of range")
        if self.profile_digest and len(self.profile_digest) != SOURCE_DIGEST_LENGTH:
            raise ValueError("provider profile digest must be a sha256 hex digest")
        if self.approval_requirement not in APPROVAL_REQUIREMENTS:
            raise ValueError("provider profile approval requirement is outside the vocabulary")
        if self.billing_requirement not in BILLING_REQUIREMENTS:
            raise ValueError("provider profile billing requirement is outside the vocabulary")
        for auxiliary in self.auxiliary_hosts:
            _require_typed_auxiliary_host(auxiliary, primary_domain=self.registrable_domain)
        for name, url in self._declared_urls():
            _require_admitted_url(url, field=name, domain=self.registrable_domain)

    def flows(self) -> tuple[FlowSpec, ...]:
        """The declared credential-producing flows, in a stable field order."""

        return (self.developer_app_flow, self.oauth_flow, self.api_key_flow, self.pat_flow)

    def operational_urls(self) -> tuple[str, ...]:
        """Every https URL this profile authorizes the browser to visit."""

        return tuple(dict.fromkeys(url for _, url in self._declared_urls()))

    def allowed_hosts(
        self,
        *,
        access_route: BrowserAccessRoute = "self_serve",
    ) -> BrowserAllowedHosts:
        """Derive the run allow-list. Narrowing only — never widens policy.

        PRE:  the profile is committed, so its URLs already resolve to
              ``registrable_domain``.
        POST: ``vendor_wildcard_domains == (self.registrable_domain,)``, every
              auxiliary host appears in ``exact_hosts`` and nowhere else, and
              every URL in ``operational_urls()`` is admitted by
              ``evaluate_navigation`` against the returned allow-list.
        RAISES: ``BrowserPolicyInactiveError`` rather than returning a widened or
              substituted allow-list.

        The derivation is delegated to ``build_browser_allowed_hosts``, which
        reaches ``discovered_policy_from_research`` — deliberately the only code
        in the repo that turns a URL into a host. This projection supplies an
        ``OperationalResearch`` view of the profile and then narrows the result;
        it never parses a host itself, so the profile boundary and the reviewed
        browser boundary cannot drift apart about who owns a domain.

        The explicit ``profile_authority`` branch prevents the checked-in recipe
        from being mixed into this projection. A resolved domain different from
        the profile's own single domain is refused, as is any declared URL the
        derived list would not admit; either result means the construction
        invariant was weakened.
        """

        resolved = build_browser_allowed_hosts(
            self.app_slug,
            self._as_operational_research(access_route=access_route),
            access_route=access_route,
            allow_domain_discovery=True,
            profile_authority=True,
        )
        if resolved.vendor_wildcard_domains != (self.registrable_domain,):
            raise BrowserPolicyInactiveError(self.app_slug, "profile_domain_mismatch")
        allowed = BrowserAllowedHosts(
            app_slug=self.app_slug,
            # Auxiliary hosts are additive EXACT entries only. Folding here is
            # what makes ``*.provider.com`` cover ``cdn.provider.com`` without
            # ``login.okta.com`` ever gaining subdomains of its own.
            exact_hosts=tuple(
                dict.fromkeys(
                    (
                        *resolved.exact_hosts,
                        *(_folded_host(auxiliary.host) for auxiliary in self.auxiliary_hosts),
                    )
                )
            ),
            vendor_wildcard_domains=resolved.vendor_wildcard_domains,
        )
        # Only four of the profile's up-to-eight declared URLs reach the
        # derivation (the research contract has four operational URL slots), so
        # completeness is asserted here against the fail-closed evaluator rather
        # than assumed from the four that were read.
        for url in self.operational_urls():
            if not evaluate_navigation(url, allowed).allowed:
                raise BrowserPolicyInactiveError(self.app_slug, "discovery_domain_unproven")
        return allowed

    def _as_operational_research(
        self,
        *,
        access_route: BrowserAccessRoute,
    ) -> OperationalResearch:
        """Project the profile onto the research contract the host policy reads.

        Only the four operational URL fields
        ``discovered_policy_from_research`` consults carry meaning; the remaining
        fields exist to satisfy the contract and are deliberately empty, because
        a profile makes no claim about API shape, scopes, or contacts. Passing the
        profile's real URLs (rather than just its domain) keeps the existing
        single-domain agreement check load-bearing: were the construction
        invariant ever weakened, the URLs would disagree and the derivation would
        fail closed instead of inventing an allow-list.

        A flow's entry URL is mapped onto ``credential_management_url`` because
        that is what it is — the page where a credential is viewed or created.
        """

        flow_entry_urls = tuple(
            flow.entry_url for flow in self.flows() if flow.entry_url is not None
        )
        candidates: dict[str, str | None] = {
            "developer_portal_url": self.developer_portal_url,
            "signup_url": self.signup_url,
            "login_url": self.login_url,
            "credential_management_url": flow_entry_urls[0] if flow_entry_urls else None,
        }
        if not any(candidates.values()):
            # A profile may legitimately declare no URL at all, and its
            # registrable domain is itself corroborated evidence (it carries its
            # own ``FieldEvidence``). Naming the apex keeps the projection total
            # without widening it: the domain derived is the one already declared.
            candidates["developer_portal_url"] = f"https://{self.registrable_domain}/"
        return OperationalResearch(
            # Unread by the derivation, but the contract bounds it, so the slug —
            # which construction already validated — is the safe fallback.
            app_name=self.provider_name.strip()[:200] or self.app_slug,
            app_slug=self.app_slug,
            api_available=None,
            api_type="",
            api_base_url=None,
            auth_methods=[],
            authorization_url=None,
            token_url=None,
            credential_fields=[],
            scopes=[],
            developer_portal_url=_entry_point_view(candidates["developer_portal_url"]),
            signup_url=_entry_point_view(candidates["signup_url"]),
            login_url=_entry_point_view(candidates["login_url"]),
            credential_management_url=_entry_point_view(candidates["credential_management_url"]),
            access_route=access_route,
            production_approval_required=None,
            contact_email=None,
            contact_url=None,
            evidence_urls=list(self.operational_urls()),
            confidence=self.confidence,
        )

    def _declared_urls(self) -> tuple[tuple[str, str], ...]:
        """Named URL declarations, so validation and projection cannot diverge."""

        declared: list[tuple[str, str]] = []
        for name, value in (
            ("developer_portal_url", self.developer_portal_url),
            ("signup_url", self.signup_url),
            ("login_url", self.login_url),
            ("developer_docs_url", self.developer_docs_url),
        ):
            if value is not None:
                declared.append((name, value))
        for flow in self.flows():
            if flow.entry_url is not None:
                declared.append((f"{flow.kind} flow entry url", flow.entry_url))
        return tuple(declared)


def compute_profile_digest(profile: ProviderProfile) -> str:
    """Content-address a profile deterministically.

    PRE:  profile fields are populated; ``profile_digest`` may be empty.
    POST: sha256 hex over canonical JSON of the profile body with ``run_id``,
          ``built_at``, ``adapters_engaged``, ``profile_digest`` and every
          ``FieldEvidence.extracted_at`` removed.

    The exclusions are exactly the fields that differ between two runs which
    reached identical conclusions about the provider, which is what makes the
    digest a content address rather than a per-run nonce: "attributable to this
    profile" stays a stable claim across runs. ``profile_digest`` itself is
    excluded so the digest can be stored on the object it addresses without the
    computation depending on its own output. Everything else is body, so a
    different signup URL, a different flow, or a different citation is a
    different profile.
    """

    return hashlib.sha256(canonical_profile_body_json(profile).encode("utf-8")).hexdigest()


def canonical_profile_body_json(profile: ProviderProfile) -> str:
    """The exact bytes the content address is computed over.

    Exposed because the profile store persists this string as the profile's
    immutable body: "a different body under an existing digest" is then a string
    comparison against the same serialization the digest was taken of, rather
    than a second, drifting notion of what a profile body is.
    """

    return json.dumps(
        _canonical_digest_body(profile),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


# Digest exclusions keyed by the type that declares them, not by bare field name:
# ``extracted_at`` must be stripped from every ``FieldEvidence`` wherever it is
# nested (profile-level evidence and each ``FlowSpec.evidence``), while a
# same-named field added to some other type must not be dropped silently.
_DIGEST_EXCLUDED_FIELDS: Mapping[type[object], frozenset[str]] = {
    ProviderProfile: frozenset({"run_id", "built_at", "adapters_engaged", "profile_digest"}),
    FieldEvidence: frozenset({"extracted_at"}),
}


def _canonical_digest_body(value: object) -> object:
    """Project a profile into JSON-canonicalizable primitives, minus the exclusions.

    Nested dataclasses become mappings keyed by declared field name, so the
    caller's ``sort_keys`` fixes key order independently of declaration order and
    reordering a field in the class cannot change an existing digest. Sequence
    order is preserved because it is body: reordered flow steps describe a
    different flow.
    """

    if is_dataclass(value) and not isinstance(value, type):
        excluded = _DIGEST_EXCLUDED_FIELDS.get(type(value), frozenset())
        return {
            field.name: _canonical_digest_body(getattr(value, field.name))
            for field in fields(value)
            if field.name not in excluded
        }
    if isinstance(value, (tuple, list)):
        return [_canonical_digest_body(item) for item in value]
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    # Reached only if a profile field gains a type this canonical form does not
    # define. Failing loudly beats digesting an unstable ``repr()`` and silently
    # changing every content address.
    raise TypeError(f"profile field type is not canonicalizable: {type(value).__name__}")


def _folded_host(host: str) -> str:
    """Fold a host to its allow-list comparison form: lower case, no trailing dot.

    The same folding ``ops.browser.host_policy.host_matches_patterns`` applies to
    the host it is checking, so an allow-list entry and a navigation target are
    compared in one form. ``rstrip`` cannot remove more than the one trailing dot
    a host may carry, because a host with two would have an empty label and
    ``registrable_domain`` refuses it.
    """

    return host.strip().rstrip(".").casefold()


def _entry_point_view(url: str | None) -> str | None:
    """Project a declared URL onto the research contract's entry-point shape.

    The contract refuses a query or fragment on an operational URL, because such
    a field must name a stable page rather than a live session artifact. Neither
    part participates in host derivation, so dropping them changes nothing the
    allow-list depends on. This rewrites a URL to a URL and never resolves a host,
    which is what keeps ``discovered_policy_from_research`` the only URL-to-host
    converter.
    """

    if url is None:
        return None
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _require_admitted_url(value: str, *, field: str, domain: str) -> None:
    """Refuse a URL that is not https or that points outside the profile's domain.

    The host is compared through ``resolve_registrable_domain``, which folds case
    and strips trailing dots, so ``https://APP.Provider.com./login`` is admitted
    for ``provider.com`` while ``https://provider.com.evil.io/login`` is not.
    """

    try:
        validate_https_url(value)
    except ValueError as exc:
        raise ValueError(f"profile {field} must be an absolute https url") from exc
    hostname = urlsplit(value).hostname or ""
    if resolve_registrable_domain(hostname) != domain:
        raise ValueError(f"profile {field} resolves outside the profile registrable domain")


def _require_typed_auxiliary_host(auxiliary: AuxiliaryHost, *, primary_domain: str) -> None:
    """Refuse an untyped, malformed, or primary-restating auxiliary host."""

    if auxiliary.kind not in AUXILIARY_HOST_KINDS:
        raise ValueError("auxiliary host kind is outside the typed vocabulary")
    if len(auxiliary.source_digest) != SOURCE_DIGEST_LENGTH:
        raise ValueError("auxiliary host requires a sha256 source digest")
    host = _folded_host(auxiliary.host)
    if resolve_registrable_domain(host) is None:
        raise ValueError("auxiliary host must be a resolvable hostname")
    if host == primary_domain:
        # An auxiliary entry naming the primary domain is either redundant or an
        # attempt to declare a second primary; both are refused so "exactly one
        # primary registrable domain" stays true by construction.
        raise ValueError("auxiliary host cannot restate the primary registrable domain")


__all__ = [
    "APPROVAL_REQUIREMENTS",
    "AUXILIARY_HOST_KINDS",
    "BILLING_REQUIREMENTS",
    "MAX_FLOW_STEPS",
    "MAX_FLOW_STEP_CHARACTERS",
    "SOURCE_DIGEST_LENGTH",
    "ApprovalRequirement",
    "AuxiliaryHost",
    "AuxiliaryHostKind",
    "BillingRequirement",
    "BrowserAccessRoute",
    "CredentialKind",
    "FieldEvidence",
    "FlowKind",
    "FlowSpec",
    "ProfileField",
    "ProviderProfile",
    "canonical_profile_body_json",
    "compute_profile_digest",
]
