"""The research ports the per-run provider profile is built from.

A brand-new provider has no reviewed recipe, so the only description of its
signup page, login page, and credential-minting flows is whatever research
produces. This module owns the boundary that research arrives through: three
``typing.Protocol`` ports — discovery, fetch, extraction — plus
:class:`ProfileClaim`, the single untrusted fact an extractor is allowed to
return.

Two of the three ports are deliberately not new shapes.
    ``ops.research.operational_research`` already runs adapters behind
    ``EvidenceDiscovery.discover`` and ``EvidenceContentFetcherLike.fetch_many``
    (Perplexity search, the You.com contents fetcher, the guarded HTTP fetcher).
    :class:`ProfileDiscovery` and :class:`ProfileEvidenceFetcher` restate those
    two signatures exactly, so every one of those adapters satisfies the profile
    ports structurally, with no wrapper. That matters beyond convenience: a
    wrapper is where a bound gets dropped — the redirect limit, the response-size
    limit, the excerpt truncation, the host policy all live inside those adapters,
    and an adapting shim is free to forget one. ``_reused_ports_are_verbatim``
    below turns "verbatim" into a claim the type checker rejects if it stops being
    true, and ``tests/test_provider_profile_builder_ports.py`` compares the
    signatures member by member.

:class:`ProfileExtractor` is the one genuinely additive port.
    ``EvidenceExtractor.extract`` returns an ``OperationalResearch`` and requires
    a ``p1_record`` — a reviewed-catalog row that a provider the repo has never
    seen does not have. A profile also needs per-field provenance that
    ``OperationalResearch`` does not carry beyond ``operational_url_claims``,
    because ``FieldEvidence`` has to name the document each value came from. So
    extraction gets a new signature keyed on the provider name and the fetched
    documents alone, returning claims rather than a research object.

Discovery reports emptiness as a value, never as an exception.
    ``discover`` returning ``()`` is a normal result: Requirement 2.3 and 2.4
    require one failing or silent adapter to degrade the run rather than fail it,
    and only *every* adapter coming back empty is terminal
    (``research_adapters_unavailable``). Stating that in the port keeps the
    builder's guard honest — it still catches exceptions, because a port cannot
    force an adapter to behave, but an adapter that honors this contract makes
    "no candidates" distinguishable from "adapter broke", and those two facts get
    recorded differently.

Adapter identity is supplied at registration, not demanded by the port.
    ``FieldEvidence.adapters`` records which adapters surfaced a source URL, so
    the builder needs a name per adapter. Requiring a ``name`` attribute on
    :class:`ProfileDiscovery` would immediately disqualify
    ``PerplexitySearchDiscovery``, which has none — the verbatim reuse above
    would be lost to a one-attribute mismatch. The base port therefore stays
    method-only and :class:`NamedProfileDiscovery` is the opt-in narrowing for an
    adapter that carries its own identifier.

The operator hint URL does not travel through the port either. Requirement 1.11
makes a hint one candidate source contributing at most one corroboration, which
is bookkeeping the builder does when it seeds its candidate list; pushing the
hint into ``discover`` would change the reused signature to buy nothing.

``build_profile`` is the other half of the module: discovery, bounded fetch,
re-verification of every claim against the document it cites, corroboration
counting over distinct cited-excerpt digests, resolution of exactly one
registrable domain, and the commit of one immutable profile — or
:class:`ResearchInconclusive`, which blocks the run before anything can cost
anything.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final, Literal, Protocol, cast, runtime_checkable
from urllib.parse import urlsplit

from ops.browser.host_policy import registrable_domain as resolve_registrable_domain
from ops.core.config import Settings
from ops.core.models import validate_https_url
from ops.onboarding.phase import OnboardingReasonCode
from ops.providers.errors import ConfigurationRequiredError, PhaseUnavailableError
from ops.providers.profile import (
    APPROVAL_REQUIREMENTS,
    BILLING_REQUIREMENTS,
    ApprovalRequirement,
    BillingRequirement,
    CredentialKind,
    FieldEvidence,
    FlowKind,
    FlowSpec,
    ProfileField,
    ProviderProfile,
    compute_profile_digest,
)
from ops.providers.profile_store import PROFILE_FIELDS, ProviderProfileStore
from ops.research.operational_research import (
    MAX_EVIDENCE_DOCUMENTS,
    MAX_EXCERPT_CHARACTERS,
    EvidenceDocument,
    PerplexitySearchDiscovery,
)

if TYPE_CHECKING:
    from ops.research.operational_research import EvidenceContentFetcherLike, EvidenceDiscovery

LOGGER = logging.getLogger("composio_ops.provider_profile_builder")


@runtime_checkable
class ProfileDiscovery(Protocol):
    """Turn a provider name into candidate evidence URLs. Never authoritative.

    Verbatim ``ops.research.operational_research.EvidenceDiscovery``. Discovery only
    proposes: nothing a discovery adapter returns is believed until it has been
    fetched, extracted, corroborated by a second document, and confined to the
    profile's registrable domain.

    ``isinstance`` against this protocol checks that a ``discover`` attribute
    exists, not that its signature matches; the signature claim is asserted
    statically here and in the port tests.
    """

    async def discover(self, *, app_name: str) -> tuple[str, ...]:
        """Return candidate https URLs for ``app_name``, best-first.

        PRE:  ``app_name`` is non-empty.
        POST: every returned value is an absolute https URL carrying no userinfo,
              and the count is bounded by the adapter's own result cap (the
              builder additionally truncates to
              ``ops.research.operational_research.MAX_EVIDENCE_DOCUMENTS`` before
              fetching). An adapter that finds nothing, is unconfigured, or is
              rate-limited returns ``()`` rather than raising, so the builder
              degrades to the remaining adapters instead of failing the run.
        """


@runtime_checkable
class NamedProfileDiscovery(ProfileDiscovery, Protocol):
    """A discovery adapter that carries the identifier recorded on the evidence.

    The narrowing exists so ``FieldEvidence.adapters`` can name its sources
    without the base port requiring an attribute that would disqualify the
    existing adapters. An adapter without a ``name`` is registered with an
    identifier supplied at the composition boundary.
    """

    name: str


@runtime_checkable
class ProfileEvidenceFetcher(Protocol):
    """Bounded fetch of candidate documents.

    Verbatim ``ops.research.operational_research.EvidenceContentFetcherLike``, which is
    what makes ``YouContentsFetcher``, ``GuardedHTTPEvidenceFetcher`` (the
    batch adapter over ``OfficialEvidenceFetcher``), and
    ``FallbackEvidenceContentFetcher`` usable here unchanged — together with the
    SSRF guard, redirect limit, response-size limit, and host policy they
    already enforce.
    """

    async def fetch_many(self, urls: Sequence[str]) -> tuple[EvidenceDocument, ...]:
        """Fetch with bounded size, bounded count, and per-document excerpting.

        PRE:  every url is https.
        POST: ``len(result) <= len(urls)``; every ``EvidenceDocument`` carries a
              ``relevant_text`` no longer than
              ``ops.research.operational_research.MAX_EXCERPT_CHARACTERS``; a URL that
              could not be fetched is omitted rather than returned as an empty
              or synthesized document, because a fabricated excerpt would
              corroborate a claim that nothing supports.
        """


@runtime_checkable
class ProfileExtractor(Protocol):
    """Structured extraction of profile claims, each citing one document.

    The additive port. Unlike ``EvidenceExtractor.extract`` it takes no
    ``p1_record`` — a brand-new provider has no reviewed catalog row — and it
    returns per-field claims rather than an ``OperationalResearch``, because a
    profile field is only believable with the document it came from attached.
    """

    async def extract(
        self,
        *,
        app_name: str,
        documents: tuple[EvidenceDocument, ...],
    ) -> tuple[ProfileClaim, ...]:
        """Return claims, each citing the exact document it came from.

        PRE:  ``documents`` is non-empty.
        POST: every ``ProfileClaim.source_url`` equals some
              ``documents[i].source_url``, and every claim value literally occurs
              in that document's ``relevant_text``. Both halves are re-verified
              by the builder against the same document set rather than trusted,
              so an extractor cannot launder an invented URL through a citation
              it made up; a claim that fails either check is discarded.
        """


@dataclass(frozen=True, slots=True)
class ProfileClaim:
    """One extracted, not-yet-believed statement about a profile field.

    A claim is untrusted input in the same sense a fetched page is: it names a
    field, a value, and the document it was read from, and that is all. Whether
    the value survives is decided by the builder, which re-checks the literal
    occurrence in the cited excerpt, counts distinct citing documents, and
    confines every URL to one registrable domain. Validation here covers only
    the shape a downstream check would otherwise have to keep re-testing.
    """

    field: ProfileField
    value: str
    source_url: str
    confidence: float

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise ValueError("profile claim requires a non-empty value")
        if not self.source_url.strip():
            raise ValueError("profile claim requires the source url it was read from")
        # Written as a range test rather than two comparisons so a NaN confidence
        # — which an extractor can produce from malformed model output, and which
        # compares False against everything — is refused instead of silently
        # ranking below every real claim.
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("profile claim confidence is out of range")


if TYPE_CHECKING:

    def _reused_ports_are_verbatim(
        discovery: EvidenceDiscovery,
        fetcher: EvidenceContentFetcherLike,
    ) -> tuple[ProfileDiscovery, ProfileEvidenceFetcher]:
        """Static proof that the two reused ports were copied, not paraphrased.

        Type checked, never executed. Any drift between these ports and the
        ``ops.research.operational_research`` ports they restate — a renamed keyword, an
        added parameter, a changed return type — makes this assignment invalid
        and fails ``make typecheck``, which is the only thing keeping the
        existing research adapters usable here without a shim.
        """

        return discovery, fetcher


# --- the builder ----------------------------------------------------------

# Two sources for the fields that authorize spending or navigation, one for the
# rest. Being wrong about a signup or login URL creates an account or hands
# credentials to a look-alike host; being wrong about a flow entry URL or the
# docs URL costs an action-loop retry.
MIN_CORROBORATIONS: Final = 2

# The fields a profile cannot be assembled without. They are also the only
# claims that vote on which registrable domain the provider owns: a blog post's
# link to a third-party mirror, an OAuth flow hosted on an identity provider, or
# a docs URL on a documentation SaaS must not get a say in domain ownership —
# they are admitted only if they already agree with the resolved domain.
_REQUIRED_FIELDS: Final[frozenset[str]] = frozenset(
    {"registrable_domain", "signup_url", "login_url"}
)

# Claim fields whose value is an https URL, and therefore subject to the HTTPS +
# matching-registrable-domain admission check.
_URL_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "developer_portal_url",
        "signup_url",
        "login_url",
        "developer_docs_url",
        "developer_app_flow",
        "oauth_flow",
        "api_key_flow",
        "pat_flow",
    }
)

# Claim field -> the flow slot it fills. A claim's value is the flow's entry URL;
# a flow with no admitted claim is declared unsupported rather than guessed.
_FLOW_FIELDS: Final[Mapping[str, FlowKind]] = {
    "developer_app_flow": "developer_app",
    "oauth_flow": "oauth",
    "api_key_flow": "api_key",  # pragma: allowlist secret
    "pat_flow": "pat",
}

# What each flow mints, keyed by flow kind rather than by provider: research may
# say *where* a credential comes from, never what kind of material a page will
# hand over.
_FLOW_PRODUCES: Final[Mapping[FlowKind, tuple[CredentialKind, ...]]] = {
    "developer_app": ("oauth_client_id", "oauth_client_secret"),
    "oauth": ("oauth_client_id", "oauth_client_secret"),
    "api_key": ("api_key",),
    "pat": ("personal_access_token",),
    "client_credentials": ("client_credentials_pair",),
}

_ENUM_VOCABULARIES: Final[Mapping[str, frozenset[str]]] = {
    "approval_requirement": APPROVAL_REQUIREMENTS,
    "billing_requirement": BILLING_REQUIREMENTS,
}

# The three ways research can end without a profile. A strict subset of
# ``OnboardingReasonCode`` — see ``_reason_codes_are_onboarding_codes`` — so the
# orchestrator commits the code the builder returned rather than translating it.
ResearchReasonCode = Literal[
    "research_no_evidence",
    "research_domain_disagreement",
    "research_adapters_unavailable",
]

ResearchFactKind = Literal[
    "adapter_failed",
    "adapter_returned_nothing",
    "candidate_url_excluded",
    "candidate_urls_capped",
    "fetch_returned_nothing",
    "document_not_requested",
    "claim_discarded",
    "url_excluded",
    "field_uncorroborated",
    "domain_disagreement",
]


@dataclass(frozen=True, slots=True)
class ResearchFact:
    """One durable, non-secret note about something research refused to believe.

    Every exclusion the build performs produces one of these: an adapter that
    failed, a candidate URL that was not https, a claim absent from the excerpt
    it cited, a URL pointing off the resolved domain, a required field that never
    reached two sources. ``subject`` is a host, a field name, or an adapter name,
    and ``detail`` is the check that failed — deliberately never the page text or
    the rejected value's surroundings, because excerpts are untrusted
    third-party content.
    """

    kind: ResearchFactKind
    subject: str
    detail: str = ""


class ResearchFactRecorder(Protocol):
    """Where research facts become durable. Satisfied by the run's audit writer.

    Exceptions are not swallowed: a fact that cannot be recorded would make the
    profile's exclusions unattributable, and an unattributable exclusion is worse
    than a failed build.
    """

    def record(self, *, run_id: str, fact: ResearchFact) -> None: ...


@dataclass(frozen=True, slots=True)
class DiscoveryAdapter:
    """A discovery port bound to the identifier recorded on the evidence.

    Identity is supplied here rather than demanded by :class:`ProfileDiscovery`,
    so an adapter that carries no ``name`` of its own — ``PerplexitySearchDiscovery``
    is one — is registered without a wrapper that could drop one of its bounds.

    ``attempts`` is Requirement 2.5's per-adapter cap, carried per adapter rather
    than as one number inside the builder so a fast local adapter and a flaky
    remote one are not forced to share a retry budget.
    """

    name: str
    port: ProfileDiscovery
    attempts: int = 1

    def __post_init__(self) -> None:
        if self.attempts < 1:
            raise ValueError("a discovery adapter must be attempted at least once")


def discovery_adapter(
    port: ProfileDiscovery,
    *,
    name: str | None = None,
    attempts: int = 1,
) -> DiscoveryAdapter:
    """Register a discovery port, taking its own ``name`` when it has one."""

    declared = getattr(port, "name", "")
    resolved = name or (declared if isinstance(declared, str) else "")
    if not resolved.strip():
        raise ValueError("a discovery adapter requires an identifier for its evidence")
    return DiscoveryAdapter(name=resolved, port=port, attempts=attempts)


# --- registration ---------------------------------------------------------

# The phase these capability errors are reported against, matching the research
# phase the rest of the runtime reports (``ops/runs/service.py`` uses the same
# number for You.com research).
_RESEARCH_PHASE: Final = 2


@dataclass(frozen=True, slots=True)
class _AdapterRegistration:
    """One row of the adapter table: a flag, a credential, and a constructor.

    A new research adapter is a new row plus a port implementation. Nothing in
    the builder, the driver, or the orchestrator changes, which is the property
    Requirement 2.1 asks for and the reason this table is data rather than a
    chain of ``if`` statements in a composition function.
    """

    name: str
    enabled: Callable[[Settings], bool]
    keyed: Callable[[Settings], bool]
    missing_key_reason: str
    build: Callable[[Settings], ProfileDiscovery]


def _perplexity_discovery(settings: Settings) -> ProfileDiscovery:
    """The Perplexity search adapter, used as-is.

    ``PerplexitySearchDiscovery`` already satisfies :class:`ProfileDiscovery`
    structurally, so it is registered directly. Wrapping it would put the one
    bounded request, ``max_retries=0``, the explicit timeout, and the five-result
    cap behind a shim that is free to forget one of them.
    """

    key = settings.perplexity_api_key
    if key is None:  # pragma: no cover - registration checks the key first
        raise ConfigurationRequiredError(
            phase=_RESEARCH_PHASE,
            capability="onboarding research adapter perplexity_search",
            reason_code="perplexity_api_key_required",
        )
    return PerplexitySearchDiscovery(key)


# The registered adapters, in the order discovery engages them.
#
# You.com is deliberately absent, and it is worth saying why rather than leaving
# a gap: every You.com adapter in this repo (``YouSearchDiscovery``,
# ``YouContentsFetcher``, ``YouResearchFallback``) takes the official host list
# as an argument and returns nothing without one. Profile research exists to
# DISCOVER that host list, so those adapters cannot serve this phase, and a flag
# for one would be a switch that turns nothing on. A You.com profile-discovery
# adapter is a new port implementation plus one row here.
_REGISTRATIONS: Final[tuple[_AdapterRegistration, ...]] = (
    _AdapterRegistration(
        name="perplexity_search",
        enabled=lambda settings: settings.onboarding_research_perplexity_enabled,
        keyed=lambda settings: settings.perplexity_api_key is not None,
        missing_key_reason="perplexity_api_key_required",
        build=_perplexity_discovery,
    ),
)


def research_adapters(settings: Settings) -> tuple[DiscoveryAdapter, ...]:
    """Turn configuration into the discovery adapters this run may engage.

    PRE:  none.
    POST: every returned adapter is opted into by its own flag and holds the
          credential it needs; each carries
          ``settings.onboarding_research_adapter_attempts`` as its cap.

    Two failure modes are explicit rather than degraded, per the
    ``ConfigurationRequiredError`` / ``PhaseUnavailableError`` rule in
    ``CLAUDE.md``:

    - a flag is on and its credential is absent — that is a deployment mistake,
      and silently dropping the adapter would turn it into a quieter, harder to
      diagnose "research found nothing";
    - nothing is enabled at all — there is no adapter to degrade *to*. Note this
      is not Requirement 2.7's ``research_adapters_unavailable``: that code names
      configured adapters that all came back empty, which is a run outcome the
      builder returns. No configured adapter is a configuration outcome, raised
      before a run starts spending. Either way the run never proceeds on a
      guessed domain.
    """

    registered: list[DiscoveryAdapter] = []
    for registration in _REGISTRATIONS:
        if not registration.enabled(settings):
            continue
        if not registration.keyed(settings):
            raise ConfigurationRequiredError(
                phase=_RESEARCH_PHASE,
                capability=f"onboarding research adapter {registration.name}",
                reason_code=registration.missing_key_reason,
            )
        registered.append(
            DiscoveryAdapter(
                name=registration.name,
                port=registration.build(settings),
                attempts=settings.onboarding_research_adapter_attempts,
            )
        )
    if not registered:
        raise PhaseUnavailableError(
            phase=_RESEARCH_PHASE,
            capability="onboarding provider research",
            reason_code="research_adapters_not_configured",
        )
    return tuple(registered)


@dataclass(frozen=True, slots=True)
class ResearchInconclusive:
    """Research ended without a profile. The run blocks; nothing was spent.

    Carries the facts collected up to the point research gave up, so the
    orchestrator can commit phase ``blocked`` with both a reason code and the
    exclusions that produced it.
    """

    reason_code: ResearchReasonCode
    facts: tuple[ResearchFact, ...] = ()


ProfileBuildOutcome = ProviderProfile | ResearchInconclusive


async def build_profile(
    *,
    run_id: str,
    provider_name: str,
    app_slug: str,
    hint_url: str | None = None,
    adapters: Sequence[DiscoveryAdapter],
    fetcher: ProfileEvidenceFetcher,
    extractor: ProfileExtractor,
    store: ProviderProfileStore,
    facts: ResearchFactRecorder | None = None,
) -> ProfileBuildOutcome:
    """Build, corroborate, digest and persist one immutable profile for this run.

    PRE:
      P1. ``app_slug`` matches ``^[a-z0-9]+(?:-[a-z0-9]+)*$``.
      P2. no browser session exists for this run and no side effect has been
          reserved. Research runs before anything can cost anything, which is why
          the profile is committed here, at the end of this function, and every
          later phase reads it back from the store.

    POST (success):
      Q1. every https URL on the profile resolves to ``profile.registrable_domain``.
      Q2. ``profile.profile_digest == compute_profile_digest(profile)`` and the
          profile is persisted under that digest for this run.
      Q3. every ``FieldEvidence.source_url`` is a document that was fetched, and
          its value literally occurred in that document's excerpt.
      Q4. ``corroborations`` counts DISTINCT cited-excerpt digests, so fetching
          the same text twice contributes one.

    POST (inconclusive):
      Q5. nothing is persisted through this function, no session exists, no
          effect key is reserved, and the reason code is one of
          ``research_adapters_unavailable`` | ``research_no_evidence`` |
          ``research_domain_disagreement``.

    A fresh profile is built on every call: the fetch layer may serve a cached
    document, but the excerpt is re-hashed, corroboration is re-counted, and the
    digest is recomputed from this run's own evidence, so a cache hit can never
    substitute for the corroboration step.
    """

    log = _FactLog(run_id=run_id, recorder=facts)

    candidates = await _candidate_urls(
        hint_url=hint_url,
        adapters=adapters,
        provider_name=provider_name,
        log=log,
    )
    if not candidates.urls:
        return ResearchInconclusive("research_adapters_unavailable", log.collected())

    requested = candidates.urls[:MAX_EVIDENCE_DOCUMENTS]
    if len(candidates.urls) > MAX_EVIDENCE_DOCUMENTS:
        log.add("candidate_urls_capped", subject=str(len(candidates.urls)), detail="fetch_budget")
    documents = _requested_documents(await fetcher.fetch_many(requested), requested, log=log)
    if not documents:
        return ResearchInconclusive("research_no_evidence", log.collected())

    # Digest per document, computed here rather than taken from the fetcher, so a
    # cached document and a freshly fetched one are counted the same way and two
    # documents with identical text collapse into one corroboration.
    digests = {
        document.source_url: _excerpt_digest(document.relevant_text) for document in documents
    }

    verified = _verified_claims(
        await extractor.extract(app_name=provider_name, documents=documents),
        documents=documents,
        log=log,
    )
    domain = _resolve_domain(verified, log=log)
    if domain is None:
        return ResearchInconclusive("research_domain_disagreement", log.collected())

    admitted = _admitted_claims(verified, domain=domain, log=log)
    evidence = _corroborated_evidence(
        admitted,
        digests=digests,
        adapters_engaged=candidates.engaged,
        log=log,
    )
    chosen = _best_per_field(evidence)
    if not _REQUIRED_FIELDS.issubset(chosen):
        for field in sorted(_REQUIRED_FIELDS - set(chosen)):
            log.add("field_uncorroborated", subject=field, detail="required_field_missing")
        return ResearchInconclusive("research_no_evidence", log.collected())

    profile = _assemble(
        run_id=run_id,
        provider_name=provider_name,
        app_slug=app_slug,
        domain=domain,
        chosen=chosen,
        adapters_engaged=candidates.engaged,
    )
    profile = replace(profile, profile_digest=compute_profile_digest(profile))
    store.put(profile)
    LOGGER.info(
        "provider profile %s committed for run %s on %s",
        profile.profile_digest[:12],
        run_id,
        domain,
    )
    return profile


class _FactLog:
    """Collect research facts in order and make each one durable as it happens."""

    def __init__(self, *, run_id: str, recorder: ResearchFactRecorder | None) -> None:
        self._run_id = run_id
        self._recorder = recorder
        self._facts: list[ResearchFact] = []

    def add(self, kind: ResearchFactKind, *, subject: str, detail: str = "") -> None:
        fact = ResearchFact(kind=kind, subject=subject[:200], detail=detail[:200])
        self._facts.append(fact)
        if self._recorder is not None:
            self._recorder.record(run_id=self._run_id, fact=fact)

    def collected(self) -> tuple[ResearchFact, ...]:
        return tuple(self._facts)


@dataclass(frozen=True, slots=True)
class _Candidates:
    """Deduplicated https candidate URLs and the adapters that produced them."""

    urls: tuple[str, ...]
    engaged: tuple[str, ...]


async def _candidate_urls(
    *,
    hint_url: str | None,
    adapters: Sequence[DiscoveryAdapter],
    provider_name: str,
    log: _FactLog,
) -> _Candidates:
    """Seed the operator hint, then let each adapter degrade independently.

    The hint is one candidate URL like any other, which is exactly what makes it
    contribute at most one corroboration: corroboration counts distinct excerpt
    digests, and the hint yields one document.
    """

    urls: list[str] = []
    if hint_url:
        urls.extend(_admissible_candidates((hint_url,), source="operator_hint", log=log))
    engaged: list[str] = []
    for adapter in adapters:
        found = await _discover(adapter, provider_name=provider_name, log=log)
        if found is None:
            # Every attempt against this adapter raised. The run degrades to the
            # remaining adapters and the candidates already discovered are
            # untouched.
            continue
        if not found:
            log.add("adapter_returned_nothing", subject=adapter.name)
            continue
        engaged.append(adapter.name)
        urls.extend(_admissible_candidates(found, source=adapter.name, log=log))
    return _Candidates(urls=tuple(dict.fromkeys(urls)), engaged=tuple(dict.fromkeys(engaged)))


async def _discover(
    adapter: DiscoveryAdapter,
    *,
    provider_name: str,
    log: _FactLog,
) -> tuple[str, ...] | None:
    """Call one adapter within its attempt cap. ``None`` means every attempt raised.

    Only a raising attempt is retried. An adapter that returns ``()`` has
    answered — Requirement 2.4 treats that as a normal result — and asking it
    again would re-spend for the same answer, so emptiness is returned as-is and
    the adapter is left out of ``adapters_engaged`` by the caller.

    Each failed attempt records its own durable fact carrying the exception TYPE
    and the attempt ordinal, never the exception message: a provider error can
    quote a URL, a query, or a response body.
    """

    for attempt in range(1, adapter.attempts + 1):
        try:
            return await adapter.port.discover(app_name=provider_name)
        except Exception as error:  # noqa: BLE001 - one adapter must not fail the run
            log.add(
                "adapter_failed",
                subject=adapter.name,
                detail=f"{type(error).__name__}/attempt={attempt}",
            )
    return None


def _admissible_candidates(
    urls: Sequence[str],
    *,
    source: str,
    log: _FactLog,
) -> tuple[str, ...]:
    """Drop a candidate the fetch port's precondition forbids, and record why."""

    admissible: list[str] = []
    for url in urls:
        try:
            admissible.append(validate_https_url(url))
        except ValueError:
            log.add("candidate_url_excluded", subject=source, detail="not_an_https_url")
    return tuple(admissible)


def _requested_documents(
    documents: Sequence[EvidenceDocument],
    requested: Sequence[str],
    *,
    log: _FactLog,
) -> tuple[EvidenceDocument, ...]:
    """Keep only documents for URLs this run asked for, one per URL.

    A document for an unrequested URL cannot be attributed to a candidate, and a
    second document for the same URL would double-count as corroboration if its
    text happened to differ.
    """

    wanted = set(requested)
    kept: dict[str, EvidenceDocument] = {}
    for document in documents:
        if document.source_url not in wanted:
            log.add(
                "document_not_requested", subject=document.source_url, detail="url_not_a_candidate"
            )
            continue
        kept.setdefault(document.source_url, document)
    return tuple(kept.values())


def _verified_claims(
    claims: Sequence[ProfileClaim],
    *,
    documents: Sequence[EvidenceDocument],
    log: _FactLog,
) -> tuple[ProfileClaim, ...]:
    """Re-check every claim against the document it cites. Never trust extraction.

    A claim survives only when its cited URL is one of the fetched documents and
    its value occurs literally in that document's excerpt, so an extractor cannot
    launder an invented URL through a citation it made up.
    """

    excerpts = {document.source_url: _excerpt(document.relevant_text) for document in documents}
    verified: list[ProfileClaim] = []
    for claim in claims:
        if claim.field not in PROFILE_FIELDS:
            log.add("claim_discarded", subject=str(claim.field), detail="field_outside_vocabulary")
            continue
        excerpt = excerpts.get(claim.source_url)
        if excerpt is None:
            log.add("claim_discarded", subject=claim.field, detail="cited_document_not_fetched")
            continue
        if claim.value not in excerpt:
            log.add("claim_discarded", subject=claim.field, detail="value_absent_from_excerpt")
            continue
        verified.append(claim)
    return tuple(verified)


def _resolve_domain(claims: Sequence[ProfileClaim], *, log: _FactLog) -> str | None:
    """Resolve exactly one registrable domain, or ``None`` for a disagreement.

    Only the required fields vote. Their agreement *is* the evidence that the
    domain is the provider's: two independent documents naming the same signup
    host is a stronger claim about ownership than any single page's assertion.
    """

    domains: set[str] = set()
    for claim in claims:
        if claim.field not in _REQUIRED_FIELDS:
            continue
        resolved = _claim_domain(claim)
        if resolved is not None:
            domains.add(resolved)
    if len(domains) == 1:
        return domains.pop()
    log.add(
        "domain_disagreement",
        subject=",".join(sorted(domains)[:4]) or "none",
        detail=f"registrable_domains={len(domains)}",
    )
    return None


def _claim_domain(claim: ProfileClaim) -> str | None:
    """The registrable domain a claim implies, through the one domain authority."""

    if claim.field == "registrable_domain":
        return resolve_registrable_domain(claim.value)
    try:
        host = _host(validate_https_url(claim.value))
    except ValueError:
        return None
    return resolve_registrable_domain(host)


def _admitted_claims(
    claims: Sequence[ProfileClaim],
    *,
    domain: str,
    log: _FactLog,
) -> tuple[tuple[ProfileField, str, ProfileClaim], ...]:
    """Admit a claim, pairing it with the value the profile will carry.

    The admitted set can only shrink from here: a URL on a second registrable
    domain is dropped and recorded, never merged, which is the mechanical form of
    "narrowing only". Host comparison goes through the same
    ``registrable_domain`` the browser policy uses, so ``https://APP.Provider.com./x``
    is admitted for ``provider.com`` while ``https://provider.com.evil.io/x`` is not.
    """

    admitted: list[tuple[ProfileField, str, ProfileClaim]] = []
    for claim in claims:
        field = claim.field
        if field in _URL_FIELDS:
            value = _admitted_url(claim, domain=domain, log=log)
        elif field == "registrable_domain":
            value = domain if resolve_registrable_domain(claim.value) == domain else None
            if value is None:
                log.add("url_excluded", subject=claim.value, detail="registrable_domain_mismatch")
        elif field in _ENUM_VOCABULARIES:
            value = claim.value if claim.value in _ENUM_VOCABULARIES[field] else None
            if value is None:
                log.add("claim_discarded", subject=field, detail="value_outside_vocabulary")
        else:  # pragma: no cover - every ProfileField is covered above
            log.add("claim_discarded", subject=field, detail="field_not_buildable")
            value = None
        if value is not None:
            admitted.append((field, value, claim))
    return tuple(admitted)


def _admitted_url(claim: ProfileClaim, *, domain: str, log: _FactLog) -> str | None:
    """Admit an https URL on the resolved domain; record the failed check otherwise."""

    try:
        url = validate_https_url(claim.value)
    except ValueError:
        log.add("url_excluded", subject=_host(claim.value), detail="scheme_not_https")
        return None
    host = _host(url)
    if resolve_registrable_domain(host) != domain:
        log.add("url_excluded", subject=host, detail="registrable_domain_mismatch")
        return None
    return url


def _corroborated_evidence(
    admitted: Sequence[tuple[ProfileField, str, ProfileClaim]],
    *,
    digests: Mapping[str, str],
    adapters_engaged: Sequence[str],
    log: _FactLog,
) -> tuple[FieldEvidence, ...]:
    """Count distinct cited-excerpt digests per value and keep what clears the bar."""

    support: dict[tuple[ProfileField, str], set[str]] = {}
    confidences: dict[tuple[ProfileField, str], list[float]] = {}
    for field, value, claim in admitted:
        key = (field, value)
        support.setdefault(key, set()).add(digests[claim.source_url])
        confidences.setdefault(key, []).append(claim.confidence)

    urls_by_digest = _urls_by_digest(digests)
    evidence: list[FieldEvidence] = []
    for (field, value), sources in sorted(support.items()):
        required = MIN_CORROBORATIONS if field in _REQUIRED_FIELDS else 1
        if len(sources) < required:
            log.add(
                "field_uncorroborated",
                subject=field,
                detail=f"corroborations={len(sources)}/{required}",
            )
            continue
        source_digest = sorted(sources)[0]
        evidence.append(
            FieldEvidence(
                field=field,
                value=value,
                source_url=urls_by_digest[source_digest],
                source_digest=source_digest,
                adapters=tuple(adapters_engaged),
                corroborations=len(sources),
                confidence=_field_confidence(confidences[(field, value)], len(sources)),
                extracted_at=_utc_now(),
            )
        )
    return tuple(evidence)


def _best_per_field(evidence: Sequence[FieldEvidence]) -> dict[str, FieldEvidence]:
    """One value per field: most corroborated, then most confident, then stable.

    Two documents disagreeing about the signup URL is not a domain disagreement —
    both are on the resolved domain — so the better-supported value wins rather
    than blocking the run.
    """

    best: dict[str, FieldEvidence] = {}
    for item in sorted(
        evidence,
        key=lambda candidate: (candidate.corroborations, candidate.confidence, candidate.value),
        reverse=True,
    ):
        best.setdefault(item.field, item)
    return best


def _assemble(
    *,
    run_id: str,
    provider_name: str,
    app_slug: str,
    domain: str,
    chosen: Mapping[str, FieldEvidence],
    adapters_engaged: Sequence[str],
) -> ProviderProfile:
    """Assemble the profile from admitted evidence. Absent evidence is never guessed."""

    approval = cast(
        ApprovalRequirement, _enum_value(chosen, "approval_requirement", default="unknown")
    )
    billing = cast(
        BillingRequirement, _enum_value(chosen, "billing_requirement", default="unknown")
    )
    flows = {
        field: _flow(
            kind,
            evidence=chosen.get(field),
            requires_approval=approval in {"manual_review", "invite_only"},
            requires_billing=billing in {"card_required", "paid_plan_required"},
        )
        for field, kind in _FLOW_FIELDS.items()
    }
    profile_evidence = tuple(chosen[field] for field in sorted(chosen) if field not in _FLOW_FIELDS)
    return ProviderProfile(
        run_id=run_id,
        provider_name=provider_name,
        app_slug=app_slug,
        registrable_domain=domain,
        # Auxiliary hosts are additive and typed, and no claim field carries a
        # kind for one, so research declares none rather than inferring one from
        # a URL it happened to see.
        auxiliary_hosts=(),
        developer_portal_url=_url_value(chosen, "developer_portal_url"),
        signup_url=_url_value(chosen, "signup_url"),
        login_url=_url_value(chosen, "login_url"),
        developer_docs_url=_url_value(chosen, "developer_docs_url"),
        developer_app_flow=flows["developer_app_flow"],
        oauth_flow=flows["oauth_flow"],
        api_key_flow=flows["api_key_flow"],
        pat_flow=flows["pat_flow"],
        approval_requirement=approval,
        billing_requirement=billing,
        evidence=profile_evidence,
        confidence=_profile_confidence(chosen),
        adapters_engaged=tuple(adapters_engaged),
        built_at=_utc_now(),
    )


def _flow(
    kind: FlowKind,
    *,
    evidence: FieldEvidence | None,
    requires_approval: bool,
    requires_billing: bool,
) -> FlowSpec:
    """A flow is supported only when a corroborated entry URL was admitted for it."""

    if evidence is None:
        return FlowSpec(kind=kind, supported=False, entry_url=None)
    return FlowSpec(
        kind=kind,
        supported=True,
        entry_url=evidence.value,
        produces=_FLOW_PRODUCES[kind],
        requires_approval=requires_approval,
        requires_billing=requires_billing,
        evidence=(evidence,),
    )


def _url_value(chosen: Mapping[str, FieldEvidence], field: str) -> str | None:
    evidence = chosen.get(field)
    return None if evidence is None else evidence.value


def _enum_value(chosen: Mapping[str, FieldEvidence], field: str, *, default: str) -> str:
    """The corroborated enum value, or ``unknown``. An absent claim is not a `none`."""

    evidence = chosen.get(field)
    return default if evidence is None else evidence.value


def _profile_confidence(chosen: Mapping[str, FieldEvidence]) -> float:
    """The weakest required field's confidence: a profile is as good as its floor."""

    required = [chosen[field].confidence for field in sorted(_REQUIRED_FIELDS) if field in chosen]
    return min(required) if required else 0.0


def _field_confidence(claim_confidences: Sequence[float], corroborations: int) -> float:
    """Extraction confidence, capped by how many documents actually agreed.

    A single source cannot express more than half-belief no matter how sure the
    extractor claims to be, which is what stops a confident model from standing
    in for a second document.
    """

    extracted = sum(claim_confidences) / len(claim_confidences)
    return round(min(extracted, min(1.0, 0.5 * corroborations)), 6)


def _urls_by_digest(digests: Mapping[str, str]) -> dict[str, str]:
    """One citation URL per excerpt digest, chosen deterministically.

    Two URLs serving identical text share a digest and therefore one
    corroboration; the lexicographically first URL is cited so the same evidence
    produces the same profile digest across runs.
    """

    by_digest: dict[str, str] = {}
    for url, digest in sorted(digests.items()):
        by_digest.setdefault(digest, url)
    return by_digest


def _excerpt(text: str) -> str:
    """The bounded excerpt a claim may be verified against."""

    return text[:MAX_EXCERPT_CHARACTERS]


def _excerpt_digest(text: str) -> str:
    return hashlib.sha256(_excerpt(text).encode("utf-8")).hexdigest()


def _host(url: str) -> str:
    """The hostname a URL names, or the empty string when it names none."""

    return urlsplit(url).hostname or ""


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


if TYPE_CHECKING:

    def _reason_codes_are_onboarding_codes(code: ResearchReasonCode) -> OnboardingReasonCode:
        """Static proof that every inconclusive reason code is an onboarding code.

        Type checked, never executed. It is what lets the orchestrator commit the
        code this module returned instead of maintaining a translation table.
        """

        return code


__all__ = [
    "MIN_CORROBORATIONS",
    "DiscoveryAdapter",
    "NamedProfileDiscovery",
    "ProfileBuildOutcome",
    "ProfileClaim",
    "ProfileDiscovery",
    "ProfileEvidenceFetcher",
    "ProfileExtractor",
    "ResearchFact",
    "ResearchFactKind",
    "ResearchFactRecorder",
    "ResearchInconclusive",
    "ResearchReasonCode",
    "build_profile",
    "discovery_adapter",
    "research_adapters",
]
