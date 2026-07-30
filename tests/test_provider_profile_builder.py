"""Happy path for ``build_profile``, plus the one genuinely different branch.

Fake discovery, fake fetch, and fake extraction stand in for the research
adapters; the profile store is the real SQLite one, because "the profile is
committed under its digest" is the point of the build.
"""

from __future__ import annotations

from collections.abc import Sequence

import pytest

from ops.core.config import Settings
from ops.providers.errors import ConfigurationRequiredError, PhaseUnavailableError
from ops.providers.profile import ProviderProfile, compute_profile_digest
from ops.providers.profile_builder import (
    ProfileClaim,
    ResearchFact,
    ResearchInconclusive,
    build_profile,
    discovery_adapter,
    research_adapters,
)
from ops.providers.profile_store import SQLiteProviderProfileStore
from ops.research.operational_research import EvidenceDocument, PerplexitySearchDiscovery

DOCS_URL = "https://developers.provider.com/docs"
GUIDE_URL = "https://developers.provider.com/guide"
SIGNUP_URL = "https://provider.com/signup"
LOGIN_URL = "https://app.provider.com/login"
API_KEY_URL = "https://app.provider.com/settings/api"  # pragma: allowlist secret
LOOKALIKE_URL = "https://provider.com.evil.io/portal"


class FakeDiscovery:
    """A named discovery adapter that proposes candidates and nothing more."""

    def __init__(self, name: str, urls: tuple[str, ...]) -> None:
        self.name = name
        self._urls = urls

    async def discover(self, *, app_name: str) -> tuple[str, ...]:
        assert app_name
        return self._urls


class FakeFetcher:
    """Returns prepared excerpts for the URLs it was asked for."""

    def __init__(self, documents: dict[str, str]) -> None:
        self._documents = documents
        self.requested: list[str] = []

    async def fetch_many(self, urls: Sequence[str]) -> tuple[EvidenceDocument, ...]:
        self.requested.extend(urls)
        return tuple(
            EvidenceDocument(source_url=url, title="Provider docs", relevant_text=text)
            for url in urls
            if (text := self._documents.get(url)) is not None
        )


class FakeExtractor:
    """Emits the same claim set against every document it is handed."""

    def __init__(self, fields: dict[str, str], *, per_document: dict[str, dict[str, str]]) -> None:
        self._fields = fields
        self._per_document = per_document

    async def extract(
        self,
        *,
        app_name: str,
        documents: tuple[EvidenceDocument, ...],
    ) -> tuple[ProfileClaim, ...]:
        claims: list[ProfileClaim] = []
        for document in documents:
            declared = {**self._fields, **self._per_document.get(document.source_url, {})}
            for field, value in declared.items():
                claims.append(
                    ProfileClaim(
                        field=field,  # type: ignore[arg-type]
                        value=value,
                        source_url=document.source_url,
                        confidence=0.9,
                    )
                )
        return tuple(claims)


class RecordingFacts:
    def __init__(self) -> None:
        self.facts: list[ResearchFact] = []

    def record(self, *, run_id: str, fact: ResearchFact) -> None:
        assert run_id
        self.facts.append(fact)


@pytest.fixture
def store(tmp_path) -> SQLiteProviderProfileStore:
    return SQLiteProviderProfileStore(
        tmp_path / "private" / "provider_profiles.db", owner="ops-owner"
    )


def _excerpt(*values: str) -> str:
    return "Provider developer documentation. " + " ".join(values)


async def test_corroborated_research_commits_one_digested_profile(store) -> None:
    documents = {
        DOCS_URL: _excerpt(
            "provider.com", SIGNUP_URL, LOGIN_URL, API_KEY_URL, DOCS_URL, LOOKALIKE_URL
        ),
        GUIDE_URL: _excerpt("provider.com", SIGNUP_URL, LOGIN_URL, "card_required"),
    }
    facts = RecordingFacts()

    outcome = await build_profile(
        run_id="run-001",
        provider_name="Provider",
        app_slug="provider",
        adapters=[discovery_adapter(FakeDiscovery("fake-search", (DOCS_URL, GUIDE_URL)))],
        fetcher=FakeFetcher(documents),
        extractor=FakeExtractor(
            {
                "registrable_domain": "provider.com",
                "signup_url": SIGNUP_URL,
                "login_url": LOGIN_URL,
            },
            per_document={
                DOCS_URL: {
                    "api_key_flow": API_KEY_URL,
                    "developer_docs_url": DOCS_URL,
                    # An invented look-alike host the extractor cited honestly:
                    # admission has to drop it and say so.
                    "developer_portal_url": LOOKALIKE_URL,
                },
                GUIDE_URL: {"billing_requirement": "card_required"},
            },
        ),
        store=store,
        facts=facts,
    )

    assert isinstance(outcome, ProviderProfile)
    assert outcome.registrable_domain == "provider.com"
    assert outcome.signup_url == SIGNUP_URL
    assert outcome.login_url == LOGIN_URL
    assert outcome.developer_docs_url == DOCS_URL
    assert outcome.adapters_engaged == ("fake-search",)

    # Required fields cleared two distinct excerpt digests; the single-source
    # flow entry URL cleared one.
    supported = {item.field: item for item in outcome.evidence}
    assert supported["signup_url"].corroborations == 2
    assert supported["registrable_domain"].corroborations == 2
    assert outcome.api_key_flow.supported is True
    assert outcome.api_key_flow.entry_url == API_KEY_URL
    assert outcome.api_key_flow.evidence[0].corroborations == 1
    assert outcome.oauth_flow.supported is False

    # Uncorroborated enums stay unknown; a corroborated one is carried.
    assert outcome.approval_requirement == "unknown"
    assert outcome.billing_requirement == "card_required"

    # The look-alike host was excluded and the exclusion is durable.
    assert outcome.developer_portal_url is None
    assert ("url_excluded", "provider.com.evil.io") in {
        (fact.kind, fact.subject) for fact in facts.facts
    }

    assert outcome.profile_digest == compute_profile_digest(outcome)
    assert store.get_for_run(run_id="run-001") == outcome


async def test_operational_urls_disagreeing_on_a_domain_block_the_run(store) -> None:
    other_login = "https://accounts.other.com/login"
    documents = {
        DOCS_URL: _excerpt("provider.com", SIGNUP_URL, other_login),
        GUIDE_URL: _excerpt("provider.com", SIGNUP_URL, other_login),
    }

    outcome = await build_profile(
        run_id="run-002",
        provider_name="Provider",
        app_slug="provider",
        adapters=[discovery_adapter(FakeDiscovery("fake-search", (DOCS_URL, GUIDE_URL)))],
        fetcher=FakeFetcher(documents),
        extractor=FakeExtractor(
            {
                "registrable_domain": "provider.com",
                "signup_url": SIGNUP_URL,
                "login_url": other_login,
            },
            per_document={},
        ),
        store=store,
        facts=RecordingFacts(),
    )

    assert isinstance(outcome, ResearchInconclusive)
    assert outcome.reason_code == "research_domain_disagreement"
    assert any(fact.kind == "domain_disagreement" for fact in outcome.facts)
    # Nothing was committed, so no browser session or effect key can be
    # attributed to a profile that does not exist.
    assert store.get_for_run(run_id="run-002") is None


class FailingDiscovery:
    """A discovery adapter that only ever raises."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.calls = 0

    async def discover(self, *, app_name: str) -> tuple[str, ...]:
        assert app_name
        self.calls += 1
        raise TimeoutError("provider search timed out")


def test_only_enabled_research_adapters_are_registered() -> None:
    """Requirement 2.2: each adapter is opted into on its own flag.

    Enabled and keyed registers the adapter with its attempt cap; not enabled
    leaves nothing to degrade to, and an enabled adapter missing its credential
    is a deployment mistake — both are raised rather than turned into a quieter
    "research found nothing".
    """

    enabled = Settings.from_env(
        env={
            "ONBOARDING_RESEARCH_PERPLEXITY_ENABLED": "true",
            "PERPLEXITY_API_KEY": "pplx-test-key",  # pragma: allowlist secret
        }
    )
    registered = research_adapters(enabled)
    assert [adapter.name for adapter in registered] == ["perplexity_search"]
    assert isinstance(registered[0].port, PerplexitySearchDiscovery)
    assert registered[0].attempts == enabled.onboarding_research_adapter_attempts == 2

    keyed_but_disabled = {"PERPLEXITY_API_KEY": "pplx-test-key"}  # pragma: allowlist secret
    with pytest.raises(PhaseUnavailableError, match="research"):
        research_adapters(Settings.from_env(env=keyed_but_disabled))

    with pytest.raises(ConfigurationRequiredError, match="perplexity"):
        research_adapters(Settings.from_env(env={"ONBOARDING_RESEARCH_PERPLEXITY_ENABLED": "true"}))


async def test_a_failing_adapter_degrades_to_the_working_one(store) -> None:
    """Requirements 2.3, 2.4, 2.5: one adapter's failure is not the run's.

    The failing adapter is retried up to its cap, each attempt recorded as a
    durable fact naming the adapter and the exception type, and it never reaches
    ``adapters_engaged``. The empty adapter is excluded too. The build completes
    on the working adapter's candidates alone.
    """

    documents = {
        DOCS_URL: _excerpt("provider.com", SIGNUP_URL, LOGIN_URL, "reference"),
        GUIDE_URL: _excerpt("provider.com", SIGNUP_URL, LOGIN_URL, "getting started"),
    }
    failing = FailingDiscovery("flaky-search")
    facts = RecordingFacts()

    outcome = await build_profile(
        run_id="run-003",
        provider_name="Provider",
        app_slug="provider",
        adapters=[
            discovery_adapter(failing, attempts=2),
            discovery_adapter(FakeDiscovery("silent-search", ())),
            discovery_adapter(FakeDiscovery("fake-search", (DOCS_URL, GUIDE_URL))),
        ],
        fetcher=FakeFetcher(documents),
        extractor=FakeExtractor(
            {
                "registrable_domain": "provider.com",
                "signup_url": SIGNUP_URL,
                "login_url": LOGIN_URL,
            },
            per_document={},
        ),
        store=store,
        facts=facts,
    )

    assert isinstance(outcome, ProviderProfile)
    assert outcome.adapters_engaged == ("fake-search",)
    assert failing.calls == 2
    recorded = [(fact.kind, fact.subject, fact.detail) for fact in facts.facts]
    assert recorded.count(("adapter_failed", "flaky-search", "TimeoutError/attempt=1")) == 1
    assert recorded.count(("adapter_failed", "flaky-search", "TimeoutError/attempt=2")) == 1
    assert ("adapter_returned_nothing", "silent-search", "") in recorded
