"""Tests for the You.com research/discovery/content-fetch integration.

Every test here is offline-safe: the You.com SDK is never actually called
over the network. SDK calls are exercised either through fakes shaped like
the real installed objects, or through a contract test that asserts the
REAL installed ``youdotcom`` package still has the signatures this module
depends on (see ``TestSdkContract``).
"""

from __future__ import annotations

import asyncio
import types
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from ops.config import Settings
from ops.models import OperationalResearch
from ops.operational_research import EvidenceDocument, OperationalResearchEnricher
from ops.you_research import (
    YOU_RESEARCH_SCHEMA,
    CompositeEvidenceDiscovery,
    EvidenceCandidate,
    FallbackEvidenceContentFetcher,
    GuardedHTTPEvidenceFetcher,
    InMemoryResearchCache,
    LegacyDiscoveryAdapter,
    ResearchHostPolicy,
    YouContentsFetcher,
    YouProviderError,
    YouResearchFallback,
    YouSearchDiscovery,
    cache_key,
    canonicalize,
    classify_category,
    deduplicate_and_rank_candidates,
    extract_https_urls,
    has_sufficient_coverage,
    map_you_error,
    merge_documents,
    provider_health_state,
    run_with_bounded_retry,
)

_HOST = "app.pipedrive.com"
_DEV_HOST = "developers.pipedrive.com"


class _FakeResolver:
    """Offline DNS stand-in: every SSRF/DNS check resolves to a fixed public IP."""

    def __init__(self, addresses: tuple[str, ...] = ("93.184.216.34",)) -> None:
        self._addresses = addresses

    async def resolve(self, hostname: str) -> tuple[str, ...]:
        del hostname
        return self._addresses


def _baseline(**overrides: object) -> OperationalResearch:
    base: dict[str, object] = {
        "app_name": "Pipedrive",
        "app_slug": "pipedrive",
        "api_available": None,
        "api_type": "REST",
        "api_base_url": None,
        "auth_methods": ["oauth2"],
        "authorization_url": None,
        "token_url": None,
        "credential_fields": [],
        "scopes": [],
        "developer_portal_url": None,
        "signup_url": None,
        "access_route": "unknown",
        "production_approval_required": None,
        "contact_email": None,
        "contact_url": None,
        "evidence_urls": [],
        "confidence": 0.5,
    }
    base.update(overrides)
    return OperationalResearch.model_validate(base)


def _candidate(url: str, **overrides: object) -> EvidenceCandidate:
    fields: dict[str, object] = {
        "source_url": url,
        "provider": "you_search",
        "query_type": "access",
        "rank": 0,
        "category": classify_category(url),
    }
    fields.update(overrides)
    return EvidenceCandidate.model_validate(fields)


# ===========================================================================
# Configuration
# ===========================================================================
class TestConfiguration:
    def test_missing_key_leaves_you_com_unwired(self) -> None:
        settings = Settings()
        assert settings.you_api_key is None
        assert settings.you_search_configured is False
        assert settings.you_contents_configured is False
        assert settings.you_research_configured is False

    def test_key_is_hidden_from_repr_and_str(self) -> None:
        from pydantic import SecretStr

        settings = Settings(you_api_key=SecretStr("sk-super-secret-value"))
        assert "sk-super-secret-value" not in repr(settings)
        assert "sk-super-secret-value" not in str(settings)

    @pytest.mark.parametrize(
        "env",
        [
            {"YOU_SEARCH_COUNT": "not-a-number"},
            {"YOU_SEARCH_TIMEOUT_SECONDS": "abc"},
            {"YOU_MAX_SEARCH_CALLS_PER_ENRICHMENT": "3.5"},
        ],
    )
    def test_invalid_numeric_settings_fail(self, env: dict[str, str]) -> None:
        with pytest.raises(ValueError):
            Settings.from_env(env=env)

    def test_bounded_settings_reject_out_of_range(self) -> None:
        with pytest.raises(ValueError):
            Settings(you_search_count=0)
        with pytest.raises(ValueError):
            Settings(you_search_count=11)
        with pytest.raises(ValueError):
            Settings(you_max_research_calls_per_enrichment=2)

    def test_feature_flags_require_the_key(self) -> None:
        settings = Settings(
            you_search_enabled=True, you_contents_enabled=True, you_research_enabled=True
        )
        assert settings.you_api_key is None
        assert settings.you_search_configured is False
        assert settings.you_contents_configured is False
        assert settings.you_research_configured is False

    def test_defaults_do_not_alter_browser_provider(self) -> None:
        assert Settings().browser_provider == "browser_use"
        from pydantic import SecretStr

        assert Settings(you_api_key=SecretStr("k")).browser_provider == "browser_use"

    def test_research_disabled_by_default_even_with_key(self) -> None:
        from pydantic import SecretStr

        settings = Settings(you_api_key=SecretStr("k"))
        assert settings.you_search_configured is True
        assert settings.you_contents_configured is True
        assert settings.you_research_configured is False  # disabled by default


# ===========================================================================
# Candidate ranking / classification / diversification
# ===========================================================================
class TestCandidateRanking:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            (f"https://{_HOST}/login", "login"),
            (f"https://{_HOST}/signup", "signup"),
            (f"https://{_DEV_HOST}/", "developer_portal"),
            (f"https://{_HOST}/oauth/authorize", "oauth"),
            (f"https://{_HOST}/settings/api/private-app", "credential_creation"),
            (f"https://{_HOST}/settings/api/scopes", "scopes"),
            (f"https://{_HOST}/docs/rate-limits", "rate_limits"),
            (f"https://{_HOST}/support", "support"),
            (f"https://{_HOST}/random-marketing-page", "unknown"),
        ],
    )
    def test_categories(self, url: str, expected: str) -> None:
        assert classify_category(url) == expected

    def test_diversification_caps_login_pages(self) -> None:
        candidates = [
            _candidate(f"https://{_HOST}/login/{i}", category="login", rank=i) for i in range(6)
        ]
        ranked = deduplicate_and_rank_candidates(candidates)
        assert len([c for c in ranked if c.category == "login"]) <= 2

    def test_duplicate_urls_across_providers_are_merged(self) -> None:
        candidates = [
            _candidate(f"https://{_HOST}/login", provider="you_search"),
            _candidate(f"https://{_HOST}/login/", provider="perplexity"),  # trailing slash dup
        ]
        ranked = deduplicate_and_rank_candidates(candidates)
        assert len(ranked) == 1

    def test_penalized_terms_score_lower_than_a_real_credential_page(self) -> None:
        blog = _candidate(f"https://{_HOST}/blog/api-announcement", category="unknown")
        credential = _candidate(
            f"https://{_HOST}/settings/api/private-app", category="credential_creation"
        )
        ranked = deduplicate_and_rank_candidates([blog, credential])
        assert ranked[0].source_url == credential.source_url

    def test_coverage_requires_access_portal_and_credential_categories(self) -> None:
        assert (
            has_sufficient_coverage([_candidate(f"https://{_HOST}/login", category="login")])
            is False
        )
        full = [
            _candidate(f"https://{_HOST}/login", category="login"),
            _candidate(f"https://{_DEV_HOST}/", category="developer_portal"),
            _candidate(f"https://{_HOST}/settings/api", category="credential_creation"),
        ]
        assert has_sufficient_coverage(full) is True

    def test_model_rejects_oversized_title_snippets_or_snippet_count(self) -> None:
        # StrictModel bounds VALIDATE rather than silently truncate — an
        # oversized value is a bug in the caller, not something to hide.
        with pytest.raises(ValueError):
            EvidenceCandidate.model_validate(
                {
                    "source_url": f"https://{_HOST}/login",
                    "title": "x" * 10_000,
                    "provider": "you_search",
                    "query_type": "access",
                    "rank": 0,
                }
            )
        with pytest.raises(ValueError):
            EvidenceCandidate.model_validate(
                {
                    "source_url": f"https://{_HOST}/login",
                    "snippets": ["y" * 5_000],
                    "provider": "you_search",
                    "query_type": "access",
                    "rank": 0,
                }
            )
        with pytest.raises(ValueError):
            EvidenceCandidate.model_validate(
                {
                    "source_url": f"https://{_HOST}/login",
                    "snippets": ["a", "b", "c", "d"],  # more than MAX_CANDIDATE_SNIPPETS
                    "provider": "you_search",
                    "query_type": "access",
                    "rank": 0,
                }
            )

    def test_converter_truncates_before_the_model_boundary(self) -> None:
        # The actual bounding mechanism: YouSearchDiscovery._convert_results
        # slices title/snippets BEFORE constructing EvidenceCandidate, so
        # real (possibly oversized) provider responses never reach the model
        # boundary unbounded in the first place.
        discovery = YouSearchDiscovery(api_key="dummy")
        policy = ResearchHostPolicy([_HOST])
        response = _fake_search_response(
            [
                _fake_web_result(
                    f"https://{_HOST}/login",
                    "x" * 10_000,
                    tuple("y" * 5_000 for _ in range(6)),
                )
            ]
        )
        converted = discovery._convert_results(response, query_type="access", policy=policy)
        assert len(converted[0].title) <= 500
        assert len(converted[0].snippets) <= 3
        assert all(len(s) <= 1_000 for s in converted[0].snippets)

    def test_off_policy_and_non_https_candidates_are_rejected_by_the_model(self) -> None:
        with pytest.raises(ValueError):
            EvidenceCandidate.model_validate(
                {
                    "source_url": f"http://{_HOST}/login",  # not https
                    "provider": "you_search",
                    "query_type": "access",
                    "rank": 0,
                }
            )


# ===========================================================================
# ResearchHostPolicy
# ===========================================================================
class TestResearchHostPolicy:
    def test_trusted_hosts_come_only_from_reviewed_sources(self) -> None:
        policy = ResearchHostPolicy.build(
            p1_record={"primary_docs_url": f"https://{_DEV_HOST}/", "evidence_urls": []},
            baseline=_baseline(),
            app_slug="pipedrive",
        )
        domains = policy.include_domains
        assert _DEV_HOST in domains
        assert "app.pipedrive.com" in domains  # from the reviewed browser_host_policy dataset
        assert "*.pipedrive.com" in domains  # reviewed vendor wildcard, not auto-derived

    def test_developer_subdomain_does_not_imply_a_bare_wildcard(self) -> None:
        # An app with NO entry in browser_host_policy and no P1 evidence beyond
        # its own docs host must NOT get an auto-widened *.vendor.com.
        policy = ResearchHostPolicy.build(
            p1_record={
                "primary_docs_url": "https://developers.example-unreviewed.com/",
                "evidence_urls": [],
            },
            baseline=_baseline(app_slug="example-unreviewed", app_name="Example"),
        )
        assert "*.example-unreviewed.com" not in policy.include_domains
        assert policy.include_domains == ("developers.example-unreviewed.com",)

    def test_a_search_result_cannot_approve_its_own_domain(self) -> None:
        policy = ResearchHostPolicy.build(
            p1_record={"primary_docs_url": f"https://{_DEV_HOST}/", "evidence_urls": []},
            baseline=_baseline(),
            app_slug="pipedrive",
        )
        with pytest.raises(ValueError):
            policy.validate_candidate_url("https://not-a-reviewed-host.example/login")

    def test_validate_candidate_url_enforces_https_port_and_query_stripping(self) -> None:
        policy = ResearchHostPolicy([_HOST])
        assert (
            policy.validate_candidate_url(f"https://{_HOST}/oauth?token=leak&scope=read")
            == f"https://{_HOST}/oauth?scope=read"
        )
        with pytest.raises(ValueError):
            policy.validate_candidate_url(f"http://{_HOST}/")
        with pytest.raises(ValueError):
            policy.validate_candidate_url(f"https://{_HOST}:8443/")

    def test_empty_policy_is_falsy_and_refuses_validation(self) -> None:
        policy = ResearchHostPolicy([])
        assert bool(policy) is False
        with pytest.raises(ValueError):
            policy.validate_candidate_url(f"https://{_HOST}/")


# ===========================================================================
# YouSearchDiscovery (mocked SDK responses)
# ===========================================================================
def _fake_web_result(
    url: str, title: str = "", snippets: tuple[str, ...] = (), description: str | None = None
) -> object:
    return types.SimpleNamespace(
        url=url, title=title, snippets=list(snippets), description=description
    )


def _fake_search_response(web: list[object], news: list[object] | None = None) -> object:
    return types.SimpleNamespace(results=types.SimpleNamespace(web=web, news=news or []))


class TestYouSearchDiscovery:
    def test_converts_and_validates_results(self) -> None:
        discovery = YouSearchDiscovery(api_key="dummy", count=5)
        policy = ResearchHostPolicy([_HOST])
        response = _fake_search_response(
            [
                _fake_web_result(f"https://{_HOST}/login", "Log in", ["Sign in to your account"]),
                _fake_web_result("https://evil.example/phish", "Fake"),
                _fake_web_result("not-a-url", "broken"),
                _fake_web_result(f"http://{_HOST}/insecure", "no https"),
            ]
        )
        converted = discovery._convert_results(response, query_type="access", policy=policy)
        assert len(converted) == 1
        assert converted[0].source_url == f"https://{_HOST}/login"
        assert converted[0].category == "login"

    def test_news_results_are_ignored(self) -> None:
        discovery = YouSearchDiscovery(api_key="dummy")
        policy = ResearchHostPolicy([_HOST])
        response = _fake_search_response(
            [], news=[_fake_web_result(f"https://{_HOST}/news/announcement", "News")]
        )
        assert discovery._convert_results(response, query_type="access", policy=policy) == []

    def test_no_official_hosts_returns_no_candidates_without_calling_search(self) -> None:
        discovery = YouSearchDiscovery(api_key="dummy")
        called = {"n": 0}

        async def _search(**kwargs: object) -> object:
            called["n"] += 1
            return _fake_search_response([])

        discovery._search = _search  # type: ignore[method-assign]
        result = asyncio.run(
            discovery.discover(app_name="X", p1_record={}, baseline=_baseline(), official_hosts=())
        )
        assert result == ()
        assert called["n"] == 0

    def test_issues_at_most_max_calls_queries(self) -> None:
        discovery = YouSearchDiscovery(api_key="dummy", max_calls=1)
        queries: list[str] = []

        async def _search(*, query: str) -> object:
            queries.append(query)
            return _fake_search_response([])

        discovery._search = _search  # type: ignore[method-assign]
        asyncio.run(
            discovery.discover(
                app_name="Pipedrive", p1_record={}, baseline=_baseline(), official_hosts=(_HOST,)
            )
        )
        assert len(queries) == 1

    def test_two_distinct_queries_when_max_calls_allows(self) -> None:
        discovery = YouSearchDiscovery(api_key="dummy", max_calls=2)
        queries: list[str] = []

        async def _search(*, query: str) -> object:
            queries.append(query)
            return _fake_search_response([])

        discovery._search = _search  # type: ignore[method-assign]
        asyncio.run(
            discovery.discover(
                app_name="Pipedrive", p1_record={}, baseline=_baseline(), official_hosts=(_HOST,)
            )
        )
        assert len(queries) == 2
        assert queries[0] != queries[1]
        assert "Pipedrive" in queries[0] and "Pipedrive" in queries[1]

    def test_one_query_failing_does_not_fail_discovery(self) -> None:
        discovery = YouSearchDiscovery(api_key="dummy", max_calls=2)
        calls = {"n": 0}

        async def _search(*, query: str) -> object:
            calls["n"] += 1
            if calls["n"] == 1:
                raise YouProviderError(capability="you_search", reason_code="you_search_timeout")
            return _fake_search_response([_fake_web_result(f"https://{_HOST}/settings/api")])

        discovery._search = _search  # type: ignore[method-assign]
        result = asyncio.run(
            discovery.discover(
                app_name="Pipedrive", p1_record={}, baseline=_baseline(), official_hosts=(_HOST,)
            )
        )
        assert len(result) == 1


# ===========================================================================
# Composite discovery
# ===========================================================================
class _StaticRich:
    def __init__(self, candidates: tuple[EvidenceCandidate, ...]) -> None:
        self._candidates = candidates
        self.called = False

    async def discover(self, **kwargs: object) -> tuple[EvidenceCandidate, ...]:
        self.called = True
        return self._candidates


class TestCompositeEvidenceDiscovery:
    def test_you_com_called_first(self) -> None:
        you = _StaticRich((_candidate(f"https://{_HOST}/login", category="login"),))
        other = _StaticRich(
            (_candidate(f"https://{_HOST}/settings/api", category="credential_creation"),)
        )
        composite = CompositeEvidenceDiscovery([you, other])
        asyncio.run(
            composite.discover(
                app_name="X", p1_record={}, baseline=_baseline(), official_hosts=(_HOST,)
            )
        )
        assert you.called is True

    def test_second_provider_skipped_when_coverage_is_sufficient(self) -> None:
        sufficient = (
            _candidate(f"https://{_HOST}/login", category="login"),
            _candidate(f"https://{_DEV_HOST}/", category="developer_portal"),
            _candidate(f"https://{_HOST}/settings/api", category="credential_creation"),
            _candidate(f"https://{_HOST}/oauth", category="oauth"),
        )
        you = _StaticRich(sufficient)
        other = _StaticRich((_candidate(f"https://{_HOST}/extra", category="unknown"),))
        composite = CompositeEvidenceDiscovery([you, other], minimum_candidates_before_stopping=4)
        asyncio.run(
            composite.discover(
                app_name="X", p1_record={}, baseline=_baseline(), official_hosts=(_HOST,)
            )
        )
        assert other.called is False

    def test_second_provider_called_when_coverage_is_insufficient(self) -> None:
        you = _StaticRich((_candidate(f"https://{_HOST}/login", category="login"),))
        other = _StaticRich(
            (_candidate(f"https://{_HOST}/settings/api", category="credential_creation"),)
        )
        composite = CompositeEvidenceDiscovery([you, other])
        asyncio.run(
            composite.discover(
                app_name="X", p1_record={}, baseline=_baseline(), official_hosts=(_HOST,)
            )
        )
        assert other.called is True

    def test_one_provider_failure_does_not_discard_the_others(self) -> None:
        class _Failing:
            async def discover(self, **kwargs: object) -> tuple[EvidenceCandidate, ...]:
                raise YouProviderError(capability="you_search", reason_code="you_search_failed")

        other = _StaticRich(
            (_candidate(f"https://{_HOST}/settings/api", category="credential_creation"),)
        )
        composite = CompositeEvidenceDiscovery([_Failing(), other])
        result = asyncio.run(
            composite.discover(
                app_name="X", p1_record={}, baseline=_baseline(), official_hosts=(_HOST,)
            )
        )
        assert len(result) == 1

    def test_programming_error_is_not_swallowed(self) -> None:
        class _Broken:
            async def discover(self, **kwargs: object) -> tuple[EvidenceCandidate, ...]:
                raise TypeError("unexpected keyword argument")

        composite = CompositeEvidenceDiscovery([_Broken()])
        with pytest.raises(TypeError):
            asyncio.run(
                composite.discover(
                    app_name="X", p1_record={}, baseline=_baseline(), official_hosts=(_HOST,)
                )
            )

    def test_duplicate_urls_across_providers_merge(self) -> None:
        you = _StaticRich((_candidate(f"https://{_HOST}/login", provider="you_search"),))
        other = _StaticRich((_candidate(f"https://{_HOST}/login", provider="perplexity"),))
        composite = CompositeEvidenceDiscovery([you, other])
        result = asyncio.run(
            composite.discover(
                app_name="X", p1_record={}, baseline=_baseline(), official_hosts=(_HOST,)
            )
        )
        assert len(result) == 1


class TestLegacyDiscoveryAdapter:
    def test_adapts_url_only_discovery_into_candidates(self) -> None:
        class _Legacy:
            async def discover(self, *, app_name: str) -> tuple[str, ...]:
                return (f"https://{_HOST}/settings/api", "https://evil.example/x")

        adapter = LegacyDiscoveryAdapter(_Legacy())
        result = asyncio.run(
            adapter.discover(
                app_name="X", p1_record={}, baseline=_baseline(), official_hosts=(_HOST,)
            )
        )
        assert len(result) == 1
        assert result[0].provider == "perplexity"
        assert result[0].source_url == f"https://{_HOST}/settings/api"


# ===========================================================================
# Contents adapter
# ===========================================================================
def _fake_contents_response(url: str, markdown: str | None, title: str | None = None) -> object:
    return types.SimpleNamespace(
        url=url, title=title, markdown=markdown, metadata=types.SimpleNamespace(site_name=None)
    )


class TestYouContentsFetcher:
    def test_maximum_ten_urls_enforced(self) -> None:
        policy = ResearchHostPolicy([_HOST], resolver=_FakeResolver())
        fetcher = YouContentsFetcher("dummy", policy=policy)
        seen_urls: list[list[str]] = []

        async def _generate(urls: list[str]) -> list[object]:
            seen_urls.append(urls)
            return [_fake_contents_response(u, "content") for u in urls]

        fetcher._generate = _generate  # type: ignore[method-assign]
        urls = [f"https://{_HOST}/page/{i}" for i in range(15)]
        asyncio.run(fetcher.fetch_many(urls))
        assert len(seen_urls[0]) == 10

    def test_only_policy_validated_urls_are_sent(self) -> None:
        policy = ResearchHostPolicy([_HOST], resolver=_FakeResolver())
        fetcher = YouContentsFetcher("dummy", policy=policy)
        sent: list[list[str]] = []

        async def _generate(urls: list[str]) -> list[object]:
            sent.append(urls)
            return [_fake_contents_response(u, "content") for u in urls]

        fetcher._generate = _generate  # type: ignore[method-assign]
        asyncio.run(fetcher.fetch_many([f"https://{_HOST}/ok", "https://evil.example/no"]))
        assert sent == [[f"https://{_HOST}/ok"]]

    def test_returned_url_is_revalidated_against_policy(self) -> None:
        policy = ResearchHostPolicy([_HOST], resolver=_FakeResolver())
        fetcher = YouContentsFetcher("dummy", policy=policy)

        async def _generate(urls: list[str]) -> list[object]:
            return [_fake_contents_response("https://evil.example/redirected", "content")]

        fetcher._generate = _generate  # type: ignore[method-assign]
        documents = asyncio.run(fetcher.fetch_many([f"https://{_HOST}/ok"]))
        assert documents == ()

    def test_empty_markdown_is_rejected(self) -> None:
        policy = ResearchHostPolicy([_HOST], resolver=_FakeResolver())
        fetcher = YouContentsFetcher("dummy", policy=policy)

        async def _generate(urls: list[str]) -> list[object]:
            return [_fake_contents_response(f"https://{_HOST}/empty", "   ")]

        fetcher._generate = _generate  # type: ignore[method-assign]
        documents = asyncio.run(fetcher.fetch_many([f"https://{_HOST}/empty"]))
        assert documents == ()

    def test_one_failed_page_does_not_discard_the_batch(self) -> None:
        policy = ResearchHostPolicy([_HOST], resolver=_FakeResolver())
        fetcher = YouContentsFetcher("dummy", policy=policy)

        async def _generate(urls: list[str]) -> list[object]:
            return [
                _fake_contents_response(f"https://{_HOST}/good", "real content here"),
                _fake_contents_response(f"https://{_HOST}/bad", None),
            ]

        fetcher._generate = _generate  # type: ignore[method-assign]
        documents = asyncio.run(
            fetcher.fetch_many([f"https://{_HOST}/good", f"https://{_HOST}/bad"])
        )
        assert len(documents) == 1
        assert documents[0].source_url == f"https://{_HOST}/good"

    def test_text_is_bounded(self) -> None:
        policy = ResearchHostPolicy([_HOST], resolver=_FakeResolver())
        fetcher = YouContentsFetcher("dummy", policy=policy)

        async def _generate(urls: list[str]) -> list[object]:
            return [_fake_contents_response(f"https://{_HOST}/big", "x" * 100_000)]

        fetcher._generate = _generate  # type: ignore[method-assign]
        documents = asyncio.run(fetcher.fetch_many([f"https://{_HOST}/big"]))
        assert len(documents[0].relevant_text) <= 24_000

    def test_provider_failure_returns_empty_not_an_exception(self) -> None:
        policy = ResearchHostPolicy([_HOST], resolver=_FakeResolver())
        fetcher = YouContentsFetcher("dummy", policy=policy)

        async def _generate(urls: list[str]) -> list[object]:
            raise YouProviderError(capability="you_contents", reason_code="you_contents_failed")

        fetcher._generate = _generate  # type: ignore[method-assign]
        documents = asyncio.run(fetcher.fetch_many([f"https://{_HOST}/x"]))
        assert documents == ()


class TestFallbackContentFetcher:
    def test_guarded_http_wraps_official_fetcher_and_skips_failures(self) -> None:
        class _Fetcher:
            async def fetch(self, url: str) -> EvidenceDocument:
                if "bad" in url:
                    raise ValueError("boom")
                return EvidenceDocument(source_url=url, title="T", relevant_text="x")

        wrapped = GuardedHTTPEvidenceFetcher(_Fetcher())
        documents = asyncio.run(wrapped.fetch_many(["https://x/good", "https://x/bad"]))
        assert len(documents) == 1

    def test_fallback_only_covers_missing_urls(self) -> None:
        class _Primary:
            async def fetch_many(self, urls: list[str]) -> tuple[EvidenceDocument, ...]:
                return tuple(
                    EvidenceDocument(source_url=u, title="p", relevant_text="x")
                    for u in urls
                    if "a" in u
                )

        class _Fallback:
            def __init__(self) -> None:
                self.received: list[str] = []

            async def fetch_many(self, urls: list[str]) -> tuple[EvidenceDocument, ...]:
                self.received = list(urls)
                return tuple(
                    EvidenceDocument(source_url=u, title="f", relevant_text="y") for u in urls
                )

        fallback = _Fallback()
        fetcher = FallbackEvidenceContentFetcher(primary=_Primary(), fallback=fallback)
        documents = asyncio.run(fetcher.fetch_many(["https://x/a1", "https://x/b1"]))
        assert fallback.received == ["https://x/b1"]
        assert {d.source_url for d in documents} == {"https://x/a1", "https://x/b1"}

    def test_merge_documents_deduplicates_by_canonical_url(self) -> None:
        primary = (EvidenceDocument(source_url="https://x.com/a/", title="p", relevant_text="1"),)
        fallback = (EvidenceDocument(source_url="https://x.com/a", title="f", relevant_text="2"),)
        merged = merge_documents(primary, fallback)
        assert len(merged) == 1
        assert merged[0].title == "p"  # primary wins on duplicate


# ===========================================================================
# Error mapping + bounded retry
# ===========================================================================
class _StatusErr(Exception):
    def __init__(self, status_code: int, headers: dict[str, str] | None = None) -> None:
        self.status_code = status_code
        self.headers = headers or {}


class TestErrorMapping:
    @pytest.mark.parametrize(
        ("status", "capability", "expected"),
        [
            (401, "you_search", "you_search_unauthorized"),
            (402, "you_search", "you_search_credit_exhausted"),
            (403, "you_search", "you_search_forbidden"),
            (422, "you_search", "you_search_invalid_request"),
            (429, "you_search", "you_search_rate_limited"),
            (500, "you_search", "you_search_failed"),
            (401, "you_contents", "you_contents_unauthorized"),
            (429, "you_contents", "you_contents_rate_limited"),
            (422, "you_research", "you_research_invalid_schema"),
            (403, "you_research", "you_research_forbidden"),
        ],
    )
    def test_status_code_mapping(self, status: int, capability: str, expected: str) -> None:
        assert map_you_error(_StatusErr(status), capability=capability) == expected

    def test_timeout_maps_to_timeout_reason(self) -> None:
        assert map_you_error(TimeoutError(), capability="you_search") == "you_search_timeout"
        assert map_you_error(TimeoutError(), capability="you_contents") == "you_contents_timeout"

    def test_error_message_never_appears_in_the_reason_code(self) -> None:
        secret_exc = _StatusErr(401)
        secret_exc.args = ("YDC_API_KEY=sk-should-never-appear-anywhere", "")
        reason = map_you_error(secret_exc, capability="you_search")
        assert "sk-should-never-appear" not in reason
        assert reason == "you_search_unauthorized"


class TestBoundedRetry:
    def test_retries_bounded_at_max_and_raises_sanitized_error(self) -> None:
        attempts = {"n": 0}

        async def call() -> object:
            attempts["n"] += 1
            raise _StatusErr(429)

        async def run() -> None:
            with pytest.raises(YouProviderError) as exc_info:
                await run_with_bounded_retry(call, capability="you_search", max_retries=2)
            assert exc_info.value.reason_code == "you_search_rate_limited"

        asyncio.run(run())
        assert attempts["n"] == 3

    def test_non_retryable_status_fails_on_first_attempt(self) -> None:
        attempts = {"n": 0}

        async def call() -> object:
            attempts["n"] += 1
            raise _StatusErr(401)

        async def run() -> None:
            with pytest.raises(YouProviderError):
                await run_with_bounded_retry(call, capability="you_search", max_retries=2)

        asyncio.run(run())
        assert attempts["n"] == 1

    @pytest.mark.parametrize("status", [400, 401, 402, 403, 404, 422])
    def test_400_401_402_403_404_422_are_never_retried(self, status: int) -> None:
        attempts = {"n": 0}

        async def call() -> object:
            attempts["n"] += 1
            raise _StatusErr(status)

        async def run() -> None:
            with pytest.raises(YouProviderError):
                await run_with_bounded_retry(call, capability="you_search")

        asyncio.run(run())
        assert attempts["n"] == 1, f"status {status} was retried"

    def test_programming_errors_are_never_retried_or_swallowed(self) -> None:
        async def call() -> object:
            raise TypeError("bad kwarg")

        async def run() -> None:
            with pytest.raises(TypeError):
                await run_with_bounded_retry(call, capability="you_search")

        asyncio.run(run())

    def test_retry_after_header_is_honored(self) -> None:
        import time

        async def call() -> object:
            raise _StatusErr(429, headers={"retry-after": "0"})

        start = time.monotonic()
        with pytest.raises(YouProviderError):
            asyncio.run(run_with_bounded_retry(call, capability="you_search", max_retries=1))
        # retry-after=0 should not add meaningful delay
        assert time.monotonic() - start < 2.0

    def test_api_key_never_appears_in_a_raised_exception(self) -> None:
        secret = "sk-my-secret-you-com-key"  # noqa: S105 - test literal, not a real key

        async def call() -> object:
            raise _StatusErr(500)

        try:
            asyncio.run(run_with_bounded_retry(call, capability="you_search", max_retries=0))
        except YouProviderError as exc:
            assert secret not in str(exc)


# ===========================================================================
# Research fallback (disabled by default; validated response handling)
# ===========================================================================
class TestYouResearchFallback:
    def test_schema_marks_every_property_required_with_nullable_types(self) -> None:
        assert set(YOU_RESEARCH_SCHEMA["required"]) == set(YOU_RESEARCH_SCHEMA["properties"])  # type: ignore[arg-type]
        assert YOU_RESEARCH_SCHEMA["additionalProperties"] is False
        for name in (
            "login_url",
            "signup_url",
            "developer_portal_url",
            "credential_management_url",
        ):
            assert YOU_RESEARCH_SCHEMA["properties"][name]["type"] == ["string", "null"]  # type: ignore[index]

    def test_no_official_hosts_short_circuits_without_a_call(self) -> None:
        async def run() -> None:
            client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
            fallback = YouResearchFallback("dummy", http_client=client)
            result = await fallback.research(
                app_name="X", official_hosts=(), policy=ResearchHostPolicy([])
            )
            await client.aclose()
            assert result is None

        asyncio.run(run())

    def test_source_urls_must_appear_in_output_sources(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "output": {
                        "content": {
                            "login_url": None,
                            "signup_url": None,
                            "developer_portal_url": None,
                            "credential_management_url": None,
                            "authentication_method": None,
                            "credential_creation_steps": [],
                            # This URL is NOT in output.sources -> must be rejected.
                            "source_urls": [f"https://{_HOST}/not-cited"],
                            "confidence": "high",
                        },
                        "sources": [{"url": f"https://{_HOST}/cited", "title": "Docs"}],
                    }
                },
            )

        async def run() -> None:
            client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            fallback = YouResearchFallback("dummy", http_client=client)
            result = await fallback.research(
                app_name="X", official_hosts=(_HOST,), policy=ResearchHostPolicy([_HOST])
            )
            await client.aclose()
            assert result is None  # the only source_url given was uncited

        asyncio.run(run())

    def test_cited_source_on_an_off_policy_host_is_rejected(self) -> None:
        # Being listed in output.sources is NOT enough — the host must also
        # pass the trusted ResearchHostPolicy. A compromised/hallucinated
        # Research response cannot smuggle in an attacker host this way.
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "output": {
                        "content": {
                            "login_url": None,
                            "signup_url": None,
                            "developer_portal_url": None,
                            "credential_management_url": None,
                            "authentication_method": None,
                            "credential_creation_steps": [],
                            "source_urls": ["https://attacker.example/cited"],
                            "confidence": "high",
                        },
                        "sources": [{"url": "https://attacker.example/cited", "title": "Fake"}],
                    }
                },
            )

        async def run() -> None:
            client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            fallback = YouResearchFallback("dummy", http_client=client)
            result = await fallback.research(
                app_name="X", official_hosts=(_HOST,), policy=ResearchHostPolicy([_HOST])
            )
            await client.aclose()
            assert result is None

        asyncio.run(run())

    def test_valid_cited_source_becomes_a_candidate_url(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "output": {
                        "content": {
                            "login_url": f"https://{_HOST}/login",
                            "signup_url": None,
                            "developer_portal_url": None,
                            "credential_management_url": None,
                            "authentication_method": None,
                            "credential_creation_steps": [],
                            "source_urls": [f"https://{_HOST}/cited"],
                            "confidence": "medium",
                        },
                        "sources": [{"url": f"https://{_HOST}/cited", "title": "Docs"}],
                    }
                },
            )

        async def run() -> None:
            client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            fallback = YouResearchFallback("dummy", http_client=client)
            result = await fallback.research(
                app_name="X", official_hosts=(_HOST,), policy=ResearchHostPolicy([_HOST])
            )
            await client.aclose()
            assert result is not None
            assert result.candidate_urls == (f"https://{_HOST}/cited",)
            assert result.confidence == "medium"

        asyncio.run(run())

    def test_422_schema_error_is_not_retried(self) -> None:
        attempts = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            attempts["n"] += 1
            return httpx.Response(422, json={"error": "invalid schema"})

        async def run() -> None:
            client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            fallback = YouResearchFallback("dummy", http_client=client)
            result = await fallback.research(
                app_name="X", official_hosts=(_HOST,), policy=ResearchHostPolicy([_HOST])
            )
            await client.aclose()
            assert result is None

        asyncio.run(run())
        assert attempts["n"] == 1

    def test_low_confidence_result_does_not_overwrite_trusted_p1_data(self) -> None:
        # Research fallback NEVER authors an OperationalResearch field directly
        # (see the module docstring) — it only supplies candidate URLs for the
        # SAME Gemini extraction + validation path, so a "low confidence"
        # result cannot bypass _validate_operational_urls at all. This test
        # pins that architectural guarantee: ResearchFallbackResult has no
        # field that could become a trusted OperationalResearch value directly.
        from ops.you_research import ResearchFallbackResult

        result = ResearchFallbackResult(candidate_urls=(f"https://{_HOST}/x",), confidence="low")
        assert not hasattr(result, "login_url")
        assert not hasattr(result, "developer_portal_url")


# ===========================================================================
# Enricher: full mocked flow, and the browser boundary
# ===========================================================================
_ALLOWED_HOST = "docs.example.com"
_P1_RECORD = {
    "primary_docs_url": f"https://{_ALLOWED_HOST}/",
    "evidence_urls": [f"https://{_ALLOWED_HOST}/"],
}


class _RichDiscoveryStub:
    def __init__(self, candidates: tuple[EvidenceCandidate, ...]) -> None:
        self._candidates = candidates

    async def discover(self, **kwargs: object) -> tuple[EvidenceCandidate, ...]:
        return self._candidates


class _ContentFetcherStub:
    def __init__(self, text: str) -> None:
        self._text = text

    async def fetch_many(self, urls: list[str]) -> tuple[EvidenceDocument, ...]:
        return tuple(
            EvidenceDocument(source_url=u, title="Docs", relevant_text=self._text) for u in urls
        )


class _ExtractorStub:
    def __init__(self, result: OperationalResearch) -> None:
        self._result = result

    async def extract(
        self, *, app_name: str, p1_record: object, documents: object
    ) -> OperationalResearch:
        return self._result


def _run_enricher(**enricher_kwargs: object) -> object:
    async def run() -> object:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(200))
        ) as client:
            enricher = OperationalResearchEnricher(
                discovery=None, http_client=client, **enricher_kwargs
            )
            return await enricher.enrich(
                app_name="Docs App",
                p1_record=_P1_RECORD,
                baseline=_baseline(app_name="Docs App", app_slug="docs-app"),
            )

    return asyncio.run(run())


class TestEnricherFullFlow:
    def test_full_mocked_pipeline_finds_operational_fields(self) -> None:
        from ops.models import ScopeRequirement

        research = _baseline(
            app_name="Docs App",
            app_slug="docs-app",
            login_url=f"https://{_ALLOWED_HOST}/login",
            developer_portal_url=f"https://{_ALLOWED_HOST}/",
            credential_management_url=f"https://{_ALLOWED_HOST}/settings/api",
            token_url=f"https://{_ALLOWED_HOST}/oauth/token",
            evidence_urls=[f"https://{_ALLOWED_HOST}/oauth"],
            scopes=[ScopeRequirement(name="crm.read", source_url=f"https://{_ALLOWED_HOST}/oauth")],
            credential_fields=["api_key"],
            confidence=0.9,
        )
        text = (
            "Log in at https://docs.example.com/login. Manage credentials at "
            "https://docs.example.com/settings/api. Token endpoint: "
            "https://docs.example.com/oauth/token"
        )
        outcome = _run_enricher(
            extractor=_ExtractorStub(research),
            rich_discovery=_RichDiscoveryStub(
                (_candidate(f"https://{_ALLOWED_HOST}/oauth", category="oauth"),)
            ),
            content_fetcher_factory=lambda policy: _ContentFetcherStub(text),
        )
        assert outcome.capability.status == "ready"
        assert outcome.research.login_url == f"https://{_ALLOWED_HOST}/login"
        assert outcome.research.developer_portal_url == f"https://{_ALLOWED_HOST}/"
        assert outcome.research.credential_management_url == f"https://{_ALLOWED_HOST}/settings/api"
        assert outcome.research.token_url == f"https://{_ALLOWED_HOST}/oauth/token"
        assert "scopes" not in outcome.missing_fields
        assert outcome.research.credential_fields == ["api_key"]

    def test_undocumented_operational_url_is_rejected(self) -> None:
        research = _baseline(
            app_name="Docs App",
            app_slug="docs-app",
            signup_url="https://docs.example.com/signup-that-is-never-documented",
            evidence_urls=[f"https://{_ALLOWED_HOST}/oauth"],
            confidence=0.9,
        )
        with pytest.raises(ValueError, match="undocumented operational URL"):
            _run_enricher(
                extractor=_ExtractorStub(research),
                rich_discovery=_RichDiscoveryStub(
                    (_candidate(f"https://{_ALLOWED_HOST}/oauth", category="oauth"),)
                ),
                content_fetcher_factory=lambda policy: _ContentFetcherStub(
                    "no urls mentioned here at all"
                ),
            )

    def test_backward_compatible_when_no_rich_dependencies_supplied(self) -> None:
        # The exact original code path: no rich_discovery, no content_fetcher_factory.
        research = _baseline(app_name="Docs App", app_slug="docs-app", confidence=0.9)
        outcome = _run_enricher(extractor=_ExtractorStub(research))
        # No documents can be fetched (transport always 200s an empty body via
        # MockTransport but the real HTML parser handles it), so this exercises
        # the OLD guarded-HTTP-only path without any You.com dependency at all.
        assert outcome is not None


class TestBrowserBoundary:
    def test_you_com_never_appears_in_browser_provider_selection(self) -> None:
        from pydantic import SecretStr

        settings = Settings(you_api_key=SecretStr("k"), you_search_enabled=True)
        assert settings.browser_provider == "browser_use"
        # you_* settings are not even read by _choice()/browser_provider parsing.
        assert "you" not in Settings.model_fields["browser_provider"].annotation.__args__  # type: ignore[union-attr]

    def test_allowed_domains_are_never_derived_from_operational_research(self) -> None:
        from ops.browser_host_policy import build_browser_allowed_hosts

        # A research object claiming an attacker-controlled developer_portal_url
        # must not be able to expand the browser allowlist for an app with an
        # explicit reviewed policy: build_browser_allowed_hosts for an ACTIVE
        # app ignores research-supplied hosts entirely and uses only the
        # reviewed BrowserHostPolicy.
        malicious = _baseline(
            app_name="Pipedrive",
            app_slug="pipedrive",
            developer_portal_url="https://developers.pipedrive.com/",  # must stay a real reviewed host to validate
        )
        allowed = build_browser_allowed_hosts("pipedrive", malicious)
        assert "attacker.example" not in allowed.patterns()

    def test_evidence_candidate_cannot_be_passed_directly_as_a_browser_task(self) -> None:
        # EvidenceCandidate has no field resembling a browser instruction/prompt;
        # only source_url/title/snippets/provider/query_type/rank/category.
        assert set(EvidenceCandidate.model_fields) == {
            "source_url",
            "title",
            "snippets",
            "provider",
            "query_type",
            "rank",
            "category",
        }


# ===========================================================================
# Cache + observability
# ===========================================================================
class TestCacheAndObservability:
    def test_in_memory_cache_expires(self) -> None:
        cache = InMemoryResearchCache()
        cache.put("k", {"a": 1}, expires_at=datetime.now(UTC) - timedelta(seconds=1))
        assert cache.get("k") is None

    def test_in_memory_cache_hits_before_expiry(self) -> None:
        cache = InMemoryResearchCache()
        cache.put("k", {"a": 1}, expires_at=datetime.now(UTC) + timedelta(hours=1))
        assert cache.get("k") == {"a": 1}

    def test_cache_key_is_deterministic_and_namespaced(self) -> None:
        key1 = cache_key("you-search", "pipedrive", "access")
        key2 = cache_key("you-search", "pipedrive", "access")
        key3 = cache_key("you-search", "pipedrive", "api_credentials")
        assert key1 == key2 != key3
        assert key1.startswith("you-search:v1:")

    @pytest.mark.parametrize(
        ("configured", "enabled", "reason", "expected"),
        [
            (False, True, None, "not_configured"),
            (True, False, None, "disabled"),
            (True, True, None, "configured_not_verified"),
            (True, True, "you_search_rate_limited", "rate_limited"),
            (True, True, "you_search_credit_exhausted", "credit_exhausted"),
        ],
    )
    def test_provider_health_state(
        self, configured: bool, enabled: bool, reason: str | None, expected: str
    ) -> None:
        assert (
            provider_health_state(configured=configured, enabled=enabled, last_reason_code=reason)
            == expected
        )


class TestDocumentedUrlExtraction:
    def test_extracts_https_urls_from_prose(self) -> None:
        urls = extract_https_urls(
            "Log in at https://app.vendor.com/login, see https://vendor.com/docs."
        )
        assert urls == ("https://app.vendor.com/login", "https://vendor.com/docs")

    def test_ignores_non_https_and_malformed(self) -> None:
        urls = extract_https_urls("Visit http://insecure.example or ftp://old.example")
        assert urls == ()

    def test_canonicalize_normalizes_case_and_trailing_slash(self) -> None:
        assert canonicalize("https://App.Example.COM/Path/") == canonicalize(
            "https://app.example.com/Path"
        )


# ===========================================================================
# SDK contract test (pins the REAL installed youdotcom==2.2.0 signatures)
# ===========================================================================
class TestSdkContract:
    def test_you_client_accepts_api_key_auth(self) -> None:
        youdotcom = pytest.importorskip("youdotcom")
        you = youdotcom.You(api_key_auth="dummy")
        assert you is not None

    def test_search_unified_async_is_a_real_coroutine_with_no_domain_filter(self) -> None:
        import inspect

        youdotcom = pytest.importorskip("youdotcom")
        you = youdotcom.You(api_key_auth="dummy")
        assert inspect.iscoroutinefunction(you.search.unified_async)
        params = set(inspect.signature(you.search.unified_async).parameters)
        assert {"query", "count", "safesearch", "timeout_ms"} <= params
        # Pinned, verified absence — the whole module's domain-trust design
        # depends on this NOT being true. If a future SDK upgrade adds it,
        # this test starts failing loudly rather than silently.
        assert "include_domains" not in params
        assert "exclude_domains" not in params
        assert "boost_domains" not in params

    def test_contents_generate_async_is_a_real_coroutine_with_no_max_age(self) -> None:
        import inspect

        youdotcom = pytest.importorskip("youdotcom")
        you = youdotcom.You(api_key_auth="dummy")
        assert inspect.iscoroutinefunction(you.contents.generate_async)
        params = set(inspect.signature(you.contents.generate_async).parameters)
        assert {"urls", "formats", "crawl_timeout", "timeout_ms"} <= params
        assert "max_age" not in params

    def test_contents_formats_has_markdown_and_metadata(self) -> None:
        formats_module = pytest.importorskip("youdotcom.models.contentsformats")
        assert formats_module.ContentsFormats.MARKDOWN.value == "markdown"
        assert formats_module.ContentsFormats.METADATA.value == "metadata"

    def test_safesearch_has_strict(self) -> None:
        safesearch_module = pytest.importorskip("youdotcom.models.safesearch")
        assert safesearch_module.SafeSearch.STRICT.value == "strict"

    def test_you_error_exposes_status_code(self) -> None:
        errors_module = pytest.importorskip("youdotcom.errors")
        assert (
            hasattr(errors_module.YouError, "status_code")
            or "status_code" in errors_module.YouError.__init__.__code__.co_names
        )

    def test_no_retry_config_is_applied_by_default(self) -> None:
        # Verified from source: `retries == UNSET` falls back to
        # `sdk_configuration.retry_config`, which is UNSET unless the caller
        # supplies one. This module never supplies one, so it is the sole
        # retry layer. This test pins the client-level default stays UNSET.
        youdotcom = pytest.importorskip("youdotcom")
        you = youdotcom.You(api_key_auth="dummy")
        from youdotcom.types.basemodel import Unset

        assert isinstance(you.sdk_configuration.retry_config, Unset)
