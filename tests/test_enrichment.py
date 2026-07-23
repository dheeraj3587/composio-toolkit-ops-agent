"""Offline guards for the one-probe official-evidence enrichment boundary.

Every test here is offline-safe: DNS resolution is faked and all HTTP traffic is
served by an in-process ``httpx.MockTransport``. No live provider is contacted.
"""

from __future__ import annotations

import httpx
import pytest

from ops.models import CapabilityAvailability, OperationalResearch, ScopeRequirement
from ops.operational_research import (
    EvidenceDocument,
    OfficialEvidenceFetcher,
    OfficialURLPolicy,
    OperationalResearchEnricher,
)

PUBLIC_ADDRESS = ("93.184.216.34",)
ALLOWED_HOST = "docs.example.com"
P1_RECORD = {
    "primary_docs_url": f"https://{ALLOWED_HOST}/",
    "evidence_urls": [f"https://{ALLOWED_HOST}/"],
}


class _FakeResolver:
    def __init__(self, addresses: tuple[str, ...]) -> None:
        self._addresses = addresses

    async def resolve(self, hostname: str) -> tuple[str, ...]:
        del hostname
        return self._addresses


class _FakeDiscovery:
    def __init__(self, urls: tuple[str, ...]) -> None:
        self._urls = urls

    async def discover(self, *, app_name: str) -> tuple[str, ...]:
        del app_name
        return self._urls


class _FakeExtractor:
    def __init__(self, research: OperationalResearch) -> None:
        self._research = research

    async def extract(self, *, app_name, p1_record, documents) -> OperationalResearch:  # type: ignore[no-untyped-def]
        del app_name, p1_record, documents
        return self._research


def _research(**overrides: object) -> OperationalResearch:
    base: dict[str, object] = {
        "app_name": "Docs App",
        "app_slug": "docs-app",
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


def _policy(addresses: tuple[str, ...] = PUBLIC_ADDRESS) -> OfficialURLPolicy:
    return OfficialURLPolicy([ALLOWED_HOST], resolver=_FakeResolver(addresses))


def test_sanitize_candidate_enforces_https_allowlist_port_and_strips_secrets() -> None:
    policy = _policy()

    assert (
        policy.sanitize_candidate(f"https://{ALLOWED_HOST}/oauth?token=leak&scope=read")
        == f"https://{ALLOWED_HOST}/oauth?scope=read"
    )
    with pytest.raises(ValueError):
        policy.sanitize_candidate(f"http://{ALLOWED_HOST}/")
    with pytest.raises(ValueError):
        policy.sanitize_candidate("https://evil.example.net/")
    with pytest.raises(ValueError):
        policy.sanitize_candidate(f"https://{ALLOWED_HOST}:8443/")


@pytest.mark.parametrize("addresses", [("127.0.0.1",), ("10.0.0.5",), ("169.254.1.1",)])
async def test_validate_for_request_rejects_non_public_resolution(
    addresses: tuple[str, ...],
) -> None:
    policy = _policy(addresses)
    with pytest.raises(ValueError):
        await policy.validate_for_request(f"https://{ALLOWED_HOST}/oauth")


async def test_fetcher_rejects_redirect_outside_the_allowlist() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example.net/"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        fetcher = OfficialEvidenceFetcher(client, _policy())
        with pytest.raises(ValueError):
            await fetcher.fetch(f"https://{ALLOWED_HOST}/oauth")


async def test_fetcher_rejects_unsupported_content_type() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "application/pdf"}, content=b"%PDF-")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        fetcher = OfficialEvidenceFetcher(client, _policy())
        with pytest.raises(ValueError):
            await fetcher.fetch(f"https://{ALLOWED_HOST}/oauth")


async def test_fetcher_rejects_oversized_declared_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/html", "content-length": str(1024 * 1024)},
            text="<html></html>",
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        fetcher = OfficialEvidenceFetcher(client, _policy())
        with pytest.raises(ValueError):
            await fetcher.fetch(f"https://{ALLOWED_HOST}/oauth")


async def test_fetcher_returns_bounded_document_for_allowlisted_html() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/html; charset=utf-8"},
            text="<html><head><title>OAuth</title></head><body>Token endpoint.</body></html>",
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        document = await OfficialEvidenceFetcher(client, _policy()).fetch(
            f"https://{ALLOWED_HOST}/oauth"
        )

    assert document.source_url == f"https://{ALLOWED_HOST}/oauth"
    assert document.title == "OAuth"
    assert "Token endpoint." in document.relevant_text


async def test_enricher_without_providers_retains_baseline_configuration_required() -> None:
    baseline = _research()
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _r: httpx.Response(200))
    ) as client:
        enricher = OperationalResearchEnricher(
            discovery=None,
            extractor=None,
            http_client=client,
            resolver=_FakeResolver(PUBLIC_ADDRESS),
        )
        outcome = await enricher.enrich(app_name="Docs App", p1_record=P1_RECORD, baseline=baseline)

    assert outcome.capability.status == "configuration_required"
    assert outcome.documents_fetched == 0
    assert outcome.research == baseline


async def test_enricher_extracts_from_fetched_allowlisted_evidence() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text="<html><title>Docs</title><body>OAuth scopes and token URL.</body></html>",
        )

    enriched = _research(
        signup_url=f"https://{ALLOWED_HOST}/signup",
        developer_portal_url=f"https://{ALLOWED_HOST}/",
        token_url=f"https://{ALLOWED_HOST}/oauth/token",
        evidence_urls=[f"https://{ALLOWED_HOST}/oauth"],
        scopes=[ScopeRequirement(name="crm.read", source_url=f"https://{ALLOWED_HOST}/oauth")],
        confidence=0.9,
    )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        enricher = OperationalResearchEnricher(
            discovery=_FakeDiscovery((f"https://{ALLOWED_HOST}/oauth",)),
            extractor=_FakeExtractor(enriched),
            http_client=client,
            resolver=_FakeResolver(PUBLIC_ADDRESS),
        )
        outcome = await enricher.enrich(
            app_name="Docs App", p1_record=P1_RECORD, baseline=_research()
        )

    assert outcome.capability.status == "ready"
    assert outcome.documents_fetched >= 1
    assert outcome.research.token_url == f"https://{ALLOWED_HOST}/oauth/token"
    assert "scopes" not in outcome.missing_fields


async def test_enricher_rejects_changed_app_identity() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<html></html>")

    impostor = _research(app_slug="different-app", evidence_urls=[f"https://{ALLOWED_HOST}/oauth"])

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        enricher = OperationalResearchEnricher(
            discovery=_FakeDiscovery((f"https://{ALLOWED_HOST}/oauth",)),
            extractor=_FakeExtractor(impostor),
            http_client=client,
            resolver=_FakeResolver(PUBLIC_ADDRESS),
        )
        with pytest.raises(ValueError):
            await enricher.enrich(app_name="Docs App", p1_record=P1_RECORD, baseline=_research())


def test_capability_availability_is_sanitized_contract() -> None:
    capability = CapabilityAvailability(
        capability="operational_research",
        status="ready",
        reason_code="official_evidence_enriched",
        detail="Fetched allowlisted official evidence.",
    )
    assert capability.status == "ready"
    assert isinstance(EvidenceDocument, type)
