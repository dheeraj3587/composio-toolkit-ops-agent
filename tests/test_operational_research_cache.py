"""Offline cache coverage for fully validated operational-research outcomes."""

from __future__ import annotations

import httpx
import pytest

from ops.models import OperationalUrlClaim
from ops.operational_research import EvidenceDocument, OperationalResearchEnricher
from ops.p1_adapter import load_verified_snapshot, to_operational_research
from ops.you_research import InMemoryResearchCache


class _Discovery:
    async def discover(self, **kwargs: object) -> tuple[object, ...]:
        del kwargs
        return ()


class _ContentFetcher:
    def __init__(self, document: EvidenceDocument) -> None:
        self.document = document
        self.calls = 0

    async def fetch_many(self, urls: object) -> tuple[EvidenceDocument, ...]:
        del urls
        self.calls += 1
        return (self.document,)


class _Extractor:
    def __init__(self, research: object) -> None:
        self.research = research
        self.calls = 0

    async def extract(self, **kwargs: object) -> object:
        del kwargs
        self.calls += 1
        return self.research


@pytest.mark.asyncio
async def test_rich_outcome_cache_skips_second_extraction_and_revalidates() -> None:
    record = next(item for item in load_verified_snapshot().records if item.slug == "pipedrive")
    baseline = to_operational_research(record)
    source_url = record.evidence_urls[0]
    document = EvidenceDocument(
        source_url=source_url,
        title="Official Pipedrive documentation",
        # The cached claim is accepted only because its URL is literally in this
        # fetched document projection, exactly as it would be after a live fetch.
        relevant_text=f"Developer portal: {source_url}",
    )
    research = baseline.model_copy(
        update={
            "developer_portal_url": source_url,
            "evidence_urls": [source_url],
            "operational_url_claims": (
                OperationalUrlClaim(
                    field="developer_portal_url",
                    url=source_url,
                    source_url=source_url,
                ),
            ),
        }
    )
    extractor = _Extractor(research)
    fetcher = _ContentFetcher(document)
    client = httpx.AsyncClient()
    try:
        enricher = OperationalResearchEnricher(
            discovery=None,
            extractor=extractor,  # type: ignore[arg-type]
            http_client=client,
            rich_discovery=_Discovery(),
            content_fetcher_factory=lambda policy: fetcher,
            outcome_cache=InMemoryResearchCache(),
        )
        first = await enricher.enrich(
            app_name=record.app,
            p1_record=record.model_dump(mode="json"),
            baseline=baseline,
        )
        second = await enricher.enrich(
            app_name=record.app,
            p1_record=record.model_dump(mode="json"),
            baseline=baseline,
        )
    finally:
        await client.aclose()

    assert first.capability.status == "ready"
    assert first.provider_metrics["operational_research_cache"] == "miss"
    assert second.capability.status == "ready"
    assert second.provider_metrics["operational_research_cache"] == "hit"
    assert extractor.calls == 1
    assert fetcher.calls == 1
