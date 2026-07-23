"""Provider-neutral contracts for future official-evidence enrichment."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ops.graph import PhaseUnavailableError
from ops.models import OperationalResearch


@dataclass(frozen=True, slots=True)
class EvidenceDocument:
    """A bounded, fetched excerpt from an official evidence URL."""

    source_url: str
    title: str
    relevant_text: str


class OperationalResearchProvider(Protocol):
    """Stable interface implemented by a verified Phase 2 enrichment provider."""

    async def enrich(
        self,
        *,
        app_name: str,
        p1_record: dict[str, object],
        evidence_documents: tuple[EvidenceDocument, ...],
    ) -> OperationalResearch: ...


class UnavailableOperationalResearchProvider:
    """Default provider for Phase 0/1; performs no model or search calls."""

    async def enrich(
        self,
        *,
        app_name: str,
        p1_record: dict[str, object],
        evidence_documents: tuple[EvidenceDocument, ...],
    ) -> OperationalResearch:
        del app_name, p1_record, evidence_documents
        raise PhaseUnavailableError(phase=2, capability="operational research enrichment")
