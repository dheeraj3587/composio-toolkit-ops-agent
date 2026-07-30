"""The profile research ports, and the claim that two of them were copied.

The whole value of ``ProfileDiscovery`` and ``ProfileEvidenceFetcher`` is that
they are the ``ops.research.operational_research`` signatures verbatim, so the research
adapters already in the repo satisfy them with no wrapper — and no wrapper is a
place to drop a redirect limit, a size cap, or a host check. That claim is only
worth anything if something fails when it stops being true, so this module
compares the port signatures member by member and checks a real adapter instance
against each port, rather than asserting that the classes merely exist.

``ProfileExtractor`` is asserted to be *different* on purpose: the reused
extraction signature demands a reviewed-catalog ``p1_record`` a brand-new
provider does not have, and returns a research object instead of per-field
claims.
"""

from __future__ import annotations

import inspect
import math
from dataclasses import FrozenInstanceError
from typing import Any

import pytest

from ops.providers.profile_builder import (
    NamedProfileDiscovery,
    ProfileClaim,
    ProfileDiscovery,
    ProfileEvidenceFetcher,
    ProfileExtractor,
)
from ops.research.operational_research import (
    EvidenceContentFetcherLike,
    EvidenceDiscovery,
    EvidenceDocument,
    EvidenceExtractor,
    PerplexitySearchDiscovery,
)
from ops.you.contents import GuardedHTTPEvidenceFetcher


class SilentDiscovery:
    """An adapter with nothing to report, which is a value and not an error."""

    name = "silent-discovery"

    async def discover(self, *, app_name: str) -> tuple[str, ...]:
        del app_name
        return ()


# --------------------------------------------------------------------------
# The verbatim claim: port signature == reused port signature
# --------------------------------------------------------------------------


def test_profile_discovery_restates_evidence_discovery_exactly() -> None:
    assert inspect.signature(ProfileDiscovery.discover) == inspect.signature(
        EvidenceDiscovery.discover
    )


def test_profile_evidence_fetcher_restates_the_content_fetcher_exactly() -> None:
    assert inspect.signature(ProfileEvidenceFetcher.fetch_many) == inspect.signature(
        EvidenceContentFetcherLike.fetch_many
    )


# --------------------------------------------------------------------------
# The consequence: existing adapters conform without modification
# --------------------------------------------------------------------------


def test_existing_discovery_adapter_satisfies_the_profile_port() -> None:
    """``PerplexitySearchDiscovery`` is usable as a ``ProfileDiscovery`` as-is."""

    adapter = PerplexitySearchDiscovery("test-key")

    assert isinstance(adapter, ProfileDiscovery)
    assert inspect.signature(type(adapter).discover) == inspect.signature(ProfileDiscovery.discover)


def test_existing_content_fetcher_satisfies_the_profile_port() -> None:
    """The batch adapter over ``OfficialEvidenceFetcher`` conforms unchanged."""

    fetcher = GuardedHTTPEvidenceFetcher(object())

    assert isinstance(fetcher, ProfileEvidenceFetcher)
    assert inspect.signature(type(fetcher).fetch_many) == inspect.signature(
        ProfileEvidenceFetcher.fetch_many
    )


def test_the_base_discovery_port_does_not_demand_an_adapter_name() -> None:
    """Why ``name`` sits on the narrowing: an existing adapter has none.

    Requiring the identifier on the base port would disqualify
    ``PerplexitySearchDiscovery`` outright, so the base port stays method-only
    and ``NamedProfileDiscovery`` is opt-in.
    """

    unnamed = PerplexitySearchDiscovery("test-key")

    assert isinstance(unnamed, ProfileDiscovery)
    assert not isinstance(unnamed, NamedProfileDiscovery)
    assert isinstance(SilentDiscovery(), NamedProfileDiscovery)


# --------------------------------------------------------------------------
# The extraction port is additive on purpose
# --------------------------------------------------------------------------


def test_profile_extractor_is_additive_rather_than_reused() -> None:
    reused = inspect.signature(EvidenceExtractor.extract)
    additive = inspect.signature(ProfileExtractor.extract)

    assert set(additive.parameters) == {"self", "app_name", "documents"}
    # The reason it cannot be the reused signature: a reviewed-catalog record a
    # brand-new provider does not have, and a research object instead of claims.
    assert "p1_record" in reused.parameters
    assert additive.return_annotation == "tuple[ProfileClaim, ...]"
    assert reused.return_annotation == "OperationalResearch"


# --------------------------------------------------------------------------
# Discovery degrades by returning (), not by raising
# --------------------------------------------------------------------------


async def test_empty_discovery_is_a_value_not_an_exception() -> None:
    adapter: ProfileDiscovery = SilentDiscovery()

    assert await adapter.discover(app_name="Unknown Provider") == ()


# --------------------------------------------------------------------------
# ProfileClaim shape
# --------------------------------------------------------------------------


def _claim(**overrides: Any) -> ProfileClaim:
    values: dict[str, Any] = {
        "field": "signup_url",
        "value": "https://provider.com/signup",
        "source_url": "https://provider.com/docs",
        "confidence": 0.75,
    }
    values.update(overrides)
    return ProfileClaim(**values)


def test_claim_keeps_the_field_value_and_citation_it_was_given() -> None:
    claim = _claim()

    assert claim.field == "signup_url"
    assert claim.value == "https://provider.com/signup"
    assert claim.source_url == "https://provider.com/docs"
    assert claim.confidence == pytest.approx(0.75)


def test_claim_is_immutable() -> None:
    claim = _claim()

    with pytest.raises(FrozenInstanceError):
        claim.value = "https://evil.io/signup"  # type: ignore[misc]


@pytest.mark.parametrize("value", ["", "   "])
def test_claim_rejects_an_empty_value(value: str) -> None:
    with pytest.raises(ValueError, match="non-empty value"):
        _claim(value=value)


def test_claim_rejects_a_missing_citation() -> None:
    with pytest.raises(ValueError, match="source url"):
        _claim(source_url="  ")


@pytest.mark.parametrize("confidence", [-0.01, 1.01, math.nan])
def test_claim_rejects_a_confidence_outside_the_unit_range(confidence: float) -> None:
    """NaN included: it compares False against everything, so it must be refused."""

    with pytest.raises(ValueError, match="confidence is out of range"):
        _claim(confidence=confidence)


def test_evidence_document_is_the_shared_currency_of_both_ports() -> None:
    """Fetch produces, extraction consumes, and neither redefines the type."""

    fetch_return = inspect.signature(ProfileEvidenceFetcher.fetch_many).return_annotation
    extract_documents = inspect.signature(ProfileExtractor.extract).parameters["documents"]

    assert fetch_return == "tuple[EvidenceDocument, ...]"
    assert extract_documents.annotation == "tuple[EvidenceDocument, ...]"
    assert EvidenceDocument.model_fields.keys() == {"source_url", "title", "relevant_text"}
