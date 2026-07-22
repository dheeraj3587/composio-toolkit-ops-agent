from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path

import pytest
from pydantic import ValidationError

from ops.models import OperationalResearch
from ops.p1_adapter import (
    DEFAULT_P1_ROOT,
    P1AppRecord,
    P1LookupFound,
    P1LookupNotFound,
    P1OperationalAdapter,
    SnapshotIntegrityError,
    load_verified_snapshot,
)
from ops.routing import decide_access, resolve_access


def operational_research(**overrides: object) -> OperationalResearch:
    """Build a complete conservative record for focused routing tests."""

    values: dict[str, object] = {
        "app_name": "Route Test App",
        "app_slug": "route-test-app",
        "api_available": None,
        "api_type": "REST",
        "api_base_url": None,
        "auth_methods": [],
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
        "confidence": 0.0,
    }
    values.update(overrides)
    return OperationalResearch.model_validate(values)


def test_locked_p1_contract_has_exactly_19_strict_fields() -> None:
    assert len(P1AppRecord.model_fields) == 19
    source = json.loads((DEFAULT_P1_ROOT / "results.json").read_text(encoding="utf-8"))[0]
    source["unexpected"] = True

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        P1AppRecord.model_validate(source)


def test_hubspot_lookup_returns_verified_copied_row_case_insensitively() -> None:
    result = P1OperationalAdapter().lookup("  hUbSpOt  ")

    assert isinstance(result, P1LookupFound)
    assert result.status == "found"
    assert result.record.app == "HubSpot"
    assert result.record.slug == "hubspot"
    assert result.record.access_model.kind == "Self-Serve"
    assert (
        result.provenance.results_sha256
        == (
            "618c50441fc1f3a314f2c2a6684e5268862249cfe14056aacfd73781a24ec08c"  # pragma: allowlist secret
        )
    )


def test_lookup_matches_distinct_app_name_and_slug_case_insensitively() -> None:
    adapter = P1OperationalAdapter()

    by_name = adapter.lookup("lArK (LARKSUITE)")
    by_slug = adapter.lookup("LARK")

    assert isinstance(by_name, P1LookupFound)
    assert by_name.matched_by == "app"
    assert isinstance(by_slug, P1LookupFound)
    assert by_slug.matched_by == "slug"
    assert by_name.record == by_slug.record


def test_salesforce_gated_row_adapts_without_inventing_operational_fields() -> None:
    adapter = P1OperationalAdapter()
    lookup = adapter.lookup("SALESFORCE")
    research = asyncio.run(adapter.get_operational_research("salesforce"))
    decision = decide_access(research)

    assert isinstance(lookup, P1LookupFound)
    assert lookup.record.access_model.kind == "Gated"
    assert research.access_route == "partner_gated"
    assert research.api_available is None
    assert research.api_base_url is None
    assert research.authorization_url is None
    assert research.token_url is None
    assert research.credential_fields == []
    assert research.scopes == []
    assert research.developer_portal_url is None
    assert research.signup_url is None
    assert research.production_approval_required is None
    assert research.contact_email is None
    assert research.contact_url is None
    assert decision.route == "partner_gated"
    assert decision.reason_code == "verified_evidence_route"
    assert decision.is_final is True


def test_unknown_app_returns_typed_not_found_after_snapshot_verification() -> None:
    result = P1OperationalAdapter().lookup("Definitely Not A P1 App")

    assert isinstance(result, P1LookupNotFound)
    assert result.status == "not_found"
    assert result.record is None
    assert result.normalized_query == "definitely not a p1 app"
    assert (
        result.provenance.source_commit
        == "d69549be542e00574ba2046eb7a498bc147fa756"  # pragma: allowlist secret
    )


def test_lookup_never_mutates_locked_source_bytes() -> None:
    paths = tuple(
        DEFAULT_P1_ROOT / name
        for name in (
            "SNAPSHOT.json",
            "results.json",
            "composio_coverage.json",
        )
    )
    before = {path: path.read_bytes() for path in paths}

    adapter = P1OperationalAdapter()
    adapter.lookup("HubSpot")
    adapter.lookup("Salesforce")
    adapter.lookup("not-found")

    assert {path: path.read_bytes() for path in paths} == before


def test_tampered_snapshot_is_rejected_before_record_use(tmp_path: Path) -> None:
    snapshot_root = tmp_path / "p1"
    shutil.copytree(DEFAULT_P1_ROOT, snapshot_root)
    results_path = snapshot_root / "results.json"
    results_path.write_bytes(results_path.read_bytes() + b"\n")

    with pytest.raises(SnapshotIntegrityError, match="results hash"):
        load_verified_snapshot(snapshot_root)


def test_snapshot_reader_rejects_a_symlinked_canonical_file(tmp_path: Path) -> None:
    snapshot_root = tmp_path / "p1"
    shutil.copytree(DEFAULT_P1_ROOT, snapshot_root)
    results_path = snapshot_root / "results.json"
    results_path.unlink()
    results_path.symlink_to(DEFAULT_P1_ROOT / "results.json")

    with pytest.raises(SnapshotIntegrityError, match="unavailable"):
        load_verified_snapshot(snapshot_root)


def test_unknown_route_uses_at_most_one_injected_probe() -> None:
    research = OperationalResearch(
        app_name="Unknown App",
        app_slug="unknown-app",
        api_available=None,
        api_type="unknown",
        api_base_url=None,
        auth_methods=[],
        authorization_url=None,
        token_url=None,
        credential_fields=[],
        scopes=[],
        developer_portal_url=None,
        signup_url=None,
        access_route="unknown",
        production_approval_required=None,
        contact_email=None,
        contact_url=None,
        evidence_urls=[],
        confidence=0.0,
    )
    probe_calls = 0

    async def probe(value: OperationalResearch) -> OperationalResearch:
        nonlocal probe_calls
        probe_calls += 1
        return value

    initial = decide_access(research)
    resolved = asyncio.run(resolve_access(research, unknown_probe=probe))

    assert initial.route == "unknown"
    assert initial.is_final is False
    assert initial.unknown_probe_remaining == 1
    assert probe_calls == 1
    assert resolved.route == "unknown"
    assert resolved.is_final is True
    assert resolved.reason_code == "insufficient_evidence_after_probe"
    assert resolved.unknown_probe_attempts == 1
    assert resolved.unknown_probe_remaining == 0


def test_deterministic_operational_signals_override_evidence_route() -> None:
    research = OperationalResearch(
        app_name="Unavailable App",
        app_slug="unavailable-app",
        api_available=False,
        api_type="None",
        api_base_url=None,
        auth_methods=[],
        authorization_url=None,
        token_url=None,
        credential_fields=[],
        scopes=[],
        developer_portal_url=None,
        signup_url="https://example.invalid/signup",
        access_route="self_serve",
        production_approval_required=False,
        contact_email=None,
        contact_url=None,
        evidence_urls=["https://example.invalid/evidence"],
        confidence=1.0,
    )

    decision = decide_access(research)

    assert decision.route == "blocked"
    assert decision.reason_code == "api_unavailable"
    assert decision.is_final is True


@pytest.mark.parametrize(
    ("overrides", "expected_route", "expected_reason"),
    [
        (
            {
                "production_approval_required": True,
                "signup_url": "https://example.invalid/signup",
            },
            "hybrid",
            "production_approval_with_signup",
        ),
        (
            {"production_approval_required": True},
            "approval_required",
            "production_approval_without_signup",
        ),
        (
            {"contact_url": "https://example.invalid/contact"},
            "partner_gated",
            "contact_without_signup",
        ),
        (
            {
                "signup_url": "https://example.invalid/signup",
                "developer_portal_url": "https://example.invalid/developers",
            },
            "self_serve",
            "self_serve_portal",
        ),
        (
            {"access_route": "blocked"},
            "blocked",
            "verified_evidence_route",
        ),
    ],
)
def test_router_covers_every_final_access_class(
    overrides: dict[str, object],
    expected_route: str,
    expected_reason: str,
) -> None:
    decision = decide_access(operational_research(**overrides))

    assert decision.route == expected_route
    assert decision.reason_code == expected_reason
    assert decision.is_final is True
    assert decision.unknown_probe_remaining == 0


def test_approval_requirement_wins_over_contact_and_self_service_signals() -> None:
    decision = decide_access(
        operational_research(
            production_approval_required=True,
            signup_url="https://example.invalid/signup",
            developer_portal_url="https://example.invalid/developers",
            contact_email="partner@example.invalid",
        )
    )

    assert decision.route == "hybrid"
    assert decision.reason_code == "production_approval_with_signup"
