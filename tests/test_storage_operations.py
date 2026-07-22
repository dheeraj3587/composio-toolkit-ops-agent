"""Durable operations metadata and side-effect idempotency regressions."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ops.storage import OperationsStorage


def _create(storage: OperationsStorage) -> None:
    storage.create_run(
        run_id="run_" + "a" * 32,
        thread_id="local_" + "b" * 32,
        app_name="Example",
        app_slug="example",
        operational_research={
            "authorization_url": None,
            "token_url": None,
            "credential_fields": [],
        },
        route_reason_code="verified_evidence_route",
        route_explanation="Verified evidence selected this route.",
        missing_fields=["token_url"],
        provider_status={"browser": "not_started"},
    )


def test_structured_shapes_survive_key_aware_redaction_words(tmp_path: Path) -> None:
    storage = OperationsStorage(tmp_path / "private" / "ops.db")
    _create(storage)

    record = storage.get_run("run_" + "a" * 32)
    assert record is not None
    assert record["operational_research"] == {
        "authorization_url": None,
        "credential_fields": [],
        "token_url": None,
    }
    assert record["missing_fields"] == ["token_url"]


def test_side_effect_reservation_is_atomic_across_threads(tmp_path: Path) -> None:
    storage = OperationsStorage(tmp_path / "private" / "ops.db")
    _create(storage)
    run_id = "run_" + "a" * 32

    def reserve(_: int) -> bool:
        _, created = storage.reserve_side_effect(
            run_id=run_id,
            operation_key="gmail-outreach-1",
            provider="composio",
        )
        return created

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(reserve, range(24)))

    assert results.count(True) == 1
    assert results.count(False) == 23
    stored = storage.get_side_effect(run_id, "gmail-outreach-1")
    assert stored is not None
    assert stored["status"] == "pending"


def test_ambiguous_side_effect_outcome_is_persisted_without_payload(tmp_path: Path) -> None:
    storage = OperationsStorage(tmp_path / "private" / "ops.db")
    _create(storage)
    run_id = "run_" + "a" * 32
    storage.reserve_side_effect(
        run_id=run_id,
        operation_key="gmail-outreach-1",
        provider="composio",
    )

    updated = storage.update_side_effect(
        run_id=run_id,
        operation_key="gmail-outreach-1",
        status="outcome_unknown",
    )

    assert updated["status"] == "outcome_unknown"
    assert updated["external_id"] is None
    assert "payload" not in updated
