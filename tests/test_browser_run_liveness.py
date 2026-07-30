"""Tests for the two defects that made a live run un-driveable.

A run projected to ``browser_running`` is driven by nothing: the autonomous
advancer only sweeps ``waiting_for_hitl``, retry records no action, and the UI
reports ``can_resume: false``. Before these fixes a resume whose observation was
``failed``/``blocked`` was still projected as ``browser_running``, so the run sat
forever holding the single browser slot until the next API restart.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from typing import Any

from ops.core.config import Settings
from ops.runs.service import RunService, _parse_timestamp


class _StubTransaction:
    def __init__(self, store: dict[str, dict[str, Any]]) -> None:
        self._store = store
        self.events: list[tuple[str, str, dict[str, Any]]] = []

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        return self._store.get(run_id)

    def update_run(self, run_id: str, **changes: Any) -> dict[str, Any]:
        self._store[run_id].update(changes)
        return self._store[run_id]

    def append_audit_event(self, *, run_id: str, event_type: str, payload: dict[str, Any]) -> None:
        self.events.append((run_id, event_type, payload))


class _StubStorage:
    def __init__(self, records: list[dict[str, Any]]) -> None:
        self._store = {str(r["run_id"]): dict(r) for r in records}
        self.transaction = _StubTransaction(self._store)

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        record = self._store.get(run_id)
        return dict(record) if record else None

    def list_runs(self, *, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        return [dict(v) for v in list(self._store.values())[offset : offset + limit]]

    def unit_of_work(self) -> Any:
        transaction = self.transaction

        class _Ctx:
            def __enter__(self) -> _StubTransaction:
                return transaction

            def __exit__(self, *exc: object) -> bool:
                return False

        return _Ctx()


def _service(records: list[dict[str, Any]]) -> RunService:
    service = RunService.__new__(RunService)
    service.storage = _StubStorage(records)  # type: ignore[assignment]
    service._settings = Settings(browser_use_task_timeout_seconds=180)
    service._released: list[tuple[str, str]] = []  # type: ignore[attr-defined]

    def _release(context: object, provider: str, *, reason: str) -> None:
        service._released.append((str(provider), reason))  # type: ignore[attr-defined]

    service._release_browser_session = _release  # type: ignore[assignment]
    service._session_context_for = lambda run_id: object()  # type: ignore[assignment]
    service._browser_worker_for = lambda record: None  # type: ignore[assignment]
    service._advance_stop = threading.Event()
    return service


def _record(*, run_id: str, status: str, minutes_idle: float) -> dict[str, Any]:
    updated = datetime.now(UTC) - timedelta(minutes=minutes_idle)
    return {
        "run_id": run_id,
        "app_slug": "pipedrive",
        "status": status,
        "browser_provider": "playwright",
        "state_revision": 1,
        "updated_at": updated.isoformat().replace("+00:00", "Z"),
    }


# --- idle browser_running reconciliation --------------------------------------
def test_long_idle_browser_run_is_reconciled_and_releases_the_session() -> None:
    service = _service([_record(run_id="run_idle", status="browser_running", minutes_idle=30)])
    assert service.reconcile_idle_browser_runs() == 1
    assert service.storage.get_run("run_idle")["status"] == "configuration_required"
    # The single browser slot must be handed back, not held.
    assert service._released  # type: ignore[attr-defined]


def test_recently_updated_browser_run_is_left_alone() -> None:
    # An in-flight navigation must never be torn down.
    service = _service([_record(run_id="run_busy", status="browser_running", minutes_idle=1)])
    assert service.reconcile_idle_browser_runs() == 0
    assert service.storage.get_run("run_busy")["status"] == "browser_running"
    assert not service._released  # type: ignore[attr-defined]


def test_threshold_exceeds_the_provider_operation_timeout() -> None:
    # 180s operation timeout must not be reclaimed at 4 minutes of idleness.
    service = _service([_record(run_id="run_edge", status="browser_running", minutes_idle=4)])
    assert service.reconcile_idle_browser_runs() == 0
    assert service.storage.get_run("run_edge")["status"] == "browser_running"


def test_other_statuses_are_never_touched() -> None:
    service = _service(
        [
            _record(run_id="run_hitl", status="waiting_for_hitl", minutes_idle=600),
            _record(run_id="run_reply", status="waiting_for_reply", minutes_idle=600),
            _record(run_id="run_done", status="completed", minutes_idle=600),
            _record(run_id="run_blocked", status="blocked", minutes_idle=600),
        ]
    )
    assert service.reconcile_idle_browser_runs() == 0
    for run_id, expected in (
        ("run_hitl", "waiting_for_hitl"),
        ("run_reply", "waiting_for_reply"),
        ("run_done", "completed"),
        ("run_blocked", "blocked"),
    ):
        assert service.storage.get_run(run_id)["status"] == expected


def test_unparsable_timestamp_is_skipped_rather_than_reclaimed() -> None:
    record = _record(run_id="run_bad_ts", status="browser_running", minutes_idle=600)
    record["updated_at"] = "not-a-timestamp"
    service = _service([record])
    assert service.reconcile_idle_browser_runs() == 0
    assert service.storage.get_run("run_bad_ts")["status"] == "browser_running"


def test_reconciliation_is_idempotent() -> None:
    service = _service([_record(run_id="run_idle", status="browser_running", minutes_idle=30)])
    assert service.reconcile_idle_browser_runs() == 1
    # Second sweep finds nothing left in browser_running.
    assert service.reconcile_idle_browser_runs() == 0


# --- timestamp parsing --------------------------------------------------------
def test_parse_timestamp_accepts_stored_formats() -> None:
    assert _parse_timestamp("2026-07-27T08:10:28.436472Z") is not None
    assert _parse_timestamp("2026-07-27T08:10:28+00:00") is not None
    naive = _parse_timestamp("2026-07-27T08:10:28")
    assert naive is not None and naive.tzinfo is not None


def test_parse_timestamp_rejects_unusable_values() -> None:
    for value in ("", "whenever", None, 12345):
        assert _parse_timestamp(value) is None
