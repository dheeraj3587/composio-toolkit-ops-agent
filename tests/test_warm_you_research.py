from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts.warm_you_research import (
    _selected_records,
    _summary_row,
    _traced_apps,
    _write_summary,
)


def test_all_selection_covers_exactly_the_verified_p1_catalog() -> None:
    records = _selected_records(argparse.Namespace(all=True, app_slug=None, limit=None))

    assert len(records) == 100
    assert len({record.slug for record in records}) == 100
    assert len(_traced_apps()) == 25


def test_summary_marks_only_traced_apps_with_both_verified_urls_browser_ready() -> None:
    records = _selected_records(argparse.Namespace(all=True, app_slug=None, limit=None))
    traced = _traced_apps()
    record = next(item for item in records if item.slug in traced)
    row = _summary_row(
        record,
        status="enriched",
        missing_fields=(),
        verified_claim_count=2,
        research={
            "access_route": "self_serve",
            "login_url": "https://example.test/login",
            "credential_management_url": "https://example.test/settings/api",
        },
        traced_apps=traced,
    )

    assert row["coverage_status"] == "browser_ready"
    assert row["browser_trace_status"] == "reviewed"


def test_written_report_contains_sanitized_coverage_totals(tmp_path: Path) -> None:
    path = tmp_path / "coverage.json"
    _write_summary(
        path,
        execute=True,
        rows=(
            {"coverage_status": "browser_ready", "app_slug": "one"},
            {"coverage_status": "research_only", "app_slug": "two"},
            {"coverage_status": "research_only", "app_slug": "three"},
        ),
    )

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["selected_app_count"] == 3
    assert payload["coverage_counts"] == {
        "browser_ready": 1,
        "research_only": 2,
    }
