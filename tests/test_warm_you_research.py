"""Offline tests for the dry-run-first You.com warming command."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from ops.config import Settings

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "warm_you_research.py"


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("warm_you_research_test", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_dry_run_uses_verified_snapshot_without_executing(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    module = _module()

    async def _must_not_execute(**kwargs: object) -> list[dict[str, object]]:
        del kwargs
        raise AssertionError("dry-run must not invoke enrichment")

    monkeypatch.setattr(module, "_execute", _must_not_execute)
    assert module.main(["--app-slug", "pipedrive"]) == 0
    output = capsys.readouterr().out
    assert "DRY RUN: 1 verified P1 app(s)" in output
    assert "No You.com, Gemini, browser, or vendor calls were made." in output
    assert "pipedrive: skipped reason=dry_run" in output


def test_execute_uses_injected_runtime_boundary_and_writes_sanitized_summary(
    monkeypatch, tmp_path: Path
) -> None:
    module = _module()
    calls: dict[str, object] = {}

    async def _fake_execute(
        records: object,
        *,
        settings: Settings,
        force_refresh: bool,
        concurrency: int,
        continue_on_error: bool,
    ) -> list[dict[str, object]]:
        calls.update(
            records=list(records),
            settings=settings,
            force_refresh=force_refresh,
            concurrency=concurrency,
            continue_on_error=continue_on_error,
        )
        return [
            {
                "app_slug": "pipedrive",
                "status": "enriched",
                "reason_code": "official_evidence_enriched",
                "missing_fields": ["token_url"],
                "missing_field_count": 1,
                "verified_claim_count": 3,
            }
        ]

    monkeypatch.setattr(module, "_execute", _fake_execute)
    monkeypatch.setattr(
        module.Settings,
        "from_env",
        classmethod(lambda cls: Settings()),
    )
    summary = tmp_path / "summary.json"
    assert (
        module.main(
            [
                "--app-slug",
                "pipedrive",
                "--execute",
                "--force-refresh",
                "--max-age-seconds",
                "60",
                "--concurrency",
                "2",
                "--continue-on-error",
                "--output-summary",
                str(summary),
            ]
        )
        == 0
    )
    assert calls["force_refresh"] is True
    assert calls["concurrency"] == 2
    assert calls["continue_on_error"] is True
    assert isinstance(calls["settings"], Settings)
    assert calls["settings"].you_contents_max_age_seconds == 60  # type: ignore[index]
    content = summary.read_text(encoding="utf-8")
    assert '"mode": "execute"' in content
    assert "pipedrive" in content
    assert "api_key" not in content
