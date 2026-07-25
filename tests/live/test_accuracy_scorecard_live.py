"""Opt-in LIVE Phase D accuracy scorecard: exercises the You.com research
pipeline AND the configured browser provider (Browser Use or Playwright)
together, in one per-app run.

Disabled by default. Run explicitly with:

    RUN_LIVE_ACCURACY_SCORECARD=1 ALLOW_LIVE_BROWSER=true \\
        python -m pytest tests/live/test_accuracy_scorecard_live.py

This is a REAL browser-launching test. Read this file's docstring in full
before setting the env vars above — it does exactly what it says.

NOT executed by this repository's CI, and not executed by the agent that
wrote it (see docs/YOU_COM_INTEGRATION.md "Known limitations" for why: a
real run requires an owned test account and this environment's own safety
review found that this sandbox's .env already carries live Browser Use
credentials from earlier, unrelated work — running this file here would
risk a THIRD unintended live browser action in one session, on top of the
one already disclosed in this session's final report. An operator with
their own reviewed environment should run it deliberately.)

Requirements enforced by this file itself:

* Skipped entirely unless BOTH ``RUN_LIVE_ACCURACY_SCORECARD=1`` and
  ``ALLOW_LIVE_BROWSER=true`` are set — a scorecard run launches a real
  browser session, so it needs a stricter double opt-in than the discovery
  evaluator.
* A strict, hard-coded app budget (at most 2 apps).
* No login credential is ever submitted — this measures anonymous
  navigation reach only (developer portal / credential page found or not),
  exactly like ``python -m ops.cli accuracy-scorecard``. Testing an
  authenticated flow requires the existing owner credential-submission path.
* Prints only the sanitized ``ScorecardReport.as_dict()`` — never a full
  provider response, never page text, never a credential.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from ops.browser_scorecard import ScorecardReport, run_scorecard_for_app
from ops.config import Settings
from ops.p1_adapter import lookup_p1_record, to_operational_research

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_LIVE_ACCURACY_SCORECARD") != "1"
    or os.environ.get("ALLOW_LIVE_BROWSER") != "true",
    reason=(
        "opt-in live scorecard: set BOTH RUN_LIVE_ACCURACY_SCORECARD=1 and "
        "ALLOW_LIVE_BROWSER=true to run"
    ),
)

_MAX_LIVE_APPS = 2
_LIVE_APP_NAMES = ("Pipedrive", "Twenty")  # the only apps with an ACTIVE reviewed browser policy


def test_live_scorecard_for_reviewed_active_apps() -> None:
    settings = Settings.from_env()
    if settings.google_genai_api_key is None:
        pytest.skip("GOOGLE_GENAI_API_KEY not configured; extraction unavailable")

    from ops.run_service import RunService

    service = RunService(storage=_offline_storage(), settings=settings)
    enricher = service._build_research_enricher(settings)  # noqa: SLF001 - identical prod wiring
    try:
        worker = service._build_browser_worker(settings)  # noqa: SLF001 - identical prod wiring
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"browser worker unavailable: {type(exc).__name__}")

    async def _run() -> ScorecardReport:
        runs = []
        for app_name in _LIVE_APP_NAMES[:_MAX_LIVE_APPS]:
            lookup = lookup_p1_record(app_name)
            if lookup.status != "found" or lookup.record is None:
                continue
            baseline = to_operational_research(lookup.record)
            run = await run_scorecard_for_app(
                app_slug=baseline.app_slug,
                app_name=baseline.app_name,
                p1_record=lookup.record.model_dump(mode="json"),
                baseline=baseline,
                worker=worker,
                enricher=enricher,
            )
            runs.append(run)
        return ScorecardReport(runs=tuple(runs))

    report = asyncio.run(_run())
    print(report.as_dict())  # sanitized only — noqa: T201

    # This test REPORTS rather than gates on a specific completion rate — a
    # single live run is a data point, not a release decision. The one hard
    # invariant that DOES matter every time: zero canary leaks, when observable.
    assert report.canary_leak_count == 0


def _offline_storage() -> object:
    import tempfile
    from pathlib import Path

    from ops.storage import OperationsStorage

    tmp_path = Path(tempfile.mkdtemp()) / "scorecard_live.sqlite3"
    storage = OperationsStorage(tmp_path)
    storage.initialize()
    return storage
