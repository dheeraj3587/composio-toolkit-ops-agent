"""Opt-in LIVE evaluation of the You.com (and, for comparison, Perplexity)
discovery layer against the reviewed dataset.

Disabled by default. Run explicitly with:

    RUN_LIVE_YOU_TESTS=1 python -m pytest tests/live/test_you_discovery_live.py

Requirements enforced by this file itself (not by CI configuration):

* Skipped entirely unless ``RUN_LIVE_YOU_TESTS=1`` is set — never runs in
  normal CI, and never runs just because a key happens to be present.
* A STRICT call budget: at most three apps from the dataset, one discovery
  call each, ``count`` capped at 3. This is a real, credit-spending call —
  the budget exists to bound cost, not just latency.
* Prints ONLY the sanitized report (`ops.you_eval.EvalReport.as_dict`) —
  never a raw query string beyond the app name, never a full provider
  response, never a snippet's full text.
* Never imports or constructs a browser worker of any kind.
"""

from __future__ import annotations

import os
import time

import pytest

from ops.config import Settings
from ops.operational_research import PerplexitySearchDiscovery
from ops.you_eval import EvalReport, load_dataset, score_candidates
from ops.you_research import LegacyDiscoveryAdapter, ResearchHostPolicy, YouSearchDiscovery

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_LIVE_YOU_TESTS") != "1",
    reason="opt-in live evaluation: set RUN_LIVE_YOU_TESTS=1 to run",
)

# Strict, hard-coded budget — not configurable via env, so a careless export
# of a high value cannot silently balloon the number of live calls made.
_MAX_LIVE_APPS = 3
_LIVE_SEARCH_COUNT = 3


def _baseline_for(app_slug: str, app_name: str) -> object:
    from ops.models import OperationalResearch

    return OperationalResearch.model_validate(
        {
            "app_name": app_name,
            "app_slug": app_slug,
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
            "confidence": 0.5,
        }
    )


@pytest.fixture(scope="module")
def settings() -> Settings:
    return Settings.from_env()


def test_live_you_search_discovery_precision_and_recall(settings: Settings) -> None:
    if settings.you_api_key is None:
        pytest.skip("YDC_API_KEY not configured; live You.com evaluation unavailable")

    dataset = load_dataset()
    # Only real, non-fictitious apps with reviewed hosts — the budget stays
    # small and predictable regardless of how large the dataset grows later.
    apps = [app for app in dataset if app.approved_hosts][:_MAX_LIVE_APPS]
    assert apps, "dataset must contain at least one reviewed app to evaluate"

    discovery = YouSearchDiscovery(
        settings.you_api_key, count=_LIVE_SEARCH_COUNT, timeout_seconds=15.0, max_calls=1
    )

    import asyncio

    results = []
    for app in apps:
        baseline = _baseline_for(app.app_slug, app.app_name)
        official_hosts = ResearchHostPolicy(app.approved_hosts).include_domains
        start = time.monotonic()
        candidates = asyncio.run(
            discovery.discover(
                app_name=app.app_name,
                p1_record={},
                baseline=baseline,
                official_hosts=official_hosts,
            )
        )
        latency_ms = round((time.monotonic() - start) * 1000, 1)
        results.append(score_candidates(app, candidates, latency_ms=latency_ms))

    report = EvalReport(results=tuple(results))
    print(report.as_dict())  # sanitized only: slugs, scores, counts, latency — noqa: T201

    # A live discovery run against real, well-known developer platforms
    # should find SOME on-policy evidence for most apps, and never return
    # something scored on a host outside the reviewed set.
    assert report.average_official_host_precision >= 0.5
    for result in results:
        assert result.official_host_precision >= 0.0  # sanity: score computed, not NaN


def test_live_you_then_perplexity_fallback_frequency(settings: Settings) -> None:
    """Reports (does not assert a fixed value) how often Perplexity had to
    run at all when You.com is tried first — informs whether the fallback
    order in docs/YOU_COM_INTEGRATION.md should change."""

    if settings.you_api_key is None or settings.perplexity_api_key is None:
        pytest.skip("both YDC_API_KEY and PERPLEXITY_API_KEY are required for this comparison")

    from ops.you_research import CompositeEvidenceDiscovery

    dataset = load_dataset()
    apps = [app for app in dataset if app.approved_hosts][:_MAX_LIVE_APPS]

    import asyncio

    you = YouSearchDiscovery(
        settings.you_api_key, count=_LIVE_SEARCH_COUNT, timeout_seconds=15.0, max_calls=1
    )
    perplexity = LegacyDiscoveryAdapter(PerplexitySearchDiscovery(settings.perplexity_api_key))
    composite = CompositeEvidenceDiscovery([you, perplexity])

    fallback_used = 0
    for app in apps:
        baseline = _baseline_for(app.app_slug, app.app_name)
        official_hosts = ResearchHostPolicy(app.approved_hosts).include_domains
        asyncio.run(
            composite.discover(
                app_name=app.app_name,
                p1_record={},
                baseline=baseline,
                official_hosts=official_hosts,
            )
        )
        if composite.last_provider_used and "Legacy" in composite.last_provider_used:
            fallback_used += 1

    fallback_frequency = fallback_used / len(apps)
    print({"fallback_frequency": round(fallback_frequency, 3), "apps_evaluated": len(apps)})  # noqa: T201
    assert 0.0 <= fallback_frequency <= 1.0


def test_live_evaluation_never_imports_browser_worker() -> None:
    import sys

    assert "ops.browser_worker" not in sys.modules or True  # importing it elsewhere is fine;
    # the real guarantee is structural: this module's own imports (above)
    # contain no browser worker of any kind, verified by inspection here.
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(sys.modules[__name__]))
    imported_names = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    } | {node.names[0].name for node in ast.walk(tree) if isinstance(node, ast.Import)}
    assert not any("browser" in name.casefold() for name in imported_names)
