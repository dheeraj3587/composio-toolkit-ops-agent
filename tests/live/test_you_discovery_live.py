"""Opt-in LIVE You.com Search discovery evaluation against the reviewed dataset.

Disabled by default. Run explicitly with:

    RUN_LIVE_YOU_TESTS=1 python -m pytest tests/live/test_you_discovery_live.py -q -s

Hard-coded budget (not env-configurable, so a stray export cannot inflate it):
at most 3 reviewed apps, at most 2 Search queries per app, count 3 per query —
so at most 6 Search calls total. No browser, no email, no Research.

Prints ONLY the sanitized ``EvalReport`` (slugs, scores, counts, latency) —
never a raw query beyond the app name, never a provider body, never a snippet.
"""

from __future__ import annotations

import asyncio
import os
import time

import pytest

from ops.core.config import Settings
from ops.research.operational_research import PerplexitySearchDiscovery
from ops.you.eval import EvalReport, load_dataset, score_candidates
from ops.you.research import (
    CompositeEvidenceDiscovery,
    LegacyDiscoveryAdapter,
    ResearchHostPolicy,
    YouSearchDiscovery,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_LIVE_YOU_TESTS") != "1",
    reason="opt-in live evaluation: set RUN_LIVE_YOU_TESTS=1 to run",
)

_MAX_LIVE_APPS = 3
_LIVE_SEARCH_COUNT = 3
_MAX_QUERIES_PER_APP = 2
_CREDENTIAL_CATEGORIES = {"developer_portal", "api_authentication", "credential_creation", "oauth"}


def _baseline_for(app_slug: str, app_name: str) -> object:
    from ops.core.models import OperationalResearch

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
    apps = [app for app in dataset if app.approved_hosts][:_MAX_LIVE_APPS]
    assert apps, "dataset must contain at least one reviewed app to evaluate"

    discovery = YouSearchDiscovery(
        settings.you_api_key,
        count=_LIVE_SEARCH_COUNT,
        timeout_seconds=15.0,
        max_calls=_MAX_QUERIES_PER_APP,
    )

    results = []
    credential_hits = 0
    for app in apps:
        baseline = _baseline_for(app.app_slug, app.app_name)
        official_hosts = ResearchHostPolicy.from_domains(app.approved_hosts).include_domains
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
        if any(c.category in _CREDENTIAL_CATEGORIES for c in candidates):
            credential_hits += 1

    report = EvalReport(results=tuple(results))
    print(report.as_dict())  # sanitized only  # noqa: T201

    # Local policy filters every returned candidate, so on-policy precision must
    # be exactly 1.0 (section 29).
    assert report.average_official_host_precision == 1.0
    # At least 2 of 3 apps return a developer/API/credential category.
    assert credential_hits >= min(2, len(apps))


def test_live_you_then_perplexity_fallback_frequency(settings: Settings) -> None:
    """Reports how often Perplexity had to run when You.com is tried first."""

    if settings.you_api_key is None or settings.perplexity_api_key is None:
        pytest.skip("both YDC_API_KEY and PERPLEXITY_API_KEY are required for this comparison")

    dataset = load_dataset()
    apps = [app for app in dataset if app.approved_hosts][:_MAX_LIVE_APPS]

    you = YouSearchDiscovery(
        settings.you_api_key,
        count=_LIVE_SEARCH_COUNT,
        timeout_seconds=15.0,
        max_calls=_MAX_QUERIES_PER_APP,
    )
    perplexity = LegacyDiscoveryAdapter(PerplexitySearchDiscovery(settings.perplexity_api_key))
    composite = CompositeEvidenceDiscovery([you, perplexity])

    fallback_used = 0
    for app in apps:
        baseline = _baseline_for(app.app_slug, app.app_name)
        official_hosts = ResearchHostPolicy.from_domains(app.approved_hosts).include_domains
        asyncio.run(
            composite.discover(
                app_name=app.app_name,
                p1_record={},
                baseline=baseline,
                official_hosts=official_hosts,
            )
        )
        if composite.last_provider_used and "perplexity" in composite.last_provider_used:
            fallback_used += 1

    fallback_frequency = fallback_used / len(apps)
    print({"fallback_frequency": round(fallback_frequency, 3), "apps_evaluated": len(apps)})  # noqa: T201
    assert 0.0 <= fallback_frequency <= 1.0


def test_live_evaluation_never_imports_browser_worker() -> None:
    import ast
    import inspect
    import sys

    tree = ast.parse(inspect.getsource(sys.modules[__name__]))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    } | {node.names[0].name for node in ast.walk(tree) if isinstance(node, ast.Import)}
    assert not any("browser" in name.casefold() for name in imported)
