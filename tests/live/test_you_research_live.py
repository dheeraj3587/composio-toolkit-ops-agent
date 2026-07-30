"""Opt-in ONE-CALL LIVE You.com Research evaluation.

Disabled by default. Run explicitly with:

    RUN_LIVE_YOU_RESEARCH_TESTS=1 python -m pytest tests/live/test_you_research_live.py -q -s

Hard-coded budget: ONE app, ONE Research call, research_effort=standard, one
strict source-control domain set, minimal candidate-page schema. No browser, no
email. Never uses deep/exhaustive/frontier or background mode.

Prints only sanitized counts — never the full provider answer.

If Research is unavailable for the key's scope, the fetcher degrades to None; the
test reports a truthful skip rather than a false pass.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from ops.core.config import Settings
from ops.you.research import ResearchHostPolicy, YouResearchFallback

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_LIVE_YOU_RESEARCH_TESTS") != "1",
    reason="opt-in live Research test: set RUN_LIVE_YOU_RESEARCH_TESTS=1 to run",
)

_APP_NAME = "Pipedrive"
_APPROVED_HOSTS = ("developers.pipedrive.com", "app.pipedrive.com", "*.pipedrive.com")


def test_live_one_call_research() -> None:
    settings = Settings.from_env()
    if settings.you_api_key is None:
        pytest.skip("YDC_API_KEY not configured; live Research evaluation unavailable")

    policy = ResearchHostPolicy.from_domains(_APPROVED_HOSTS)
    fallback = YouResearchFallback(
        settings.you_api_key, timeout_seconds=settings.you_research_timeout_seconds
    )

    result = asyncio.run(
        fallback.research(
            app_name=_APP_NAME,
            official_hosts=policy.provider_include_domains,
            policy=policy,
        )
    )

    if result is None:
        pytest.skip(
            "Research returned no usable structured result (unavailable for this key's scope, "
            "or no candidates passed local policy) — reported truthfully, not a false pass"
        )

    print(  # noqa: T201 - sanitized: count + confidence + categories only
        {
            "candidate_count": len(result.candidates),
            "confidence": result.confidence,
            "categories": sorted({c.category for c in result.candidates}),
        }
    )

    # Every accepted candidate passed local host policy (enforced in _parse); no
    # operational field is trusted directly — Research only yields candidate URLs.
    assert result.candidates
    for candidate in result.candidates:
        assert policy.validate_candidate_url(candidate.source_url)
        assert candidate.provider == "you_research"
