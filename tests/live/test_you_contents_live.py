"""Opt-in LIVE You.com Contents evaluation.

Disabled by default. Run explicitly with:

    RUN_LIVE_YOU_CONTENTS_TESTS=1 python -m pytest tests/live/test_you_contents_live.py -q -s

Hard-coded budget: at most 3 public official documentation URLs, ONE Contents
batch, markdown only. No browser, no Research. Uses reviewed official-docs URLs
drawn from the evaluation fixture's approved hosts.

Prints only sanitized counts/URLs/titles — never full Markdown.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from ops.core.config import Settings
from ops.you.research import ResearchHostPolicy, YouContentsFetcher

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_LIVE_YOU_CONTENTS_TESTS") != "1",
    reason="opt-in live Contents test: set RUN_LIVE_YOU_CONTENTS_TESTS=1 to run",
)

# Reviewed, public official documentation pages (hosts are in the eval fixture).
_REVIEWED_DOC_URLS = (
    "https://developers.pipedrive.com/",
    "https://developers.hubspot.com/docs/api/private-apps",
    "https://www.twilio.com/docs/iam/api-keys/keys-in-console",
)
_APPROVED_HOSTS = (
    "developers.pipedrive.com",
    "developers.hubspot.com",
    "www.twilio.com",
)
_MAX_URLS = 3


def test_live_contents_extracts_reviewed_pages() -> None:
    settings = Settings.from_env()
    if settings.you_api_key is None:
        pytest.skip("YDC_API_KEY not configured; live Contents evaluation unavailable")

    policy = ResearchHostPolicy.from_domains(_APPROVED_HOSTS)
    fetcher = YouContentsFetcher(
        settings.you_api_key,
        policy=policy,
        max_age=settings.you_contents_max_age_seconds,
        request_timeout=settings.you_contents_timeout_seconds,
        max_pages=_MAX_URLS,
    )

    documents = asyncio.run(fetcher.fetch_many(list(_REVIEWED_DOC_URLS)))

    print(  # noqa: T201 - sanitized: url + title + length only, never full markdown
        {
            "pages_returned": len(documents),
            "pages": [
                {"url": d.source_url, "title": d.title[:80], "chars": len(d.relevant_text)}
                for d in documents
            ],
        }
    )

    # At least 2 of 3 reviewed pages return non-empty bounded Markdown.
    assert len(documents) >= 2
    for d in documents:
        assert d.relevant_text.strip()  # non-empty
        assert len(d.relevant_text) <= 24_000  # bounded
        # Returned URL passes local policy and carries no sensitive query.
        assert policy.validate_candidate_url(d.source_url)
        assert "?" not in d.source_url or "token=" not in d.source_url
