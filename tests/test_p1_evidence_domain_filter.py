"""The P1 evidence domain guard in ``ops/onboarding/runtime.py``.

The locked P1 snapshot sometimes lists third-party hosting links (e.g. a
``github.com`` MCP repo) in an app's ``evidence_urls``. Those foreign hosts leak
into research and make the profile resolver deadlock on a domain disagreement.
``_reviewed_evidence_urls`` now drops any P1 URL whose registrable domain is not
one the reviewed recipe itself vouches for, and logs every drop.

These tests are offline: they read only the local recipe catalog and the local
P1 snapshot, never the network.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import pytest

from ops.browser.host_policy import registrable_domain
from ops.onboarding.runtime import _recipe_authority_domains, _reviewed_evidence_urls
from ops.recipes.app_recipes import get_app_recipe
from ops.research.p1_adapter import P1LookupFound, lookup_p1_record

# On-catalog apps whose P1 evidence contains a foreign (non-authority) host.
# After the guard each collapses to a SINGLE registrable domain, so the
# ``research_domain_disagreement`` deadlock is impossible from their seed set.
CLEARING_APPS = [
    "firecrawl",
    "freshdesk",
    "help-scout",
    "linkedin-ads",
    "meta-ads",
    "ramp",
    "sendgrid",
    "snowflake",
    "telegram",
    "xero",
]


def _p1(slug: str) -> dict[str, object]:
    lookup = lookup_p1_record(slug)
    if not isinstance(lookup, P1LookupFound):
        return {}
    return lookup.record.model_dump(mode="json")


def _domain_of(url: str) -> str | None:
    return registrable_domain(urlsplit(url).hostname or "")


def test_telegram_github_mcp_url_is_dropped_and_logged(caplog: pytest.LogCaptureFixture) -> None:
    recipe = get_app_recipe("telegram")
    authority = _recipe_authority_domains(recipe)
    assert authority == {"telegram.org"}
    p1r = _p1("telegram")
    # The snapshot really does carry a github.com MCP repo link today.
    raw_evidence = p1r.get("evidence_urls")
    p1_evidence = (
        [u for u in raw_evidence if isinstance(u, str)] if isinstance(raw_evidence, list) else []
    )
    assert any("github.com" in u for u in p1_evidence)

    with caplog.at_level("WARNING"):
        filtered = _reviewed_evidence_urls(recipe, p1r)

    hosts = [urlsplit(u).hostname for u in filtered]
    assert "github.com" not in hosts
    # The reviewed telegram.org evidence survives.
    assert any("telegram.org" in (h or "") for h in hosts)
    # Every admitted URL is on the single authority domain -> no disagreement.
    assert {_domain_of(u) for u in filtered} == {"telegram.org"}
    # The drop is auditable, not silent.
    assert "dropping P1 evidence URL outside the reviewed recipe domain" in caplog.text


@pytest.mark.parametrize("slug", CLEARING_APPS)
def test_foreign_p1_evidence_drops_and_evidence_stays_single_domain(
    slug: str, caplog: pytest.LogCaptureFixture
) -> None:
    recipe = get_app_recipe(slug)
    authority = _recipe_authority_domains(recipe)
    assert authority, f"{slug} has no authority domains"
    p1r = _p1(slug)

    with caplog.at_level("WARNING"):
        filtered = _reviewed_evidence_urls(recipe, p1r)

    admitted = {_domain_of(u) for u in filtered}
    admitted.discard(None)
    # Nothing outside the reviewed recipe authority is admitted.
    assert admitted <= authority, f"{slug}: admitted {admitted} outside authority {authority}"
    # And the run's evidence resolves to exactly one registrable domain, so the
    # profile builder's domain vote cannot deadlock on the foreign leak.
    assert len(admitted) == 1, f"{slug}: evidence still spans {admitted}"
    # These apps all carried a foreign P1 host, so the guard must have logged a drop.
    assert "dropping P1 evidence URL outside the reviewed recipe domain" in caplog.text


def test_subdomain_of_authority_domain_is_kept() -> None:
    recipe = get_app_recipe("telegram")
    p1r = {
        "primary_docs_url": "https://api.telegram.org/",
        "evidence_urls": ["https://core.telegram.org/bots"],
    }
    filtered = _reviewed_evidence_urls(recipe, p1r)
    hosts = [urlsplit(u).hostname for u in filtered]
    # api.telegram.org and core.telegram.org are subdomains of the telegram.org
    # authority; they must be admitted, not dropped.
    assert "api.telegram.org" in hosts and "core.telegram.org" in hosts


def test_crafted_host_with_authority_suffix_is_dropped() -> None:
    # A host that *contains* telegram.org but is a different registrable zone
    # (telegram.org.evil.io) must be rejected — suffix matching would admit it.
    recipe = get_app_recipe("telegram")
    p1r = {"evidence_urls": ["https://telegram.org.evil.io/login"]}
    filtered = _reviewed_evidence_urls(recipe, p1r)
    assert all("telegram.org.evil.io" not in u for u in filtered)


def test_recipe_none_keeps_p1_evidence_unfiltered() -> None:
    # With no recipe there is no reviewed authority to filter against; the
    # legacy caller keeps the P1 evidence verbatim (off-catalog runs never call
    # this with a recipe, but the None guard must not throw).
    p1r = {"evidence_urls": ["https://somewhere.example.com/docs"], "primary_docs_url": None}
    assert _reviewed_evidence_urls(None, p1r) == ("https://somewhere.example.com/docs",)


def test_filter_does_not_over_drop_reviewed_multi_zone_authority() -> None:
    # neo4j genuinely spans two registrable domains (neo4j.com + neo4j.io), both
    # authori-ted by the reviewed recipe. The guard must NOT collapse that to
    # one domain or it would silently hide a real multi-zone provider.
    recipe = get_app_recipe("neo4j")
    authority = _recipe_authority_domains(recipe)
    assert len(authority) == 2
    p1r = _p1("neo4j")
    filtered = _reviewed_evidence_urls(recipe, p1r)
    admitted = {d for u in filtered if (d := _domain_of(u))}
    # Both reviewed zones survive the filter.
    assert authority <= admitted
