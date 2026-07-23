"""Per-app browser host policy: activation, isolation, and fail-closed blocking.

Offline-only. No Browser Use session is created; these tests exercise the pure
policy builder and navigation evaluator.
"""

from __future__ import annotations

import pytest

from ops.browser_host_policy import (
    BrowserPolicyInactiveError,
    build_browser_allowed_hosts,
    evaluate_navigation,
    get_browser_policy,
)
from ops.models import OperationalResearch

# Verified P1 access routes for the current 10-app matrix.
_MATRIX_ROUTES = {
    "hubspot": "self_serve",
    "pipedrive": "self_serve",
    "attio": "self_serve",
    "twenty": "self_serve",
    "zendesk": "approval_required",
    "google-ads": "approval_required",
    "whatsapp-business": "approval_required",
    "salesforce": "partner_gated",
    "close": "partner_gated",
    "sherlock": "blocked",
}
_ACTIVE_BROWSER_APPS = {"pipedrive", "twenty"}


def _research(slug: str, route: str, evidence_host: str = "developers.example.com") -> OperationalResearch:
    return OperationalResearch.model_validate(
        {
            "app_name": slug.title(),
            "app_slug": slug,
            "api_available": True,
            "api_type": "REST",
            "api_base_url": None,
            "auth_methods": ["OAuth2"],
            "authorization_url": None,
            "token_url": None,
            "credential_fields": [],
            "scopes": [],
            "developer_portal_url": f"https://{evidence_host}/",
            "signup_url": None,
            "access_route": route,
            "production_approval_required": None,
            "contact_email": None,
            "contact_url": None,
            "evidence_urls": [f"https://{evidence_host}/docs"],
            "confidence": 0.9,
        }
    )


def _build(slug: str):
    route = _MATRIX_ROUTES[slug]
    host = {
        "pipedrive": "developers.pipedrive.com",
        "twenty": "docs.twenty.com",
    }.get(slug, "developers.example.com")
    return build_browser_allowed_hosts(slug, _research(slug, route, host), access_route=route)


# 1 & 2: only Pipedrive and Twenty activate; the other eight never launch.
@pytest.mark.parametrize("slug", sorted(_MATRIX_ROUTES))
def test_only_pipedrive_and_twenty_activate_browser(slug: str) -> None:
    if slug in _ACTIVE_BROWSER_APPS:
        allowed = _build(slug)
        assert allowed.patterns()  # a real allowlist is produced
    else:
        with pytest.raises(BrowserPolicyInactiveError):
            _build(slug)


# 3: Pipedrive permits app/customer subdomains and blocks unrelated providers.
def test_pipedrive_allows_app_and_customer_subdomains_blocks_others() -> None:
    allowed = _build("pipedrive")
    for url in (
        "https://app.pipedrive.com/settings/api",
        "https://developers.pipedrive.com/docs/api/v1",
        "https://oauth.pipedrive.com/oauth/authorize",
        "https://acme-corp.pipedrive.com/settings",
    ):
        assert evaluate_navigation(url, allowed).allowed is True
    for url in ("https://app.hubspot.com/", "https://login.salesforce.com/", "https://twenty.com/"):
        assert evaluate_navigation(url, allowed).allowed is False


# 4: Twenty Cloud permits its approved app/docs/api hosts, no wildcard.
def test_twenty_cloud_allows_approved_hosts_only() -> None:
    allowed = _build("twenty")
    for url in (
        "https://app.twenty.com/settings/api",
        "https://docs.twenty.com/developers/extend/api",
        "https://api.twenty.com/oauth/authorize",
    ):
        assert evaluate_navigation(url, allowed).allowed is True
    # No wildcard: an unknown twenty.com subdomain is blocked.
    assert evaluate_navigation("https://random.twenty.com/", allowed).allowed is False
    assert evaluate_navigation("https://evil.com/", allowed).allowed is False


# 5: Twenty self-hosted requires an exact verified runtime host.
def test_twenty_self_hosted_requires_exact_runtime_host() -> None:
    research = _research("twenty", "self_serve", "docs.twenty.com")
    without = build_browser_allowed_hosts("twenty", research, access_route="self_serve")
    assert evaluate_navigation("https://crm.acme.example/settings", without).allowed is False

    with_host = build_browser_allowed_hosts(
        "twenty",
        research,
        access_route="self_serve",
        self_host_runtime_host="crm.acme.example",
    )
    assert evaluate_navigation("https://crm.acme.example/settings", with_host).allowed is True
    # A different arbitrary customer domain is still not wildcarded.
    assert evaluate_navigation("https://other.acme.example/", with_host).allowed is False


# 6: Attio's reviewed hosts are app.attio.com and build.attio.com (where the
# /authorize page and developer settings live); api.attio.com is NOT here.
def test_attio_reviewed_hosts_exclude_api_host() -> None:
    policy = get_browser_policy("attio")
    assert policy is not None
    assert "app.attio.com" in policy.exact_hosts
    assert "build.attio.com" in policy.exact_hosts
    assert "api.attio.com" not in policy.exact_hosts
    # Attio is connection_required in the matrix: never activates Browser Use.
    assert policy.active is False


# 7: API/token hosts are not in the browser policy unless browser-facing.
def test_api_and_token_hosts_absent_from_browser_policies() -> None:
    hubspot = get_browser_policy("hubspot")
    assert hubspot is not None
    assert "api.hubapi.com" not in hubspot.exact_hosts  # token/API host is network-only
    # Twenty's api.twenty.com IS present because /oauth/authorize is browser-facing.
    twenty = get_browser_policy("twenty")
    assert twenty is not None
    assert "api.twenty.com" in twenty.exact_hosts


# 9: Google and Meta domains are never wildcarded.
def test_google_and_meta_never_wildcarded() -> None:
    google = get_browser_policy("google-ads")
    whatsapp = get_browser_policy("whatsapp-business")
    assert google is not None and whatsapp is not None
    assert google.vendor_wildcard_domains == ()
    assert whatsapp.vendor_wildcard_domains == ()
    # No policy anywhere wildcards a shared corporate/code host.
    for slug in _MATRIX_ROUTES:
        policy = get_browser_policy(slug)
        assert policy is not None
        for shared in ("google.com", "facebook.com", "github.com", "googleapis.com"):
            assert shared not in policy.vendor_wildcard_domains


# 10: Salesforce does not receive broad *.salesforce.com / *.force.com.
def test_salesforce_has_no_broad_wildcard() -> None:
    policy = get_browser_policy("salesforce")
    assert policy is not None
    assert policy.vendor_wildcard_domains == ()
    assert "login.salesforce.com" in policy.exact_hosts


# 11: Sherlock receives an empty policy (no hosts, inactive).
def test_sherlock_policy_is_empty_and_inactive() -> None:
    policy = get_browser_policy("sherlock")
    assert policy is not None
    assert policy.active is False
    assert policy.exact_hosts == ()
    assert policy.vendor_wildcard_domains == ()


# 12: Resume preserves the exact same policy snapshot (deterministic build).
def test_build_is_deterministic_for_resume() -> None:
    first = _build("pipedrive")
    second = _build("pipedrive")
    assert first.patterns() == second.patterns()


# 13: A run cannot inherit another app's policy.
def test_apps_do_not_inherit_each_others_hosts() -> None:
    pipedrive = _build("pipedrive")
    twenty = _build("twenty")
    assert evaluate_navigation("https://app.twenty.com/", pipedrive).allowed is False
    assert evaluate_navigation("https://app.pipedrive.com/", twenty).allowed is False


# 14: Unknown redirects fail closed with structured blocking details.
def test_unknown_redirect_fails_closed_with_details() -> None:
    allowed = _build("pipedrive")
    decision = evaluate_navigation("https://evil.example/login", allowed)
    assert decision.allowed is False
    assert decision.blocked_hostname == "evil.example"
    assert decision.reason_code == "browser_host_not_in_app_policy"
    assert decision.backend_policy_update_required is True
    assert allowed.patterns() == decision.allowed_hosts


# Unknown app fails closed to exact verified research host only (no wildcard).
def test_unknown_app_fails_closed_to_exact_research_host() -> None:
    research = _research("brand-new-app", "self_serve", "developers.newapp.example")
    allowed = build_browser_allowed_hosts("brand-new-app", research, access_route="self_serve")
    assert allowed.vendor_wildcard_domains == ()
    assert evaluate_navigation("https://developers.newapp.example/docs", allowed).allowed is True
    assert evaluate_navigation("https://sub.newapp.example/", allowed).allowed is False


# A browser policy is never built for a non-browser route.
def test_non_browser_route_is_refused() -> None:
    research = _research("pipedrive", "partner_gated", "developers.pipedrive.com")
    with pytest.raises(BrowserPolicyInactiveError) as excinfo:
        build_browser_allowed_hosts("pipedrive", research, access_route="partner_gated")
    assert excinfo.value.reason_code == "route_is_not_a_browser_route"
