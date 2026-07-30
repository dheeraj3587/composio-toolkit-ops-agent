"""Canonical recipe-backed browser host policy tests (offline only)."""

from __future__ import annotations

import pytest

from ops.browser.host_policy import (
    BrowserPolicyInactiveError,
    build_browser_allowed_hosts,
    evaluate_navigation,
)
from ops.core.models import OperationalResearch
from ops.recipes.app_recipes import get_app_recipe, recipe_to_operational_research


def _pipedrive_hosts():
    recipe = get_app_recipe("pipedrive")
    assert recipe is not None
    return build_browser_allowed_hosts(
        recipe.app_slug,
        recipe_to_operational_research(recipe),
        access_route="self_serve",
    )


def test_pipedrive_allows_only_reviewed_exact_navigation_hosts() -> None:
    allowed = _pipedrive_hosts()

    for url in (
        "https://app.pipedrive.com/settings/api",
        "https://developers.pipedrive.com/docs/api/v1",
        "https://oauth.pipedrive.com/oauth/authorize",
    ):
        assert evaluate_navigation(url, allowed).allowed is True

    for url in (
        "https://acme-corp.pipedrive.com/settings",
        "https://app.hubspot.com/",
        "https://evil.example/login",
    ):
        assert evaluate_navigation(url, allowed).allowed is False

    assert allowed.vendor_wildcard_domains == ()


def test_unknown_app_cannot_derive_browser_authority_from_research() -> None:
    research = OperationalResearch.model_validate(
        {
            "app_name": "Brand New App",
            "app_slug": "brand-new-app",
            "api_available": True,
            "api_type": "REST",
            "api_base_url": None,
            "auth_methods": ["OAuth2"],
            "authorization_url": None,
            "token_url": None,
            "credential_fields": [],
            "scopes": [],
            "developer_portal_url": "https://developers.newapp.example/",
            "signup_url": None,
            "access_route": "self_serve",
            "production_approval_required": None,
            "contact_email": None,
            "contact_url": None,
            "evidence_urls": ["https://developers.newapp.example/docs"],
            "confidence": 0.9,
        }
    )

    with pytest.raises(BrowserPolicyInactiveError) as raised:
        build_browser_allowed_hosts(
            "brand-new-app",
            research,
            access_route="self_serve",
        )

    assert raised.value.reason_code == "reviewed_browser_policy_required"


def test_non_browser_route_is_refused_before_policy_resolution() -> None:
    recipe = get_app_recipe("pipedrive")
    assert recipe is not None

    with pytest.raises(BrowserPolicyInactiveError) as raised:
        build_browser_allowed_hosts(
            recipe.app_slug,
            recipe_to_operational_research(recipe),
            access_route="partner_gated",
        )

    assert raised.value.reason_code == "route_is_not_a_browser_route"


def test_policy_snapshot_is_deterministic_for_resume() -> None:
    assert _pipedrive_hosts().patterns() == _pipedrive_hosts().patterns()
