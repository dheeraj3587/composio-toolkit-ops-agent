"""Focused contract tests for the reviewed 50-app route catalog."""

from __future__ import annotations

import json
from collections import Counter
from copy import deepcopy
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from ops.app_recipes import (
    GATED_SLUGS,
    MANAGED_AUTH_SLUGS,
    PLAYWRIGHT_SLUGS,
    AppRecipeCatalogError,
    get_app_recipe,
    load_app_recipe_catalog,
    parse_app_recipe_catalog,
    recipe_to_operational_research,
    recipes_for_route,
)
from ops.browser_api_trace_catalog import get_browser_api_trace
from ops.browser_host_policy import get_browser_policy
from ops.credential_capture_specs import get_capture_spec
from ops.credential_validator import pipedrive_validation_policy

_ROOT = Path(__file__).resolve().parents[1]
_CATALOG_PATH = _ROOT / "ops" / "app_recipes.json"
_P1_PATH = _ROOT / "data" / "p1" / "results.json"
_COMPOSIO_PATH = _ROOT / "data" / "p1" / "composio_coverage.json"


def _raw_catalog() -> dict[str, object]:
    value = json.loads(_CATALOG_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _raw_recipe(value: dict[str, object], app_slug: str) -> dict[str, object]:
    apps = value["apps"]
    assert isinstance(apps, list)
    return next(item for item in apps if isinstance(item, dict) and item["app_slug"] == app_slug)


def test_catalog_is_the_exact_approved_25_14_11_matrix() -> None:
    catalog = load_app_recipe_catalog()
    expected = (*MANAGED_AUTH_SLUGS, *PLAYWRIGHT_SLUGS, *GATED_SLUGS)

    assert catalog.schema_version == "1.0"
    assert tuple(recipe.app_slug for recipe in catalog.apps) == expected
    assert Counter(recipe.route_kind for recipe in catalog.apps) == {
        "managed_auth": 25,
        "playwright": 14,
        "gated": 11,
    }
    assert tuple(recipe.app_slug for recipe in recipes_for_route("managed_auth")) == (
        MANAGED_AUTH_SLUGS
    )
    assert tuple(recipe.app_slug for recipe in recipes_for_route("playwright")) == (
        PLAYWRIGHT_SLUGS
    )
    assert tuple(recipe.app_slug for recipe in recipes_for_route("gated")) == GATED_SLUGS


def test_catalog_routes_match_locked_p1_and_managed_composio_coverage() -> None:
    catalog = load_app_recipe_catalog()
    p1 = {item["slug"]: item for item in json.loads(_P1_PATH.read_text(encoding="utf-8"))}
    coverage = json.loads(_COMPOSIO_PATH.read_text(encoding="utf-8"))["apps"]

    assert set(recipe.app_slug for recipe in catalog.apps) <= set(p1)
    for recipe in recipes_for_route("managed_auth"):
        report = coverage[recipe.app_slug]
        assert recipe.toolkit_slug == report["toolkit_slug"]
        assert report["status"] == "Active"
        assert "OAUTH2" in report["managed_auth_schemes"]


def test_pipedrive_recipe_matches_reviewed_trace_capture_host_and_validation() -> None:
    recipe = get_app_recipe("pipedrive")
    trace = get_browser_api_trace("pipedrive")
    capture = get_capture_spec("pipedrive")
    host_policy = get_browser_policy("pipedrive")
    validation = pipedrive_validation_policy()

    assert recipe is not None
    assert trace is not None
    assert capture is not None
    assert host_policy is not None
    assert recipe.readiness_tier == "browser_ready"
    assert recipe.browser_ready is True
    assert recipe.browser is not None
    assert recipe.browser.scope == "credential_surface"
    assert recipe.browser.signup is not None
    assert recipe.browser.signup.flow == "email_first"
    assert recipe.browser.signup.entry_path_prefixes == ("/en/register",)
    assert recipe.browser.signup.entry_submit_labels == ("Sign up in two minutes",)
    assert recipe.browser.signup.entry_submit_implies_legal_acceptance is True
    assert recipe.urls.login == "https://app.pipedrive.com/auth/login"
    assert recipe.urls.credential_management == trace.start_url == capture.url
    assert set(recipe.browser.exact_hosts) <= set(host_policy.exact_hosts)
    assert recipe.browser.success.url_path_contains == trace.success.url_path_contains
    assert recipe.browser.success.visible_text_contains == trace.success.visible_text_contains
    assert recipe.capture.field_name == capture.field_kind == validation.credential_field
    assert recipe.capture.selectors == capture.selectors
    assert recipe.capture.value_pattern == capture.value_pattern
    assert recipe.capture.expected_path_prefix == capture.expected_path_prefix
    assert recipe.capture.expected_heading == capture.expected_heading
    assert recipe.validation is not None
    assert recipe.validation.endpoint == validation.allowed_endpoints[0]
    assert recipe.validation.auth_scheme == validation.auth_scheme
    assert recipe.validation.header_name == validation.header_name


def test_other_playwright_routes_are_entry_only_and_owner_submitted() -> None:
    recipes = recipes_for_route("playwright")
    assert Counter(recipe.readiness_tier for recipe in recipes) == {
        "browser_ready": 1,
        "owner_submit_ready": 13,
    }

    for recipe in recipes:
        assert recipe.urls.login is not None
        assert recipe.browser is not None
        assert recipe.browser.steps[0].action == "navigate"
        assert recipe.browser.steps[0].target_url == recipe.urls.login
        if recipe.app_slug == "pipedrive":
            continue
        assert recipe.browser.exact_hosts == (urlsplit(recipe.urls.login).hostname,)
        assert recipe.browser.scope == "entry_only"
        assert recipe.capture.mode == "owner_submit"
        assert recipe.validation is None
        assert recipe.urls.credential_management is None
        assert recipe.browser_ready is False


def test_gated_routes_expose_only_reviewed_email_outreach() -> None:
    email_ready = {"close", "freshdesk", "ahrefs", "brex"}
    for recipe in recipes_for_route("gated"):
        assert recipe.outreach is not None
        if recipe.app_slug in email_ready:
            assert recipe.readiness_tier == "outreach_ready"
            assert recipe.outreach.contact_email is not None
        else:
            assert recipe.readiness_tier == "outreach_review_required"
        assert recipe.outreach.sending_policy == "controlled_sink_only"
        assert recipe.browser is None


def test_readiness_and_navigation_overclaims_fail_closed() -> None:
    owner_overclaim = deepcopy(_raw_catalog())
    _raw_recipe(owner_overclaim, "telegram")["readiness_tier"] = "browser_ready"
    with pytest.raises(AppRecipeCatalogError, match="browser-ready contract is incomplete"):
        parse_app_recipe_catalog(owner_overclaim)

    wildcard_navigation = deepcopy(_raw_catalog())
    pipedrive = _raw_recipe(wildcard_navigation, "pipedrive")
    browser = pipedrive["browser"]
    assert isinstance(browser, dict)
    browser["exact_hosts"] = ["*.pipedrive.com"]
    with pytest.raises(AppRecipeCatalogError, match="must be an exact host"):
        parse_app_recipe_catalog(wildcard_navigation)

    signup_without_policy = deepcopy(_raw_catalog())
    pipedrive_without_policy = _raw_recipe(signup_without_policy, "pipedrive")
    pipedrive_browser = pipedrive_without_policy["browser"]
    assert isinstance(pipedrive_browser, dict)
    pipedrive_browser.pop("signup")
    with pytest.raises(AppRecipeCatalogError, match="signup URL requires a reviewed signup policy"):
        parse_app_recipe_catalog(signup_without_policy)

    unreviewed_signup_path = deepcopy(_raw_catalog())
    pipedrive_unreviewed_path = _raw_recipe(unreviewed_signup_path, "pipedrive")
    signup_browser = pipedrive_unreviewed_path["browser"]
    assert isinstance(signup_browser, dict)
    signup_policy = signup_browser["signup"]
    assert isinstance(signup_policy, dict)
    signup_policy["entry_path_prefixes"] = ["/register-v2"]
    with pytest.raises(AppRecipeCatalogError, match="does not match the reviewed entry path"):
        parse_app_recipe_catalog(unreviewed_signup_path)

    contact_overclaim = deepcopy(_raw_catalog())
    close = _raw_recipe(contact_overclaim, "close")
    close["readiness_tier"] = "outreach_ready"
    outreach = close["outreach"]
    assert isinstance(outreach, dict)
    outreach["contact_url"] = None
    outreach["contact_email"] = None
    with pytest.raises(AppRecipeCatalogError, match="needs a contact"):
        parse_app_recipe_catalog(contact_overclaim)


def test_operational_research_projection_preserves_the_locked_p1_contract() -> None:
    pipedrive = get_app_recipe("pipedrive")
    github = get_app_recipe("github")
    close = get_app_recipe("close")
    assert pipedrive is not None and github is not None and close is not None

    pipedrive_research = recipe_to_operational_research(pipedrive)
    assert pipedrive_research.app_slug == "pipedrive"
    assert pipedrive_research.access_route == "self_serve"
    assert pipedrive_research.login_url == pipedrive.urls.login
    assert pipedrive_research.credential_management_url == pipedrive.urls.credential_management
    assert pipedrive_research.credential_fields == ["api_token"]

    github_research = recipe_to_operational_research(github, app_name="GitHub")
    assert github_research.access_route == "self_serve"
    assert github_research.credential_fields == []

    close_research = recipe_to_operational_research(close)
    assert close_research.access_route == "partner_gated"
    assert close_research.production_approval_required is True
    assert close_research.contact_url is None
