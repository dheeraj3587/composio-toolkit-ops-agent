"""Deterministic top-25 browser API traces, offline and secret-free."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

from api.assignment_runtime import assignment_policy
from ops.browser_api_trace_catalog import (
    get_browser_api_trace,
    load_browser_api_trace_catalog,
    render_browser_api_trace,
)
from ops.browser_host_policy import get_browser_policy, host_matches_patterns
from ops.browser_worker import _official_target_url, _render_browser_task
from ops.models import OperationalResearch

_ROOT = Path(__file__).resolve().parents[1]
_CATALOG_PATH = _ROOT / "ops" / "browser_api_traces.json"
_P1_PATH = _ROOT / "data" / "p1" / "results.json"


def _research() -> OperationalResearch:
    return OperationalResearch.model_validate(
        {
            "app_name": "Pipedrive",
            "app_slug": "pipedrive",
            "api_available": True,
            "api_type": "REST",
            "api_base_url": None,
            "auth_methods": ["API Key", "OAuth2"],
            "authorization_url": None,
            "token_url": None,
            "credential_fields": [],
            "scopes": [],
            "developer_portal_url": "https://developers.pipedrive.com/docs/api/v1",
            "signup_url": None,
            "access_route": "self_serve",
            "production_approval_required": False,
            "contact_email": None,
            "contact_url": None,
            "evidence_urls": ["https://developers.pipedrive.com/docs/api/v1/Oauth"],
            "confidence": 0.95,
        }
    )


def test_catalog_is_exactly_the_first_25_p1_snapshot_records() -> None:
    catalog = load_browser_api_trace_catalog()
    p1_records = json.loads(_P1_PATH.read_text(encoding="utf-8"))

    assert catalog.schema_version == "1.0"
    assert catalog.selection_source == "data/p1/results.json"
    assert "not a popularity ranking" in catalog.selection_basis
    assert len(catalog.apps) == 25
    assert [trace.position for trace in catalog.apps] == list(range(1, 26))
    assert [(trace.app_slug, trace.app_name) for trace in catalog.apps] == [
        (record["slug"], record["app"]) for record in p1_records[:25]
    ]

    for trace, record in zip(catalog.apps, p1_records[:25], strict=True):
        assert trace.evidence_url in record["evidence_urls"]
        assert len(trace.checkpoints) >= 2
        assert [step.order for step in trace.checkpoints] == list(
            range(1, len(trace.checkpoints) + 1)
        )


def test_catalog_contains_no_secret_capable_fields_or_bearer_urls() -> None:
    raw = json.loads(_CATALOG_PATH.read_text(encoding="utf-8"))
    forbidden_keys = {
        "access_token",
        "api_key",
        "authorization_code",
        "cdp_url",
        "client_secret",
        "cookie",
        "credential_value",
        "live_url",
        "otp",
        "password",
        "private_key",
        "refresh_token",
        "secret",
        "signed_url",
        "token",
        "totp",
    }

    def assert_safe_fields(value: object) -> None:
        if isinstance(value, dict):
            assert forbidden_keys.isdisjoint(key.casefold() for key in value)
            for nested in value.values():
                assert_safe_fields(nested)
        elif isinstance(value, list):
            for nested in value:
                assert_safe_fields(nested)

    assert_safe_fields(raw)
    serialized = json.dumps(raw).casefold()
    for marker in (
        "vault://",
        "access_token=",
        "api_key=",
        "authorization_code=",
        "client_secret=",
        "password=",
        "refresh_token=",
        "token=",
        "-----begin private key-----",
    ):
        assert marker not in serialized

    for trace in load_browser_api_trace_catalog().apps:
        for url in (trace.start_url, trace.evidence_url):
            parsed = urlsplit(url)
            assert parsed.scheme == "https"
            assert parsed.hostname
            assert parsed.username is None
            assert parsed.password is None
            assert parsed.query == ""
            assert parsed.fragment == ""


def test_catalog_start_urls_fit_every_already_active_host_policy() -> None:
    catalog = load_browser_api_trace_catalog()
    checked_core: set[str] = set()
    checked_assignment: set[str] = set()

    for trace in catalog.apps:
        hostname = urlsplit(trace.start_url).hostname
        assert hostname is not None

        core_policy = get_browser_policy(trace.app_slug)
        if core_policy is not None and core_policy.active:
            patterns = (
                *core_policy.exact_hosts,
                *(f"*.{domain}" for domain in core_policy.vendor_wildcard_domains),
            )
            assert host_matches_patterns(hostname, patterns)
            checked_core.add(trace.app_slug)

        live_policy = assignment_policy(trace.app_slug)
        if live_policy is not None and live_policy.active:
            patterns = (
                *live_policy.exact_hosts,
                *(f"*.{domain}" for domain in live_policy.vendor_wildcard_domains),
            )
            assert host_matches_patterns(hostname, patterns)
            checked_assignment.add(trace.app_slug)

    assert checked_core == {"pipedrive", "twenty"}
    assert checked_assignment == {
        "attio",
        "close",
        "hubspot",
        "pipedrive",
        "salesforce",
        "twenty",
        "zendesk",
    }


def test_catalog_url_is_only_preferred_inside_existing_allowlist() -> None:
    research = _research()
    allowed = ("developers.pipedrive.com", "app.pipedrive.com")

    assert (
        _official_target_url(
            research,
            allowed,
            preferred_url="https://app.pipedrive.com/settings/api",
        )
        == "https://app.pipedrive.com/settings/api"
    )
    assert (
        _official_target_url(
            research,
            allowed,
            preferred_url="https://unapproved.example/settings/api",
        )
        == "https://developers.pipedrive.com/docs/api/v1"
    )


def test_trace_is_rendered_into_browser_task_with_fail_closed_divergence() -> None:
    trace = get_browser_api_trace("pipedrive")
    assert trace is not None

    guidance = render_browser_api_trace(trace)
    task = _render_browser_task(
        trace.start_url,
        ("app.pipedrive.com", "*.pipedrive.com"),
        None,
        trace=trace,
    )

    assert "STRICT APP TRACE: Pipedrive" in guidance
    assert "Personal preferences" in guidance
    assert "DIVERGENCE:" in guidance
    assert guidance in task
    assert f"START: Open {trace.start_url}" in task
    assert "Never navigate to any other domain" in task
    assert "do not attempt these yourself" in task


def test_unknown_app_keeps_generic_browser_behavior() -> None:
    assert get_browser_api_trace("not-in-the-catalog") is None
    task = _render_browser_task(
        "https://developers.example.com/",
        ("developers.example.com",),
        None,
    )
    assert "STRICT APP TRACE" not in task
    assert "GOAL: Reach the page where the account's API credentials" in task
