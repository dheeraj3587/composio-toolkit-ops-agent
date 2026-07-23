"""Offline Composio capability preflight classification.

A fake catalog/connection client drives every case. No live Composio call,
email, browser session, or credential action occurs.
"""

from __future__ import annotations

from pydantic import SecretStr

from ops.composio_capability import (
    ComposioCapabilityPreflight,
    ToolkitInfo,
    classify_capability,
    normalize_app_slug,
)
from ops.config import Settings


class _FakeCatalog:
    def __init__(self, toolkit: ToolkitInfo | None, *, active: bool = False) -> None:
        self._toolkit = toolkit
        self._active = active
        self.toolkit_queries: list[str] = []
        self.connection_queries: list[str] = []

    async def get_toolkit(self, slug: str) -> ToolkitInfo | None:
        self.toolkit_queries.append(slug)
        return self._toolkit

    async def has_active_connection(self, toolkit_slug: str) -> bool:
        self.connection_queries.append(toolkit_slug)
        return self._active


def _preflight(catalog: _FakeCatalog) -> ComposioCapabilityPreflight:
    return ComposioCapabilityPreflight(settings=Settings(), catalog=catalog)


def test_normalize_app_slug_collapses_name_variants() -> None:
    assert normalize_app_slug("Help Scout") == "help-scout"
    assert normalize_app_slug("WhatsApp_Business") == "whatsapp-business"
    assert normalize_app_slug("salesforce") == "salesforce"


async def test_case_a_active_connection_is_composio_ready() -> None:
    catalog = _FakeCatalog(
        ToolkitInfo(
            slug="hubspot",
            available=True,
            managed_auth=True,
            tools=("HUBSPOT_CREATE_CONTACT",),
        ),
        active=True,
    )
    report = await _preflight(catalog).evaluate(
        app_name="HubSpot",
        app_slug="hubspot",
        required_tools=("HUBSPOT_CREATE_CONTACT",),
    )

    assert report.capability_state == "composio_ready"
    assert report.outreach_allowed is False
    assert report.active_connected_account is True
    assert report.required_tools_present is True


async def test_case_b_managed_auth_without_connection_requires_connection() -> None:
    catalog = _FakeCatalog(
        ToolkitInfo(slug="slack", available=True, managed_auth=True, tools=("SLACK_SEND",)),
        active=False,
    )
    report = await _preflight(catalog).evaluate(app_name="Slack", app_slug="slack")

    assert report.capability_state == "connection_required"
    assert report.outreach_allowed is False
    assert report.managed_auth_available is True


async def test_case_c_custom_auth_preserves_gated_outreach() -> None:
    catalog = _FakeCatalog(
        ToolkitInfo(
            slug="zendesk",
            available=True,
            managed_auth=False,
            auth_schemes=("oauth2_custom",),
            tools=("ZENDESK_CREATE_TICKET",),
        ),
        active=False,
    )
    report = await _preflight(catalog).evaluate(app_name="Zendesk", app_slug="zendesk")

    # Zendesk is a real Composio toolkit; it is never "toolkit_unavailable".
    assert report.toolkit_available is True
    assert report.capability_state == "custom_auth_or_approval_required"
    assert report.outreach_allowed is True


async def test_case_d_missing_toolkit_falls_back_to_p1_route() -> None:
    catalog = _FakeCatalog(None)
    report = await _preflight(catalog).evaluate(
        app_name="Obscure Vendor", app_slug="obscure-vendor"
    )

    assert report.toolkit_available is False
    assert report.toolkit_slug is None
    assert report.capability_state == "toolkit_unavailable"
    assert report.outreach_allowed is True


async def test_unavailable_flag_is_treated_as_missing_toolkit() -> None:
    catalog = _FakeCatalog(ToolkitInfo(slug="ghost", available=False))
    report = await _preflight(catalog).evaluate(app_name="Ghost", app_slug="ghost")

    assert report.capability_state == "toolkit_unavailable"
    assert catalog.connection_queries == []  # no connection probe for an absent toolkit


async def test_active_connection_but_missing_required_tools_is_not_ready() -> None:
    catalog = _FakeCatalog(
        ToolkitInfo(slug="gmail", available=True, managed_auth=False, tools=("GMAIL_SEND_EMAIL",)),
        active=True,
    )
    report = await _preflight(catalog).evaluate(
        app_name="Gmail",
        app_slug="gmail",
        required_tools=("GMAIL_FETCH_EMAILS",),
    )

    assert report.required_tools_present is False
    assert report.capability_state == "custom_auth_or_approval_required"


async def test_unconfigured_composio_cannot_check_and_reports_configuration_required() -> None:
    preflight = ComposioCapabilityPreflight(settings=Settings())  # no catalog, no api key

    report = await preflight.evaluate(app_name="Salesforce", app_slug="salesforce")

    assert report.capability_state == "configuration_required"
    assert report.reason_code == "composio_not_configured"
    assert report.outreach_allowed is False


async def test_configured_settings_build_a_live_catalog_without_calling_it() -> None:
    # A configured settings object yields a live catalog adapter; constructing it
    # performs no network call (the SDK is imported lazily on first query).
    settings = Settings(
        composio_api_key=SecretStr("test-key"),  # pragma: allowlist secret
        composio_gmail_connected_account_id="acct-1",
    )
    preflight = ComposioCapabilityPreflight(settings=settings)
    catalog = preflight._build_catalog()

    assert catalog is not None


def test_classify_capability_precedence_is_deterministic() -> None:
    available = ToolkitInfo(slug="x", available=True, managed_auth=True, tools=("T",))
    ready, _, _ = classify_capability(
        toolkit=available, active_connection=True, required_tools=("T",)
    )
    connect, _, _ = classify_capability(
        toolkit=available, active_connection=False, required_tools=()
    )
    custom, _, _ = classify_capability(
        toolkit=ToolkitInfo(slug="x", available=True, managed_auth=False),
        active_connection=False,
        required_tools=(),
    )
    missing, _, _ = classify_capability(toolkit=None, active_connection=False, required_tools=())

    assert (ready, connect, custom, missing) == (
        "composio_ready",
        "connection_required",
        "custom_auth_or_approval_required",
        "toolkit_unavailable",
    )
