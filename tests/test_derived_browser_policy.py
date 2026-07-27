"""Offline tests for research-derived browser policies and their routing effect.

The reviewed matrix only covers a handful of apps. These tests pin the behavior
that lets the remaining verified apps execute: the derived allowlist must stay
inside the app's own vendor domain, must never wildcard a shared domain, and must
never override a reviewed decision.
"""

from __future__ import annotations

from typing import Any

from api.assignment_runtime import (
    _assignment_after_browser,
    _assignment_after_route,
    assignment_allowed_hosts,
    assignment_browser_ready,
    resolved_browser_policy,
)
from ops.browser_worker import validate_allowed_domains
from ops.derived_browser_policy import (
    MAX_ALLOWED_PATTERNS,
    derive_browser_host_policy,
    registrable_domain,
)
from ops.models import CompanyProfile, OperationalResearch, OperationsRequest
from ops.operational_baselines import apply_reviewed_operational_baseline
from ops.p1_adapter import load_verified_snapshot, to_operational_research
from ops.provider_errors import ProviderContractError
from ops.routing import decide_access


def _research(
    slug: str,
    *,
    evidence: list[str],
    route: str = "self_serve",
) -> OperationalResearch:
    return OperationalResearch.model_validate(
        {
            "app_name": slug.replace("-", " ").title(),
            "app_slug": slug,
            "api_available": True,
            "api_type": "REST",
            "api_base_url": None,
            "auth_methods": ["API Key"],
            "authorization_url": None,
            "token_url": None,
            "credential_fields": [],
            "scopes": [],
            "developer_portal_url": None,
            "signup_url": None,
            "access_route": route,
            "production_approval_required": None,
            "contact_email": None,
            "contact_url": None,
            "evidence_urls": evidence,
            "confidence": 0.8,
        }
    )


def _company() -> CompanyProfile:
    return CompanyProfile(
        legal_name="Example Labs",
        website="https://example.com",
        work_email_ref="vault://company/work_email/test",
        use_case="Build an authorized integration for the operations team.",
    )


def test_registrable_domain_handles_multi_label_suffixes() -> None:
    assert registrable_domain("developers.notion.com") == "notion.com"
    assert registrable_domain("api.example.co.uk") == "example.co.uk"
    assert registrable_domain("localhost") is None


def test_derived_policy_wildcards_only_the_app_vendor_domain() -> None:
    research = _research("notion", evidence=["https://developers.notion.com/reference"])
    policy = derive_browser_host_policy(research)

    assert policy is not None
    assert policy.active is True
    assert policy.vendor_wildcard_domains == ("notion.com",)
    # The apex is included explicitly because ``*.notion.com`` does not match it.
    assert policy.exact_hosts[0] == "notion.com"
    assert "developers.notion.com" in policy.exact_hosts


def test_derived_policy_drops_third_party_evidence_hosts() -> None:
    """A cited GitHub repo or partner page must not widen the allowlist."""

    research = _research(
        "dealcloud",
        evidence=[
            "https://api.docs.dealcloud.com/docs/apikeys",
            "https://github.com/some/repo",
            "https://www.synchub.io/integrations",
        ],
    )
    policy = derive_browser_host_policy(research)

    assert policy is not None
    assert policy.vendor_wildcard_domains == ("dealcloud.com",)
    assert all(
        host == "dealcloud.com" or host.endswith(".dealcloud.com") for host in policy.exact_hosts
    )


def test_shared_domain_is_usable_for_its_owner_but_never_wildcarded() -> None:
    research = _research("github", evidence=["https://docs.github.com/en/rest"])
    policy = derive_browser_host_policy(research)

    assert policy is not None
    assert policy.vendor_wildcard_domains == ()
    assert policy.exact_hosts[0] == "github.com"
    assert "docs.github.com" in policy.exact_hosts


def test_shared_domain_alone_yields_no_policy_for_an_unrelated_app() -> None:
    """An app documented only on someone else's platform gets no browser route."""

    research = _research("acme-widgets", evidence=["https://developers.facebook.com/docs"])

    assert derive_browser_host_policy(research) is None
    assert resolved_browser_policy(research) is None
    assert assignment_browser_ready(research) is False


def test_reviewed_policy_wins_over_derivation() -> None:
    """HubSpot keeps its hand-verified hosts instead of a derived allowlist."""

    research = _research("hubspot", evidence=["https://legacydocs.hubspot.com/docs"])
    policy = resolved_browser_policy(research)

    assert policy is not None
    assert policy.exact_hosts == ("developers.hubspot.com", "app.hubspot.com")


def test_reviewed_inactive_policy_blocks_derivation() -> None:
    """An explicit reviewed "no" (Sherlock) is never rescued by derivation."""

    research = _research("sherlock", evidence=["https://sherlock.example.com/docs"])

    assert resolved_browser_policy(research) is None
    assert assignment_browser_ready(research) is False
    try:
        assignment_allowed_hosts(research)
    except ProviderContractError as error:
        assert error.reason_code == "browser_policy_inactive_for_app"
    else:  # pragma: no cover - the call above must fail closed
        raise AssertionError("an inactive reviewed policy must refuse an allowlist")


def test_derived_self_serve_app_reaches_the_browser_node() -> None:
    research = _research("notion", evidence=["https://developers.notion.com/reference"])
    state: dict[str, Any] = {
        "request": OperationsRequest(
            app_name="Notion", company=_company(), dry_run=False
        ).model_dump(mode="json"),
        "app_slug": "notion",
        "access_route": "self_serve",
        "operational_research": research.model_dump(mode="json"),
    }

    assert _assignment_after_route(object(), state) == "browser_start"


def test_gated_app_still_sends_outreach_after_a_browser_inspection() -> None:
    state: dict[str, Any] = {
        "access_route": "partner_gated",
        "browser_observation": {"status": "credential_page_ready"},
    }

    assert _assignment_after_browser(None, state) == "outreach_send"  # type: ignore[arg-type]

    already_sent = {**state, "gmail_thread_id": "thread-1"}
    assert _assignment_after_browser(None, already_sent) == "finalize"  # type: ignore[arg-type]

    self_serve = {**state, "access_route": "self_serve"}
    assert _assignment_after_browser(None, self_serve) == "finalize"  # type: ignore[arg-type]


def test_every_verified_app_is_executable_or_verifiably_blocked() -> None:
    """No app in the snapshot may silently dead-end without a reachable node."""

    snapshot = load_verified_snapshot()
    assert len(snapshot.records) == 100

    unreachable: list[str] = []
    for record in snapshot.records:
        research, _ = apply_reviewed_operational_baseline(to_operational_research(record))
        route = decide_access(research).route
        if route == "blocked":
            # Verified evidence says there is no usable API; outreach and browser
            # would both be dishonest here.
            continue
        if assignment_browser_ready(research):
            allowed = assignment_allowed_hosts(research)
            patterns = allowed.patterns()
            assert validate_allowed_domains(patterns) == patterns
            assert len(patterns) <= MAX_ALLOWED_PATTERNS
            continue
        # Not browser-ready is acceptable only when outreach can still run, which
        # needs a route that is not blocked. Record anything else.
        if route == "unknown":
            unreachable.append(record.slug)

    assert unreachable == []
