from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from ops.automation_contracts import (
    BrowserAutomationContract,
    ContractEvidence,
    ContractHosts,
    ContractLogin,
    ContractRouting,
    ContractSignup,
    ContractValidationError,
    SQLiteAutomationContractRegistry,
    evidence_hash_for,
)
from ops.contract_host_policy import (
    ContractEgressStage,
    ReviewedDomainRules,
    build_contract_allowed_hosts,
)
from ops.contract_refresh import ContractRefreshService, RefreshSignals
from ops.contract_routing import decide_contract_route

_NOW = datetime(2026, 7, 27, tzinfo=UTC)
_SOURCE = "https://docs.example.com/automation"


def contract(
    *,
    route: str = "self_serve",
    version: str = "1.0.0",
    generated_at: str = "2026-07-27T00:00:00Z",
    expires_at: str = "2099-07-27T00:00:00Z",
    source_urls: tuple[str, ...] = (_SOURCE,),
    vendor_hosts: tuple[str, ...] = ("app.example.com",),
    authentication_hosts: tuple[str, ...] = ("login.example.com",),
) -> BrowserAutomationContract:
    browser_route = route in {"self_serve", "self_serve_with_hitl", "hybrid"}
    return BrowserAutomationContract(
        app_slug="example",
        app_name="Example",
        contract_version=version,
        status="active",
        generated_at=generated_at,
        expires_at=expires_at,
        confidence=0.94,
        evidence_hash=evidence_hash_for(source_urls),
        routing=ContractRouting(
            route_classification=route,  # type: ignore[arg-type]
            signup_supported=browser_route,
            login_supported=browser_route,
            production_approval_required=route in {"hybrid", "approval_required"},
            developer_app_creation_supported=browser_route,
            credential_creation_supported=browser_route,
        ),
        hosts=ContractHosts(
            vendor_hosts=vendor_hosts,
            authentication_hosts=authentication_hosts,
            email_verification_hosts=("verify.example.com",),
            developer_console_hosts=("developers.example.com",),
            credential_surface_hosts=("keys.example.com",),
            passive_asset_hosts=("static.example.com",),
            prohibited_hosts=("tracking.invalid",),
        ),
        signup=ContractSignup(
            entrypoints=("https://app.example.com/signup",) if browser_route else (),
            required_semantic_fields=("signup_email", "account_password"),
            optional_semantic_fields=("legal_name", "company_website"),
            success_predicates=("account-home-visible",),
        ),
        login=ContractLogin(
            entrypoints=("https://login.example.com/",) if browser_route else (),
            login_patterns=("email-password",),
            authentication_success_predicates=("account-home-visible",),
            authentication_failure_predicates=("invalid-credentials",),
        ),
        evidence=ContractEvidence(
            source_urls=source_urls,
            field_sources={"routing": source_urls, "hosts": source_urls},
        ),
    )


def test_contract_registry_round_trips_versioned_contract(tmp_path) -> None:
    registry = SQLiteAutomationContractRegistry(tmp_path / "contracts.db")
    value = contract()

    registry.put(value)

    assert registry.get("example", "1.0.0") == value
    assert registry.latest_fresh("example", now=_NOW) == value


def test_contract_rejects_malformed_or_expired_input() -> None:
    with pytest.raises(ValidationError):
        contract(vendor_hosts=("https://app.example.com/path",))

    expired = contract(
        generated_at="2026-07-20T00:00:00Z",
        expires_at="2026-07-26T00:00:00Z",
    )
    with pytest.raises(ContractValidationError):
        expired.assert_usable(now=_NOW)


class Discovery:
    def __init__(self, urls: tuple[str, ...]) -> None:
        self.urls = urls
        self.calls = 0

    async def discover(self, *, app_slug: str, app_name: str) -> tuple[str, ...]:
        assert (app_slug, app_name) == ("example", "Example")
        self.calls += 1
        return self.urls


class Generator:
    def __init__(self, result: BrowserAutomationContract) -> None:
        self.result = result
        self.calls = 0

    async def propose(
        self,
        *,
        app_slug: str,
        app_name: str,
        official_source_urls: tuple[str, ...],
        previous_contract: BrowserAutomationContract | None,
    ) -> BrowserAutomationContract:
        assert (app_slug, app_name) == ("example", "Example")
        assert official_source_urls
        del previous_contract
        self.calls += 1
        return self.result


@pytest.mark.asyncio
async def test_fresh_contract_avoids_discovery(tmp_path) -> None:
    registry = SQLiteAutomationContractRegistry(tmp_path / "contracts.db")
    current = contract()
    registry.put(current)
    discovery = Discovery((_SOURCE,))
    generator = Generator(contract(version="1.0.1"))
    service = ContractRefreshService(
        registry=registry,
        discovery=discovery,
        proposal_generator=generator,
    )

    resolved = await service.resolve(
        app_slug="example",
        app_name="Example",
        official_domains=("example.com",),
        now=_NOW,
    )

    assert resolved.contract == current
    assert resolved.trigger == "fresh_cache"
    assert discovery.calls == 0
    assert generator.calls == 0


@pytest.mark.asyncio
async def test_stale_contract_refreshes_from_official_evidence(tmp_path) -> None:
    registry = SQLiteAutomationContractRegistry(tmp_path / "contracts.db")
    registry.put(
        contract(
            version="0.9.0",
            generated_at="2026-07-20T00:00:00Z",
            expires_at="2026-07-26T00:00:00Z",
        )
    )
    refreshed = contract(version="1.1.0")
    discovery = Discovery((_SOURCE,))
    generator = Generator(refreshed)
    service = ContractRefreshService(
        registry=registry,
        discovery=discovery,
        proposal_generator=generator,
    )

    resolved = await service.resolve(
        app_slug="example",
        app_name="Example",
        official_domains=("example.com",),
        now=_NOW,
    )

    assert resolved.contract == refreshed
    assert resolved.refreshed is True
    assert discovery.calls == 1
    assert generator.calls == 1
    assert registry.latest("example") == refreshed


@pytest.mark.asyncio
async def test_invalid_refresh_keeps_previous_verified_contract(tmp_path) -> None:
    registry = SQLiteAutomationContractRegistry(tmp_path / "contracts.db")
    previous = contract()
    registry.put(previous)
    discovery = Discovery(("https://unofficial.invalid/page",))
    generator = Generator(contract(version="2.0.0"))
    service = ContractRefreshService(
        registry=registry,
        discovery=discovery,
        proposal_generator=generator,
    )

    resolved = await service.resolve(
        app_slug="example",
        app_name="Example",
        official_domains=("example.com",),
        signals=RefreshSignals(observed_divergence=True),
        now=_NOW,
    )

    assert resolved.contract == previous
    assert resolved.retained_previous is True
    assert registry.latest("example") == previous
    assert discovery.calls == 1
    assert generator.calls == 0


@pytest.mark.parametrize(
    ("route", "next_phase", "may_start_browser"),
    [
        ("self_serve", "account_discovery", True),
        ("self_serve_with_hitl", "account_discovery_with_hitl", True),
        ("hybrid", "account_discovery", True),
        ("approval_required", "provider_approval", False),
        ("partner_gated", "partner_outreach", False),
        ("blocked", "stopped", False),
        ("unsupported", "configuration_required", False),
    ],
)
def test_every_contract_route_maps_to_the_correct_phase(
    route: str,
    next_phase: str,
    may_start_browser: bool,
) -> None:
    decision = decide_contract_route(contract(route=route), account_policy="reuse_existing")

    assert decision.route == route
    assert decision.next_phase == next_phase
    assert decision.may_start_browser is may_start_browser
    assert decision.external_actions is False


def test_create_policy_requires_verified_signup_support() -> None:
    value = contract().model_copy(
        update={
            "routing": ContractRouting(
                route_classification="self_serve",
                signup_supported=False,
                login_supported=True,
            )
        }
    )

    decision = decide_contract_route(value, account_policy="create_if_missing")

    assert decision.next_phase == "configuration_required"
    assert decision.may_start_browser is False


def _reviewed_rules() -> ReviewedDomainRules:
    return ReviewedDomainRules(
        exact_hosts=(
            "app.example.com",
            "login.example.com",
            "verify.example.com",
            "developers.example.com",
            "keys.example.com",
            "static.example.com",
        )
    )


def test_verified_contract_activates_dynamic_hosts() -> None:
    policy = build_contract_allowed_hosts(contract(), reviewed_rules=_reviewed_rules())

    assert policy.permits(
        url="https://app.example.com/signup",
        stage=ContractEgressStage.SIGNUP,
    )
    assert policy.permits(
        url="https://login.example.com/authorize",
        stage=ContractEgressStage.AUTHENTICATING,
    )


def test_unreviewed_contract_host_fails_closed() -> None:
    with pytest.raises(ContractValidationError):
        build_contract_allowed_hosts(
            contract(authentication_hosts=("login.unreviewed.invalid",)),
            reviewed_rules=ReviewedDomainRules(exact_hosts=("app.example.com",)),
        )


def test_credential_surface_is_the_strictest_stage() -> None:
    policy = build_contract_allowed_hosts(contract(), reviewed_rules=_reviewed_rules())

    assert policy.permits(
        url="https://keys.example.com/api-keys",
        stage=ContractEgressStage.CREDENTIAL_SURFACE,
    )
    assert not policy.permits(
        url="https://app.example.com/dashboard",
        stage=ContractEgressStage.CREDENTIAL_SURFACE,
    )
    assert not policy.permits(
        url="https://static.example.com/pixel.gif",
        stage=ContractEgressStage.CREDENTIAL_SURFACE,
        passive_resource=True,
    )
