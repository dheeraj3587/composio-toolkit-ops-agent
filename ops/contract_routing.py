"""Route verified automation contracts into the next bounded workflow phase."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ops.automation_contracts import BrowserAutomationContract, ContractRoute
from ops.policies import AccountPolicy

ContractNextPhase = Literal[
    "account_discovery",
    "account_discovery_with_hitl",
    "provider_approval",
    "partner_outreach",
    "stopped",
    "configuration_required",
]


@dataclass(frozen=True, slots=True)
class ContractRouteDecision:
    route: ContractRoute
    next_phase: ContractNextPhase
    reason_code: str
    may_start_browser: bool
    external_actions: bool = False


def decide_contract_route(
    contract: BrowserAutomationContract,
    *,
    account_policy: AccountPolicy,
) -> ContractRouteDecision:
    """Map a verified route without requiring a legacy handwritten trace."""

    contract.assert_usable()
    route = contract.routing.route_classification

    if route == "self_serve":
        if account_policy == "create_if_missing" and not contract.routing.signup_supported:
            return ContractRouteDecision(
                route=route,
                next_phase="configuration_required",
                reason_code="signup_not_supported_by_verified_contract",
                may_start_browser=False,
            )
        if account_policy == "reuse_existing" and not contract.routing.login_supported:
            return ContractRouteDecision(
                route=route,
                next_phase="configuration_required",
                reason_code="login_not_supported_by_verified_contract",
                may_start_browser=False,
            )
        return ContractRouteDecision(
            route=route,
            next_phase="account_discovery",
            reason_code="verified_self_serve_contract",
            may_start_browser=True,
        )

    if route == "self_serve_with_hitl":
        return ContractRouteDecision(
            route=route,
            next_phase="account_discovery_with_hitl",
            reason_code="verified_self_serve_contract_with_human_gates",
            may_start_browser=True,
        )

    if route == "hybrid":
        return ContractRouteDecision(
            route=route,
            next_phase="account_discovery",
            reason_code="verified_hybrid_contract",
            may_start_browser=True,
        )

    if route == "approval_required":
        return ContractRouteDecision(
            route=route,
            next_phase="provider_approval",
            reason_code="production_approval_required",
            may_start_browser=False,
        )

    if route == "partner_gated":
        return ContractRouteDecision(
            route=route,
            next_phase="partner_outreach",
            reason_code="partner_application_required",
            may_start_browser=False,
        )

    if route == "blocked":
        return ContractRouteDecision(
            route=route,
            next_phase="stopped",
            reason_code="verified_contract_blocks_external_action",
            may_start_browser=False,
        )

    return ContractRouteDecision(
        route=route,
        next_phase="configuration_required",
        reason_code="verified_contract_does_not_support_automation",
        may_start_browser=False,
    )


__all__ = ["ContractNextPhase", "ContractRouteDecision", "decide_contract_route"]
