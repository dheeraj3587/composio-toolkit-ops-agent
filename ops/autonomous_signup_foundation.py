"""RunService-facing bridge for autonomous signup foundation Parts 6-11.

The browser service chooses the session ID. Therefore values are prepared
UNBOUND for session creation, then immutably bound after the create response and
before navigation. The bridge stops before form detection/filling/submission.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ops.approved_run_values import (
    ApprovedRunValues,
    ApprovedRunValuesRegistry,
    build_approved_run_values,
)
from ops.automation_contracts import (
    BrowserAutomationContract,
    SQLiteAutomationContractRegistry,
)
from ops.contract_routing import ContractRouteDecision, decide_contract_route
from ops.models import OperationsRequest
from ops.signup_state_machine import (
    SQLiteSignupStateStore,
    SignupPolicyDecision,
    SignupStateMachine,
)


@dataclass(frozen=True, slots=True)
class PreparedSignupRun:
    run_id: str
    app_slug: str
    request: OperationsRequest
    approved_values: ApprovedRunValues
    automation_contract: BrowserAutomationContract
    route_decision: ContractRouteDecision

    def create_session_payload(self) -> dict[str, object]:
        if self.approved_values.session_id is not None:
            raise RuntimeError("session-creation values must still be unbound")
        return {
            "app_slug": self.app_slug,
            "run_id": self.run_id,
            "approved_values": self.approved_values.model_dump(mode="json"),
            "automation_contract": self.automation_contract.model_dump(mode="json"),
        }


@dataclass(frozen=True, slots=True)
class BoundSignupSession:
    prepared: PreparedSignupRun
    session_id: str
    approved_values: ApprovedRunValues
    signup_decision: SignupPolicyDecision | None

    @property
    def run_id(self) -> str:
        return self.prepared.run_id

    @property
    def app_slug(self) -> str:
        return self.prepared.app_slug

    @property
    def automation_contract(self) -> BrowserAutomationContract:
        return self.prepared.automation_contract

    @property
    def route_decision(self) -> ContractRouteDecision:
        return self.prepared.route_decision

    def navigate_payload(self, *, research: dict[str, object]) -> dict[str, object]:
        return {
            "research": research,
            "account_policy": self.prepared.request.account_policy,
            "developer_app_policy": self.prepared.request.developer_app_policy,
            "credential_policy": self.prepared.request.credential_policy,
            "approved_values": self.approved_values.model_dump(mode="json"),
            "automation_contract": self.automation_contract.model_dump(mode="json"),
        }


class AutonomousSignupFoundation:
    """Prepare a run, then bind its immutable values to the created session."""

    def __init__(
        self,
        *,
        values_registry: ApprovedRunValuesRegistry,
        contract_registry: SQLiteAutomationContractRegistry,
        signup_state_machine: SignupStateMachine,
    ) -> None:
        self._values_registry = values_registry
        self._contract_registry = contract_registry
        self._signup_state_machine = signup_state_machine

    @classmethod
    def from_paths(
        cls,
        *,
        contract_db_path: str | Path,
        signup_state_db_path: str | Path,
    ) -> AutonomousSignupFoundation:
        return cls(
            values_registry=ApprovedRunValuesRegistry(),
            contract_registry=SQLiteAutomationContractRegistry(contract_db_path),
            signup_state_machine=SignupStateMachine(
                SQLiteSignupStateStore(signup_state_db_path)
            ),
        )

    def prepare_run(
        self,
        *,
        run_id: str,
        app_slug: str,
        request: OperationsRequest,
        signup_email_ref: str,
        account_password_ref: str,
    ) -> PreparedSignupRun:
        contract = self._contract_registry.latest(app_slug)
        if contract is None:
            raise LookupError("verified automation contract is missing")
        contract.assert_usable()
        if contract.app_slug != app_slug or contract.app_name.casefold() != request.app_name.casefold():
            raise ValueError("automation contract does not match the requested app")

        values = build_approved_run_values(
            run_id=run_id,
            request=request,
            signup_email_ref=signup_email_ref,
            account_password_ref=account_password_ref,
        )
        route = decide_contract_route(contract, account_policy=request.account_policy)
        return PreparedSignupRun(
            run_id=run_id,
            app_slug=app_slug,
            request=request,
            approved_values=values,
            automation_contract=contract,
            route_decision=route,
        )

    def bind_session(
        self,
        prepared: PreparedSignupRun,
        *,
        session_id: str,
        account_exists: bool,
    ) -> BoundSignupSession:
        bound = self._values_registry.bind(prepared.approved_values, session_id=session_id)
        signup: SignupPolicyDecision | None = None
        if prepared.route_decision.may_start_browser:
            signup = self._signup_state_machine.plan(
                prepared.run_id,
                account_policy=prepared.request.account_policy,
                account_exists=account_exists,
            )
        return BoundSignupSession(
            prepared=prepared,
            session_id=session_id,
            approved_values=bound,
            signup_decision=signup,
        )

    def get_values(self, *, run_id: str, session_id: str) -> ApprovedRunValues:
        return self._values_registry.get(run_id=run_id, session_id=session_id)

    def release(self, *, run_id: str, session_id: str) -> None:
        self._values_registry.release(run_id=run_id, session_id=session_id)


__all__ = [
    "AutonomousSignupFoundation",
    "BoundSignupSession",
    "PreparedSignupRun",
]
