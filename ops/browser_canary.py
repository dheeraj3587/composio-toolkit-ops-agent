"""The controlled live canary: gates, safety envelope and rollout stages.

A canary is the first time this harness touches a real vendor. That makes it the
single most dangerous thing in the project, so the preconditions are expressed as
CODE rather than as instructions in a runbook — a checklist can be skipped, a
fail-closed gate cannot.

Three independent gates must all be set (defence in depth: any one of them being
the default value keeps the canary inert):

* ``RUN_LIVE_PLAYWRIGHT_CANARY=1`` — explicit intent for THIS operation,
* ``ALLOW_LIVE_BROWSER=true`` — the project-wide live-browser opt-in,
* ``BROWSER_PROVIDER=playwright`` — the provider actually under test.

On top of that, the canary declares a safety envelope: an owned test account in a
non-production workspace on a reviewed app, read-only navigation, and a hard
prohibition on billing, legal acceptance, credential rotation, revocation and
invitation. The first objective deliberately STOPS before revealing a credential —
reaching the page structurally is the result being measured.

One concurrent session, and never in ordinary CI.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

# The environment variable that arms the canary for one operation.
CANARY_ENV_VAR = "RUN_LIVE_PLAYWRIGHT_CANARY"

# Exactly one live browser session may exist during a canary.
MAX_CONCURRENT_CANARY_SESSIONS = 1

CanaryStage = Literal[
    "stage_0_local_only",
    "stage_1_shadow_planning",
    "stage_2_read_only_canary",
    "stage_3_login_and_credential_page",
    "stage_4_deterministic_capture",
    "stage_5_production_canary",
]

# Operations a canary must never perform. Checked by name so a future objective
# cannot quietly add one of them.
FORBIDDEN_CANARY_OPERATIONS: frozenset[str] = frozenset(
    {
        "accept_legal_terms",
        "accept_terms",
        "billing_change",
        "create_invitation",
        "delete_account",
        "invite_user",
        "purchase",
        "reveal_credential",
        "revoke_credential",
        "rotate_credential",
        "transfer_ownership",
        "update_payment_method",
    }
)

# The only actions the initial canary objective may take.
READ_ONLY_CANARY_ACTIONS: frozenset[str] = frozenset(
    {"click", "focus", "goto", "press", "scroll_into_view", "wait_for"}
)


@dataclass(frozen=True, slots=True)
class CanaryGateResult:
    """Whether the canary may run, and precisely why not when it may not."""

    allowed: bool
    reason_code: str
    missing_gates: tuple[str, ...] = ()

    def describe(self) -> str:
        if self.allowed:
            return "canary gates satisfied"
        return (
            f"canary refused: {self.reason_code} (missing: {', '.join(self.missing_gates) or '-'})"
        )


def _truthy(value: str | None) -> bool:
    return (value or "").strip().casefold() in {"1", "true", "yes", "on"}


def evaluate_canary_gates(env: Mapping[str, str] | None = None) -> CanaryGateResult:
    """Check all three gates. Fails closed and reports every missing gate.

    All gates are evaluated (rather than short-circuiting) so an operator sees the
    complete list in one pass instead of discovering them one at a time.
    """

    source: Mapping[str, str] = env if env is not None else os.environ
    missing: list[str] = []

    if not _truthy(source.get(CANARY_ENV_VAR)):
        missing.append(f"{CANARY_ENV_VAR}=1")
    if not _truthy(source.get("ALLOW_LIVE_BROWSER")):
        missing.append("ALLOW_LIVE_BROWSER=true")
    if (source.get("BROWSER_PROVIDER") or "").strip().casefold() != "playwright":
        missing.append("BROWSER_PROVIDER=playwright")

    if missing:
        return CanaryGateResult(
            allowed=False, reason_code="canary_gates_not_set", missing_gates=tuple(missing)
        )
    return CanaryGateResult(allowed=True, reason_code="canary_armed")


@dataclass(frozen=True, slots=True)
class CanaryTarget:
    """The account and app a canary is permitted to touch.

    Every field is an assertion the operator must make explicitly. There is no
    default that says "yes" — an unset flag keeps the canary refused.
    """

    app_slug: str
    account_is_owned_test_account: bool = False
    workspace_is_non_production: bool = False
    app_is_reviewed: bool = False
    contains_production_data: bool = True  # pessimistic default

    def validate(self) -> CanaryGateResult:
        missing: list[str] = []
        if not self.app_slug:
            missing.append("app_slug")
        if not self.account_is_owned_test_account:
            missing.append("account_is_owned_test_account")
        if not self.workspace_is_non_production:
            missing.append("workspace_is_non_production")
        if not self.app_is_reviewed:
            missing.append("app_is_reviewed")
        if self.contains_production_data:
            # Explicitly asserted absent, never assumed.
            missing.append("contains_production_data=False")
        if missing:
            return CanaryGateResult(
                allowed=False,
                reason_code="canary_target_not_permitted",
                missing_gates=tuple(missing),
            )
        return CanaryGateResult(allowed=True, reason_code="canary_target_permitted")


@dataclass(frozen=True, slots=True)
class CanaryObjective:
    """The bounded goal of a canary run."""

    name: str
    steps: tuple[str, ...]
    stop_before: str
    allowed_actions: frozenset[str] = READ_ONLY_CANARY_ACTIONS

    def permits(self, action: str) -> bool:
        return action in self.allowed_actions


# The initial objective: prove we can reach the credential page, and stop there.
INITIAL_CANARY_OBJECTIVE = CanaryObjective(
    name="reach_reviewed_credential_page",
    steps=(
        "log in with the owned test account",
        "navigate to the reviewed developer/API settings page",
        "verify the page structurally via the reviewed checkpoint predicate",
    ),
    # The credential is deliberately NOT read: reaching the page is the result.
    stop_before="any mutation or credential reveal",
)


def validate_canary_operation(
    operation: str, *, objective: CanaryObjective = INITIAL_CANARY_OBJECTIVE
) -> CanaryGateResult:
    """Refuse any operation outside the read-only envelope."""

    normalized = (operation or "").strip().casefold()
    if not normalized:
        return CanaryGateResult(allowed=False, reason_code="operation_missing")
    if normalized in FORBIDDEN_CANARY_OPERATIONS:
        return CanaryGateResult(
            allowed=False,
            reason_code="operation_forbidden_in_canary",
            missing_gates=(normalized,),
        )
    if not objective.permits(normalized):
        # Fail closed: an action nobody reviewed is refused rather than allowed.
        return CanaryGateResult(
            allowed=False, reason_code="operation_not_read_only", missing_gates=(normalized,)
        )
    return CanaryGateResult(allowed=True, reason_code="operation_permitted")


@dataclass(frozen=True, slots=True)
class RolloutStage:
    """One step of the controlled rollout."""

    key: CanaryStage
    order: int
    summary: str
    executes_real_actions: bool
    live_vendor_contact: bool
    requires_owned_test_account: bool
    activated: bool


# The rollout ladder. Stage 5 is DEFINED so the plan is reviewable, but it is not
# activated by this work — its activation is a separate, explicit decision.
ROLLOUT_STAGES: tuple[RolloutStage, ...] = (
    RolloutStage(
        key="stage_0_local_only",
        order=0,
        summary="Local deterministic test app only; no vendor contact whatsoever.",
        executes_real_actions=True,
        live_vendor_contact=False,
        requires_owned_test_account=False,
        activated=True,
    ),
    RolloutStage(
        key="stage_1_shadow_planning",
        order=1,
        summary=(
            "Shadow planning only: Browser Use executes the real task while Playwright "
            "plans against the same sanitized observations and executes nothing."
        ),
        executes_real_actions=False,
        live_vendor_contact=False,
        requires_owned_test_account=False,
        activated=True,
    ),
    RolloutStage(
        key="stage_2_read_only_canary",
        order=2,
        summary="Read-only Playwright canary against one reviewed test app.",
        executes_real_actions=True,
        live_vendor_contact=True,
        requires_owned_test_account=True,
        activated=True,
    ),
    RolloutStage(
        key="stage_3_login_and_credential_page",
        order=3,
        summary=(
            "Playwright login plus read-only navigation to the credential page, "
            "using an owned test account."
        ),
        executes_real_actions=True,
        live_vendor_contact=True,
        requires_owned_test_account=True,
        activated=True,
    ),
    RolloutStage(
        key="stage_4_deterministic_capture",
        order=4,
        summary=(
            "Reviewed deterministic credential capture plus read-only credential "
            "validation. No mutation of the vendor account."
        ),
        executes_real_actions=True,
        live_vendor_contact=True,
        requires_owned_test_account=True,
        activated=True,
    ),
    RolloutStage(
        key="stage_5_production_canary",
        order=5,
        summary=(
            "Limited production canary: one concurrent session with automatic "
            "fallback to Browser Use. DEFINED BUT NOT ACTIVATED."
        ),
        executes_real_actions=True,
        live_vendor_contact=True,
        requires_owned_test_account=False,
        activated=False,
    ),
)


def stage(key: CanaryStage) -> RolloutStage:
    for item in ROLLOUT_STAGES:
        if item.key == key:
            return item
    raise KeyError(key)


def active_stages() -> tuple[RolloutStage, ...]:
    return tuple(item for item in ROLLOUT_STAGES if item.activated)


def production_canary_activated() -> bool:
    """Stage 5 activation status. Must be False for this phase."""

    return stage("stage_5_production_canary").activated


__all__ = [
    "CANARY_ENV_VAR",
    "FORBIDDEN_CANARY_OPERATIONS",
    "INITIAL_CANARY_OBJECTIVE",
    "MAX_CONCURRENT_CANARY_SESSIONS",
    "READ_ONLY_CANARY_ACTIONS",
    "ROLLOUT_STAGES",
    "CanaryGateResult",
    "CanaryObjective",
    "CanaryStage",
    "CanaryTarget",
    "RolloutStage",
    "active_stages",
    "evaluate_canary_gates",
    "production_canary_activated",
    "stage",
    "validate_canary_operation",
]
