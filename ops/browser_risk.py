"""Centralized browser action risk classification.

One place decides whether an action may run autonomously. The decision uses the
ACTION TYPE, an explicit action purpose, reviewed workflow authorization, and
the element's own context. A lexical verb check remains as defense in depth;
Part 14 adds a narrow purpose-aware exception for normal signup submission
without weakening the global handling of words such as "create".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from ops.browser_api_trace_catalog import BrowserApiTraceStep
from ops.browser_candidates import READ_ONLY_ACTIONS, VALUE_ACTIONS, ActionCandidate
from ops.browser_decider import SnapshotElement
from ops.policies import AccountPolicy

RiskLevelName = Literal["read_only", "reversible", "state_changing", "irreversible"]
RiskDisposition = Literal["allow", "require_hitl", "block"]
ActionPurpose = Literal[
    "signup_submit",
    "login_submit",
    "create_workspace",
    "create_developer_app",
    "save_developer_app",
    "generate_credential",
    "reveal_credential",
    "rotate_credential",
    "revoke_credential",
    "delete_resource",
    "accept_legal_terms",
    "submit_payment",
]


@dataclass(frozen=True, slots=True)
class RiskDecision:
    """The single authoritative verdict for one browser action."""

    level: RiskLevelName
    autonomous_allowed: bool
    reason_code: str
    disposition: RiskDisposition = "allow"


@dataclass(frozen=True, slots=True)
class ActionAuthorizationContext:
    """Server-owned facts used to authorize one explicit action purpose.

    Values in this context are booleans, policy enums, or durable state names.
    Browser text, selectors, credentials, and model-authored fields are never
    represented here.
    """

    purpose: ActionPurpose
    account_policy: AccountPolicy = "reuse_existing"
    contract_active: bool = False
    signup_supported: bool = False
    signup_state: str = ""
    required_fields_verified: bool = False
    submit_control_unique: bool = False
    captcha_present: bool = False
    legal_acceptance_present: bool = False
    billing_present: bool = False
    phone_verification_present: bool = False
    ownership_or_admin_change_present: bool = False
    code_owned: bool = False


# Verbs that indicate an irreversible or privilege/money/credential-affecting
# intent. They are matched against the control's own accessible name, never
# arbitrary body text.
_IRREVERSIBLE_VERBS: tuple[tuple[str, str], ...] = (
    (
        r"\b(?:create|generate|new) (?:an? )?(?:api )?"
        r"(?:key|token|credential|secret)\b",
        "credential_generation",
    ),
    (
        r"\bcreate (?:an? )?(?:developer )?(?:app|application|workspace|organization)\b"
        r"|\bnew (?:developer )?(?:app|application|workspace)\b",
        "resource_creation",
    ),
    (r"\bgenerate\b", "generation"),
    (r"\bcreate\b", "creation"),
    (r"\bsave\b|\bapply\b(?! filters)", "persist"),
    (r"\bauthori[sz]e\b|\bapprove\b|\ballow\b|\bgrant\b", "authorization"),
    (r"\binstall\b|\bconnect\b|\bpublish\b|\bdeploy\b", "integration_change"),
    (r"\binvite\b|\bsend\b|\bshare\b", "outbound_message"),
    (r"\bdelete\b|\bremove\b|\bdestroy\b|\bdeactivate\b", "destructive_change"),
    (r"\brevoke\b|\brotate\b|\bregenerate\b|\breset (?:key|token|secret)\b", "key_revocation"),
    (r"\bupgrade\b|\bsubscribe\b|\bbuy\b|\bpurchase\b|\badd payment\b|\bbilling\b", "billing"),
    (r"\bi agree\b|\baccept (?:the )?terms\b|\baccept and continue\b", "legal_acceptance"),
    (
        r"\breveal\b|\bshow (?:key|token|secret|password)\b|"
        r"\bcopy (?:key|token|secret)\b",
        "credential_exposure",
    ),
    (r"\btransfer ownership\b|\bmake admin\b", "permission_escalation"),
)

_READ_ONLY_ROLES = frozenset({"heading", "paragraph", "text", "img", "image"})
_DESTRUCTIVE_PURPOSES: frozenset[ActionPurpose] = frozenset(
    {"rotate_credential", "revoke_credential", "delete_resource"}
)
_HITL_PURPOSES: frozenset[ActionPurpose] = frozenset(
    {
        "create_workspace",
        "create_developer_app",
        "save_developer_app",
        "generate_credential",
        "reveal_credential",
        "accept_legal_terms",
        "submit_payment",
    }
)


class BrowserActionRiskPolicy:
    """Classify candidate risk and authorize explicit action purposes."""

    def authorize_purpose(self, context: ActionAuthorizationContext) -> RiskDecision:
        """Authorize one server-classified purpose using default-deny rules."""

        if context.ownership_or_admin_change_present:
            return RiskDecision(
                level="irreversible",
                autonomous_allowed=False,
                reason_code="ownership_or_admin_change_requires_human",
                disposition="block",
            )

        if context.purpose in _DESTRUCTIVE_PURPOSES:
            return RiskDecision(
                level="irreversible",
                autonomous_allowed=False,
                reason_code=f"purpose_blocked:{context.purpose}",
                disposition="block",
            )

        if context.captcha_present:
            return RiskDecision(
                level="irreversible",
                autonomous_allowed=False,
                reason_code="captcha_requires_human",
                disposition="require_hitl",
            )
        if context.phone_verification_present:
            return RiskDecision(
                level="irreversible",
                autonomous_allowed=False,
                reason_code="phone_verification_requires_human",
                disposition="require_hitl",
            )
        if context.legal_acceptance_present:
            return RiskDecision(
                level="irreversible",
                autonomous_allowed=False,
                reason_code="legal_acceptance_requires_human",
                disposition="require_hitl",
            )
        if context.billing_present:
            return RiskDecision(
                level="irreversible",
                autonomous_allowed=False,
                reason_code="billing_requires_human",
                disposition="require_hitl",
            )

        if context.purpose == "signup_submit":
            return self._authorize_signup_submit(context)

        if context.purpose == "login_submit":
            if not context.contract_active:
                return RiskDecision(
                    level="state_changing",
                    autonomous_allowed=False,
                    reason_code="login_submit_contract_inactive",
                    disposition="block",
                )
            if not context.code_owned:
                return RiskDecision(
                    level="state_changing",
                    autonomous_allowed=False,
                    reason_code="login_submit_requires_code_owned_flow",
                    disposition="block",
                )
            return RiskDecision(
                level="state_changing",
                autonomous_allowed=True,
                reason_code="code_owned_login_submit",
                disposition="allow",
            )

        if context.purpose in _HITL_PURPOSES:
            return RiskDecision(
                level="irreversible",
                autonomous_allowed=False,
                reason_code=f"purpose_requires_human:{context.purpose}",
                disposition="require_hitl",
            )

        return RiskDecision(
            level="irreversible",
            autonomous_allowed=False,
            reason_code="action_purpose_not_authorized",
            disposition="block",
        )

    @staticmethod
    def _authorize_signup_submit(context: ActionAuthorizationContext) -> RiskDecision:
        if context.account_policy != "create_if_missing":
            return RiskDecision(
                level="state_changing",
                autonomous_allowed=False,
                reason_code="signup_submit_account_policy_blocked",
                disposition="block",
            )
        if not context.contract_active:
            return RiskDecision(
                level="state_changing",
                autonomous_allowed=False,
                reason_code="signup_submit_contract_inactive",
                disposition="block",
            )
        if not context.signup_supported:
            return RiskDecision(
                level="state_changing",
                autonomous_allowed=False,
                reason_code="signup_submit_not_supported_by_contract",
                disposition="block",
            )
        if context.signup_state != "signup_submission_ready":
            return RiskDecision(
                level="state_changing",
                autonomous_allowed=False,
                reason_code="signup_submit_state_not_ready",
                disposition="block",
            )
        if not context.required_fields_verified:
            return RiskDecision(
                level="state_changing",
                autonomous_allowed=False,
                reason_code="signup_submit_fields_not_verified",
                disposition="block",
            )
        if not context.submit_control_unique:
            return RiskDecision(
                level="state_changing",
                autonomous_allowed=False,
                reason_code="signup_submit_control_not_unique",
                disposition="block",
            )
        if not context.code_owned:
            return RiskDecision(
                level="state_changing",
                autonomous_allowed=False,
                reason_code="signup_submit_requires_code_owned_flow",
                disposition="block",
            )
        return RiskDecision(
            level="state_changing",
            autonomous_allowed=True,
            reason_code="signup_submit_authorized",
            disposition="allow",
        )

    def classify(
        self,
        *,
        candidate: ActionCandidate,
        checkpoint: BrowserApiTraceStep,
        element: SnapshotElement | None,
        purpose_context: ActionAuthorizationContext | None = None,
    ) -> RiskDecision:
        """Classify a generated candidate, optionally with explicit purpose facts."""

        purpose_decision: RiskDecision | None = None
        if purpose_context is not None:
            purpose_decision = self.authorize_purpose(purpose_context)
            if not purpose_decision.autonomous_allowed:
                return purpose_decision

        label = f"{candidate.semantic_target} {element.name if element is not None else ''}"
        lowered = label.casefold()
        matched_categories = tuple(
            category
            for pattern, category in _IRREVERSIBLE_VERBS
            if re.search(pattern, lowered)
        )
        purpose_is_authorized_signup = (
            purpose_context is not None
            and purpose_context.purpose == "signup_submit"
            and purpose_decision is not None
            and purpose_decision.autonomous_allowed
        )

        # Candidate generation remains conservative and still labels every "create"
        # control as HITL. A purpose-aware signup path may downgrade only a control
        # whose complete irreversible classification is exactly normal creation.
        if candidate.risk == "requires_hitl" and not (
            purpose_is_authorized_signup
            and matched_categories
            and set(matched_categories) == {"creation"}
        ):
            return RiskDecision(
                level="irreversible",
                autonomous_allowed=False,
                reason_code="candidate_marked_requires_hitl",
                disposition="require_hitl",
            )

        # The lexical guard remains global. The only exception is a fully authorized
        # signup_submit purpose, whose complete server-owned preconditions were
        # evaluated above. A label combining creation with legal, billing, privilege,
        # credential, or destructive intent is never downgraded.
        for category in matched_categories:
            if candidate.action in READ_ONLY_ACTIONS:
                break
            if purpose_is_authorized_signup and category == "creation":
                continue
            return RiskDecision(
                level="irreversible",
                autonomous_allowed=False,
                reason_code=f"irreversible_intent:{category}",
                disposition="require_hitl",
            )

        if element is not None and element.secretish and candidate.action not in READ_ONLY_ACTIONS:
            return RiskDecision(
                level="irreversible",
                autonomous_allowed=False,
                reason_code="credential_field_requires_code_injection",
                disposition="block",
            )

        if candidate.action in READ_ONLY_ACTIONS:
            return RiskDecision(
                level="read_only",
                autonomous_allowed=True,
                reason_code="read_only_action",
                disposition="allow",
            )

        if candidate.action in VALUE_ACTIONS or candidate.action in {"check", "uncheck"}:
            if candidate.value_ref is not None and candidate.value_ref not in set(
                checkpoint.allowed_value_refs
            ):
                return RiskDecision(
                    level="state_changing",
                    autonomous_allowed=False,
                    reason_code="value_ref_not_authorized_by_checkpoint",
                    disposition="block",
                )
            return RiskDecision(
                level="reversible",
                autonomous_allowed=True,
                reason_code="reversible_form_input",
                disposition="allow",
            )

        if candidate.action == "goto":
            return RiskDecision(
                level="state_changing",
                autonomous_allowed=True,
                reason_code="reviewed_trace_navigation",
                disposition="allow",
            )

        if element is not None and element.role.casefold() in _READ_ONLY_ROLES:
            return RiskDecision(
                level="read_only",
                autonomous_allowed=True,
                reason_code="non_interactive_element",
                disposition="allow",
            )
        if checkpoint.requires_hitl:
            return RiskDecision(
                level="state_changing",
                autonomous_allowed=False,
                reason_code="checkpoint_requires_hitl",
                disposition="require_hitl",
            )
        return RiskDecision(
            level="state_changing",
            autonomous_allowed=True,
            reason_code="authorized_checkpoint_progression",
            disposition="allow",
        )


__all__ = [
    "ActionAuthorizationContext",
    "ActionPurpose",
    "BrowserActionRiskPolicy",
    "RiskDecision",
    "RiskDisposition",
    "RiskLevelName",
]
