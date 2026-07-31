"""Centralized browser action risk classification.

One place decides whether an action may run autonomously. The decision uses the
ACTION TYPE, the reviewed trace authorization for the current checkpoint, and
the element's own context — not a naive substring scan of the page. A verb
lexicon contributes, but only in combination with those structural facts, so an
innocuous label containing "save" in prose cannot by itself trip a HITL, and a
genuinely irreversible control cannot slip through because its label was phrased
unusually.

Risk levels:

* ``read_only`` — observes/positions only (focus, scroll_into_view).
* ``reversible`` — sets a value or toggles a control that can be set back
  (fill, select_option, check/uncheck) with no side effect beyond the form.
* ``state_changing`` — submits/navigates in a way the vendor may act on
  (click, press, goto). Allowed autonomously only when the reviewed checkpoint
  authorizes progressing here.
* ``irreversible`` — destroys credentials or accounts, authorizes privilege,
  spends, publishes, or exposes a credential. These actions are never autonomous.
  Credential creation/generation and the save that commits that reviewed flow are
  the narrow exception: they may run only when the immutable run policy explicitly
  authorizes ``create_if_missing``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from ops.browser.api_trace_catalog import BrowserApiTraceStep
from ops.browser.candidates import READ_ONLY_ACTIONS, VALUE_ACTIONS, ActionCandidate
from ops.browser.decider import SnapshotElement

RiskLevelName = Literal["read_only", "reversible", "state_changing", "irreversible"]


@dataclass(frozen=True, slots=True)
class RiskDecision:
    """The single authoritative verdict for one candidate action."""

    level: RiskLevelName
    autonomous_allowed: bool
    reason_code: str


# Verbs that indicate an irreversible or privilege/money/credential-affecting
# intent. Matched against an element's ACCESSIBLE NAME/role (a control label),
# never against arbitrary body text. Word-boundary anchored so "saved searches"
# or "removed items" in a heading cannot trip the destructive branch.
_IRREVERSIBLE_VERBS: tuple[tuple[str, str], ...] = (
    (r"\bcreate\b|\bgenerate\b|\bnew (?:api )?(?:key|token|app)\b", "creation"),
    (r"\bsave\b|\bapply\b(?! filters)", "persist"),
    (r"\bauthori[sz]e\b|\bapprove\b|\ballow\b|\bgrant\b", "authorization"),
    (r"\binstall\b|\bconnect\b|\bpublish\b|\bdeploy\b", "integration_change"),
    (r"\binvite\b|\bsend\b|\bshare\b", "outbound_message"),
    (r"\bdelete\b|\bremove\b|\bdestroy\b|\bdeactivate\b", "destructive_change"),
    (r"\brevoke\b|\brotate\b|\bregenerate\b|\breset (?:key|token|secret)\b", "key_revocation"),
    (r"\bupgrade\b|\bsubscribe\b|\bbuy\b|\bpurchase\b|\badd payment\b|\bbilling\b", "billing"),
    (r"\bi agree\b|\baccept (?:the )?terms\b|\baccept and continue\b", "legal_acceptance"),
    (
        r"\breveal\b|\bshow (?:key|token|secret|password)\b|\bcopy (?:key|token|secret)\b",
        "credential_exposure",
    ),
    (r"\btransfer ownership\b|\bmake admin\b", "permission_escalation"),
)

# Element roles/types that can only ever read or position.
_READ_ONLY_ROLES = frozenset({"heading", "paragraph", "text", "img", "image"})


class BrowserActionRiskPolicy:
    """Classify a candidate action's risk and whether it may run autonomously."""

    def classify(
        self,
        *,
        candidate: ActionCandidate,
        checkpoint: BrowserApiTraceStep,
        element: SnapshotElement | None,
        credential_creation_authorized: bool = False,
    ) -> RiskDecision:
        # 1) The candidate generator may already have flagged the intent as
        # requiring a human; that verdict is never downgraded here. Credential
        # create/generate/save candidates are deliberately not pre-flagged, so
        # their explicit run authority is evaluated by the verb policy below.
        if candidate.risk == "requires_hitl":
            return RiskDecision(
                level="irreversible",
                autonomous_allowed=False,
                reason_code="candidate_marked_requires_hitl",
            )

        label = f"{candidate.semantic_target} {element.name if element is not None else ''}"
        lowered = label.casefold()

        # 2) Consequential VERBS are matched only on the actual control label,
        # never page prose. Creation/generation and its persistence step are
        # allowed solely under the immutable create-if-missing run authority.
        # Exposure, destructive, privilege, money, legal, and outbound effects
        # remain denied regardless of that authority.
        for pattern, category in _IRREVERSIBLE_VERBS:
            if re.search(pattern, lowered):
                # A read-only action (focus/scroll) on such a control does not
                # trigger it, so it stays safe.
                if candidate.action in READ_ONLY_ACTIONS:
                    break
                if credential_creation_authorized and category in {"creation", "persist"}:
                    candidate_names = {
                        " ".join(candidate.semantic_target.casefold().split()),
                        " ".join((element.name if element is not None else "").casefold().split()),
                    }
                    reviewed_names = {
                        " ".join(name.casefold().split())
                        for name in checkpoint.credential_creation_controls
                    }
                    if candidate_names & reviewed_names:
                        return RiskDecision(
                            level="state_changing",
                            autonomous_allowed=True,
                            reason_code=f"authorized_credential_{category}",
                        )
                    return RiskDecision(
                        level="irreversible",
                        autonomous_allowed=False,
                        reason_code="credential_creation_control_not_reviewed",
                    )
                return RiskDecision(
                    level="irreversible",
                    autonomous_allowed=False,
                    reason_code=f"irreversible_intent:{category}",
                )

        # 3) A credential-bearing element is never typed into or toggled by the
        # agent (code-owned injection handles credentials).
        if element is not None and element.secretish and candidate.action not in READ_ONLY_ACTIONS:
            return RiskDecision(
                level="irreversible",
                autonomous_allowed=False,
                reason_code="credential_field_requires_code_injection",
            )

        # 4) Structural classification by action type.
        if candidate.action in READ_ONLY_ACTIONS:
            return RiskDecision(
                level="read_only", autonomous_allowed=True, reason_code="read_only_action"
            )

        if candidate.action in VALUE_ACTIONS or candidate.action in {"check", "uncheck"}:
            # A value action must use a reviewed, non-secret value reference and
            # the checkpoint must authorize that reference.
            if candidate.value_ref is not None:
                if candidate.value_ref not in set(checkpoint.allowed_value_refs):
                    return RiskDecision(
                        level="state_changing",
                        autonomous_allowed=False,
                        reason_code="value_ref_not_authorized_by_checkpoint",
                    )
            return RiskDecision(
                level="reversible", autonomous_allowed=True, reason_code="reversible_form_input"
            )

        if candidate.action == "goto":
            # Only reviewed trace URLs ever become goto candidates.
            return RiskDecision(
                level="state_changing",
                autonomous_allowed=True,
                reason_code="reviewed_trace_navigation",
            )

        # click / press: progressing the reviewed checkpoint.
        if element is not None and element.role.casefold() in _READ_ONLY_ROLES:
            return RiskDecision(
                level="read_only", autonomous_allowed=True, reason_code="non_interactive_element"
            )
        if checkpoint.requires_hitl:
            return RiskDecision(
                level="state_changing",
                autonomous_allowed=False,
                reason_code="checkpoint_requires_hitl",
            )
        return RiskDecision(
            level="state_changing",
            autonomous_allowed=True,
            reason_code="authorized_checkpoint_progression",
        )


__all__ = ["BrowserActionRiskPolicy", "RiskDecision", "RiskLevelName"]
