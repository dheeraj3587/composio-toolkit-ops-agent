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
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from ops.browser.candidates import READ_ONLY_ACTIONS, VALUE_ACTIONS, ActionCandidate
from ops.browser.decider import SnapshotElement

if TYPE_CHECKING:  # pragma: no cover - imported for typing only
    # Typing-only since the refactor onto ``ActionAuthorization``: this module no
    # longer reads a trace step at runtime, only the four reviewed facts one
    # carries. Keeping the import lazy is what lets the driver's action loop —
    # which has a phase goal and no trace at all — consult the same policy.
    from ops.browser.api_trace_catalog import BrowserApiTraceStep

RiskLevelName = Literal["read_only", "reversible", "state_changing", "irreversible"]


@dataclass(frozen=True, slots=True)
class RiskDecision:
    """The single authoritative verdict for one candidate action."""

    level: RiskLevelName
    autonomous_allowed: bool
    reason_code: str

    @property
    def category(self) -> str:
        """The irreversible verb family this verdict named, or ``""``.

        The reason code is the durable string; this is the part of it a caller
        needs when it has to tell a human *what kind* of decision is being asked
        for. Derived rather than stored so the two cannot drift.
        """

        if self.reason_code.startswith("irreversible_intent:"):
            return self.reason_code.split(":", 1)[1]
        if self.reason_code == "credential_creation_control_not_reviewed":
            return "creation"
        return ""


@dataclass(frozen=True, slots=True)
class ActionAuthorization:
    """What a REVIEWED step authorizes, decoupled from where it was reviewed.

    ``classify`` used to take a :class:`BrowserApiTraceStep` directly, which
    quietly made the policy unusable anywhere a trace does not exist — and the
    driver's action loop is exactly that place: it drives a
    :class:`~ops.onboarding.action_loop.PhaseGoal`, not a checkpoint. The
    consequence was not a missing feature but a hole: the loop fell back to
    ``ops/browser/candidates.py``'s substring list, which does not name
    ``create``/``generate`` or ``save``/``apply``, so "Create API key" and "Save"
    were emitted as low-risk and were autonomously clickable on that path —
    bypassing the credential-creation authority this class exists to carry.

    Every field defaults to the closed answer. An authorization nobody
    constructed authorizes nothing.
    """

    # Non-secret value references the step approved for fill/select.
    allowed_value_refs: tuple[str, ...] = ()
    # The exact accessible names of the controls a human reviewed as the ones
    # that may create a credential. Empty means "none were reviewed", which is
    # why ``credential_creation_authorized`` cannot be true without it.
    credential_creation_controls: tuple[str, ...] = ()
    # The reviewed step itself says a human must act here.
    requires_hitl: bool = False
    # The run's immutable policy said ``create_if_missing`` AND controls were
    # reviewed. Derived by the constructors below rather than passed separately,
    # because the two call sites that used to compute it inline are precisely
    # where one of them forgot to.
    credential_creation_authorized: bool = False

    @classmethod
    def from_checkpoint(
        cls,
        checkpoint: BrowserApiTraceStep,
        *,
        credential_creation_policy: str = "reuse_only",
    ) -> ActionAuthorization:
        """The authorization a reviewed API-trace checkpoint carries."""

        controls = tuple(checkpoint.credential_creation_controls)
        return cls(
            allowed_value_refs=tuple(checkpoint.allowed_value_refs),
            credential_creation_controls=controls,
            requires_hitl=bool(checkpoint.requires_hitl),
            credential_creation_authorized=(
                credential_creation_policy == "create_if_missing" and bool(controls)
            ),
        )

    @classmethod
    def for_phase(
        cls,
        *,
        allowed_value_refs: Sequence[str] = (),
        credential_creation_controls: Sequence[str] = (),
        requires_hitl: bool = False,
        credential_creation_policy: str = "reuse_only",
    ) -> ActionAuthorization:
        """The authorization a driver phase goal carries.

        Same shape, same defaults, same derivation of
        ``credential_creation_authorized`` — so a phase cannot authorize
        credential creation on terms a checkpoint could not.
        """

        controls = tuple(credential_creation_controls)
        return cls(
            allowed_value_refs=tuple(allowed_value_refs),
            credential_creation_controls=controls,
            requires_hitl=requires_hitl,
            credential_creation_authorized=(
                credential_creation_policy == "create_if_missing" and bool(controls)
            ),
        )


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
        authorization: ActionAuthorization,
        element: SnapshotElement | None,
    ) -> RiskDecision:
        """The verdict for one candidate under one reviewed authorization.

        Takes an :class:`ActionAuthorization` rather than a trace checkpoint so
        every path that drives a browser — the worker's trace loop and the
        driver's phase loop — can be gated by this one function. See that class
        for what went wrong while only one of them could call it.
        """

        credential_creation_authorized = authorization.credential_creation_authorized
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
                        for name in authorization.credential_creation_controls
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
                if candidate.value_ref not in set(authorization.allowed_value_refs):
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
        if authorization.requires_hitl:
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


__all__ = [
    "ActionAuthorization",
    "BrowserActionRiskPolicy",
    "RiskDecision",
    "RiskLevelName",
]
