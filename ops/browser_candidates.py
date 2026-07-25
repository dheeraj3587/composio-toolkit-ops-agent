"""Policy-generated action candidates: the model chooses, it never authors.

The model previously returned an action payload (selector index, URL, typed text).
That is removed. Deterministic code now derives a BOUNDED candidate set from the
reviewed trace checkpoint plus the current inspection, and the model may reply
with only:

* one opaque ``candidate_id`` from that set, or
* ``report_hitl``, or
* ``report_blocked``.

So a model can never invent a selector, a URL, or a value to type. Every candidate
carries its permitted action type, semantic target, the exact expected element
identity (used to re-resolve the element immediately before execution), a risk
level, the expected postcondition, and the trace/checkpoint version it came from.

Irreversible or privilege-changing intents (billing, legal acceptance, permission
escalation, destructive change, key revocation, account deletion) are never
executable candidates: they are emitted as ``requires_hitl`` so a human decides.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal

from ops.browser_decider import SnapshotElement

CandidateAction = Literal["click", "type", "press", "goto"]
RiskLevel = Literal["low", "medium", "high", "requires_hitl"]

# Intents a bot must never perform autonomously. Matched against the element's
# accessible name/role, NOT against arbitrary body text.
_IRREVERSIBLE_INTENTS: tuple[tuple[str, str], ...] = (
    ("delete account", "account_deletion"),
    ("close account", "account_deletion"),
    ("delete workspace", "destructive_change"),
    ("delete", "destructive_change"),
    ("remove", "destructive_change"),
    ("revoke", "key_revocation"),
    ("rotate", "key_revocation"),
    ("regenerate", "key_revocation"),
    ("deactivate", "destructive_change"),
    ("transfer ownership", "permission_escalation"),
    ("make admin", "permission_escalation"),
    ("grant access", "permission_escalation"),
    ("change plan", "billing"),
    ("upgrade", "billing"),
    ("add payment", "billing"),
    ("billing", "billing"),
    ("subscribe", "billing"),
    ("accept terms", "legal_acceptance"),
    ("i agree", "legal_acceptance"),
    ("accept and continue", "legal_acceptance"),
)

# Non-secret value references a `type` candidate may use. A model never supplies
# free text; it selects a candidate whose value comes from this reviewed mapping.
APPROVED_VALUE_REFS: frozenset[str] = frozenset({"company_name", "company_website", "work_email"})

_ALLOWED_KEYS: frozenset[str] = frozenset({"Enter", "Escape", "Tab"})


@dataclass(frozen=True, slots=True)
class ElementIdentity:
    """The stable identity used to re-resolve a target just before execution.

    Deliberately role/name/type — never a positional ``nth`` index, which becomes
    wrong the moment the DOM changes.
    """

    role: str
    name: str
    element_type: str = ""

    def matches(self, element: SnapshotElement) -> bool:
        return (
            element.role == self.role
            and element.name == self.name
            and element.element_type == self.element_type
        )


@dataclass(frozen=True, slots=True)
class ActionCandidate:
    """One policy-approved option the model may select by ID."""

    candidate_id: str
    action: CandidateAction
    semantic_target: str
    identity: ElementIdentity | None
    risk: RiskLevel
    expected_postcondition: str
    trace_version: str
    checkpoint_order: int
    # Only set for `type` (an approved reference, never literal text) / `press`
    # (a reviewed key) / `goto` (a reviewed trace URL).
    value_ref: str | None = None
    press_key: str | None = None
    url: str | None = None
    # Snapshot index at generation time: a hint for resolution, never trusted.
    hint_index: int | None = field(default=None)

    @property
    def executable(self) -> bool:
        return self.risk != "requires_hitl"


def _candidate_id(*parts: object) -> str:
    """A short opaque id. Opaque so the model cannot derive intent or forge one."""

    digest = hashlib.sha256("|".join(str(part) for part in parts).encode()).hexdigest()
    return f"c_{digest[:12]}"


def classify_irreversible(name: str, role: str = "") -> tuple[bool, str]:
    """Return (is_irreversible, category) for an element's accessible name."""

    lowered = f"{name} {role}".casefold()
    for needle, category in _IRREVERSIBLE_INTENTS:
        if needle in lowered:
            return True, category
    return False, ""


def _normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip()


def generate_candidates(
    *,
    elements: Sequence[SnapshotElement],
    checkpoint_signals: Sequence[str],
    checkpoint_order: int,
    trace_version: str,
    expected_postcondition: str,
    reviewed_goto_urls: Sequence[str] = (),
    allow_value_refs: Sequence[str] = (),
    max_candidates: int = 8,
) -> tuple[ActionCandidate, ...]:
    """Derive the bounded candidate set for the current checkpoint.

    Only elements plausibly related to the checkpoint's expected signals become
    candidates, so the set stays small and on-policy. Secret-bearing fields are
    never `type` candidates (code-owned injection handles those), and irreversible
    controls are emitted as ``requires_hitl`` rather than as executable actions.
    """

    needles = [_normalize(signal) for signal in checkpoint_signals if signal.strip()]
    candidates: list[ActionCandidate] = []

    for element in elements:
        if len(candidates) >= max_candidates:
            break
        haystack = _normalize(element.name)
        if needles and not any(needle and needle in haystack for needle in needles):
            continue
        if not element.name:
            continue
        identity = ElementIdentity(element.role, element.name, element.element_type)
        irreversible, category = classify_irreversible(element.name, element.role)
        risk: RiskLevel = "requires_hitl" if irreversible else "low"
        candidates.append(
            ActionCandidate(
                candidate_id=_candidate_id(
                    trace_version, checkpoint_order, "click", element.role, element.name
                ),
                action="click",
                semantic_target=element.name[:120],
                identity=identity,
                risk=risk,
                expected_postcondition=(
                    f"human_decision:{category}" if irreversible else expected_postcondition
                ),
                trace_version=trace_version,
                checkpoint_order=checkpoint_order,
                hint_index=element.index,
            )
        )

    # `type` candidates: only into a NON-secret input, and only an approved
    # non-secret value reference (never model-supplied text).
    for element in elements:
        if len(candidates) >= max_candidates:
            break
        if element.element_type not in {"text", "email", "search", "url", "tel"}:
            continue
        if element.secretish:
            continue  # code-owned injection only
        for ref in allow_value_refs:
            if ref not in APPROVED_VALUE_REFS:
                continue
            candidates.append(
                ActionCandidate(
                    candidate_id=_candidate_id(
                        trace_version, checkpoint_order, "type", ref, element.name
                    ),
                    action="type",
                    semantic_target=element.name[:120] or element.element_type,
                    identity=ElementIdentity(element.role, element.name, element.element_type),
                    risk="low",
                    expected_postcondition=expected_postcondition,
                    trace_version=trace_version,
                    checkpoint_order=checkpoint_order,
                    value_ref=ref,
                    hint_index=element.index,
                )
            )
            break

    # `goto` candidates come ONLY from the reviewed trace, never from the model.
    for url in reviewed_goto_urls:
        if len(candidates) >= max_candidates:
            break
        candidates.append(
            ActionCandidate(
                candidate_id=_candidate_id(trace_version, checkpoint_order, "goto", url),
                action="goto",
                semantic_target="reviewed trace URL",
                identity=None,
                risk="low",
                expected_postcondition=expected_postcondition,
                trace_version=trace_version,
                checkpoint_order=checkpoint_order,
                url=url,
            )
        )

    # A keyboard candidate targets a REVIEWED element, never page-global input.
    for element in elements:
        if len(candidates) >= max_candidates:
            break
        if element.element_type in {"text", "email", "search"} and not element.secretish:
            candidates.append(
                ActionCandidate(
                    candidate_id=_candidate_id(
                        trace_version, checkpoint_order, "press", "Enter", element.name
                    ),
                    action="press",
                    semantic_target=element.name[:120] or element.element_type,
                    identity=ElementIdentity(element.role, element.name, element.element_type),
                    risk="low",
                    expected_postcondition=expected_postcondition,
                    trace_version=trace_version,
                    checkpoint_order=checkpoint_order,
                    press_key="Enter",
                    hint_index=element.index,
                )
            )
            break

    return tuple(candidates[:max_candidates])


def executable_candidates(
    candidates: Sequence[ActionCandidate],
) -> tuple[ActionCandidate, ...]:
    return tuple(candidate for candidate in candidates if candidate.executable)


def select_candidate(candidates: Sequence[ActionCandidate], candidate_id: str) -> ActionCandidate:
    """Resolve a model-selected id, refusing unknown or non-executable choices."""

    for candidate in candidates:
        if candidate.candidate_id == candidate_id:
            if not candidate.executable:
                raise ValueError("selected candidate requires human authorization")
            return candidate
    raise ValueError("selected candidate id is not in the generated policy set")


def render_candidates(candidates: Sequence[ActionCandidate]) -> str:
    """Render the choice list for the prompt (ids + semantics only)."""

    if not candidates:
        return "(no candidates available)"
    lines = []
    for candidate in candidates:
        if not candidate.executable:
            continue
        detail = candidate.semantic_target
        if candidate.action == "type" and candidate.value_ref:
            detail = f"{detail} (fill approved value: {candidate.value_ref})"
        elif candidate.action == "press" and candidate.press_key:
            detail = f"{detail} (press {candidate.press_key})"
        elif candidate.action == "goto":
            detail = "reviewed trace URL"
        lines.append(f"{candidate.candidate_id}: {candidate.action} -> {detail}")
    return "\n".join(lines) or "(no executable candidates)"


def validate_press_key(key: str) -> str:
    if key not in _ALLOWED_KEYS:
        raise ValueError("press key is not reviewed")
    return key


__all__ = [
    "APPROVED_VALUE_REFS",
    "ActionCandidate",
    "CandidateAction",
    "ElementIdentity",
    "RiskLevel",
    "classify_irreversible",
    "executable_candidates",
    "generate_candidates",
    "render_candidates",
    "select_candidate",
    "validate_press_key",
]
