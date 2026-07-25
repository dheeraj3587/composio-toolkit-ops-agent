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

# Phase 2 vocabulary. "type" is retained as a backward-compatible alias for
# "fill" (Phase 1 candidates and their tests use it); new code emits "fill".
CandidateAction = Literal[
    "click",
    "fill",
    "type",
    "press",
    "goto",
    "select_option",
    "check",
    "uncheck",
    "scroll_into_view",
    "focus",
]
RiskLevel = Literal["low", "medium", "high", "requires_hitl"]

# Actions that only observe/position and change no application state.
READ_ONLY_ACTIONS: frozenset[str] = frozenset({"scroll_into_view", "focus"})
# Actions that put a value into a control (never a secret — see APPROVED_VALUE_REFS).
VALUE_ACTIONS: frozenset[str] = frozenset({"fill", "type", "select_option"})


@dataclass(frozen=True, slots=True)
class ElementPredicate:
    """A structural expectation about ONE element, used in a postcondition.

    Deliberately identity-shaped (role/name/frame/test id) rather than a
    selector, so a postcondition can never smuggle in an authored selector.
    """

    role: str = ""
    name: str = ""
    element_type: str = ""
    frame_path: tuple[str, ...] = ()
    test_id: str | None = None

    def matches(self, element: SnapshotElement) -> bool:
        if self.test_id:
            return element.test_id == self.test_id
        if self.role and element.role != self.role:
            return False
        if self.element_type and element.element_type != self.element_type:
            return False
        if self.frame_path and tuple(element.frame_path) != tuple(self.frame_path):
            return False
        if self.name:
            return _normalize(self.name) in _normalize(element.name)
        return bool(self.role or self.element_type)


@dataclass(frozen=True, slots=True)
class CandidatePostcondition:
    """What must become true for THIS action to count as a real state transition.

    A successful click is not a successful transition: the action's own
    postcondition must be verified against a freshly inspected page. Verified by
    ``ops.playwright_worker.postcondition_satisfied`` using Playwright
    auto-waiting — never ``networkidle`` as a success proxy and never a sleep.
    """

    # The element the action was performed ON. Required for checked/selected
    # assertions: without it an UNRELATED checkbox or select elsewhere on the page
    # could satisfy the postcondition, so a no-op would look like a real transition.
    target: ElementPredicate | None = None
    url_changed: bool = False
    url_matches: tuple[str, ...] = ()
    element_appears: tuple[ElementPredicate, ...] = ()
    element_disappears: tuple[ElementPredicate, ...] = ()
    text_appears: tuple[str, ...] = ()
    selected_value: str | None = None
    checked_state: bool | None = None

    def is_empty(self) -> bool:
        """True when nothing is asserted, so this cannot prove a transition."""

        return not (
            self.url_changed
            or self.url_matches
            or self.element_appears
            or self.element_disappears
            or self.text_appears
            or self.selected_value is not None
            or self.checked_state is not None
            # A target-only postcondition is asserted for select_option, where the
            # expected label is supplied by the executor at verification time.
            or self.target is not None
        )


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
# free text; it selects a candidate whose value comes from this reviewed mapping
# (resolved by ops.playwright_worker.ApprovedBrowserValueResolver). NEVER contains
# a vault reference, password, API key, OTP, or magic link. Kept in sync with
# ops.browser_api_trace_catalog._ALLOWED_VALUE_REFS.
APPROVED_VALUE_REFS: frozenset[str] = frozenset(
    {"company_name", "company_website", "application_name", "use_case", "expected_volume"}
)

_ALLOWED_KEYS: frozenset[str] = frozenset({"Enter", "Escape", "Tab"})


@dataclass(frozen=True, slots=True)
class ElementIdentity:
    """The stable identity used to re-resolve a target just before execution.

    Deliberately identity-based — never a positional ``nth`` index, which becomes
    wrong the moment the DOM changes. Phase 2 adds the frame path plus stronger
    identity hints (reviewed test id, safe href PATH, nearby reviewed heading).
    All new fields are defaulted so Phase 1 constructions keep working.

    Resolution is strict and ordered (see :func:`resolve_identity`):
    reviewed test id -> frame path + exact role/name -> associated label ->
    placeholder -> safe href path -> nearby reviewed heading. Exactly one match
    is required at every tier; ambiguity is reported, never guessed.
    """

    role: str
    name: str
    element_type: str = ""
    frame_path: tuple[str, ...] = ()
    test_id: str | None = None
    href_path: str | None = None
    nearby_heading: str | None = None

    def matches(self, element: SnapshotElement) -> bool:
        """Exact role/name/type match WITHIN the same frame.

        The frame is part of identity: the same accessible name in a different
        frame is a different element and must never be silently substituted.
        """

        return (
            element.role == self.role
            and element.name == self.name
            and element.element_type == self.element_type
            and tuple(element.frame_path) == tuple(self.frame_path)
        )


# Ordered identity tiers. Each returns the elements matching that tier; a tier is
# only accepted when it yields EXACTLY one element.
def _tier_test_id(
    identity: ElementIdentity, elements: Sequence[SnapshotElement]
) -> list[SnapshotElement]:
    if not identity.test_id:
        return []
    return [e for e in elements if e.test_id and e.test_id == identity.test_id]


def _tier_frame_role_name(
    identity: ElementIdentity, elements: Sequence[SnapshotElement]
) -> list[SnapshotElement]:
    return [e for e in elements if identity.matches(e)]


def _tier_label_or_placeholder(
    identity: ElementIdentity, elements: Sequence[SnapshotElement]
) -> list[SnapshotElement]:
    if not identity.name:
        return []
    needle = _normalize(identity.name)
    return [
        e
        for e in elements
        if tuple(e.frame_path) == tuple(identity.frame_path)
        and e.role == identity.role
        and needle
        and needle == _normalize(e.name)
    ]


def _tier_href_path(
    identity: ElementIdentity, elements: Sequence[SnapshotElement]
) -> list[SnapshotElement]:
    if not identity.href_path:
        return []
    return [
        e
        for e in elements
        if e.href_path
        and e.href_path == identity.href_path
        and tuple(e.frame_path) == tuple(identity.frame_path)
    ]


def _tier_nearby_heading(
    identity: ElementIdentity, elements: Sequence[SnapshotElement]
) -> list[SnapshotElement]:
    if not identity.nearby_heading or not identity.name:
        return []
    heading = _normalize(identity.nearby_heading)
    needle = _normalize(identity.name)
    return [
        e
        for e in elements
        if e.nearby_heading
        and _normalize(e.nearby_heading) == heading
        and needle
        and needle in _normalize(e.name)
        and tuple(e.frame_path) == tuple(identity.frame_path)
    ]


IdentityResolution = Literal["resolved", "not_found", "ambiguous"]


def resolve_identity(
    identity: ElementIdentity, elements: Sequence[SnapshotElement]
) -> tuple[IdentityResolution, SnapshotElement | None]:
    """Resolve an identity to exactly ONE element using the strict tier order.

    Returns ``("resolved", element)`` only when a tier yields a single match.
    A tier that matches several elements short-circuits to ``"ambiguous"`` — we
    never fall through to a weaker tier or a positional ``nth`` guess, because
    that is exactly how the wrong control gets clicked.
    """

    for tier in (
        _tier_test_id,
        _tier_frame_role_name,
        _tier_label_or_placeholder,
        _tier_href_path,
        _tier_nearby_heading,
    ):
        hits = tier(identity, elements)
        if len(hits) == 1:
            return "resolved", hits[0]
        if len(hits) > 1:
            return "ambiguous", None
    return "not_found", None


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
    # Phase 2: the action-specific state transition that must be verified after
    # execution. Empty means "no specific transition asserted" — the caller then
    # falls back to the checkpoint predicate alone.
    postcondition: CandidatePostcondition = field(default_factory=CandidatePostcondition)
    # Reviewed option value for `select_option` (never model-authored).
    option_value: str | None = None

    @property
    def executable(self) -> bool:
        return self.risk != "requires_hitl"

    @property
    def is_value_action(self) -> bool:
        return self.action in VALUE_ACTIONS


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
        # Phase 2: a hidden or disabled control is not actionable, so it never
        # becomes a candidate (Playwright would simply time out on it).
        if not element.actionable():
            continue
        identity = _identity_of(element)
        irreversible, category = classify_irreversible(element.name, element.role)
        risk: RiskLevel = "requires_hitl" if irreversible else "low"
        candidates.append(
            ActionCandidate(
                candidate_id=_candidate_id(
                    trace_version,
                    checkpoint_order,
                    "click",
                    element.role,
                    element.name,
                    "/".join(element.frame_path),
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
                # A click must produce SOME observable transition: either the URL
                # moves, or this control goes away (typical SPA behavior).
                postcondition=CandidatePostcondition(
                    url_changed=True,
                    element_disappears=(
                        ElementPredicate(
                            role=element.role,
                            name=element.name,
                            frame_path=element.frame_path,
                        ),
                    ),
                ),
            )
        )

    # `fill` candidates: only into a NON-secret input, and only an approved
    # non-secret value reference (never model-supplied text).
    for element in elements:
        if len(candidates) >= max_candidates:
            break
        if element.element_type not in {"text", "email", "search", "url", "tel"}:
            continue
        if element.secretish or not element.actionable():
            continue  # code-owned injection only; never a hidden/disabled field
        for ref in allow_value_refs:
            if ref not in APPROVED_VALUE_REFS:
                continue
            candidates.append(
                ActionCandidate(
                    candidate_id=_candidate_id(
                        trace_version, checkpoint_order, "fill", ref, element.name
                    ),
                    action="fill",
                    semantic_target=element.name[:120] or element.element_type,
                    identity=_identity_of(element),
                    risk="low",
                    expected_postcondition=expected_postcondition,
                    trace_version=trace_version,
                    checkpoint_order=checkpoint_order,
                    value_ref=ref,
                    hint_index=element.index,
                )
            )
            break

    # `select_option` candidates come from the element's REVIEWED options only.
    for element in elements:
        if len(candidates) >= max_candidates:
            break
        if element.role.casefold() != "select" or not element.actionable():
            continue
        for ref in allow_value_refs:
            if ref not in APPROVED_VALUE_REFS:
                continue
            candidates.append(
                ActionCandidate(
                    candidate_id=_candidate_id(
                        trace_version, checkpoint_order, "select_option", ref, element.name
                    ),
                    action="select_option",
                    semantic_target=element.name[:120] or "select",
                    identity=_identity_of(element),
                    risk="low",
                    expected_postcondition=expected_postcondition,
                    trace_version=trace_version,
                    checkpoint_order=checkpoint_order,
                    value_ref=ref,
                    hint_index=element.index,
                    # Bound to THIS select, so an unrelated selected option
                    # elsewhere cannot satisfy the assertion. The expected LABEL is
                    # supplied by the executor at verification time (the reference
                    # name is not the option text).
                    postcondition=CandidatePostcondition(target=_predicate_of(element)),
                )
            )
            break

    # `check` / `uncheck`: only for a real checkbox/radio, and the postcondition
    # asserts the resulting checked state so the transition is verifiable.
    for element in elements:
        if len(candidates) >= max_candidates:
            break
        if element.element_type.casefold() not in {"checkbox", "radio"}:
            continue
        if not element.actionable() or element.secretish:
            continue
        irreversible, category = classify_irreversible(element.name, element.role)
        if irreversible:
            continue  # handled by the click branch as requires_hitl
        desired = not bool(element.checked)
        action: CandidateAction = "check" if desired else "uncheck"
        candidates.append(
            ActionCandidate(
                candidate_id=_candidate_id(trace_version, checkpoint_order, action, element.name),
                action=action,
                semantic_target=element.name[:120] or element.element_type,
                identity=_identity_of(element),
                risk="low",
                expected_postcondition=expected_postcondition,
                trace_version=trace_version,
                checkpoint_order=checkpoint_order,
                hint_index=element.index,
                # Bound to THIS checkbox: any-element matching previously let an
                # unrelated already-checked box satisfy a no-op.
                postcondition=CandidatePostcondition(
                    target=_predicate_of(element), checked_state=desired
                ),
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
                postcondition=CandidatePostcondition(url_matches=(_url_path(url),)),
            )
        )

    # A keyboard candidate targets a REVIEWED element, never page-global input.
    for element in elements:
        if len(candidates) >= max_candidates:
            break
        if (
            element.element_type in {"text", "email", "search"}
            and not element.secretish
            and element.actionable()
        ):
            candidates.append(
                ActionCandidate(
                    candidate_id=_candidate_id(
                        trace_version, checkpoint_order, "press", "Enter", element.name
                    ),
                    action="press",
                    semantic_target=element.name[:120] or element.element_type,
                    identity=_identity_of(element),
                    risk="low",
                    expected_postcondition=expected_postcondition,
                    trace_version=trace_version,
                    checkpoint_order=checkpoint_order,
                    press_key="Enter",
                    hint_index=element.index,
                    postcondition=CandidatePostcondition(url_changed=True),
                )
            )
            break

    return tuple(candidates[:max_candidates])


def _predicate_of(element: SnapshotElement) -> ElementPredicate:
    """Build a postcondition predicate that identifies exactly THIS element.

    Used to bind ``checked_state``/``selected_value`` to the element that was acted
    on. Identity-shaped (role/name/type/frame/test id), so a postcondition can
    never smuggle in an authored selector.
    """

    return ElementPredicate(
        role=element.role,
        name=element.name,
        element_type=element.element_type,
        frame_path=tuple(element.frame_path),
        test_id=element.test_id,
    )


def _identity_of(element: SnapshotElement) -> ElementIdentity:
    """Build the full Phase 2 identity for an element (frame + stable hints)."""

    return ElementIdentity(
        role=element.role,
        name=element.name,
        element_type=element.element_type,
        frame_path=tuple(element.frame_path),
        test_id=element.test_id,
        href_path=element.href_path,
        nearby_heading=element.nearby_heading,
    )


def _url_path(url: str) -> str:
    from urllib.parse import urlsplit

    return urlsplit(url).path or "/"


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
    "READ_ONLY_ACTIONS",
    "VALUE_ACTIONS",
    "ActionCandidate",
    "CandidateAction",
    "CandidatePostcondition",
    "ElementIdentity",
    "ElementPredicate",
    "IdentityResolution",
    "RiskLevel",
    "classify_irreversible",
    "executable_candidates",
    "generate_candidates",
    "render_candidates",
    "resolve_identity",
    "select_candidate",
    "validate_press_key",
]
