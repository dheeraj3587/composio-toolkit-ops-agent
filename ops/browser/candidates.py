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

from ops.browser.decider import SnapshotElement
from ops.browser.setup_values import APPROVED_BROWSER_VALUE_REFS
from ops.core.model_input_dlp import sanitize_url

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
    ``ops.playwright.worker.postcondition_satisfied`` using Playwright
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

# Non-secret value references a `type` candidate may use. The canonical set is
# shared with request/RPC validation in ``ops.browser.setup_values``.
APPROVED_VALUE_REFS: frozenset[str] = APPROVED_BROWSER_VALUE_REFS

_ALLOWED_KEYS: frozenset[str] = frozenset({"Enter", "Escape", "Tab"})

# How many candidates ONE action kind may contribute to the set.
#
# The check/uncheck and press loops used to end in an unconditional ``break``, so
# each emitted at most one candidate however many controls the page offered. On a
# signup form with three checkboxes the model saw one, could not pick the right
# one, and had to spend a whole loop iteration per box — which the repeated-state
# limit kills before the form is complete.
#
# The only pre-existing bound was the GLOBAL ``max_candidates`` (default 8),
# re-checked at the top of every loop. That still bounds the total, but on its own
# it would let one kind fill the entire set and crowd out the click/fill options
# the checkpoint actually needs. Four is chosen deliberately: it covers the real
# case that motivated the fix (a consent form's three checkboxes) with one to
# spare, and stays well under the global cap so the mix of kinds survives.
_MAX_PER_ACTION_KIND: int = 4

# How many approved references may be offered for ONE element.
#
# `fill` and `select_option` are a CROSS PRODUCT of elements and references, so a
# bound that counts per PAGE is spent entirely on whichever input happens to come
# first in the snapshot: on a signup form with four allowed references the
# "Company name" box took all four slots and the "Website" and "Team name" boxes
# got zero candidates — the agent could only ever type into one field per page.
# Two, not one: `allow_value_refs` is ordered by relevance and its top two entries
# are the genuine "company_name vs organization_name" ambiguity the model should
# get to resolve. Beyond two, the extra offers for the SAME box are near-synonyms
# that cost budget another input needs.
_MAX_VALUE_REFS_PER_ELEMENT: int = 2

# Global ceiling on ONE value-action kind, so a 30-input page cannot flood the
# set. Six is two references across the three-input signup form that motivated
# this fix, and it stays a real ceiling: because the offers are interleaved
# breadth-first (see :func:`_interleave`), truncation removes a SECOND offer for
# one input before it removes the ONLY offer for another.
_MAX_VALUE_CANDIDATES: int = 6


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


def _identity_parts(element: SnapshotElement) -> tuple[str, ...]:
    """The element facets an id must fold in so two candidates never collide.

    Two options that RENDER differently must not hash to the same id. A settings
    page with a "Save" under "Notification preferences" and a "Save" under "API
    tokens" used to produce ONE id for both, because the digest covered only
    role/name/frame: the choice list then carried a duplicate, the schema enum
    offered it once, and selecting the second returned the first. The check branch
    was weaker still — it hashed the name alone, so the same label in two frames
    collided too.

    Every facet here is already-sanitized snapshot data and never leaves the hash,
    so the id the model receives stays opaque and unforgeable.
    """

    return (
        element.role,
        element.name,
        element.element_type,
        "/".join(element.frame_path),
        element.test_id or "",
        element.nearby_heading or "",
    )


def classify_irreversible(name: str, role: str = "") -> tuple[bool, str]:
    """Return (is_irreversible, category) for an element's accessible name."""

    lowered = f"{name} {role}".casefold()
    for needle, category in _IRREVERSIBLE_INTENTS:
        if needle in lowered:
            return True, category
    return False, ""


def _normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip()


def _interleave(groups: Sequence[Sequence[ActionCandidate]], limit: int) -> list[ActionCandidate]:
    """Flatten per-element candidate groups breadth-first, under ``limit``.

    PRE: ``groups`` holds one entry per element, each ordered by descending
    relevance (the recipe's own ``allow_value_refs`` order).
    POST: at most ``limit`` candidates, and every group contributes its first
    entry before any group contributes its second.

    WHY breadth-first: depth-first flattening reproduces the very defect this
    guards against at a smaller scale — a truncated depth-first list is still
    "several ways to fill the first box and no way to fill the second".
    """

    flattened: list[ActionCandidate] = []
    depth = max((len(group) for group in groups), default=0)
    for index in range(depth):
        for group in groups:
            if len(flattened) >= limit:
                return flattened
            if index < len(group):
                flattened.append(group[index])
    return flattened


def _allocate(
    groups: Sequence[Sequence[ActionCandidate]], max_candidates: int
) -> tuple[ActionCandidate, ...]:
    """Merge the per-kind groups into one budgeted, order-preserving set.

    PRE: ``groups`` is in emission order, one group per action kind.
    POST: at most ``max_candidates`` candidates, emitted in group order; and --
    the invariant that matters -- if the page affords a ``goto``, a ``press`` and
    a ``fill``, all three appear, because every non-empty group is seated once
    before any group is seated twice (whenever the non-empty groups fit the cap).

    WHY: the kinds used to be appended to one shared list in sequence, so `fill`
    and `select_option` spent the whole default budget of eight before `goto`,
    `press` or `check` were reached. Navigation and form submission were starved
    to zero on exactly the pages where the agent could type.
    """

    quotas = [0] * len(groups)
    remaining = max(max_candidates, 0)
    while remaining > 0:
        progressed = False
        for index, group in enumerate(groups):
            if remaining <= 0:
                break
            if quotas[index] >= len(group):
                continue
            quotas[index] += 1
            remaining -= 1
            progressed = True
        if not progressed:
            break  # every group exhausted; the budget is simply larger than the page

    merged: list[ActionCandidate] = []
    for group, quota in zip(groups, quotas, strict=True):
        merged.extend(group[:quota])
    return tuple(merged)


def _by_need(elements: Sequence[SnapshotElement]) -> list[SnapshotElement]:
    """Order elements so the ones still WITHOUT a value are offered first.

    PRE: ``elements`` is in snapshot order.
    POST: same elements, stably partitioned -- every ``has_value=False`` element
    precedes every ``has_value=True`` one, snapshot order preserved within each
    part.

    WHY: the value bounds (``_MAX_VALUE_CANDIDATES``, and then ``_allocate``'s
    round-robin share of the global budget) mean only the FIRST couple of inputs
    on a form are ever offered a `fill`. In snapshot order those are the same two
    inputs every iteration, because a SUCCESSFUL fill does not withhold the
    candidate next time round -- so a form with more inputs than the budget could
    never be completed. Ordering by need rolls the budget forward: once inputs
    0-1 hold a value they sort last, inputs 2-3 come first, and the form finishes
    in ceil(n / share) iterations.

    Deliberately an ORDERING, not a filter: a filled input is still offered when
    budget remains, so an input filled from the wrong reference can be corrected.
    """

    return sorted(elements, key=lambda element: bool(element.has_value))


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

    # Each kind accumulates into its OWN group; the shared budget is applied once
    # at the end by :func:`_allocate`. Appending every kind to a single list made
    # the budget first-come-first-served, which starved the kinds emitted last.
    clicks: list[ActionCandidate] = []

    # The signal filter is a relevance heuristic, not an authorization boundary --
    # every surviving element is still risk-classified downstream. When it matches
    # nothing it used to leave the loop with an empty executable set, which the
    # worker reports as "needs a human" on a page that may hold exactly the control
    # the step described. Falling back to the unfiltered pass keeps the loop moving;
    # the reviewed trace, the value-ref allowlist and the risk policy still decide
    # what may actually run.
    if needles and not any(
        any(needle and needle in _normalize(element.name) for needle in needles)
        for element in elements
        if element.name and element.actionable()
    ):
        needles = []

    for element in elements:
        if len(clicks) >= max_candidates:
            break  # no allocation can ever seat more clicks than the whole budget
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
        clicks.append(
            ActionCandidate(
                candidate_id=_candidate_id(
                    trace_version, checkpoint_order, "click", *_identity_parts(element)
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
    #
    # This is a CROSS PRODUCT of elements and references, so it is bounded twice:
    # PER ELEMENT by ``_MAX_VALUE_REFS_PER_ELEMENT`` (the inner loop), and
    # GLOBALLY by ``_MAX_VALUE_CANDIDATES`` once the per-element groups are
    # interleaved. A single page-wide counter — which is what this used to be —
    # is consumed entirely by the first matching input, so every other input on
    # the form is offered nothing and the form cannot be completed.
    #
    # Iterated in NEED order (see :func:`_by_need`), not snapshot order, so the
    # bounds below spend themselves on inputs that are still empty before they
    # re-offer one that already holds a value.
    fill_groups: list[list[ActionCandidate]] = []
    for element in _by_need(elements):
        if len(fill_groups) >= _MAX_VALUE_CANDIDATES:
            break  # each group seats at least one, so further groups are unreachable
        if element.element_type not in {"text", "email", "search", "url", "tel"}:
            continue
        if element.secretish or not element.actionable():
            continue  # code-owned injection only; never a hidden/disabled field
        element_fills: list[ActionCandidate] = []
        for ref in allow_value_refs:
            if len(element_fills) >= _MAX_VALUE_REFS_PER_ELEMENT:
                break
            if ref not in APPROVED_VALUE_REFS:
                continue
            element_fills.append(
                ActionCandidate(
                    candidate_id=_candidate_id(
                        trace_version, checkpoint_order, "fill", ref, *_identity_parts(element)
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
        if element_fills:
            fill_groups.append(element_fills)
    fills = _interleave(fill_groups, _MAX_VALUE_CANDIDATES)

    # `select_option` candidates come from the element's REVIEWED options only.
    # Bounded per element and then globally, for the same cross-product reason as
    # `fill` above, and in the same NEED order for the same reason.
    select_groups: list[list[ActionCandidate]] = []
    for element in _by_need(elements):
        if len(select_groups) >= _MAX_VALUE_CANDIDATES:
            break
        if element.role.casefold() != "select" or not element.actionable():
            continue
        element_selects: list[ActionCandidate] = []
        for ref in allow_value_refs:
            if len(element_selects) >= _MAX_VALUE_REFS_PER_ELEMENT:
                break
            if ref not in APPROVED_VALUE_REFS:
                continue
            element_selects.append(
                ActionCandidate(
                    candidate_id=_candidate_id(
                        trace_version,
                        checkpoint_order,
                        "select_option",
                        ref,
                        *_identity_parts(element),
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
        if element_selects:
            select_groups.append(element_selects)
    selects = _interleave(select_groups, _MAX_VALUE_CANDIDATES)

    # `check` / `uncheck`: only for a real checkbox/radio, and the postcondition
    # asserts the resulting checked state so the transition is verifiable. EVERY
    # matching box becomes its own candidate (up to _MAX_PER_ACTION_KIND) so a
    # consent form's three checkboxes are three distinguishable options rather
    # than one arbitrary box and two wasted iterations.
    toggles: list[ActionCandidate] = []
    for element in elements:
        if len(toggles) >= _MAX_PER_ACTION_KIND:
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
        toggles.append(
            ActionCandidate(
                candidate_id=_candidate_id(
                    trace_version, checkpoint_order, action, *_identity_parts(element)
                ),
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

    # `goto` candidates come ONLY from the reviewed trace, never from the model.
    gotos: list[ActionCandidate] = []
    for url in reviewed_goto_urls:
        if len(gotos) >= max_candidates:
            break
        gotos.append(
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
    # Bounded per kind like check/uncheck above: a page with a search box and an
    # email field offers two meaningfully different "submit this one" moves, and
    # emitting only the first made the second unreachable.
    presses: list[ActionCandidate] = []
    for element in elements:
        if len(presses) >= _MAX_PER_ACTION_KIND:
            break
        if (
            element.element_type in {"text", "email", "search"}
            and not element.secretish
            and element.actionable()
        ):
            presses.append(
                ActionCandidate(
                    candidate_id=_candidate_id(
                        trace_version,
                        checkpoint_order,
                        "press",
                        "Enter",
                        *_identity_parts(element),
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

    # One shared budget, allocated fairly across the kinds the page actually
    # affords, in emission order. See :func:`_allocate` for the invariant.
    return _allocate((clicks, fills, selects, toggles, gotos, presses), max_candidates)


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


def _goto_detail(url: str) -> str:
    """Describe a reviewed goto target well enough to tell two of them apart.

    Every goto used to render as the literal string "reviewed trace URL", so N
    reviewed destinations were N textually IDENTICAL options and the model was
    choosing between them at random.

    The projection is :func:`ops.core.model_input_dlp.sanitize_url`'s — the repo's
    single DLP boundary for a URL — rather than a hand-rolled split, for three
    reasons that all matter here:

    * The query string and fragment are dropped unconditionally. That is where a
      URL carries a session token or an OAuth code, so origin+path is the most
      that may ever be rendered even though these URLs are reviewed recipe data
      rather than page-derived text.
    * An identifier-shaped or high-entropy path SEGMENT is replaced with
      ``[REDACTED]``, so a token embedded in a path cannot ride out either.
    * The result keeps its ``https://`` scheme. ``contains_secret_material`` — the
      last-line assertion in ``ops.playwright.worker`` before the prompt leaves
      the process — sweeps every whitespace-separated token for high entropy, and
      exempts URL-shaped ones. A bare ``host/path`` is neither URL-shaped nor
      hostname-shaped: ``app.mercury.com/settings/api-tokens`` scores 4.07 bits
      against a 4.0 threshold, so rendering it WITHOUT the scheme would trip the
      assertion and refuse the whole prompt on a page that holds nothing secret.

    Nothing here widens what the model may emit: it still replies with an opaque
    ``candidate_id``, and the URL actually navigated to is the reviewed one held
    on the candidate, never a string read back out of this text.
    """

    return sanitize_url(url) or "reviewed trace URL"


def render_candidates(candidates: Sequence[ActionCandidate]) -> str:
    """Render the choice list for the prompt (ids + semantics only).

    The model gets no selector, no raw value and no free-text field — only the
    opaque id it must echo back, what the action would do, and enough context to
    choose between two similarly named controls: the element's role, the section
    heading it sits under, and the policy risk level. Risk is included because
    "click Save" and "click Cancel" read identically without it.
    """

    if not candidates:
        return "(no candidates available)"
    lines = []
    for candidate in candidates:
        if not candidate.executable:
            continue
        detail = candidate.semantic_target
        if candidate.action in VALUE_ACTIONS and candidate.value_ref:
            detail = f"{detail} (approved value: {candidate.value_ref})"
        elif candidate.action == "press" and candidate.press_key:
            detail = f"{detail} (press {candidate.press_key})"
        elif candidate.action == "goto":
            detail = _goto_detail(candidate.url or "")
        context: list[str] = []
        identity = candidate.identity
        if identity is not None:
            if identity.role:
                context.append(identity.role)
            if identity.nearby_heading:
                # Already sanitized at source by ``build_snapshot``; bounded here
                # only so one long heading cannot dominate the choice list.
                context.append(f'under "{identity.nearby_heading[:80]}"')
        context.append(f"risk={candidate.risk}")
        lines.append(
            f"{candidate.candidate_id}: {candidate.action} -> {detail} [{', '.join(context)}]"
        )
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
