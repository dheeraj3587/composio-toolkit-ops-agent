"""Proof rules: did the page reach the reviewed state, and did the action work?

These predicates are the only thing allowed to say "progress happened". Every one of
them is deliberately conservative, because the alternative to a false negative is a
run that believes it advanced when it did not:

* A predicate with no positive condition can never PROVE progress and returns
  False, leaving escalation to the trace's own ``requires_hitl``.
* A postcondition target must resolve to EXACTLY one element; ambiguity fails
  rather than picking a match, since two identical checkboxes would otherwise let
  the wrong one prove the transition.
* Checked/selected assertions are target-bound, because scanning every element let
  an unrelated control that already had the desired state prove a no-op.
* A successful click is not a successful transition, so an action is verified by
  re-inspecting the page rather than by trusting a return value. Any one satisfied
  assertion counts, which is what makes this work for SPAs where client-side
  routing or partial DOM replacement is the only observable effect.

Nothing here sleeps or waits for ``networkidle``: a persistent WebSocket or a
background poll means idle may never arrive.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from urllib.parse import urlsplit

from ops.browser.api_trace_catalog import BrowserApiTrace, BrowserApiTraceStep, CheckpointPredicate
from ops.browser.candidates import CandidatePostcondition, ElementPredicate
from ops.browser.decider import SnapshotElement
from ops.playwright.page_inspection import PageInspection


def predicate_satisfied(predicate: CheckpointPredicate, inspection: PageInspection) -> bool:
    """True only when every POSITIVE condition holds and no forbidden text appears.

    A predicate with no positive condition can never PROVE progress and returns
    False (the state machine then relies on ``requires_hitl`` to escalate).
    """

    path = urlsplit(inspection.url).path.casefold()
    title = inspection.title.casefold()
    text = inspection.visible_text.casefold()
    names = tuple(name.casefold() for name in inspection.accessible_names())

    for token in predicate.forbidden_text:
        needle = token.casefold()
        if needle and (needle in text or needle in title):
            return False
    if not predicate.has_positive_condition():
        return False
    if any(token.casefold() not in path for token in predicate.url_path_contains):
        return False
    if any(token.casefold() not in title for token in predicate.title_contains):
        return False
    if any(token.casefold() not in text for token in predicate.visible_text_contains):
        return False
    for required in predicate.required_accessible_names:
        needle = required.casefold()
        if not any(needle in name for name in names):
            return False
    return True


def checkpoint_satisfied(checkpoint: BrowserApiTraceStep, inspection: PageInspection) -> bool:
    """True when the checkpoint's reviewed completion predicate is proven on the page."""

    return predicate_satisfied(checkpoint.completion, inspection)


def _predicate_present(predicate: ElementPredicate, inspection: PageInspection) -> bool:
    return any(predicate.matches(element) for element in inspection.elements)


def _unique_target(
    predicate: ElementPredicate | None, inspection: PageInspection
) -> SnapshotElement | None:
    """Resolve a postcondition target to EXACTLY one element, else None.

    Ambiguity must fail the postcondition rather than pick a match: two identical
    checkboxes would otherwise let the wrong one prove the transition.
    """

    if predicate is None:
        return None
    matches = [element for element in inspection.elements if predicate.matches(element)]
    return matches[0] if len(matches) == 1 else None


def postcondition_satisfied(
    postcondition: CandidatePostcondition,
    *,
    before: PageInspection,
    after: PageInspection,
    expected_selected_label: str | None = None,
) -> bool:
    """Verify an ACTION's own state transition (Phase 2, section 3/5).

    A successful click is not a successful transition. This compares a freshly
    inspected page against the pre-action inspection and requires the action's
    specific assertion to hold. ANY satisfied assertion counts (a click may
    legitimately either navigate or replace part of the DOM), which is what makes
    it work for SPAs: client-side routing changes the URL, partial DOM
    replacement makes the control disappear or new text appear.

    Deliberately NOT ``networkidle`` (a persistent WebSocket or background poll
    means idle may never arrive) and never a sleep.
    """

    if postcondition.is_empty():
        return False

    if postcondition.url_matches:
        path = urlsplit(after.url).path.casefold()
        if any(token.casefold() in path for token in postcondition.url_matches):
            return True

    if postcondition.url_changed and after.url != before.url:
        return True

    for predicate in postcondition.element_appears:
        if _predicate_present(predicate, after) and not _predicate_present(predicate, before):
            return True

    for predicate in postcondition.element_disappears:
        if _predicate_present(predicate, before) and not _predicate_present(predicate, after):
            return True

    if postcondition.text_appears:
        text = after.visible_text.casefold()
        before_text = before.visible_text.casefold()
        if any(
            token.casefold() in text and token.casefold() not in before_text
            for token in postcondition.text_appears
        ):
            return True

    # Checked/selected assertions are TARGET-BOUND: they must hold for the element
    # the action was performed on. Scanning every element let an unrelated control
    # that already had the desired state prove a no-op.
    if postcondition.checked_state is not None:
        target = _unique_target(postcondition.target, after)
        if target is not None and target.checked is postcondition.checked_state:
            return True

    # For a select, the expected LABEL comes from the executor (the resolved option
    # text), because the approved-value reference name is not the option's label.
    needle_source = expected_selected_label or postcondition.selected_value
    if needle_source:
        target = _unique_target(postcondition.target, after)
        if target is not None:
            needle = needle_source.casefold()
            observed = (target.selected_label or "").casefold()
            if observed and needle in observed:
                return True

    return False


def structural_change(before: PageInspection, after: PageInspection) -> bool:
    """A bounded structural DOM change: the interactive surface actually differs.

    Used as the SPA fallback when a candidate asserted no specific postcondition:
    it proves *something* changed without trusting a click's return value.
    """

    return before.fingerprint != after.fingerprint


def current_checkpoint(trace: BrowserApiTrace, index: int) -> BrowserApiTraceStep | None:
    """Return the checkpoint at ``index``, or None when the trace is exhausted."""

    if 0 <= index < len(trace.checkpoints):
        return trace.checkpoints[index]
    return None


def _normalize_signal(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip()


def matched_success_signals(
    signals: Sequence[str], *, url: str, title: str, text: str
) -> tuple[str, ...]:
    """Return the reviewed success signals actually observed on the page.

    A signal counts only when it appears in the URL, the page title, or the visible
    body text. This is the gate for declaring the credential page reached, so it is
    deliberately evidence-based rather than inferred.
    """

    haystack = _normalize_signal(f"{url} {title} {text}")
    if not haystack:
        return ()
    hits = [
        signal for signal in signals if (needle := _normalize_signal(signal)) and needle in haystack
    ]
    return tuple(hits)
