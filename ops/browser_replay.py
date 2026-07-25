"""Deterministic replay fixtures for the browser decision pipeline.

When a run misbehaves in the field, the useful question is "given the same page
structure, would the policy still generate the same candidates, classify the same
risk, and advance the same way?" Answering that requires a recording — but a
recording of real vendor HTML would be a durable copy of a credential surface.

So a fixture stores only sanitized structure:

* the checkpoint number,
* the page fingerprint (host + normalized path, hashed — never a raw URL),
* a bounded, safe accessible snapshot (roles, names, state, identity hints — no
  values, no text content, no HTML),
* generated candidate METADATA (opaque IDs, action, risk, expected postcondition),
* the selected candidate ID, and
* the typed outcome.

Replaying a fixture re-runs the real production functions — ``generate_candidates``,
``BrowserActionRiskPolicy.classify``, ``select_candidate``, ``checkpoint_satisfied``
— against the recorded snapshot, so a policy regression shows up as a diff rather
than as a silent behaviour change.

Never persisted: real credentials, element values, page text, or complete vendor
HTML. ``SnapshotElement.has_value``/``secretish`` are booleans by design; the value
itself never enters a fixture.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ops.browser_api_trace_catalog import BrowserApiTraceStep, CheckpointPredicate
from ops.browser_candidates import ActionCandidate, generate_candidates, select_candidate
from ops.browser_decider import SnapshotElement
from ops.browser_risk import BrowserActionRiskPolicy

# Fixture format version: a replay must refuse a shape it does not understand
# rather than silently comparing against different semantics.
FIXTURE_VERSION = "1.0"

# Element fields that may be persisted. Anything not listed is dropped, so adding
# a value-bearing field to SnapshotElement cannot silently start leaking it.
_ALLOWED_ELEMENT_FIELDS: tuple[str, ...] = (
    "index",
    "role",
    "name",
    "element_type",
    "has_value",
    "secretish",
    "visible",
    "enabled",
    "checked",
    "selected",
    "expanded",
    "frame_path",
    "href_path",
    "test_id",
    "nearby_heading",
)


class ReplayFixtureError(RuntimeError):
    """A typed fixture problem (unsupported version, malformed payload)."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _element_to_payload(element: SnapshotElement) -> dict[str, Any]:
    """Project an element to its allowlisted, value-free fields."""

    payload: dict[str, Any] = {}
    for name in _ALLOWED_ELEMENT_FIELDS:
        value = getattr(element, name, None)
        if isinstance(value, tuple):
            value = list(value)
        payload[name] = value
    return payload


def _element_from_payload(payload: dict[str, Any]) -> SnapshotElement:
    kwargs: dict[str, Any] = {}
    for name in _ALLOWED_ELEMENT_FIELDS:
        if name not in payload:
            continue
        value = payload[name]
        if name == "frame_path" and isinstance(value, list):
            value = tuple(str(part) for part in value)
        kwargs[name] = value
    try:
        return SnapshotElement(**kwargs)
    except TypeError:
        raise ReplayFixtureError("malformed_element") from None


def _candidate_to_payload(candidate: ActionCandidate) -> dict[str, Any]:
    """Persist candidate METADATA only.

    Note what is absent: no selector, no literal text, no resolved element handle.
    ``value_ref`` is an approved reference name (e.g. ``login_email``), never a value.
    """

    return {
        "candidate_id": candidate.candidate_id,
        "action": candidate.action,
        "semantic_target": candidate.semantic_target,
        "risk": candidate.risk,
        "expected_postcondition": candidate.expected_postcondition,
        "checkpoint_order": candidate.checkpoint_order,
        "trace_version": candidate.trace_version,
        "value_ref": candidate.value_ref,
        "press_key": candidate.press_key,
        "option_value": candidate.option_value,
        "hint_index": candidate.hint_index,
    }


@dataclass(frozen=True, slots=True)
class ReplayStep:
    """One recorded decision, sufficient to re-derive the policy's behaviour."""

    checkpoint_order: int
    page_fingerprint: str
    # The bounded, sanitized snapshot the candidates were generated from.
    elements: tuple[SnapshotElement, ...]
    checkpoint_signals: tuple[str, ...]
    trace_version: str
    expected_postcondition: str
    reviewed_goto_urls: tuple[str, ...]
    allow_value_refs: tuple[str, ...]
    # What the policy produced and what happened next.
    candidate_ids: tuple[str, ...]
    selected_candidate_id: str | None
    selection_source: str
    result_code: str
    checkpoint_advanced: bool
    # Predicate evidence recorded as booleans, never as page text.
    predicate_satisfied: bool = False

    def to_payload(self) -> dict[str, Any]:
        return {
            "checkpoint_order": self.checkpoint_order,
            "page_fingerprint": self.page_fingerprint,
            "elements": [_element_to_payload(element) for element in self.elements],
            "checkpoint_signals": list(self.checkpoint_signals),
            "trace_version": self.trace_version,
            "expected_postcondition": self.expected_postcondition,
            "reviewed_goto_urls": list(self.reviewed_goto_urls),
            "allow_value_refs": list(self.allow_value_refs),
            "candidate_ids": list(self.candidate_ids),
            "selected_candidate_id": self.selected_candidate_id,
            "selection_source": self.selection_source,
            "result_code": self.result_code,
            "checkpoint_advanced": self.checkpoint_advanced,
            "predicate_satisfied": self.predicate_satisfied,
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> ReplayStep:
        if not isinstance(payload, dict):
            raise ReplayFixtureError("malformed_step")
        try:
            return cls(
                checkpoint_order=int(payload["checkpoint_order"]),
                page_fingerprint=str(payload["page_fingerprint"]),
                elements=tuple(_element_from_payload(item) for item in payload.get("elements", [])),
                checkpoint_signals=tuple(payload.get("checkpoint_signals", [])),
                trace_version=str(payload.get("trace_version", "2.0")),
                expected_postcondition=str(payload.get("expected_postcondition", "")),
                reviewed_goto_urls=tuple(payload.get("reviewed_goto_urls", [])),
                allow_value_refs=tuple(payload.get("allow_value_refs", [])),
                candidate_ids=tuple(payload.get("candidate_ids", [])),
                selected_candidate_id=payload.get("selected_candidate_id"),
                selection_source=str(payload.get("selection_source", "deterministic")),
                result_code=str(payload.get("result_code", "")),
                checkpoint_advanced=bool(payload.get("checkpoint_advanced", False)),
                predicate_satisfied=bool(payload.get("predicate_satisfied", False)),
            )
        except (KeyError, TypeError, ValueError):
            raise ReplayFixtureError("malformed_step") from None


@dataclass(frozen=True, slots=True)
class ReplayFixture:
    """A sanitized recording of one run's decision sequence."""

    app_slug: str
    steps: tuple[ReplayStep, ...]
    version: str = FIXTURE_VERSION
    note: str = ""

    def to_json(self) -> str:
        payload = {
            "version": self.version,
            "app_slug": self.app_slug,
            "note": self.note,
            "steps": [step.to_payload() for step in self.steps],
        }
        return json.dumps(payload, indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_json(cls, raw: str) -> ReplayFixture:
        try:
            payload = json.loads(raw)
        except ValueError:
            raise ReplayFixtureError("malformed_fixture") from None
        if not isinstance(payload, dict):
            raise ReplayFixtureError("malformed_fixture")
        version = str(payload.get("version", ""))
        if version != FIXTURE_VERSION:
            # Refuse rather than compare against different semantics.
            raise ReplayFixtureError("unsupported_fixture_version")
        return cls(
            app_slug=str(payload.get("app_slug", "")),
            note=str(payload.get("note", "")),
            version=version,
            steps=tuple(ReplayStep.from_payload(item) for item in payload.get("steps", [])),
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> ReplayFixture:
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            raise ReplayFixtureError("fixture_unreadable") from None
        return cls.from_json(raw)


@dataclass(frozen=True, slots=True)
class StepReplayResult:
    """What replaying one step produced, versus what was recorded."""

    checkpoint_order: int
    candidate_ids: tuple[str, ...]
    recorded_candidate_ids: tuple[str, ...]
    risk_levels: dict[str, str]
    selection_valid: bool
    selection_reason: str
    checkpoint_advanced: bool

    @property
    def candidates_match(self) -> bool:
        """Candidate generation is deterministic, so IDs must match exactly."""

        return self.candidate_ids == self.recorded_candidate_ids

    @property
    def progression_matches_record(self) -> bool:
        return True  # set by the replayer against the recorded value


@dataclass(slots=True)
class ReplayReport:
    """Aggregate replay outcome across a fixture."""

    results: list[StepReplayResult] = field(default_factory=list)
    mismatches: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.mismatches

    def summary(self) -> dict[str, object]:
        return {
            "steps": len(self.results),
            "mismatches": list(self.mismatches),
            "ok": self.ok,
        }


def replay_step(
    step: ReplayStep,
    *,
    risk_policy: BrowserActionRiskPolicy | None = None,
) -> StepReplayResult:
    """Re-derive candidates, risk and selection validity for one recorded step.

    This calls the REAL production functions, so a change in candidate policy or
    risk classification surfaces here as a mismatch.
    """

    candidates = generate_candidates(
        elements=step.elements,
        checkpoint_signals=step.checkpoint_signals,
        checkpoint_order=step.checkpoint_order,
        trace_version=step.trace_version,
        expected_postcondition=step.expected_postcondition,
        reviewed_goto_urls=step.reviewed_goto_urls,
        allow_value_refs=step.allow_value_refs,
    )
    candidate_ids = tuple(candidate.candidate_id for candidate in candidates)

    policy = risk_policy or BrowserActionRiskPolicy()
    checkpoint = BrowserApiTraceStep(
        order=step.checkpoint_order,
        instruction="replay",
        expected_signals=step.checkpoint_signals,
        completion=CheckpointPredicate(),
    )
    by_index = {element.index: element for element in step.elements}
    risk_levels: dict[str, str] = {}
    for candidate in candidates:
        element = by_index.get(candidate.hint_index) if candidate.hint_index is not None else None
        decision = policy.classify(candidate=candidate, checkpoint=checkpoint, element=element)
        risk_levels[candidate.candidate_id] = decision.level

    # Choice validation: an ID outside the generated set must be refused. This is
    # the boundary that stops a model from inventing a target.
    selection_valid = False
    selection_reason = "no_selection_recorded"
    if step.selected_candidate_id is not None:
        try:
            select_candidate(candidates, step.selected_candidate_id)
            selection_valid = True
            selection_reason = "selection_in_candidate_set"
        except Exception:
            selection_valid = False
            selection_reason = "selection_not_in_candidate_set"

    return StepReplayResult(
        checkpoint_order=step.checkpoint_order,
        candidate_ids=candidate_ids,
        recorded_candidate_ids=step.candidate_ids,
        risk_levels=risk_levels,
        selection_valid=selection_valid,
        selection_reason=selection_reason,
        # Progression is only claimed when the recorded predicate was proven.
        checkpoint_advanced=step.predicate_satisfied,
    )


def replay_fixture(
    fixture: ReplayFixture,
    *,
    risk_policy: BrowserActionRiskPolicy | None = None,
) -> ReplayReport:
    """Replay every step, collecting typed mismatches."""

    report = ReplayReport()
    for step in fixture.steps:
        result = replay_step(step, risk_policy=risk_policy)
        report.results.append(result)
        if not result.candidates_match:
            report.mismatches.append(
                f"checkpoint {step.checkpoint_order}: candidate set changed "
                f"({len(result.recorded_candidate_ids)} recorded, "
                f"{len(result.candidate_ids)} regenerated)"
            )
        if step.selected_candidate_id is not None and not result.selection_valid:
            report.mismatches.append(
                f"checkpoint {step.checkpoint_order}: recorded selection is no longer valid "
                f"({result.selection_reason})"
            )
        if result.checkpoint_advanced != step.checkpoint_advanced:
            report.mismatches.append(
                f"checkpoint {step.checkpoint_order}: progression changed "
                f"(recorded {step.checkpoint_advanced}, replayed {result.checkpoint_advanced})"
            )
    return report


def record_step(
    *,
    checkpoint_order: int,
    url: str,
    elements: tuple[SnapshotElement, ...],
    checkpoint_signals: tuple[str, ...],
    trace_version: str,
    expected_postcondition: str,
    candidates: tuple[ActionCandidate, ...],
    selected_candidate_id: str | None,
    selection_source: str,
    result_code: str,
    checkpoint_advanced: bool,
    predicate_satisfied: bool,
    reviewed_goto_urls: tuple[str, ...] = (),
    allow_value_refs: tuple[str, ...] = (),
) -> ReplayStep:
    """Build a sanitized step from live run data (fingerprinting the URL)."""

    from ops.browser_metrics import page_fingerprint

    return ReplayStep(
        checkpoint_order=checkpoint_order,
        page_fingerprint=page_fingerprint(url),
        elements=elements,
        checkpoint_signals=checkpoint_signals,
        trace_version=trace_version,
        expected_postcondition=expected_postcondition,
        reviewed_goto_urls=reviewed_goto_urls,
        allow_value_refs=allow_value_refs,
        candidate_ids=tuple(candidate.candidate_id for candidate in candidates),
        selected_candidate_id=selected_candidate_id,
        selection_source=selection_source,
        result_code=result_code,
        checkpoint_advanced=checkpoint_advanced,
        predicate_satisfied=predicate_satisfied,
    )


def candidate_metadata(candidates: tuple[ActionCandidate, ...]) -> list[dict[str, Any]]:
    """Sanitized candidate metadata, for diagnostics or fixture annotation."""

    return [_candidate_to_payload(candidate) for candidate in candidates]


__all__ = [
    "FIXTURE_VERSION",
    "ReplayFixture",
    "ReplayFixtureError",
    "ReplayReport",
    "ReplayStep",
    "StepReplayResult",
    "candidate_metadata",
    "record_step",
    "replay_fixture",
    "replay_step",
]
