"""Shadow evaluation: Playwright plans, Browser Use executes.

The safest way to build confidence in a new harness is to let it make decisions on
real traffic while it cannot act on them. In shadow mode:

* Browser Use performs the real run, exactly as it does today,
* Playwright's decision pipeline receives the SAME sanitized observation and
  produces candidates, a risk classification and an expected next action, and
* the two interpretations are compared offline.

The guarantee that makes this safe is structural, not procedural: this module has
no page, no browser, and no execution path. It is a pure function from a sanitized
observation to a plan. There is nothing here that *could* launch a second vendor
login, type a credential, or mutate anything — the capability is absent rather than
merely unused.

Consequently a shadow evaluation cannot affect the real run: it never touches the
run's state, never writes to the vault, and its failures are captured as a typed
reason code rather than propagated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from ops.browser_api_trace_catalog import BrowserApiTraceStep
from ops.browser_candidates import ActionCandidate, generate_candidates
from ops.browser_decider import SnapshotElement
from ops.browser_risk import BrowserActionRiskPolicy

ShadowHitlDecision = Literal["autonomous", "requires_hitl", "no_action_available"]

# Field names a shadow observation may carry. Anything else is dropped at the
# boundary, so a caller cannot accidentally hand the shadow path a credential.
_ALLOWED_OBSERVATION_FIELDS = frozenset(
    {"status", "current_url", "page_title", "human_action_type", "credential_field_labels"}
)


class ShadowExecutionForbidden(RuntimeError):
    """Raised if anything ever asks the shadow planner to act.

    Defence in depth: the planner has no executor, so this exists to make an
    accidental future wiring fail loudly instead of quietly acting.
    """

    def __init__(self, attempted: str) -> None:
        self.attempted = attempted
        super().__init__(f"shadow mode cannot execute: {attempted}")


@dataclass(frozen=True, slots=True)
class ShadowObservation:
    """The sanitized input a shadow evaluation is allowed to see.

    Note what is NOT here: cookies, storage state, credential values, page HTML,
    or full page text. The shadow planner reasons over structure only.
    """

    checkpoint_order: int
    url_path: str
    page_title: str
    elements: tuple[SnapshotElement, ...]
    checkpoint_signals: tuple[str, ...]
    trace_version: str = "2.0"
    expected_postcondition: str = ""
    human_action_type: str | None = None

    @classmethod
    def from_observation(
        cls,
        observation: object,
        *,
        checkpoint_order: int,
        elements: tuple[SnapshotElement, ...],
        checkpoint_signals: tuple[str, ...],
        trace_version: str = "2.0",
        expected_postcondition: str = "",
    ) -> ShadowObservation:
        """Project a live BrowserObservation down to shadow-safe fields."""

        from urllib.parse import urlsplit

        def _read(name: str) -> object:
            if name not in _ALLOWED_OBSERVATION_FIELDS:
                return None
            return getattr(observation, name, None)

        raw_url = _read("current_url")
        path = "/"
        if isinstance(raw_url, str) and raw_url:
            # Path only: a query string can carry a token.
            path = urlsplit(raw_url).path or "/"
        title = _read("page_title")
        action_type = _read("human_action_type")
        return cls(
            checkpoint_order=checkpoint_order,
            url_path=path,
            page_title=str(title) if isinstance(title, str) else "",
            elements=elements,
            checkpoint_signals=checkpoint_signals,
            trace_version=trace_version,
            expected_postcondition=expected_postcondition,
            human_action_type=str(action_type) if isinstance(action_type, str) else None,
        )


@dataclass(frozen=True, slots=True)
class ShadowPlan:
    """What Playwright WOULD have done. Nothing was executed."""

    checkpoint_order: int
    candidate_ids: tuple[str, ...]
    expected_action: str | None
    expected_candidate_id: str | None
    risk_levels: dict[str, str]
    hitl_decision: ShadowHitlDecision
    checkpoint_interpretation: str
    reason_code: str = "planned"
    # Always False. Present so a comparison record states it explicitly rather
    # than leaving "did this act?" to inference.
    executed: bool = False

    def as_comparison_fields(self) -> dict[str, object]:
        return {
            "checkpoint_order": self.checkpoint_order,
            "candidate_count": len(self.candidate_ids),
            "candidate_ids": list(self.candidate_ids),
            "expected_action": self.expected_action,
            "expected_candidate_id": self.expected_candidate_id,
            "hitl_decision": self.hitl_decision,
            "checkpoint_interpretation": self.checkpoint_interpretation,
            "reason_code": self.reason_code,
            "executed": self.executed,
        }


class ShadowPlanner:
    """Produces a plan from a sanitized observation. Cannot execute anything.

    There is deliberately no ``page``, no ``worker``, and no ``execute`` method: the
    class holds only reviewed policy objects.
    """

    def __init__(self, risk_policy: BrowserActionRiskPolicy | None = None) -> None:
        self._risk_policy = risk_policy or BrowserActionRiskPolicy()

    def plan(self, observation: ShadowObservation) -> ShadowPlan:
        """Derive candidates, risk and the expected next action. Executes nothing."""

        try:
            candidates = generate_candidates(
                elements=observation.elements,
                checkpoint_signals=observation.checkpoint_signals,
                checkpoint_order=observation.checkpoint_order,
                trace_version=observation.trace_version,
                expected_postcondition=observation.expected_postcondition,
            )
        except Exception as exc:
            # A shadow failure must never surface as a run failure.
            return ShadowPlan(
                checkpoint_order=observation.checkpoint_order,
                candidate_ids=(),
                expected_action=None,
                expected_candidate_id=None,
                risk_levels={},
                hitl_decision="no_action_available",
                checkpoint_interpretation=self._interpret(observation),
                reason_code=f"shadow_planning_failed:{type(exc).__name__}",
            )

        checkpoint = BrowserApiTraceStep(
            order=observation.checkpoint_order,
            instruction="shadow",
            expected_signals=observation.checkpoint_signals,
        )
        by_index = {element.index: element for element in observation.elements}
        risk_levels: dict[str, str] = {}
        autonomous: list[ActionCandidate] = []
        for candidate in candidates:
            element = (
                by_index.get(candidate.hint_index) if candidate.hint_index is not None else None
            )
            decision = self._risk_policy.classify(
                candidate=candidate, checkpoint=checkpoint, element=element
            )
            risk_levels[candidate.candidate_id] = decision.level
            if decision.autonomous_allowed:
                autonomous.append(candidate)

        if not candidates:
            hitl: ShadowHitlDecision = "no_action_available"
        elif autonomous:
            hitl = "autonomous"
        else:
            hitl = "requires_hitl"

        chosen = autonomous[0] if autonomous else None
        return ShadowPlan(
            checkpoint_order=observation.checkpoint_order,
            candidate_ids=tuple(candidate.candidate_id for candidate in candidates),
            expected_action=chosen.action if chosen else None,
            expected_candidate_id=chosen.candidate_id if chosen else None,
            risk_levels=risk_levels,
            hitl_decision=hitl,
            checkpoint_interpretation=self._interpret(observation),
        )

    @staticmethod
    def _interpret(observation: ShadowObservation) -> str:
        """A coarse, non-secret reading of what page the harness thinks it is on."""

        if observation.human_action_type:
            return f"gate:{observation.human_action_type}"
        haystack = f"{observation.url_path} {observation.page_title}".casefold()
        for needle, label in (
            ("api", "credential_surface"),
            ("token", "credential_surface"),
            ("developer", "developer_portal"),
            ("setting", "settings"),
            ("login", "login"),
            ("sign in", "login"),
            ("verify", "verification"),
        ):
            if needle in haystack:
                return label
        return "unknown"

    # Explicit refusals: if some future wiring mistakes this for an executor, it
    # fails loudly rather than acting.
    def execute(self, *_args: object, **_kwargs: object) -> None:
        raise ShadowExecutionForbidden("execute")

    def type_credential(self, *_args: object, **_kwargs: object) -> None:
        raise ShadowExecutionForbidden("type_credential")


@dataclass(frozen=True, slots=True)
class ShadowDivergence:
    """One difference between the executing harness and the shadow plan."""

    dimension: Literal[
        "checkpoint_interpretation",
        "candidate_set",
        "risk_classification",
        "expected_action",
        "hitl_decision",
    ]
    executed_value: str
    shadow_value: str

    def describe(self) -> str:
        return f"{self.dimension}: executed={self.executed_value!r} shadow={self.shadow_value!r}"


@dataclass(slots=True)
class ShadowComparison:
    """Offline comparison of the real run against the shadow plan."""

    divergences: list[ShadowDivergence] = field(default_factory=list)
    agreements: list[str] = field(default_factory=list)

    @property
    def agreed(self) -> bool:
        return not self.divergences

    def summary(self) -> dict[str, object]:
        return {
            "agreed": self.agreed,
            "divergence_count": len(self.divergences),
            "divergences": [item.describe() for item in self.divergences],
            "agreements": list(self.agreements),
        }


def compare_shadow(
    *,
    plan: ShadowPlan,
    executed_interpretation: str,
    executed_candidate_ids: tuple[str, ...],
    executed_action: str | None,
    executed_hitl_required: bool,
    executed_risk_levels: dict[str, str] | None = None,
) -> ShadowComparison:
    """Compare the five required dimensions offline.

    Purely analytical: it reads two records and returns differences. It cannot
    influence the executed run, which has already finished by this point.
    """

    comparison = ShadowComparison()

    def _check(dimension: str, executed: str, shadow: str) -> None:
        if executed == shadow:
            comparison.agreements.append(dimension)
        else:
            comparison.divergences.append(
                ShadowDivergence(
                    dimension=dimension,  # type: ignore[arg-type]
                    executed_value=executed,
                    shadow_value=shadow,
                )
            )

    _check("checkpoint_interpretation", executed_interpretation, plan.checkpoint_interpretation)
    _check(
        "candidate_set",
        ",".join(sorted(executed_candidate_ids)),
        ",".join(sorted(plan.candidate_ids)),
    )
    _check("expected_action", executed_action or "", plan.expected_action or "")
    shadow_hitl = plan.hitl_decision == "requires_hitl"
    _check("hitl_decision", str(executed_hitl_required), str(shadow_hitl))
    if executed_risk_levels is not None:
        _check(
            "risk_classification",
            ";".join(f"{key}={value}" for key, value in sorted(executed_risk_levels.items())),
            ";".join(f"{key}={value}" for key, value in sorted(plan.risk_levels.items())),
        )
    return comparison


__all__ = [
    "ShadowComparison",
    "ShadowDivergence",
    "ShadowExecutionForbidden",
    "ShadowHitlDecision",
    "ShadowObservation",
    "ShadowPlan",
    "ShadowPlanner",
    "compare_shadow",
]
