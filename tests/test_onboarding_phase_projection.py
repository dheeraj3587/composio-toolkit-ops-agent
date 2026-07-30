"""The phase → run-status projection: total, pinned, and a pure function of two inputs.

``project_status`` is the single authority for a run's coarse, externally visible
status (Requirement 12.7). Two claims are worth testing separately, because they
fail in different ways.

*Total* means every one of the 17 phases has an answer for both values of the
credential-ready flag, and that the answer comes from an exhaustive table rather
than a default. A silent default would let a newly added phase project onto some
plausible-looking status instead of failing loudly, so the mapping raising on a
non-member is asserted here on purpose.

*Depends on nothing else* is the more interesting claim: the result is a function
of ``(phase, credential_ready)`` and of no clock, attempt counter, provider state,
or accumulated module state. That is asserted three ways — behaviourally (repeated
and reordered calls agree), at the signature (there is no third input to pass), and
structurally (the function body reads exactly the two module tables and nothing
else, so a clock read would show up here).

The design's phase → status table is duplicated below rather than imported.
Duplication is the point: a silent retargeting of one phase, of the kind that would
have the console show ``failed`` where the design says ``waiting_for_hitl``, has to
be argued for against the pinned table instead of passing quietly.

_Requirements: 12.7, 12.8_
"""

from __future__ import annotations

import inspect
import itertools
import random
from typing import get_args

import pytest

from ops.core.state import _LEGAL_STATUS_TRANSITIONS, RunStatus
from ops.onboarding.phase import (
    _CREDENTIAL_READY_PHASES,
    _PHASE_STATUS,
    ONBOARDING_PHASES,
    OnboardingPhase,
    project_status,
)

_RUN_STATUSES: frozenset[str] = frozenset(get_args(RunStatus))

# Pinned from design.md, "Mapping onto the existing run-status machine" and LL-1.1.
_DESIGN_PHASE_STATUS: dict[OnboardingPhase, RunStatus] = {
    "research": "researching",
    "vault_check": "researching",
    "awaiting_admission": "waiting_for_hitl",
    "route_selected_login": "route_selected",
    "route_selected_signup": "route_selected",
    "signup": "browser_running",
    "email_verification": "browser_running",
    "authenticated": "browser_running",
    "developer_app": "browser_running",
    "credential_generation": "browser_running",
    "vault_storage": "browser_running",
    "credential_validation": "browser_running",
    "captcha_paused": "waiting_for_hitl",
    "completed": "completed",
    "paused": "waiting_for_hitl",
    "blocked": "blocked",
    # A cancelled run is externally indistinguishable from a blocked one; only the
    # phase keeps the distinction.
    "cancelled": "blocked",
}

# The one conditional in the whole projection (Requirement 12.8). Pinned separately
# so widening it to a third phase fails here.
_CREDENTIAL_READY_LIFT: frozenset[OnboardingPhase] = frozenset(
    {"vault_storage", "credential_validation"}
)

# The full input space: 17 phases × both flag values.
_GRID: tuple[tuple[OnboardingPhase, bool], ...] = tuple(
    itertools.product(ONBOARDING_PHASES, (False, True))
)

# The only module globals the projection is permitted to read. A clock, a settings
# lookup, or a provider-state read would add a name here and fail the test.
_PERMITTED_GLOBAL_READS = frozenset({"_PHASE_STATUS", "_CREDENTIAL_READY_PHASES"})


def test_phase_tuple_is_derived_from_the_literal() -> None:
    """The 17 phases of Requirement 12.1, enumerated without re-typing the type."""

    assert ONBOARDING_PHASES == get_args(OnboardingPhase)
    assert len(ONBOARDING_PHASES) == 17
    assert len(set(ONBOARDING_PHASES)) == 17


def test_status_table_matches_the_design_table() -> None:
    """The table itself is pinned, so a retargeted phase cannot land silently."""

    assert _PHASE_STATUS == _DESIGN_PHASE_STATUS


@pytest.mark.parametrize("phase", ONBOARDING_PHASES)
def test_projection_matches_the_design_table(phase: OnboardingPhase) -> None:
    assert project_status(phase) == _DESIGN_PHASE_STATUS[phase]
    assert project_status(phase, credential_ready=False) == _DESIGN_PHASE_STATUS[phase]


@pytest.mark.parametrize(("phase", "credential_ready"), _GRID)
def test_projection_is_total_and_returns_a_run_status(
    phase: OnboardingPhase, credential_ready: bool
) -> None:
    """Requirement 12.7: every (phase, flag) pair has an answer, and it is a RunStatus."""

    assert project_status(phase, credential_ready=credential_ready) in _RUN_STATUSES


def test_totality_is_exhaustive_and_not_a_default() -> None:
    """A phase absent from the table raises rather than projecting a plausible guess."""

    assert set(_PHASE_STATUS) == set(ONBOARDING_PHASES)
    with pytest.raises(KeyError):
        project_status("not_a_phase")  # type: ignore[arg-type]


def test_credential_ready_lift_covers_exactly_two_phases() -> None:
    assert _CREDENTIAL_READY_PHASES == _CREDENTIAL_READY_LIFT
    assert isinstance(_CREDENTIAL_READY_PHASES, frozenset)


@pytest.mark.parametrize("phase", ONBOARDING_PHASES)
def test_credentials_ready_is_reachable_only_from_the_two_credential_phases(
    phase: OnboardingPhase,
) -> None:
    """Requirement 12.8: the flag lifts vault_storage and credential_validation, nothing else."""

    lifted = project_status(phase, credential_ready=True)
    if phase in _CREDENTIAL_READY_LIFT:
        assert lifted == "credentials_ready"
    else:
        assert lifted == project_status(phase, credential_ready=False)
        assert lifted != "credentials_ready"


def test_credentials_ready_is_unreachable_without_the_flag() -> None:
    assert all(project_status(phase) != "credentials_ready" for phase in ONBOARDING_PHASES)


def test_projection_image_is_the_seven_statuses_the_walk_uses() -> None:
    """No phase projects onto a status the onboarding walk never occupies."""

    image = {project_status(phase, credential_ready=flag) for phase, flag in _GRID}
    assert image == {
        "researching",
        "route_selected",
        "browser_running",
        "waiting_for_hitl",
        "credentials_ready",
        "completed",
        "blocked",
    }
    assert "failed" not in image


@pytest.mark.parametrize("phase", sorted(_CREDENTIAL_READY_LIFT))
def test_the_lift_is_representable_in_the_run_status_machine(phase: OnboardingPhase) -> None:
    """Structural backing: the unlifted status can legally advance to the lifted one.

    The conditional would be unprojectable if ``ops.core.state`` refused the edge, so the
    lift is checked against the existing status table rather than assumed.
    """

    unlifted = project_status(phase, credential_ready=False)
    assert project_status(phase, credential_ready=True) == "credentials_ready"
    assert "credentials_ready" in _LEGAL_STATUS_TRANSITIONS[unlifted]


def test_repeated_calls_agree() -> None:
    """No accumulated state: the fifth call answers like the first."""

    for phase, flag in _GRID:
        results = {project_status(phase, credential_ready=flag) for _ in range(5)}
        assert len(results) == 1


def test_call_order_does_not_change_any_result() -> None:
    """No cross-call state: a shuffled traversal reproduces the ordered one."""

    ordered = {(phase, flag): project_status(phase, credential_ready=flag) for phase, flag in _GRID}
    shuffled = list(_GRID)
    random.Random(0).shuffle(shuffled)
    for phase, flag in shuffled:
        assert project_status(phase, credential_ready=flag) == ordered[(phase, flag)]


def test_projection_leaves_module_state_unchanged() -> None:
    """Exercising the whole grid mutates neither table."""

    status_before = dict(_PHASE_STATUS)
    lift_before = set(_CREDENTIAL_READY_PHASES)
    for phase, flag in _GRID:
        project_status(phase, credential_ready=flag)
    assert dict(_PHASE_STATUS) == status_before
    assert set(_CREDENTIAL_READY_PHASES) == lift_before


def test_projection_admits_no_third_input() -> None:
    """There is nowhere to pass a clock, an attempt number, or a provider state."""

    parameters = inspect.signature(project_status).parameters
    assert list(parameters) == ["phase", "credential_ready"]
    assert parameters["phase"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert parameters["phase"].default is inspect.Parameter.empty
    assert parameters["credential_ready"].kind is inspect.Parameter.KEYWORD_ONLY
    assert parameters["credential_ready"].default is False

    with pytest.raises(TypeError):
        project_status("research", True)  # type: ignore[misc]


def test_projection_reads_nothing_but_the_two_tables() -> None:
    """Structural backing for "depends on nothing else".

    The names a function body loads from module scope are visible on its code
    object. Restricting them to the two tables is what makes "no clock, no attempt
    counter, no provider state" checkable rather than a comment.
    """

    code = project_status.__code__
    assert set(code.co_names) <= _PERMITTED_GLOBAL_READS
    assert "_PHASE_STATUS" in code.co_names
    assert code.co_freevars == ()
    assert project_status.__closure__ is None
