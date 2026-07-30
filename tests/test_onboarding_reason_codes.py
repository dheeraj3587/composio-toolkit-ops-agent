"""The onboarding reason vocabulary: closed, unique, and API-projectable.

A reason code is the whole explanation an operator gets for a paused, blocked, or
retried run, so two things have to hold at once. The list must stay *closed* —
derived from the ``Literal`` rather than re-typed, with no duplicate member — and
every member must satisfy the character class ``api.models.ReasonCode`` enforces,
because there is no translation layer between the two. A code that failed the
pattern would surface as a 500 at the projection boundary, not as a lint error.

The split between ``flow_unsupported`` and ``capture_spec_unavailable`` is
asserted here as well: it is the point of the vocabulary that a provider which
offers no drivable flow (Requirement 9.10) is distinguishable from a contract
this side could not construct (Requirement 10.11 and the missing-``entry_url``
capture path), and a single overloaded code would erase that distinction.
"""

from __future__ import annotations

from typing import get_args

import pytest
from pydantic import TypeAdapter, ValidationError

from api.models import ReasonCode
from ops.onboarding.phase import (
    ONBOARDING_REASON_CODES,
    REASON_CODE_PATTERN,
    OnboardingReasonCode,
)

_API_REASON_CODE: TypeAdapter[str] = TypeAdapter(ReasonCode)

# The two codes whose separation this module exists to protect.
_SPLIT_CODES = ("flow_unsupported", "capture_spec_unavailable")


def test_reason_codes_are_derived_from_the_literal() -> None:
    """The exported tuple cannot drift from the type it claims to enumerate."""

    assert ONBOARDING_REASON_CODES == get_args(OnboardingReasonCode)
    assert len(ONBOARDING_REASON_CODES) > 0


def test_reason_codes_are_unique() -> None:
    assert len(set(ONBOARDING_REASON_CODES)) == len(ONBOARDING_REASON_CODES)


def test_every_reason_code_matches_the_checked_pattern() -> None:
    for code in ONBOARDING_REASON_CODES:
        assert REASON_CODE_PATTERN.match(code) is not None, code


def test_every_reason_code_projects_to_the_api_without_translation() -> None:
    """Requirement 20.2: the API accepts each code as written."""

    for code in ONBOARDING_REASON_CODES:
        assert _API_REASON_CODE.validate_python(code) == code


def test_local_pattern_is_the_api_pattern_and_not_a_looser_one() -> None:
    """Guard against the local pattern drifting into a vacuous check."""

    for rejected in ("Flow Unsupported", "flow unsupported", "_flow_unsupported", "", "a" * 65):
        assert REASON_CODE_PATTERN.match(rejected) is None, rejected
        with pytest.raises(ValidationError):
            _API_REASON_CODE.validate_python(rejected)


@pytest.mark.parametrize("code", _SPLIT_CODES)
def test_split_codes_are_both_members_of_the_closed_list(code: str) -> None:
    """Requirements 9.10 and 10.11 name two distinct pauses, so both codes exist."""

    assert code in ONBOARDING_REASON_CODES


def test_split_codes_are_distinct() -> None:
    assert len(set(_SPLIT_CODES)) == 2
