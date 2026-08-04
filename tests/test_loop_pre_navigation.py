"""The loop must not deny its own blank tab before it has navigated anywhere.

A fresh Playwright session opens on ``about:blank``, and the loop's first
``observe`` runs before any navigation. ``evaluate_navigation`` refuses that URL
because no app allow-list contains it, so the "where we actually are" check at
``action_loop.py`` used to return ``denied_fatal`` on iteration one — for every
app, before a single candidate was generated. The reviewed ``goto`` candidate that
would have navigated to the real signup page never got the chance to run.

The exemption is deliberately the narrowest thing that works, and these tests pin
both halves of that narrowness:

* EXACT string match, never the reason code and never an ``about:`` prefix. Every
  refused URL shape shares the one code ``browser_url_not_https_or_malformed``, so
  the code says nothing about whether a URL is safe. ``data:``, ``file://``,
  ``chrome://`` and ``""`` turn out to be refused even earlier, by
  ``sanitize_browser_url`` inside ``BrowserObservation`` — but ``about:srcdoc``
  passes that sanitizer, shares the reason code, and carries attacker-controlled
  inline HTML. It alone makes exact matching load-bearing, and it is also what
  rules out a prefix test.
* Only while ``actions == 0``. A page that goes blank *after* the session has acted
  is a session that lost its page, and planning against it must still be fatal.

The per-candidate navigation check ("where we may GO") is a separate boundary and
is asserted here to remain strict.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence

import pytest

from ops.browser.candidates import ActionCandidate
from ops.browser.host_policy import BrowserAllowedHosts, evaluate_navigation
from ops.browser.worker import BrowserObservation
from ops.onboarding.action_loop import (
    LoopBudget,
    LoopObservation,
    PhaseGoal,
    run_action_loop,
)

_ALLOWED = BrowserAllowedHosts(
    app_slug="resend",
    exact_hosts=("resend.com",),
    vendor_wildcard_domains=("resend.com",),
)
_SIGNUP_URL = "https://resend.com/signup"

# Refused by ``evaluate_navigation`` under the SAME reason code as ``about:blank``,
# AND constructible as an observation URL — so this is what can actually reach the
# "where we are" check and be wrongly admitted. ``about:srcdoc`` is the whole reason
# the predicate must be an exact string match: it survives ``sanitize_browser_url``
# and it carries attacker-controlled inline HTML.
_REACHES_THE_CHECK_WITH_THE_SAME_REASON_CODE = ("about:srcdoc",)

# Refused EARLIER, by ``sanitize_browser_url`` inside ``BrowserObservation``, so they
# can never reach the loop at all. Asserted separately below, because "blocked one
# layer earlier" is a stronger guarantee than "blocked at the loop".
_REFUSED_AT_OBSERVATION_CONSTRUCTION = (
    "",
    "chrome://settings",
    "data:text/html,<h1>x",
    "file:///etc/passwd",
)


class _BlankThenSignup:
    """Opens blank, then reports the signup page once a ``goto`` has executed."""

    def __init__(self, *, blank_url: str = "about:blank") -> None:
        self.acted: list[ActionCandidate] = []
        self._blank_url = blank_url

    async def observe(self) -> LoopObservation:
        if self.acted:
            return LoopObservation(
                observation=BrowserObservation(
                    status="navigating",
                    current_url=_SIGNUP_URL,
                    page_title="Sign up · Resend",
                ),
            )
        return LoopObservation(
            observation=BrowserObservation(
                status="navigating",
                current_url=self._blank_url,
                # A pre-navigation page has no title of its own; the seam
                # substitutes a fixed label rather than emitting an empty one.
                page_title="Untitled page",
            ),
        )

    async def act(self, candidate: ActionCandidate) -> None:
        self.acted.append(candidate)


class _BlankAfterActing:
    """Navigates once, then loses its page — blank in the STEADY state."""

    def __init__(self) -> None:
        self.acted: list[ActionCandidate] = []

    async def observe(self) -> LoopObservation:
        if self.acted:
            return LoopObservation(
                observation=BrowserObservation(
                    status="navigating",
                    current_url="about:blank",
                    page_title="Untitled page",
                ),
            )
        return LoopObservation(
            observation=BrowserObservation(
                status="navigating",
                current_url=_SIGNUP_URL,
                page_title="Sign up · Resend",
            ),
            raw_elements=(
                {"role": "button", "name": "Sign up", "visible": True, "enabled": True},
            ),
        )

    async def act(self, candidate: ActionCandidate) -> None:
        self.acted.append(candidate)


class _Decider:
    def __init__(self) -> None:
        self.prompts: list[str] = []

    async def choose(self, prompt: str, *, schema: Mapping[str, object]) -> Mapping[str, object]:
        self.prompts.append(prompt)
        properties = schema["properties"]
        assert isinstance(properties, Mapping)
        candidate_id = properties["candidate_id"]
        assert isinstance(candidate_id, Mapping)
        ids = candidate_id["enum"]
        assert isinstance(ids, Sequence)
        return {"decision": "select_candidate", "candidate_id": ids[0], "reason": "open signup"}


class _Telemetry:
    def __init__(self) -> None:
        self.denials: list[str] = []
        self.rejects: list[str] = []
        self.dlp_refusals = 0

    def denial(self, reason_code: str) -> None:
        self.denials.append(reason_code)

    def reject(self, reason_code: str) -> None:
        self.rejects.append(reason_code)

    def dlp_refusal(self) -> None:
        self.dlp_refusals += 1

    def action(self, *, candidate_id: str, actions_executed: int) -> None:
        return None

    def model_call(self, *, model_calls: int) -> None:
        return None

    def progress(self, *, step_index: int, stage: str, elapsed_ms: int) -> None:
        return None


def _signup_goal() -> PhaseGoal:
    return PhaseGoal.for_phase(
        "signup",
        provider_name="Resend",
        description="Create an account so an API key can be generated.",
        instruction="Open the signup page and create an account.",
        success_reason_code="signup_submitted",
        reviewed_goto_urls=(_SIGNUP_URL,),
    )


def _run(session: object, *, telemetry: _Telemetry | None = None) -> object:
    return asyncio.run(
        run_action_loop(
            phase="signup",
            goal=_signup_goal(),
            session=session,  # type: ignore[arg-type]
            allowed=_ALLOWED,
            budget=LoopBudget(),
            decider=_Decider(),
            telemetry=telemetry or _Telemetry(),
            sleep=_no_sleep,
        )
    )


async def _no_sleep(_seconds: float) -> None:
    """Keep backoff from making these tests wall-clock bound."""


def test_a_pre_navigation_blank_page_does_not_end_the_run() -> None:
    """The regression: iteration one used to return ``denied_fatal``."""

    session = _BlankThenSignup()
    telemetry = _Telemetry()
    result = _run(session, telemetry=telemetry)

    assert result.outcome != "denied_fatal"  # type: ignore[attr-defined]
    # It did not merely survive — it navigated, via the reviewed goto candidate.
    # Only the FIRST action is pinned: this fake never satisfies the signup
    # postconditions, so the loop legitimately keeps trying until a budget stops it.
    assert session.acted, "the loop must reach its first action"
    assert session.acted[0].action == "goto"
    assert session.acted[0].url == _SIGNUP_URL
    # Admitting the blank tab is not a denial, so nothing is counted against the
    # navigation-denial budget.
    assert telemetry.denials == []


def test_a_blank_page_after_acting_is_still_fatal() -> None:
    """The steady state must not be widened: a lost page stops the run."""

    session = _BlankAfterActing()
    telemetry = _Telemetry()
    result = _run(session, telemetry=telemetry)

    assert result.outcome == "denied_fatal"  # type: ignore[attr-defined]
    assert result.reason_code == "browser_url_not_https_or_malformed"  # type: ignore[attr-defined]
    # The session HAD acted, which is exactly what makes this fatal rather than
    # the pre-navigation case above.
    assert len(session.acted) == 1
    assert telemetry.denials == ["browser_url_not_https_or_malformed"]


@pytest.mark.parametrize("url", _REACHES_THE_CHECK_WITH_THE_SAME_REASON_CODE)
def test_only_the_blank_page_is_admitted_not_other_about_urls(url: str) -> None:
    """``data:``, ``file://``, ``chrome://`` and ``about:srcdoc`` stay fatal.

    These are the URLs a reason-code check would have let through: each is refused
    by ``evaluate_navigation`` under the identical code as ``about:blank``.
    """

    session = _BlankThenSignup(blank_url=url)
    result = _run(session)

    assert result.outcome == "denied_fatal"  # type: ignore[attr-defined]
    assert session.acted == []


@pytest.mark.parametrize(
    "url",
    [
        "about:blank",
        *_REACHES_THE_CHECK_WITH_THE_SAME_REASON_CODE,
        *_REFUSED_AT_OBSERVATION_CONSTRUCTION,
        "about:blank#x",
    ],
)
def test_the_shared_reason_code_is_why_exact_matching_is_required(url: str) -> None:
    """Pins the premise of the fix, so a future refactor cannot silently break it.

    If these ever stop sharing one reason code, the exact-match requirement can be
    revisited; while they do share it, the reason code carries no information about
    whether a URL is safe to admit.
    """

    decision = evaluate_navigation(url, _ALLOWED)
    assert decision.allowed is False
    assert decision.reason_code == "browser_url_not_https_or_malformed"


def test_a_disallowed_https_host_is_never_admitted_pre_navigation() -> None:
    """The exemption covers ABSENCE of a location, not a wrong location."""

    session = _BlankThenSignup(blank_url="https://evil.example.com/signup")
    result = _run(session)

    assert result.outcome == "denied_fatal"  # type: ignore[attr-defined]
    assert result.reason_code == "browser_host_not_in_app_policy"  # type: ignore[attr-defined]
    assert session.acted == []
