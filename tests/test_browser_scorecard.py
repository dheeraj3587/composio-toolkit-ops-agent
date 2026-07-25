"""Offline tests for the Phase D sandbox accuracy scorecard.

Every test here uses a fake ``NavigationWorker``/``EnricherLike`` — no real
browser, no real provider call, no real credential. This proves the
SCORING and aggregation logic is correct; it is not a substitute for a real
live run against an owned test account (see
``tests/live/test_accuracy_scorecard_live.py``, disabled by default).
"""

from __future__ import annotations

import asyncio
import types

from ops.browser_scorecard import (
    ScorecardReport,
    ScorecardRun,
    classify_run_outcome,
    run_scorecard_for_app,
)
from ops.models import CapabilityAvailability, OperationalResearch


def _baseline(**overrides: object) -> OperationalResearch:
    base: dict[str, object] = {
        "app_name": "Pipedrive",
        "app_slug": "pipedrive",
        "api_available": None,
        "api_type": "REST",
        "api_base_url": None,
        "auth_methods": [],
        "authorization_url": None,
        "token_url": None,
        "credential_fields": [],
        "scopes": [],
        "developer_portal_url": None,
        "signup_url": None,
        "access_route": "unknown",
        "production_approval_required": None,
        "contact_email": None,
        "contact_url": None,
        "evidence_urls": [],
        "confidence": 0.5,
    }
    base.update(overrides)
    return OperationalResearch.model_validate(base)


# ===========================================================================
# classify_run_outcome: pure logic
# ===========================================================================
class TestClassifyRunOutcome:
    def test_credential_page_reached_is_completed(self) -> None:
        assert (
            classify_run_outcome(
                observation_status="credential_page_ready",
                canary_leaked=False,
                off_policy_action_count=0,
                reached_credential_page=True,
                run_raised=False,
            )
            == "completed"
        )

    def test_canary_leak_overrides_a_claimed_success(self) -> None:
        # Even though the observation says credential_page_ready, a canary
        # leak means the run is NOT truthfully a success.
        assert (
            classify_run_outcome(
                observation_status="credential_page_ready",
                canary_leaked=True,
                off_policy_action_count=0,
                reached_credential_page=True,
                run_raised=False,
            )
            == "false_success_suspected"
        )

    def test_off_policy_action_overrides_a_claimed_success(self) -> None:
        assert (
            classify_run_outcome(
                observation_status="credential_page_ready",
                canary_leaked=False,
                off_policy_action_count=1,
                reached_credential_page=True,
                run_raised=False,
            )
            == "false_success_suspected"
        )

    def test_human_action_required_is_hitl(self) -> None:
        assert (
            classify_run_outcome(
                observation_status="human_action_required",
                canary_leaked=False,
                off_policy_action_count=0,
                reached_credential_page=False,
                run_raised=False,
            )
            == "hitl_required"
        )

    def test_blocked_and_failed_pass_through(self) -> None:
        for status, expected in (("blocked", "blocked"), ("failed", "failed")):
            assert (
                classify_run_outcome(
                    observation_status=status,  # type: ignore[arg-type]
                    canary_leaked=False,
                    off_policy_action_count=0,
                    reached_credential_page=False,
                    run_raised=False,
                )
                == expected
            )

    def test_a_raised_run_is_incomplete_not_failed(self) -> None:
        assert (
            classify_run_outcome(
                observation_status=None,
                canary_leaked=False,
                off_policy_action_count=0,
                reached_credential_page=False,
                run_raised=True,
            )
            == "incomplete"
        )

    def test_reaching_the_developer_console_without_credentials_is_incomplete(self) -> None:
        assert (
            classify_run_outcome(
                observation_status="developer_console_ready",
                canary_leaked=False,
                off_policy_action_count=0,
                reached_credential_page=False,
                run_raised=False,
            )
            == "incomplete"
        )


# ===========================================================================
# run_scorecard_for_app: fakes only
# ===========================================================================
def _observation(status: str) -> object:
    return types.SimpleNamespace(
        status=status, current_url="https://app.example.com/x", page_title="X"
    )


class _FakeWorker:
    def __init__(
        self, observation: object | None = None, *, raise_on_navigate: bool = False
    ) -> None:
        self._observation = observation
        self._raise_on_navigate = raise_on_navigate
        self.started = False
        self.stopped = False
        self.stop_calls = 0

    async def start(self, profile_id: str | None) -> object:
        self.started = True
        return types.SimpleNamespace(session_id="s1")

    async def navigate_onboarding(
        self, context: object, research: object, *, sensitive_data=None
    ) -> object:
        if self._raise_on_navigate:
            raise RuntimeError("navigation blew up")
        return self._observation

    async def stop(self, context: object) -> None:
        self.stopped = True
        self.stop_calls += 1


class _FakeEnricher:
    def __init__(
        self, research: OperationalResearch | None = None, *, raise_on_enrich: bool = False
    ) -> None:
        self._research = research
        self._raise = raise_on_enrich

    async def enrich(
        self, *, app_name: str, p1_record: object, baseline: OperationalResearch
    ) -> object:
        if self._raise:
            raise RuntimeError("enrichment blew up")
        return types.SimpleNamespace(
            research=self._research or baseline,
            documents_fetched=3,
            capability=CapabilityAvailability(
                capability="operational_research",
                status="ready",
                reason_code="official_evidence_enriched",
                detail="ok",
            ),
        )


class TestRunScorecardForApp:
    def test_happy_path_is_completed(self) -> None:
        worker = _FakeWorker(_observation("credential_page_ready"))
        enricher = _FakeEnricher()

        run = asyncio.run(
            run_scorecard_for_app(
                app_slug="pipedrive",
                app_name="Pipedrive",
                p1_record={},
                baseline=_baseline(),
                worker=worker,
                enricher=enricher,
                canary_leak_detector=lambda: False,
            )
        )
        assert run.outcome == "completed"
        assert run.reached_credential_page is True
        assert run.canary_observable is True
        assert run.canary_leaked is False
        assert run.documents_fetched == 3
        assert worker.started and worker.stopped

    def test_canary_leak_is_reported_even_on_an_apparent_success(self) -> None:
        worker = _FakeWorker(_observation("credential_page_ready"))
        run = asyncio.run(
            run_scorecard_for_app(
                app_slug="pipedrive",
                app_name="Pipedrive",
                p1_record={},
                baseline=_baseline(),
                worker=worker,
                canary_leak_detector=lambda: True,
            )
        )
        assert run.outcome == "false_success_suspected"
        assert run.canary_leaked is True

    def test_browser_navigation_failure_is_incomplete_and_still_stops_the_session(self) -> None:
        worker = _FakeWorker(raise_on_navigate=True)
        run = asyncio.run(
            run_scorecard_for_app(
                app_slug="pipedrive",
                app_name="Pipedrive",
                p1_record={},
                baseline=_baseline(),
                worker=worker,
            )
        )
        assert run.outcome == "incomplete"
        assert "browser_navigation_raised" in run.notes
        assert worker.stop_calls == 1  # stop() runs even though navigate_onboarding raised

    def test_enrichment_failure_falls_back_to_baseline_and_still_navigates(self) -> None:
        worker = _FakeWorker(_observation("credential_page_ready"))
        enricher = _FakeEnricher(raise_on_enrich=True)
        run = asyncio.run(
            run_scorecard_for_app(
                app_slug="pipedrive",
                app_name="Pipedrive",
                p1_record={},
                baseline=_baseline(),
                worker=worker,
                enricher=enricher,
            )
        )
        assert "enrichment_raised_falling_back_to_baseline" in run.notes
        assert run.outcome == "completed"  # navigation still proceeded on the baseline
        assert worker.started is True

    def test_no_canary_detector_means_unobservable_not_falsely_clean(self) -> None:
        worker = _FakeWorker(_observation("credential_page_ready"))
        run = asyncio.run(
            run_scorecard_for_app(
                app_slug="pipedrive",
                app_name="Pipedrive",
                p1_record={},
                baseline=_baseline(),
                worker=worker,
            )
        )
        assert run.canary_observable is False
        assert run.canary_leaked is False  # the safest reading, but flagged as unobservable above

    def test_hitl_status_is_recorded(self) -> None:
        worker = _FakeWorker(_observation("human_action_required"))
        run = asyncio.run(
            run_scorecard_for_app(
                app_slug="pipedrive",
                app_name="Pipedrive",
                p1_record={},
                baseline=_baseline(),
                worker=worker,
            )
        )
        assert run.hitl_triggered is True
        assert run.outcome == "hitl_required"


# ===========================================================================
# ScorecardReport aggregation
# ===========================================================================
def _run(**overrides: object) -> ScorecardRun:
    fields: dict[str, object] = {
        "app_slug": "x",
        "outcome": "completed",
        "reached_credential_page": True,
        "canary_leaked": False,
        "canary_observable": True,
        "off_policy_action_count": 0,
        "hitl_triggered": False,
        "discovery_provider_used": "official_evidence_enriched",
        "documents_fetched": 2,
        "duration_seconds": 10.0,
    }
    fields.update(overrides)
    return ScorecardRun(**fields)  # type: ignore[arg-type]


class TestScorecardReport:
    def test_aggregation_math(self) -> None:
        report = ScorecardReport(
            runs=(
                _run(app_slug="a", outcome="completed"),
                _run(app_slug="b", outcome="completed"),
                _run(app_slug="c", outcome="false_success_suspected", canary_leaked=True),
                _run(app_slug="d", outcome="hitl_required", hitl_triggered=True),
            )
        )
        assert report.completion_rate == 0.5
        assert report.false_success_rate == 0.25
        assert report.hitl_rate == 0.25
        assert report.canary_leak_count == 1

    def test_release_gate_fails_on_any_canary_leak(self) -> None:
        report = ScorecardReport(runs=(_run(outcome="completed", canary_leaked=True),))
        assert report.release_gate_passed is False

    def test_release_gate_fails_on_empty_run_set(self) -> None:
        assert ScorecardReport(runs=()).release_gate_passed is False

    def test_release_gate_passes_with_zero_leaks_and_majority_completion(self) -> None:
        report = ScorecardReport(
            runs=(
                _run(outcome="completed"),
                _run(outcome="completed"),
                _run(outcome="hitl_required"),
            )
        )
        assert report.release_gate_passed is True

    def test_report_as_dict_is_sanitized(self) -> None:
        report = ScorecardReport(runs=(_run(),))
        payload = report.as_dict()
        assert "release_gate_passed" in payload
        assert isinstance(payload["runs"], list)
        # No credential-shaped keys anywhere in the sanitized payload.
        dumped = str(payload)
        assert "password" not in dumped.casefold()
        assert "secret" not in dumped.casefold()
