"""Phase 4 offline tests: observability, replay, shadow evaluation and canary gates.

These run without Chromium and without a network, so they can live in the ordinary
unit-test job. They cover the parts of Phase 4 whose correctness is about DATA
DISCIPLINE rather than browser behaviour:

* a decision event must be useful for debugging and still carry no secret,
* a replay fixture must reproduce the pipeline and persist no vendor content,
* shadow mode must be structurally incapable of acting, and
* the canary must fail closed on every gate.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ops.browser_canary import (
    CANARY_ENV_VAR,
    FORBIDDEN_CANARY_OPERATIONS,
    INITIAL_CANARY_OBJECTIVE,
    MAX_CONCURRENT_CANARY_SESSIONS,
    ROLLOUT_STAGES,
    CanaryTarget,
    active_stages,
    evaluate_canary_gates,
    production_canary_activated,
    stage,
    validate_canary_operation,
)
from ops.browser_candidates import generate_candidates
from ops.browser_decider import SnapshotElement
from ops.browser_metrics import (
    FORBIDDEN_EVENT_FIELDS,
    BrowserDecisionEvent,
    BrowserRunMetrics,
    assert_sanitized,
    build_decision_event,
    normalize_path,
    page_fingerprint,
)
from ops.browser_replay import (
    FIXTURE_VERSION,
    ReplayFixture,
    ReplayFixtureError,
    candidate_metadata,
    record_step,
    replay_fixture,
    replay_step,
)
from ops.browser_shadow import (
    ShadowExecutionForbidden,
    ShadowObservation,
    ShadowPlanner,
    compare_shadow,
)

# A credential-looking value used to prove it never lands anywhere it must not.
SECRET_TOKEN = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"  # pragma: allowlist secret


def _elements() -> tuple[SnapshotElement, ...]:
    return (
        SnapshotElement(index=0, role="link", name="Developers", href_path="/developers"),
        SnapshotElement(index=1, role="button", name="Save", test_id="save-team"),
        SnapshotElement(
            index=2, role="textbox", name="Password", element_type="password", secretish=True
        ),
        SnapshotElement(index=3, role="button", name="Delete workspace"),
        SnapshotElement(index=4, role="button", name="Hidden thing", visible=False),
    )


# ============================================================== observability
class TestPageFingerprint:
    """A fingerprint must group logical pages without recovering a URL."""

    def test_query_string_and_fragment_are_excluded(self) -> None:
        """A magic-link token in a query must not influence the fingerprint."""

        clean = page_fingerprint("https://app.example/settings/api")
        with_token = page_fingerprint("https://app.example/settings/api?token=SUPERSECRET#frag")
        assert clean == with_token

    def test_identifier_segments_are_collapsed(self) -> None:
        """Two accounts on the same logical page share a fingerprint."""

        first = page_fingerprint("https://app.example/orgs/12345/settings/api")
        second = page_fingerprint("https://app.example/orgs/98765/settings/api")
        assert first == second
        # A genuinely different page does not collide.
        assert first != page_fingerprint("https://app.example/orgs/12345/billing")

    def test_uuid_and_hex_segments_are_collapsed(self) -> None:
        base = "https://app.example/w/{}/api"
        uuid_path = base.format("6f3c1a2e-7b4d-4c1f-9e2a-0b1c2d3e4f50")
        hex_path = base.format("deadbeefcafebabe")
        assert page_fingerprint(uuid_path) == page_fingerprint(hex_path)

    def test_fingerprint_is_opaque_and_bounded(self) -> None:
        value = page_fingerprint("https://app.example/settings/api")
        assert len(value) == 16
        # Nothing recoverable: no host, no path.
        assert "app.example" not in value
        assert "settings" not in value

    def test_malformed_and_empty_urls_are_handled(self) -> None:
        assert page_fingerprint("") == "unknown"
        assert page_fingerprint("not a url") == "unknown"

    def test_normalize_path_keeps_structure(self) -> None:
        assert normalize_path("/Settings/API") == "/settings/api"
        assert normalize_path("") == "/"
        assert normalize_path("/orgs/42/users/7") == "/orgs/:id/users/:id"


class TestDecisionEvent:
    """Events carry structure and outcomes, never content."""

    def test_build_event_fingerprints_the_url_and_stores_no_raw_url(self) -> None:
        event = build_decision_event(
            session_id="pw_1",
            checkpoint_order=2,
            url=f"https://app.example/settings/api?token={SECRET_TOKEN}",
            candidate_ids=("c_aaaaaaaaaaaa", "c_bbbbbbbbbbbb"),
            selected_candidate_id="c_aaaaaaaaaaaa",
            selection_source="llm",
            result_code="postcondition_met",
            latency_ms=812.5,
            inference_provider="openrouter",
            action_type="click",
        )
        serialized = json.dumps(event.as_log_fields())
        # Neither the token nor the URL nor the host may appear.
        assert SECRET_TOKEN not in serialized
        assert "app.example" not in serialized
        assert "settings/api" not in serialized
        assert event.page_fingerprint

    def test_event_field_names_contain_nothing_forbidden(self) -> None:
        event = build_decision_event(
            session_id="pw_1",
            checkpoint_order=1,
            url="https://app.example/login",
            candidate_ids=(),
            selected_candidate_id=None,
            selection_source="deterministic",
            result_code="no_candidates",
            latency_ms=1.0,
        )
        offenders = assert_sanitized(event.as_log_fields().keys())
        assert offenders == ()
        # The guard list itself is meaningful.
        assert "cookies" in FORBIDDEN_EVENT_FIELDS
        assert "prompt" in FORBIDDEN_EVENT_FIELDS

    def test_assert_sanitized_detects_a_forbidden_field(self) -> None:
        """The DLP check is a real check, not a no-op."""

        assert assert_sanitized(["session_id", "cookies", "html"]) == ("cookies", "html")

    def test_event_emits_a_sanitized_structured_line(self) -> None:
        """The emitted line is JSON, carries the event name, and holds no secret.

        The ops logger sets ``propagate = False`` and owns its handler, so this
        attaches to that logger directly rather than relying on ``caplog``.
        """

        import logging

        records: list[logging.LogRecord] = []

        class _Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        logger = logging.getLogger("composio_ops.browser_link")
        handler = _Capture()
        logger.addHandler(handler)
        try:
            build_decision_event(
                session_id="pw_1",
                checkpoint_order=1,
                url=f"https://app.example/login?token={SECRET_TOKEN}",
                candidate_ids=("c_aaaaaaaaaaaa",),
                selected_candidate_id="c_aaaaaaaaaaaa",
                selection_source="deterministic",
                result_code="ok",
                latency_ms=5.0,
            ).emit()
        finally:
            logger.removeHandler(handler)

        assert records, "the decision event emitted nothing"
        message = records[-1].getMessage()
        assert "browser.decision" in message
        # The log line is valid JSON after the prefix, and carries no secret.
        payload = json.loads(message.split(" ", 1)[1])
        assert payload["event"] == "browser.decision"
        assert SECRET_TOKEN not in message
        assert "app.example" not in message


class TestRunMetrics:
    """The 12 metrics, computed from events rather than incremented ad hoc."""

    @staticmethod
    def _event(**overrides: object) -> BrowserDecisionEvent:
        defaults: dict[str, object] = {
            "session_id": "pw_1",
            "checkpoint_order": 1,
            "url": "https://app.example/settings/api",
            "candidate_ids": ("c_aaaaaaaaaaaa",),
            "selected_candidate_id": "c_aaaaaaaaaaaa",
            "selection_source": "deterministic",
            "result_code": "ok",
            "latency_ms": 10.0,
        }
        defaults.update(overrides)
        return build_decision_event(**defaults)  # type: ignore[arg-type]

    def test_undefined_rates_are_zero_not_errors(self) -> None:
        metrics = BrowserRunMetrics()
        snapshot = metrics.snapshot()
        assert snapshot["completion_rate"] == 0.0
        assert snapshot["hitl_rate"] == 0.0
        assert snapshot["deterministic_action_rate"] == 0.0

    def test_completion_and_hitl_rates(self) -> None:
        metrics = BrowserRunMetrics()
        for _ in range(4):
            metrics.record_run_started()
        metrics.record_run_completed(required_hitl=True)
        metrics.record_run_completed(required_hitl=False)
        assert metrics.completion_rate == 0.5
        assert metrics.hitl_rate == 0.25

    def test_deterministic_rate_and_model_calls(self) -> None:
        metrics = BrowserRunMetrics()
        metrics.record_run_started()
        metrics.record(self._event(selection_source="deterministic"))
        metrics.record(self._event(selection_source="deterministic"))
        metrics.record(
            self._event(selection_source="llm", inference_provider="groq", latency_ms=900.0)
        )
        assert metrics.model_calls == 1
        assert metrics.model_calls_per_run == 1.0
        assert metrics.deterministic_action_rate == round(2 / 3, 4)

    def test_checkpoint_retry_rate_counts_revisits(self) -> None:
        metrics = BrowserRunMetrics()
        metrics.record(self._event(checkpoint_order=1))
        metrics.record(self._event(checkpoint_order=1))  # a retry
        metrics.record(self._event(checkpoint_order=2))
        assert metrics.checkpoint_retry_rate == round(1 / 3, 4)

    def test_failure_rates_are_keyed_on_result_codes(self) -> None:
        metrics = BrowserRunMetrics()
        metrics.record(self._event(result_code="stale_target"))
        metrics.record(self._event(result_code="postcondition_failed"))
        metrics.record(self._event(result_code="navigation_blocked"))
        metrics.record(self._event(result_code="ok"))
        assert metrics.stale_target_rate == 0.25
        assert metrics.postcondition_failure_rate == 0.25
        assert metrics.blocked_navigation_rate == 0.25

    def test_session_duration_and_provider_latency_summaries(self) -> None:
        metrics = BrowserRunMetrics()
        for seconds in (10.0, 20.0, 30.0):
            metrics.record_session_duration(seconds)
        metrics.record(
            self._event(selection_source="llm", inference_provider="groq", latency_ms=100.0)
        )
        metrics.record(
            self._event(selection_source="llm", inference_provider="groq", latency_ms=300.0)
        )
        assert metrics.median_session_duration_seconds == 20.0
        summary = metrics.provider_latency_summary()
        assert summary["groq"]["median_ms"] == 200.0
        assert summary["groq"]["max_ms"] == 300.0

    def test_crash_and_capacity_counters(self) -> None:
        metrics = BrowserRunMetrics()
        metrics.record_browser_crash()
        metrics.record_capacity_rejection()
        metrics.record_capacity_rejection()
        snapshot = metrics.snapshot()
        assert snapshot["browser_crashes"] == 1
        assert snapshot["capacity_rejections"] == 2

    def test_snapshot_contains_every_required_metric(self) -> None:
        required = {
            "completion_rate",
            "hitl_rate",
            "model_calls_per_run",
            "deterministic_action_rate",
            "checkpoint_retry_rate",
            "stale_target_rate",
            "postcondition_failure_rate",
            "blocked_navigation_rate",
            "median_session_duration_seconds",
            "browser_crashes",
            "capacity_rejections",
            "inference_provider_latency",
        }
        assert required <= set(BrowserRunMetrics().snapshot())

    def test_snapshot_is_free_of_forbidden_fields(self) -> None:
        assert assert_sanitized(BrowserRunMetrics().snapshot().keys()) == ()


# ===================================================================== replay
class TestReplayFixtures:
    """A fixture reproduces the pipeline and persists no vendor content."""

    @staticmethod
    def _step() -> object:
        elements = _elements()
        candidates = generate_candidates(
            elements=elements,
            checkpoint_signals=("developers",),
            checkpoint_order=1,
            trace_version="2.0",
            expected_postcondition="developer_page",
        )
        return record_step(
            checkpoint_order=1,
            url=f"https://app.example/settings?token={SECRET_TOKEN}",
            elements=elements,
            checkpoint_signals=("developers",),
            trace_version="2.0",
            expected_postcondition="developer_page",
            candidates=candidates,
            selected_candidate_id=candidates[0].candidate_id if candidates else None,
            selection_source="llm",
            result_code="postcondition_met",
            checkpoint_advanced=True,
            predicate_satisfied=True,
        )

    def test_replay_reproduces_candidate_generation_exactly(self) -> None:
        step = self._step()
        result = replay_step(step)  # type: ignore[arg-type]
        assert result.candidates_match
        assert result.candidate_ids == step.candidate_ids  # type: ignore[attr-defined]

    def test_replay_validates_the_recorded_choice(self) -> None:
        step = self._step()
        result = replay_step(step)  # type: ignore[arg-type]
        assert result.selection_valid is True
        assert result.selection_reason == "selection_in_candidate_set"

    def test_replay_rejects_a_selection_outside_the_candidate_set(self) -> None:
        """The choice-validation boundary is exercised by replay too."""

        from dataclasses import replace

        step = replace(self._step(), selected_candidate_id="c_forged000000")  # type: ignore[type-var]
        result = replay_step(step)
        assert result.selection_valid is False
        assert result.selection_reason == "selection_not_in_candidate_set"

    def test_replay_classifies_risk_for_every_candidate(self) -> None:
        step = self._step()
        result = replay_step(step)  # type: ignore[arg-type]
        assert set(result.risk_levels) == set(result.candidate_ids)

    def test_irreversible_control_is_classified_as_such_on_replay(self) -> None:
        elements = _elements()
        candidates = generate_candidates(
            elements=elements,
            checkpoint_signals=("delete",),
            checkpoint_order=1,
            trace_version="2.0",
            expected_postcondition="deleted",
        )
        step = record_step(
            checkpoint_order=1,
            url="https://app.example/settings",
            elements=elements,
            checkpoint_signals=("delete",),
            trace_version="2.0",
            expected_postcondition="deleted",
            candidates=candidates,
            selected_candidate_id=None,
            selection_source="deterministic",
            result_code="requires_hitl",
            checkpoint_advanced=False,
            predicate_satisfied=False,
        )
        result = replay_step(step)
        # "Delete workspace" must never be autonomously executable.
        assert any(level == "irreversible" for level in result.risk_levels.values())

    def test_fixture_round_trips_through_json(self, tmp_path: Path) -> None:
        fixture = ReplayFixture(app_slug="vendor-test", steps=(self._step(),))  # type: ignore[arg-type]
        path = tmp_path / "fixture.json"
        fixture.save(path)
        reloaded = ReplayFixture.load(path)
        assert reloaded.app_slug == "vendor-test"
        assert len(reloaded.steps) == 1
        report = replay_fixture(reloaded)
        assert report.ok, report.summary()

    def test_fixture_persists_no_credential_or_raw_url(self, tmp_path: Path) -> None:
        """The whole point of a sanitized fixture."""

        fixture = ReplayFixture(app_slug="vendor-test", steps=(self._step(),))  # type: ignore[arg-type]
        path = tmp_path / "fixture.json"
        fixture.save(path)
        raw = path.read_text()
        assert SECRET_TOKEN not in raw
        # No raw URL, host, or query string survives.
        assert "app.example" not in raw
        assert "token=" not in raw
        assert "<html" not in raw.casefold()

    def test_fixture_stores_no_element_values(self, tmp_path: Path) -> None:
        """``secretish``/``has_value`` are booleans; the value never appears."""

        elements = (
            SnapshotElement(
                index=0,
                role="textbox",
                name="API token",
                has_value=True,
                secretish=True,
            ),
        )
        step = record_step(
            checkpoint_order=1,
            url="https://app.example/settings/api",
            elements=elements,
            checkpoint_signals=("token",),
            trace_version="2.0",
            expected_postcondition="credential_page",
            candidates=(),
            selected_candidate_id=None,
            selection_source="deterministic",
            result_code="ok",
            checkpoint_advanced=False,
            predicate_satisfied=False,
        )
        path = tmp_path / "fixture.json"
        ReplayFixture(app_slug="vendor-test", steps=(step,)).save(path)
        payload = json.loads(path.read_text())
        element = payload["steps"][0]["elements"][0]
        assert element["has_value"] is True
        assert element["secretish"] is True
        # No field carries the actual content.
        assert "value" not in element

    def test_unsupported_fixture_version_is_refused(self) -> None:
        raw = json.dumps({"version": "0.1", "app_slug": "x", "steps": []})
        with pytest.raises(ReplayFixtureError) as excinfo:
            ReplayFixture.from_json(raw)
        assert excinfo.value.reason_code == "unsupported_fixture_version"

    def test_malformed_fixture_is_refused(self) -> None:
        with pytest.raises(ReplayFixtureError) as excinfo:
            ReplayFixture.from_json("{not json")
        assert excinfo.value.reason_code == "malformed_fixture"
        assert FIXTURE_VERSION == "1.0"

    def test_candidate_metadata_carries_no_selector_or_text(self) -> None:
        candidates = generate_candidates(
            elements=_elements(),
            checkpoint_signals=("developers",),
            checkpoint_order=1,
            trace_version="2.0",
            expected_postcondition="developer_page",
        )
        payload = json.dumps(candidate_metadata(candidates))
        for forbidden in ("input[", "css=", "xpath=", "//", "https://"):
            assert forbidden not in payload


# ===================================================================== shadow
class TestShadowEvaluation:
    """Playwright plans; it cannot act."""

    @staticmethod
    def _observation(**overrides: object) -> ShadowObservation:
        defaults: dict[str, object] = {
            "checkpoint_order": 1,
            "url_path": "/settings",
            "page_title": "Settings",
            "elements": _elements(),
            "checkpoint_signals": ("developers",),
        }
        defaults.update(overrides)
        return ShadowObservation(**defaults)  # type: ignore[arg-type]

    def test_planner_produces_candidates_without_executing(self) -> None:
        plan = ShadowPlanner().plan(self._observation())
        assert plan.candidate_ids
        # The defining property of shadow mode.
        assert plan.executed is False
        assert plan.reason_code == "planned"

    def test_planner_has_no_execution_capability(self) -> None:
        """Structural, not procedural: asking it to act raises."""

        planner = ShadowPlanner()
        with pytest.raises(ShadowExecutionForbidden):
            planner.execute()
        with pytest.raises(ShadowExecutionForbidden):
            planner.type_credential("login_password")

    def test_irreversible_only_page_is_planned_as_requires_hitl(self) -> None:
        observation = self._observation(
            checkpoint_signals=("delete",),
            elements=(SnapshotElement(index=0, role="button", name="Delete workspace"),),
        )
        plan = ShadowPlanner().plan(observation)
        assert plan.hitl_decision == "requires_hitl"
        assert plan.expected_candidate_id is None

    def test_page_with_no_candidates_is_reported_as_no_action(self) -> None:
        plan = ShadowPlanner().plan(self._observation(checkpoint_signals=("nothing matches this",)))
        assert plan.candidate_ids == ()
        assert plan.hitl_decision == "no_action_available"

    def test_checkpoint_interpretation_is_coarse_and_non_secret(self) -> None:
        credential = ShadowPlanner().plan(
            self._observation(url_path="/settings/api", page_title="API")
        )
        login = ShadowPlanner().plan(self._observation(url_path="/login", page_title="Sign in"))
        gate = ShadowPlanner().plan(self._observation(human_action_type="captcha"))
        assert credential.checkpoint_interpretation == "credential_surface"
        assert login.checkpoint_interpretation == "login"
        assert gate.checkpoint_interpretation == "gate:captcha"

    def test_observation_projection_drops_query_strings_and_unknown_fields(self) -> None:
        class _FakeObservation:
            status = "human_action_required"
            current_url = f"https://app.example/settings/api?token={SECRET_TOKEN}"
            page_title = "API"
            human_action_type = "captcha"
            # Must be ignored by the projection.
            cookies = "session=SECRET"
            storage_state = {"cookies": [{"value": SECRET_TOKEN}]}

        projected = ShadowObservation.from_observation(
            _FakeObservation(),
            checkpoint_order=1,
            elements=_elements(),
            checkpoint_signals=("token",),
        )
        assert projected.url_path == "/settings/api"
        serialized = repr(projected)
        assert SECRET_TOKEN not in serialized
        assert "session=SECRET" not in serialized

    def test_comparison_reports_agreement(self) -> None:
        plan = ShadowPlanner().plan(self._observation())
        comparison = compare_shadow(
            plan=plan,
            executed_interpretation=plan.checkpoint_interpretation,
            executed_candidate_ids=plan.candidate_ids,
            executed_action=plan.expected_action,
            executed_hitl_required=False,
            executed_risk_levels=plan.risk_levels,
        )
        assert comparison.agreed is True
        assert "candidate_set" in comparison.agreements

    def test_comparison_reports_each_divergence_dimension(self) -> None:
        plan = ShadowPlanner().plan(self._observation())
        comparison = compare_shadow(
            plan=plan,
            executed_interpretation="something_else",
            executed_candidate_ids=("c_different000",),
            executed_action="goto",
            executed_hitl_required=True,
            executed_risk_levels={"c_different000": "high"},
        )
        assert comparison.agreed is False
        dimensions = {item.dimension for item in comparison.divergences}
        assert dimensions == {
            "checkpoint_interpretation",
            "candidate_set",
            "expected_action",
            "hitl_decision",
            "risk_classification",
        }

    def test_shadow_planning_failure_does_not_propagate(self) -> None:
        """A shadow error must never become a run error."""

        class _Exploding(ShadowPlanner):
            pass

        # An observation whose elements are the wrong type would raise inside
        # generate_candidates; the planner must capture it as a reason code.
        observation = ShadowObservation(
            checkpoint_order=1,
            url_path="/settings",
            page_title="Settings",
            elements=("not an element",),  # type: ignore[arg-type]
            checkpoint_signals=("developers",),
        )
        plan = _Exploding().plan(observation)
        assert plan.reason_code.startswith("shadow_planning_failed")
        assert plan.executed is False


# ===================================================================== canary
class TestCanaryGates:
    """Every gate fails closed; the envelope is enforced in code."""

    def test_no_gates_set_is_refused_and_lists_all_three(self) -> None:
        result = evaluate_canary_gates({})
        assert result.allowed is False
        assert result.reason_code == "canary_gates_not_set"
        assert len(result.missing_gates) == 3

    @pytest.mark.parametrize(
        "env",
        [
            {"ALLOW_LIVE_BROWSER": "true", "BROWSER_PROVIDER": "playwright"},
            {CANARY_ENV_VAR: "1", "BROWSER_PROVIDER": "playwright"},
            {CANARY_ENV_VAR: "1", "ALLOW_LIVE_BROWSER": "true"},
            {
                CANARY_ENV_VAR: "1",
                "ALLOW_LIVE_BROWSER": "true",
                "BROWSER_PROVIDER": "browser_use",
            },
        ],
    )
    def test_any_missing_gate_refuses_the_canary(self, env: dict[str, str]) -> None:
        """Defence in depth: two of three is still refused."""

        assert evaluate_canary_gates(env).allowed is False

    def test_all_three_gates_arm_the_canary(self) -> None:
        result = evaluate_canary_gates(
            {
                CANARY_ENV_VAR: "1",
                "ALLOW_LIVE_BROWSER": "true",
                "BROWSER_PROVIDER": "playwright",
            }
        )
        assert result.allowed is True
        assert result.reason_code == "canary_armed"

    def test_target_defaults_are_pessimistic(self) -> None:
        """An unset assertion must never mean "yes"."""

        result = CanaryTarget(app_slug="pipedrive").validate()
        assert result.allowed is False
        assert "account_is_owned_test_account" in result.missing_gates
        assert "contains_production_data=False" in result.missing_gates

    def test_fully_asserted_target_is_permitted(self) -> None:
        result = CanaryTarget(
            app_slug="pipedrive",
            account_is_owned_test_account=True,
            workspace_is_non_production=True,
            app_is_reviewed=True,
            contains_production_data=False,
        ).validate()
        assert result.allowed is True

    @pytest.mark.parametrize("operation", sorted(FORBIDDEN_CANARY_OPERATIONS))
    def test_every_forbidden_operation_is_refused(self, operation: str) -> None:
        result = validate_canary_operation(operation)
        assert result.allowed is False
        assert result.reason_code == "operation_forbidden_in_canary"

    def test_read_only_actions_are_permitted(self) -> None:
        for action in ("click", "goto", "focus", "scroll_into_view"):
            assert validate_canary_operation(action).allowed is True

    def test_unknown_operation_fails_closed(self) -> None:
        result = validate_canary_operation("some_new_action_nobody_reviewed")
        assert result.allowed is False
        assert result.reason_code == "operation_not_read_only"

    def test_write_actions_are_not_read_only(self) -> None:
        for action in ("fill", "type", "select_option", "upload_file"):
            assert validate_canary_operation(action).allowed is False

    def test_initial_objective_stops_before_credential_reveal(self) -> None:
        assert "reveal" in INITIAL_CANARY_OBJECTIVE.stop_before
        # Revealing a credential is explicitly forbidden, not merely omitted.
        assert validate_canary_operation("reveal_credential").allowed is False
        assert len(INITIAL_CANARY_OBJECTIVE.steps) == 3

    def test_one_concurrent_session_maximum(self) -> None:
        assert MAX_CONCURRENT_CANARY_SESSIONS == 1


class TestRolloutStages:
    """The ladder is reviewable, and stage 5 is not switched on."""

    def test_stages_are_ordered_and_complete(self) -> None:
        assert [item.order for item in ROLLOUT_STAGES] == [0, 1, 2, 3, 4, 5]

    def test_production_canary_is_defined_but_not_activated(self) -> None:
        """The Phase 4 constraint, asserted rather than promised."""

        assert production_canary_activated() is False
        assert stage("stage_5_production_canary").activated is False
        assert "stage_5_production_canary" not in {item.key for item in active_stages()}

    def test_stage_0_and_1_never_contact_a_vendor(self) -> None:
        for key in ("stage_0_local_only", "stage_1_shadow_planning"):
            assert stage(key).live_vendor_contact is False  # type: ignore[arg-type]

    def test_shadow_stage_executes_nothing(self) -> None:
        assert stage("stage_1_shadow_planning").executes_real_actions is False

    def test_live_stages_require_an_owned_test_account(self) -> None:
        for key in (
            "stage_2_read_only_canary",
            "stage_3_login_and_credential_page",
            "stage_4_deterministic_capture",
        ):
            assert stage(key).requires_owned_test_account is True  # type: ignore[arg-type]

    def test_unknown_stage_raises(self) -> None:
        with pytest.raises(KeyError):
            stage("stage_99_does_not_exist")  # type: ignore[arg-type]


class TestProviderDefaultUnchanged:
    """Phase 4 must not flip the production default."""

    def test_browser_provider_still_defaults_to_browser_use(self) -> None:
        from ops.config import Settings

        field = Settings.model_fields["browser_provider"]
        assert field.default == "browser_use"
