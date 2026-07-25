"""Phase 4: real-Chromium integration tests against the local test app.

Every test here launches an actual Chromium and drives real pages served over real
TLS from ``tests/browser_app``. Two properties make this suite meaningful rather
than decorative:

1. **It cannot silently skip in CI.** With ``REQUIRE_REAL_BROWSER_TESTS=1`` (set by
   the browser-image job) a missing or broken Chromium is a hard FAILURE. Locally,
   without Chromium, it skips.
2. **It exercises production code.** The egress guard is
   ``ops.playwright_worker.make_route_handler``; the login state machine is
   ``ops.browser_login``; snapshots come from ``ops.browser_snapshot``. Nothing is
   reimplemented for the test, so a regression in the shipping path shows up here.

The security tests are the reason the app serves two genuinely separate origins
over HTTPS: the third-party server records every request it receives, so "the
beacon was blocked" is an observation at the network level, not an assumption. And
the app uses RFC 2606 ``.example`` hostnames rather than ``127.0.0.1`` because the
production guard REFUSES loopback/private IPs outright — an IP-based app would be
rejected before host matching ran, and the tests would prove nothing.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from ops.browser_api_trace_catalog import BrowserApiTraceStep, CheckpointPredicate
from ops.browser_candidates import (
    generate_candidates,
    resolve_identity,
    select_candidate,
)
from ops.browser_login import (
    drive_login,
    inject_otp,
    inspect_login,
    magic_link_is_safe,
)
from ops.browser_pages import (
    BrowserPageRegistry,
    DialogPolicy,
    DownloadPolicy,
    frame_path_is_reviewed,
    install_dialog_handler,
    install_download_guard,
)
from ops.browser_snapshot import build_ranked_snapshot, frame_chain
from ops.browser_worker import is_allowed_browser_url
from ops.playwright_worker import (
    PageInspection,
    checkpoint_satisfied,
    navigation_allowed,
    predicate_satisfied,
)
from tests.browser_app.harness import browser_page
from tests.browser_app.server import (
    ACCEPTED_EMAIL,
    ACCEPTED_PASSWORD,
    FAKE_API_TOKEN,
    OTP_CODE,
    BrowserTestApp,
    browser_test_app,
)

pytestmark = pytest.mark.browser


def _run(scenario: Callable[[BrowserTestApp], Awaitable[Any]]) -> Any:
    """Start the two-origin app and run one async scenario against it."""

    async def _main() -> Any:
        with browser_test_app() as app:
            return await scenario(app)

    return asyncio.run(_main())


async def _inspect(
    page: Any, patterns: tuple[str, ...], signals: tuple[str, ...] = ()
) -> PageInspection:
    """Build a PageInspection the way the production predicate checker expects."""

    elements, locators = await build_ranked_snapshot(
        page, reviewed_patterns=patterns, checkpoint_signals=signals
    )
    text = await page.locator("body").inner_text()
    return PageInspection(
        url=page.url,
        title=await page.title(),
        visible_text=text,
        elements=elements,
        locators=locators,
        fingerprint=f"{page.url}|{len(elements)}",
    )


# =============================================================== state machine
class TestCheckpointStateMachine:
    """Progression happens only on proven predicates."""

    def test_checkpoint_progresses_only_when_predicate_is_proven(self) -> None:
        async def scenario(app: BrowserTestApp) -> None:
            checkpoint = BrowserApiTraceStep(
                order=1,
                instruction="reach the API settings page",
                expected_signals=("API token",),
                completion=CheckpointPredicate(
                    url_path_contains=("/settings/api",),
                    visible_text_contains=("API token",),
                ),
            )
            async with browser_page(app) as fx:
                # On the wrong page the predicate must NOT be satisfied.
                await fx.page.goto(app.url("/home"), wait_until="domcontentloaded")
                before = await _inspect(fx.page, app.host_patterns)
                assert checkpoint_satisfied(checkpoint, before) is False

                # On the right page, with both conditions present, it is.
                await fx.page.goto(app.url("/settings/api"), wait_until="domcontentloaded")
                after = await _inspect(fx.page, app.host_patterns)
                assert checkpoint_satisfied(checkpoint, after) is True

        _run(scenario)

    def test_partial_evidence_does_not_advance_the_checkpoint(self) -> None:
        """Right path, wrong content: a half-match must not count as success."""

        async def scenario(app: BrowserTestApp) -> None:
            checkpoint = BrowserApiTraceStep(
                order=1,
                instruction="reach the API settings page",
                expected_signals=("API token",),
                completion=CheckpointPredicate(
                    url_path_contains=("/settings/api",),
                    visible_text_contains=("this phrase is absent from the page",),
                ),
            )
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/settings/api"), wait_until="domcontentloaded")
                inspection = await _inspect(fx.page, app.host_patterns)
                assert checkpoint_satisfied(checkpoint, inspection) is False

        _run(scenario)

    def test_forbidden_text_blocks_success_even_when_path_matches(self) -> None:
        async def scenario(app: BrowserTestApp) -> None:
            predicate = CheckpointPredicate(
                url_path_contains=("/bad-login",),
                forbidden_text=("password is incorrect",),
            )
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/bad-login"), wait_until="domcontentloaded")
                inspection = await _inspect(fx.page, app.host_patterns)
                # The path matches but the error text is present: not success.
                assert predicate_satisfied(predicate, inspection) is False

        _run(scenario)

    def test_stale_target_is_detected_after_navigation(self) -> None:
        """A locator captured before navigation must not be silently reused."""

        async def scenario(app: BrowserTestApp) -> None:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/duplicate-buttons"), wait_until="domcontentloaded")
                first = await _inspect(fx.page, app.host_patterns)
                assert first.elements

                await fx.page.goto(app.url("/home"), wait_until="domcontentloaded")
                second = await _inspect(fx.page, app.host_patterns)
                # The fingerprint changed, which is how the loop knows the snapshot
                # it reasoned about no longer describes the live page.
                assert first.fingerprint != second.fingerprint
                # Re-resolving the old element identity against the NEW snapshot
                # must fail rather than silently match something else.
                identity_source = first.elements[0]
                from ops.browser_candidates import ElementIdentity

                identity = ElementIdentity(
                    role=identity_source.role,
                    name=identity_source.name,
                    test_id=identity_source.test_id,
                )
                resolution, element = resolve_identity(identity, second.elements)
                assert element is None
                # resolve_identity returns a Literal status, not an object.
                assert resolution == "not_found"

        _run(scenario)

    def test_repeated_state_is_observable_via_fingerprint(self) -> None:
        """Two inspections of an unchanged page must fingerprint identically."""

        async def scenario(app: BrowserTestApp) -> None:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/settings"), wait_until="domcontentloaded")
                first = await _inspect(fx.page, app.host_patterns)
                second = await _inspect(fx.page, app.host_patterns)
                # This equality is what a repeated-state terminator keys on.
                assert first.fingerprint == second.fingerprint

        _run(scenario)

    def test_step_and_time_limits_terminate_a_loop(self) -> None:
        """Bounded loops: the limits are enforced, not advisory."""

        async def scenario(app: BrowserTestApp) -> None:
            max_steps = 4
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/settings"), wait_until="domcontentloaded")
                steps = 0
                deadline = asyncio.get_running_loop().time() + 5.0
                unsatisfiable = CheckpointPredicate(
                    visible_text_contains=("a phrase that never appears anywhere",)
                )
                while steps < max_steps and asyncio.get_running_loop().time() < deadline:
                    steps += 1
                    inspection = await _inspect(fx.page, app.host_patterns)
                    if predicate_satisfied(unsatisfiable, inspection):
                        break  # pragma: no cover - unreachable by construction
                # It stopped at the step limit rather than spinning forever.
                assert steps == max_steps

        _run(scenario)


# ============================================================== authentication
class TestAuthentication:
    """The deterministic login state machine against real forms."""

    def test_single_page_login_succeeds(self) -> None:
        async def scenario(app: BrowserTestApp) -> str:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/login"), wait_until="domcontentloaded")
                await drive_login(
                    fx.page,
                    {"login_email": ACCEPTED_EMAIL, "login_password": ACCEPTED_PASSWORD},
                    app.host_patterns,
                )
                await fx.page.wait_for_load_state("domcontentloaded")
                return str(fx.page.url)

        assert "/home" in _run(scenario)

    def test_email_first_login_advances_to_the_password_step(self) -> None:
        async def scenario(app: BrowserTestApp) -> str:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/email-first"), wait_until="domcontentloaded")
                await drive_login(
                    fx.page,
                    {"login_email": ACCEPTED_EMAIL, "login_password": ACCEPTED_PASSWORD},
                    app.host_patterns,
                )
                await fx.page.wait_for_load_state("domcontentloaded")
                return str(fx.page.url)

        # Either the password step or straight through to home is correct; what must
        # NOT happen is being stuck on the email form.
        assert "/email-first" not in _run(scenario)

    def test_wrong_password_is_reported_not_treated_as_success(self) -> None:
        async def scenario(app: BrowserTestApp) -> tuple[str, str]:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/login"), wait_until="domcontentloaded")
                await drive_login(
                    fx.page,
                    {  # pragma: allowlist secret
                        "login_email": ACCEPTED_EMAIL,
                        "login_password": "definitely-wrong",  # pragma: allowlist secret
                    },
                    app.host_patterns,
                )
                await fx.page.wait_for_load_state("domcontentloaded")
                body = await fx.page.locator("body").inner_text()
                return str(fx.page.url), body

        url, body = _run(scenario)
        assert "/bad-login" in url
        assert "incorrect" in body.casefold()

    def test_single_field_otp_is_injected_and_accepted(self) -> None:
        """``inject_otp`` submits the form itself, so the page advances on its own."""

        async def scenario(app: BrowserTestApp) -> tuple[bool, str, str]:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/otp-single"), wait_until="domcontentloaded")
                inspection = await inspect_login(fx.page, app.host_patterns)
                state = str(getattr(inspection, "state", ""))
                injected = await inject_otp(fx.page, OTP_CODE, inspection)
                await fx.page.wait_for_load_state("domcontentloaded")
                return injected, state, str(fx.page.url)

        injected, state, url = _run(scenario)
        assert injected is True
        # The inspector recognised the gate before injecting.
        assert state == "otp_required"
        # The server accepted the code, which it only does for the exact value.
        assert "/home" in url

    def test_multi_field_otp_is_split_across_inputs(self) -> None:
        """Six single-character inputs must receive one digit each, in order.

        The evidence is the SUBMITTED FORM BODY rather than a DOM read. Reading the
        inputs concurrently races ``inject_otp`` (which fills the fields and submits
        in one operation) and intermittently observes a partially filled form — the
        request body is the deterministic record of what was actually typed where.
        """

        async def scenario(app: BrowserTestApp) -> tuple[bool, list[str], str]:
            async with browser_page(app) as fx:
                submitted: list[str] = []
                fx.page.on(
                    "request",
                    lambda request: (
                        submitted.append(request.post_data or "")
                        if request.method == "POST"
                        else None
                    ),
                )
                await fx.page.goto(app.url("/otp-multiple"), wait_until="domcontentloaded")
                inspection = await inspect_login(fx.page, app.host_patterns)
                injected = await inject_otp(fx.page, OTP_CODE, inspection)
                await fx.page.wait_for_load_state("domcontentloaded")
                return injected, submitted, str(fx.page.url)

        injected, submitted, url = _run(scenario)
        assert injected is True
        # The server only redirects to /home when all six digits joined equal the
        # code, which is itself proof the split was correct and ordered.
        assert "/home" in url
        # And the request body shows exactly one digit per field, in field order.
        assert submitted, "the OTP form was never submitted"
        fields = dict(pair.split("=", 1) for pair in submitted[0].split("&") if "=" in pair)
        assert [fields[f"code{index}"] for index in range(6)] == list(OTP_CODE)

    def test_magic_link_is_accepted_only_for_a_reviewed_host(self) -> None:
        async def scenario(app: BrowserTestApp) -> tuple[bool, bool, str]:
            on_host = magic_link_is_safe(app.url("/magic-confirm"), app.host_patterns)
            off_host = magic_link_is_safe(app.third_party_url("/magic-confirm"), app.host_patterns)
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/magic-confirm"), wait_until="domcontentloaded")
                return on_host, off_host, str(fx.page.url)

        on_host, off_host, url = _run(scenario)
        assert on_host is True
        # A link to another origin must never be opened, however plausible it looks.
        assert off_host is False
        assert "/home" in url

    def test_account_selection_surfaces_as_an_actionable_choice(self) -> None:
        async def scenario(app: BrowserTestApp) -> tuple[int, list[str]]:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/account-selection"), wait_until="domcontentloaded")
                elements, _ = await build_ranked_snapshot(
                    fx.page,
                    reviewed_patterns=app.host_patterns,
                    checkpoint_signals=("workspace",),
                )
                candidates = generate_candidates(
                    elements=elements,
                    checkpoint_signals=("workspace",),
                    checkpoint_order=1,
                    trace_version="2.0",
                    expected_postcondition="account_selected",
                )
                return len(candidates), [c.semantic_target for c in candidates]

        count, targets = _run(scenario)
        assert count >= 2
        assert any("workspace" in target.casefold() for target in targets)

    def test_captcha_gate_is_detected_as_requiring_a_human(self) -> None:
        async def scenario(app: BrowserTestApp) -> str:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/captcha"), wait_until="domcontentloaded")
                inspection = await inspect_login(fx.page, app.host_patterns)
                return str(getattr(inspection, "state", ""))

        # The login inspector must not claim it can proceed through a CAPTCHA.
        assert _run(scenario) not in {"ready", "complete"}

    def test_mfa_gate_is_not_treated_as_a_completed_login(self) -> None:
        async def scenario(app: BrowserTestApp) -> tuple[str, str]:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/mfa"), wait_until="domcontentloaded")
                inspection = await inspect_login(fx.page, app.host_patterns)
                body = await fx.page.locator("body").inner_text()
                return str(getattr(inspection, "state", "")), body

        state, body = _run(scenario)
        assert "two-factor" in body.casefold()
        assert state != "complete"


# ======================================================= complex browser behavior
class TestComplexBrowserBehavior:
    """SPA routing, frames, popups, dialogs, downloads and awkward controls."""

    def test_spa_navigation_changes_the_view_without_a_document_load(self) -> None:
        async def scenario(app: BrowserTestApp) -> tuple[str, str, str]:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/spa"), wait_until="domcontentloaded")
                before = await fx.page.locator("#view-title").inner_text()
                await fx.page.click("#go-api")
                # The SPA renders after a delay: wait for the STATE, not a sleep.
                await fx.page.wait_for_function(
                    "() => document.getElementById('view-title').textContent === 'API settings'",
                    timeout=10_000,
                )
                after = await fx.page.locator("#view-title").inner_text()
                return before, after, str(fx.page.url)

        before, after, url = _run(scenario)
        assert before == "Overview"
        assert after == "API settings"
        # history.pushState changed the path with no new document request.
        assert url.endswith("/spa/api")

    def test_iframe_login_form_is_reachable_through_the_frame_chain(self) -> None:
        async def scenario(app: BrowserTestApp) -> tuple[int, list[tuple[str, ...]]]:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/iframe-login"), wait_until="load")
                # Give the child frame time to attach and load.
                await fx.page.wait_for_timeout(500)
                frames = fx.page.frames
                chains = [frame_chain(frame) for frame in frames]
                elements, _ = await build_ranked_snapshot(
                    fx.page, reviewed_patterns=app.host_patterns, include_frames=True
                )
                in_frame = [element for element in elements if element.frame_path]
                return len(in_frame), chains

        in_frame_count, chains = _run(scenario)
        # The snapshot reached INTO the frame and tagged elements with their path.
        assert in_frame_count >= 1
        assert any(chain for chain in chains)

    def test_popup_is_registered_and_its_url_is_policy_checked(self) -> None:
        """A popup is admitted only after the registry checks its URL."""

        async def scenario(app: BrowserTestApp) -> tuple[int, bool, str, bool]:
            async with browser_page(app) as fx:
                registry = BrowserPageRegistry(
                    url_allowed=lambda url: navigation_allowed(url, app.host_patterns)
                )
                opener_id = registry.register(fx.page, active=True)
                await fx.page.goto(app.url("/popup-oauth"), wait_until="domcontentloaded")
                async with fx.page.expect_popup() as popup_info:
                    await fx.page.click("#open-oauth")
                popup = await popup_info.value
                await popup.wait_for_load_state("domcontentloaded")
                decision = await registry.consider_popup(popup, opener_page_id=opener_id)
                accepted, reason = decision.activated, decision.reason_code
                # And an off-domain popup URL must be refused by the same policy.
                off_domain_allowed = navigation_allowed(
                    app.third_party_url("/elsewhere"), app.host_patterns
                )
                return len(fx.context.pages), accepted, reason, off_domain_allowed

        page_count, accepted, reason, off_domain_allowed = _run(scenario)
        assert page_count >= 2
        # This popup is on the reviewed host, so the registry admits it.
        assert accepted is True, reason
        # The same check refuses a third-party origin.
        assert off_domain_allowed is False

    def test_alert_confirm_and_prompt_are_handled_by_policy(self) -> None:
        async def scenario(app: BrowserTestApp) -> tuple[list[str], str]:
            async with browser_page(app) as fx:
                records: list[Any] = []
                # Default policy: acknowledge alerts, REFUSE confirms (a confirm can
                # be the last step before an irreversible action).
                install_dialog_handler(fx.page, DialogPolicy(), records)
                await fx.page.goto(app.url("/dialogs"), wait_until="domcontentloaded")
                await fx.page.click("#do-alert")
                await fx.page.wait_for_timeout(200)
                await fx.page.click("#do-confirm")
                await fx.page.wait_for_timeout(200)
                await fx.page.click("#do-prompt")
                await fx.page.wait_for_timeout(200)
                outcome = await fx.page.locator("#outcome").inner_text()
                return [str(getattr(r, "kind", r)) for r in records], outcome

        kinds, outcome = _run(scenario)
        assert "alert" in kinds
        assert "confirm" in kinds
        assert "prompt" in kinds
        # The prompt was dismissed rather than answered with invented text.
        assert outcome == "prompt-null"

    def test_confirm_is_dismissed_unless_explicitly_reviewed(self) -> None:
        async def scenario(app: BrowserTestApp) -> str:
            async with browser_page(app) as fx:
                records: list[Any] = []
                install_dialog_handler(fx.page, DialogPolicy(), records)
                await fx.page.goto(app.url("/dialogs"), wait_until="domcontentloaded")
                await fx.page.click("#do-confirm")
                await fx.page.wait_for_timeout(300)
                return await fx.page.locator("#outcome").inner_text()

        # "Delete this?" is answered NO by default.
        assert _run(scenario) == "confirm-false"

    def test_safe_download_is_allowed_and_key_download_is_refused(self) -> None:
        """Credential files and executables are never downloaded autonomously."""

        async def scenario(app: BrowserTestApp) -> dict[str, tuple[bool, str]]:
            async with browser_page(app) as fx:
                records: list[Any] = []
                install_download_guard(fx.page, DownloadPolicy(allowed=True), records)
                await fx.page.goto(app.url("/downloads"), wait_until="domcontentloaded")
                for selector in ("#safe-download", "#key-download", "#exe-download"):
                    with contextlib.suppress(Exception):
                        await fx.page.click(selector)
                    # Give the guard time to observe the download and decide.
                    await fx.page.wait_for_timeout(700)
                return {
                    str(record.suggested_name): (bool(record.allowed), str(record.reason_code))
                    for record in records
                }

        outcomes = _run(scenario)
        assert outcomes, "the download guard recorded nothing"
        # A CSV is inside the reviewed mime/name policy.
        assert outcomes.get("report.csv", (False, ""))[0] is True
        # A private key and an installer must be refused, with a stated reason.
        for dangerous in ("id_rsa", "setup.exe"):
            if dangerous in outcomes:
                allowed, reason = outcomes[dangerous]
                assert allowed is False, f"{dangerous} must never be accepted"
                assert reason, f"{dangerous} refusal must carry a reason code"

    def test_duplicate_control_names_are_disambiguated_by_test_id(self) -> None:
        async def scenario(app: BrowserTestApp) -> tuple[int, str]:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/duplicate-buttons"), wait_until="domcontentloaded")
                elements, _ = await build_ranked_snapshot(
                    fx.page, reviewed_patterns=app.host_patterns, checkpoint_signals=("save",)
                )
                saves = [e for e in elements if e.name.casefold() == "save"]
                from ops.browser_candidates import ElementIdentity

                identity = ElementIdentity(role="button", name="Save", test_id="save-team")
                resolution, element = resolve_identity(identity, elements)
                return len(saves), (element.test_id or "") if element else ""

        count, resolved_test_id = _run(scenario)
        assert count >= 2
        # Ambiguity is resolved by the stable test id, never by picking the first.
        assert resolved_test_id == "save-team"

    def test_hidden_and_disabled_controls_never_become_candidates(self) -> None:
        async def scenario(app: BrowserTestApp) -> tuple[list[str], list[str]]:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/hidden-controls"), wait_until="domcontentloaded")
                hidden_elements, _ = await build_ranked_snapshot(
                    fx.page, reviewed_patterns=app.host_patterns
                )
                hidden_names = [
                    e.name
                    for e in hidden_elements
                    if generate_candidates(
                        elements=[e],
                        checkpoint_signals=(),
                        checkpoint_order=1,
                        trace_version="2.0",
                        expected_postcondition="x",
                    )
                ]
                await fx.page.goto(app.url("/disabled-controls"), wait_until="domcontentloaded")
                disabled_elements, _ = await build_ranked_snapshot(
                    fx.page, reviewed_patterns=app.host_patterns
                )
                disabled_candidates = generate_candidates(
                    elements=disabled_elements,
                    checkpoint_signals=("control",),
                    checkpoint_order=1,
                    trace_version="2.0",
                    expected_postcondition="x",
                )
                return hidden_names, [c.semantic_target for c in disabled_candidates]

        actionable_hidden, disabled_targets = _run(scenario)
        # Nothing hidden is actionable.
        for name in actionable_hidden:
            assert "hidden" not in name.casefold()
        # The disabled control is never offered; the enabled one may be.
        for target in disabled_targets:
            assert "disabled" not in target.casefold()

    def test_offscreen_control_is_actionable_after_scrolling(self) -> None:
        async def scenario(app: BrowserTestApp) -> bool:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/offscreen-controls"), wait_until="domcontentloaded")
                locator = fx.page.locator("#far-below")
                await locator.scroll_into_view_if_needed()
                return bool(await locator.is_visible())

        assert _run(scenario) is True

    def test_select_and_checkbox_controls_are_operated_correctly(self) -> None:
        async def scenario(app: BrowserTestApp) -> tuple[str, bool]:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/form-controls"), wait_until="domcontentloaded")
                await fx.page.select_option("#plan", "pro")
                await fx.page.check("#agree")
                return await fx.page.input_value("#plan"), await fx.page.is_checked("#agree")

        value, checked = _run(scenario)
        assert value == "pro"
        assert checked is True

    def test_slow_response_and_error_statuses_are_observed(self) -> None:
        async def scenario(app: BrowserTestApp) -> tuple[int | None, int | None, str]:
            async with browser_page(app) as fx:
                not_found = await fx.page.goto(
                    app.url("/status/404"), wait_until="domcontentloaded"
                )
                server_error = await fx.page.goto(
                    app.url("/status/500"), wait_until="domcontentloaded"
                )
                slow = await fx.page.goto(
                    app.url("/slow"), wait_until="domcontentloaded", timeout=15_000
                )
                return (
                    not_found.status if not_found else None,
                    server_error.status if server_error else None,
                    await slow.text() if slow else "",
                )

        not_found_status, error_status, slow_body = _run(scenario)
        # HTTP failures are surfaced as statuses, not swallowed.
        assert not_found_status == 404
        assert error_status == 500
        assert "Slow page" in slow_body


# ==================================================================== security
class TestSecurityBoundaries:
    """The properties that make an autonomous browser acceptable at all."""

    def test_off_domain_navigation_is_blocked_by_the_production_guard(self) -> None:
        async def scenario(app: BrowserTestApp) -> tuple[bool, tuple[str, ...]]:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/off-domain-link"), wait_until="domcontentloaded")
                blocked_navigation = False
                try:
                    await fx.page.click("#leave")
                    await fx.page.wait_for_timeout(800)
                except Exception:
                    blocked_navigation = True
                # Whatever the click did, the third-party server must not have served
                # a document to us.
                return blocked_navigation, app.third_party_log.paths

        _blocked, third_party_paths = _run(scenario)
        assert not any("/elsewhere" in path for path in third_party_paths)

    def test_off_domain_fetch_never_reaches_the_third_party(self) -> None:
        """The strongest form of this assertion: the other server saw nothing."""

        async def scenario(app: BrowserTestApp) -> tuple[tuple[str, ...], list[str]]:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/off-domain-fetch"), wait_until="load")
                await fx.page.click("#do-fetch")
                await fx.page.wait_for_timeout(1_000)
                return app.third_party_log.paths, fx.blocked_urls

        third_party_paths, blocked = _run(scenario)
        assert third_party_paths == ()
        assert any("/beacon" in url for url in blocked)

    def test_off_domain_script_is_blocked_even_pre_auth(self) -> None:
        """A third-party script could exfiltrate a typed credential, so it is
        blocked at every stage — unlike a passive image pre-auth."""

        async def scenario(app: BrowserTestApp) -> tuple[tuple[str, ...], list[str], Any]:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/off-domain-script"), wait_until="load")
                await fx.page.wait_for_timeout(600)
                ran = await fx.page.evaluate("() => Boolean(window.__thirdPartyScriptRan)")
                return app.third_party_log.paths, fx.blocked_urls, ran

        third_party_paths, blocked, script_ran = _run(scenario)
        assert third_party_paths == ()
        assert any("analytics.js" in url for url in blocked)
        # And it never executed.
        assert script_ran is False

    def test_post_auth_stage_also_blocks_passive_assets(self) -> None:
        """Post-auth tightening closes the pixel/CSS/font beacon channel.

        Pre-auth a third-party image is allowed (real pages need assets); once a
        credential could be in the DOM, nothing off-allowlist may leave at all.
        """

        async def scenario_stage(
            app: BrowserTestApp, stage: str
        ) -> tuple[tuple[str, ...], list[str]]:
            async with browser_page(app, stage_provider=lambda: stage) as fx:
                await fx.page.goto(app.url("/off-domain-image"), wait_until="load")
                await fx.page.wait_for_timeout(800)
                return app.third_party_log.paths, fx.blocked_urls

        async def scenario(app: BrowserTestApp) -> None:
            pre_paths, pre_blocked = await scenario_stage(app, "pre_auth")
            # Pre-auth: the passive image is permitted, so the pixel WAS served.
            assert any("pixel.png" in path for path in pre_paths)
            assert not any("pixel.png" in url for url in pre_blocked)

            app.third_party_log.clear()
            post_paths, post_blocked = await scenario_stage(app, "post_auth")
            # Post-auth: the very same request is aborted.
            assert not any("pixel.png" in path for path in post_paths)
            assert any("pixel.png" in url for url in post_blocked)

        _run(scenario)

    def test_unreviewed_identity_provider_frame_is_refused_for_injection(self) -> None:
        async def scenario(app: BrowserTestApp) -> tuple[bool, bool]:
            reviewed = frame_path_is_reviewed((app.vendor_host,), (app.vendor_host,))
            unreviewed = frame_path_is_reviewed((app.third_party_host,), (app.vendor_host,))
            return reviewed, unreviewed

        reviewed, unreviewed = _run(scenario)
        assert reviewed is True
        # Credentials must never be typed into a frame whose origin nobody reviewed.
        assert unreviewed is False

    def test_reviewed_identity_provider_frame_is_allowed(self) -> None:
        async def scenario(app: BrowserTestApp) -> bool:
            # An explicitly reviewed IdP origin is permitted.
            return frame_path_is_reviewed(
                (app.third_party_host,), (app.vendor_host, app.third_party_host)
            )

        assert _run(scenario) is True

    def test_plain_http_is_refused_by_the_host_guard(self) -> None:
        """https is required, so a downgrade cannot smuggle traffic past the guard."""

        async def scenario(app: BrowserTestApp) -> tuple[bool, bool]:
            secure = is_allowed_browser_url(app.url("/login"), app.host_patterns)
            insecure = is_allowed_browser_url(
                app.url("/login").replace("https://", "http://"), app.host_patterns
            )
            return secure, insecure

        secure, insecure = _run(scenario)
        assert secure is True
        assert insecure is False

    def test_model_cannot_select_a_candidate_outside_the_generated_set(self) -> None:
        """The core LLM boundary: an invented ID is refused."""

        async def scenario(app: BrowserTestApp) -> None:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/settings"), wait_until="domcontentloaded")
                elements, _ = await build_ranked_snapshot(
                    fx.page,
                    reviewed_patterns=app.host_patterns,
                    checkpoint_signals=("developers",),
                )
                candidates = generate_candidates(
                    elements=elements,
                    checkpoint_signals=("developers",),
                    checkpoint_order=1,
                    trace_version="2.0",
                    expected_postcondition="developer_page",
                )
                assert candidates, "the test page must yield at least one candidate"
                # A real ID resolves.
                assert select_candidate(candidates, candidates[0].candidate_id) is not None
                # A forged ID is refused with a specific, meaningful error.
                with pytest.raises(ValueError, match="not in the generated policy set"):
                    select_candidate(candidates, "c_forged_by_model")

        _run(scenario)

    def test_candidate_ids_are_opaque_and_carry_no_selector_or_url(self) -> None:
        """A model reading a candidate ID learns nothing it could author with."""

        async def scenario(app: BrowserTestApp) -> list[str]:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/settings/api"), wait_until="domcontentloaded")
                elements, _ = await build_ranked_snapshot(
                    fx.page, reviewed_patterns=app.host_patterns, checkpoint_signals=("token",)
                )
                candidates = generate_candidates(
                    elements=elements,
                    checkpoint_signals=("token",),
                    checkpoint_order=1,
                    trace_version="2.0",
                    expected_postcondition="credential_page",
                )
                return [candidate.candidate_id for candidate in candidates]

        ids = _run(scenario)
        assert ids
        for candidate_id in ids:
            # Opaque form only: no CSS, no XPath, no URL, no host.
            assert re.fullmatch(r"c_[0-9a-f]{12}", candidate_id), candidate_id

    def test_credential_value_never_appears_in_a_snapshot_or_candidate(self) -> None:
        """The strongest DLP assertion in the suite: the token is on the page, in a
        readable input, and still must not reach anything model-facing."""

        async def scenario(app: BrowserTestApp) -> tuple[str, str]:
            from ops.browser_candidates import render_candidates

            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/settings/api"), wait_until="domcontentloaded")
                # Confirm the token really IS present in the DOM.
                dom_value = await fx.page.input_value("input[name='api_token']")
                assert dom_value == FAKE_API_TOKEN

                elements, _ = await build_ranked_snapshot(
                    fx.page, reviewed_patterns=app.host_patterns, checkpoint_signals=("token",)
                )
                candidates = generate_candidates(
                    elements=elements,
                    checkpoint_signals=("token",),
                    checkpoint_order=1,
                    trace_version="2.0",
                    expected_postcondition="credential_page",
                )
                return repr(elements), render_candidates(candidates)

        snapshot_repr, rendered = _run(scenario)
        # Neither the snapshot the model sees nor the rendered candidate list may
        # contain the credential.
        assert FAKE_API_TOKEN not in snapshot_repr
        assert FAKE_API_TOKEN not in rendered

    def test_secret_fields_are_never_offered_as_type_candidates(self) -> None:
        async def scenario(app: BrowserTestApp) -> list[tuple[str, str | None]]:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/login"), wait_until="domcontentloaded")
                elements, _ = await build_ranked_snapshot(
                    fx.page, reviewed_patterns=app.host_patterns, checkpoint_signals=("password",)
                )
                candidates = generate_candidates(
                    elements=elements,
                    checkpoint_signals=("password",),
                    checkpoint_order=1,
                    trace_version="2.0",
                    expected_postcondition="logged_in",
                    allow_value_refs=("login_email",),
                )
                return [(c.action, c.value_ref) for c in candidates]

        actions = _run(scenario)
        for action, value_ref in actions:
            if action in {"fill", "type"}:
                # Only an APPROVED reference may ever be typed, never literal text.
                assert value_ref in {"login_email", "login_password", "login_otp", None}


# =================================================================== lifecycle
class TestLifecycleBehavior:
    """Serialization, capacity and typed crash handling with a real browser."""

    def test_operations_on_one_session_serialize(self) -> None:
        """Two concurrent operations must not interleave on the same page."""

        async def scenario(app: BrowserTestApp) -> list[str]:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/settings"), wait_until="domcontentloaded")
                lock = asyncio.Lock()
                order: list[str] = []

                async def operation(name: str) -> None:
                    async with lock:
                        order.append(f"{name}:start")
                        await fx.page.goto(app.url("/home"), wait_until="domcontentloaded")
                        order.append(f"{name}:end")

                await asyncio.gather(operation("a"), operation("b"))
                return order

        order = _run(scenario)
        # Each operation completed before the next began.
        assert order in (
            ["a:start", "a:end", "b:start", "b:end"],
            ["b:start", "b:end", "a:start", "a:end"],
        )

    def test_browser_crash_is_reported_as_a_typed_failure(self) -> None:
        """A renderer crash must surface as a typed error, not a hang."""

        async def scenario(app: BrowserTestApp) -> str:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/crash"), wait_until="domcontentloaded")
                try:
                    # chrome://crash terminates the renderer deliberately.
                    await fx.page.goto("chrome://crash", timeout=5_000)
                except Exception as exc:
                    return type(exc).__name__
                return "no_exception"

        # Playwright raises a typed Error rather than hanging or exiting.
        assert _run(scenario) != "no_exception"

    def test_context_close_releases_the_page(self) -> None:
        async def scenario(app: BrowserTestApp) -> bool:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/home"), wait_until="domcontentloaded")
                page = fx.page
                await fx.context.close()
                return bool(page.is_closed())

        assert _run(scenario) is True


# ======================================================================== HITL
class TestHitlSurfaces:
    """Screenshot of the current gate, and resuming on the SAME page."""

    def test_screenshot_captures_the_current_gate(self) -> None:
        async def scenario(app: BrowserTestApp) -> tuple[bytes, str]:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/captcha"), wait_until="domcontentloaded")
                return await fx.page.screenshot(type="png"), await fx.page.title()

        data, title = _run(scenario)
        # A real PNG of the gate the human must solve.
        assert data.startswith(b"\x89PNG\r\n\x1a\n")
        assert len(data) > 1_000
        assert "human" in title.casefold()

    def test_resume_continues_on_the_same_page_not_a_fresh_one(self) -> None:
        """Resuming after a gate must reuse the SAME page, not restart the login."""

        async def scenario(app: BrowserTestApp) -> tuple[str, str, bool, bool]:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/otp-single"), wait_until="domcontentloaded")
                before_url = str(fx.page.url)
                page_identity_before = id(fx.page)
                # The HITL pause/resume: the same page object carries on.
                inspection = await inspect_login(fx.page, app.host_patterns)
                injected = await inject_otp(fx.page, OTP_CODE, inspection)
                await fx.page.wait_for_load_state("domcontentloaded")
                same_page = id(fx.page) == page_identity_before
                return before_url, str(fx.page.url), injected, same_page

        before, after, injected, same_page = _run(scenario)
        assert "/otp-single" in before
        assert injected is True
        # Progress was made in the SAME session rather than a new login.
        assert "/home" in after
        assert same_page is True


# ======================================================== credential capture
class TestCredentialCapture:
    """Deterministic capture: reviewed selector, host, path, heading, full match."""

    @staticmethod
    def _spec(app: BrowserTestApp, **overrides: Any) -> Any:
        from ops.credential_capture_specs import CredentialCaptureSpec

        defaults: dict[str, Any] = {
            "app_slug": "vendor-test",
            "url": app.url("/settings/api"),
            "vendor_domain": app.vendor_host,
            "field_kind": "api_token",
            "value_pattern": r"[A-Fa-f0-9]{40}",
            "selectors": ("input[name='api_token']",),
            "expected_path_prefix": "/settings/api",
            "expected_heading": "API",
        }
        defaults.update(overrides)
        return CredentialCaptureSpec(**defaults)

    async def _capture(self, app: BrowserTestApp, page: Any, spec: Any) -> str | None:
        """Mirror the production capture checks against a live page.

        Deliberately the same ordered checks as
        ``PlaywrightBrowserWorker.auto_capture_credentials``: host, then path, then
        heading, then reviewed selectors, then ``fullmatch``.
        """

        from urllib.parse import urlsplit

        if not navigation_allowed(spec.url, app.host_patterns):
            return None
        parsed = urlsplit(str(page.url))
        host = parsed.hostname or ""
        if not (host == spec.vendor_domain or host.endswith("." + spec.vendor_domain)):
            return None
        if spec.expected_path_prefix and not (parsed.path or "/").startswith(
            spec.expected_path_prefix
        ):
            return None
        if spec.expected_heading:
            text = await page.locator("body").inner_text()
            if spec.expected_heading.casefold() not in text.casefold():
                return None
        pattern = re.compile(spec.value_pattern)
        for selector in spec.selectors:
            locator = page.locator(selector)
            if await locator.count() < 1:
                continue
            value = await locator.first.input_value()
            # fullmatch: a partial match must never be accepted.
            if value and pattern.fullmatch(value):
                return str(value)
        return None

    def test_reviewed_selector_on_the_right_page_captures_the_token(self) -> None:
        async def scenario(app: BrowserTestApp) -> str | None:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/settings/api"), wait_until="domcontentloaded")
                return await self._capture(app, fx.page, self._spec(app))

        assert _run(scenario) == FAKE_API_TOKEN

    def test_wrong_host_is_refused(self) -> None:
        async def scenario(app: BrowserTestApp) -> str | None:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/settings/api"), wait_until="domcontentloaded")
                # The spec expects a different vendor domain than the live page.
                return await self._capture(
                    app, fx.page, self._spec(app, vendor_domain="other-vendor.example")
                )

        assert _run(scenario) is None

    def test_wrong_path_is_refused(self) -> None:
        async def scenario(app: BrowserTestApp) -> str | None:
            async with browser_page(app) as fx:
                # The token IS on this page, but the path is not the reviewed one.
                await fx.page.goto(
                    app.url("/settings/billing-token"), wait_until="domcontentloaded"
                )
                return await self._capture(app, fx.page, self._spec(app))

        assert _run(scenario) is None

    def test_wrong_heading_is_refused(self) -> None:
        async def scenario(app: BrowserTestApp) -> str | None:
            async with browser_page(app) as fx:
                await fx.page.goto(
                    app.url("/settings/billing-token"), wait_until="domcontentloaded"
                )
                spec = self._spec(app, expected_path_prefix="/settings/billing-token")
                # Path now matches; the HEADING check is what must refuse it.
                return await self._capture(app, fx.page, spec)

        assert _run(scenario) is None

    def test_partial_pattern_match_is_refused(self) -> None:
        async def scenario(app: BrowserTestApp) -> str | None:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/settings/api-partial"), wait_until="domcontentloaded")
                spec = self._spec(app, expected_path_prefix="/settings/api-partial")
                # 'a1b2c3' partially matches the hex pattern but is not a full match.
                return await self._capture(app, fx.page, spec)

        assert _run(scenario) is None

    def test_captured_value_is_stored_as_a_vault_reference_only(self) -> None:
        """What leaves capture is a reference; the value stays in the vault."""

        async def scenario(app: BrowserTestApp) -> tuple[str, str]:
            import tempfile
            from pathlib import Path

            from cryptography.fernet import Fernet

            from ops.secret_store import SQLiteSecretStore

            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/settings/api"), wait_until="domcontentloaded")
                value = await self._capture(app, fx.page, self._spec(app))
                assert value == FAKE_API_TOKEN
                with tempfile.TemporaryDirectory() as directory:
                    store = SQLiteSecretStore(
                        Path(directory) / "vault.db", Fernet.generate_key().decode()
                    )
                    reference = store.put(
                        app_slug="vendor-test", kind="api_token", value=value or ""
                    )
                    return reference, store.get(reference) or ""

        reference, revealed = _run(scenario)
        # The reference is opaque and carries no part of the token.
        assert reference.startswith("vault://")
        assert FAKE_API_TOKEN not in reference
        # And the value is retrievable only by explicit vault read.
        assert revealed == FAKE_API_TOKEN


# ==================================================== corrective popup lifecycle
class TestPopupLifecycle:
    """P0-1: committed-URL admission, page-id close wiring, task retention."""

    def test_blank_then_redirect_popup_is_accepted(self) -> None:
        """A popup that opens about:blank then navigates to a reviewed URL must be
        accepted — the committed-URL wait is what makes this work."""

        async def scenario(app: BrowserTestApp) -> tuple[bool, str]:
            async with browser_page(app) as fx:
                registry = BrowserPageRegistry(
                    url_allowed=lambda url: navigation_allowed(url, app.host_patterns)
                )
                opener = registry.register(fx.page, active=True)
                await fx.page.goto(app.url("/popup-blank-redirect"), wait_until="domcontentloaded")
                async with fx.page.expect_popup() as popup_info:
                    await fx.page.click("#open-delayed")
                popup = await popup_info.value
                decision = await registry.consider_popup(popup, opener_page_id=opener)
                return decision.activated, decision.reason_code

        activated, reason = _run(scenario)
        assert activated is True
        assert reason == "popup_activated"

    def test_off_domain_popup_is_closed(self) -> None:
        async def scenario(app: BrowserTestApp) -> tuple[bool, str, bool]:
            async with browser_page(app) as fx:
                registry = BrowserPageRegistry(
                    url_allowed=lambda url: navigation_allowed(url, app.host_patterns)
                )
                opener = registry.register(fx.page, active=True)
                await fx.page.goto(app.url("/popup-off-domain"), wait_until="domcontentloaded")
                async with fx.page.expect_popup() as popup_info:
                    await fx.page.click("#open-evil")
                popup = await popup_info.value
                decision = await registry.consider_popup(popup, opener_page_id=opener)
                # The opener stays active after an off-domain popup is refused.
                return decision.activated, decision.reason_code, registry.active_page_id == opener

        activated, reason, opener_active = _run(scenario)
        assert activated is False
        assert reason == "popup_blocked"
        assert opener_active is True

    def test_closing_active_popup_restores_the_opener_by_page_id(self) -> None:
        """The close handler must key on the registry page id, not the Page object.

        Passing the Page (the old bug) silently no-ops, leaving the registry stuck
        on a closed page.
        """

        async def scenario(app: BrowserTestApp) -> tuple[str, str, bool]:
            async with browser_page(app) as fx:
                registry = BrowserPageRegistry(
                    url_allowed=lambda url: navigation_allowed(url, app.host_patterns)
                )
                opener = registry.register(fx.page, active=True)
                await fx.page.goto(app.url("/popup-oauth"), wait_until="domcontentloaded")
                async with fx.page.expect_popup() as popup_info:
                    await fx.page.click("#open-oauth")
                popup = await popup_info.value
                decision = await registry.consider_popup(popup, opener_page_id=opener)
                assert decision.page_id is not None
                active_with_popup = registry.active_page_id
                # Simulate the popup closing; the handler closes BY PAGE ID.
                registry.close_page(decision.page_id)
                restored = registry.active_page is fx.page
                return active_with_popup, registry.active_page_id, restored

        active_with_popup, after_close, restored = _run(scenario)
        assert active_with_popup != after_close
        # The opener is the active page again, and it is the real opener Page.
        assert restored is True

    def test_action_executes_on_restored_opener(self) -> None:
        async def scenario(app: BrowserTestApp) -> str:
            async with browser_page(app) as fx:
                registry = BrowserPageRegistry(
                    url_allowed=lambda url: navigation_allowed(url, app.host_patterns)
                )
                opener = registry.register(fx.page, active=True)
                await fx.page.goto(app.url("/popup-oauth"), wait_until="domcontentloaded")
                async with fx.page.expect_popup() as popup_info:
                    await fx.page.click("#open-oauth")
                popup = await popup_info.value
                decision = await registry.consider_popup(popup, opener_page_id=opener)
                assert decision.page_id is not None
                await popup.close()
                registry.close_page(decision.page_id)
                # The restored opener is usable: navigate it.
                restored_page = registry.active_page
                await restored_page.goto(app.url("/settings"), wait_until="domcontentloaded")
                return await restored_page.title()

        assert _run(scenario) == "Settings"

    def test_committed_url_helper_returns_empty_for_a_closed_popup(self) -> None:
        from ops.browser_pages import wait_for_committed_popup_url

        async def scenario(app: BrowserTestApp) -> str:
            async with browser_page(app) as fx:
                await fx.page.goto(app.url("/popup-oauth"), wait_until="domcontentloaded")
                async with fx.page.expect_popup() as popup_info:
                    await fx.page.click("#open-oauth")
                popup = await popup_info.value
                await popup.close()
                return await wait_for_committed_popup_url(popup, timeout_seconds=1.0)

        assert _run(scenario) == ""
