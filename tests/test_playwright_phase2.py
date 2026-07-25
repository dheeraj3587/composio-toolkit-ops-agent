"""Phase 2 tests: SPA state, frames, popups, dialogs, downloads, staged egress,
identity resolution and bounded LLM decisions.

Browser tests drive REAL Chromium against an extended local test app served
in-memory via Playwright routing (no vendor contact). Off-domain requests are
deliberately attempted so the guard can be observed refusing them. Pure-policy
tests need no browser.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest

from ops.browser_api_trace_catalog import BrowserApiTraceStep, CheckpointPredicate
from ops.browser_candidates import (
    ActionCandidate,
    CandidatePostcondition,
    ElementIdentity,
    ElementPredicate,
    generate_candidates,
    resolve_identity,
    select_candidate,
)
from ops.browser_decider import SnapshotElement, build_snapshot, validate_choice
from ops.browser_egress import EgressStage, EgressStageTracker, build_egress_policy
from ops.browser_pages import (
    BrowserPageRegistry,
    DialogPolicy,
    DialogRecord,
    DownloadPolicy,
    DownloadRecord,
    frame_path_is_reviewed,
    install_dialog_handler,
    install_download_guard,
)
from ops.browser_risk import BrowserActionRiskPolicy
from ops.browser_snapshot import build_ranked_snapshot, rank_raw_elements
from ops.inference import DecisionBudget, DecisionFailed, JsonInference
from ops.playwright_worker import (
    PageInspection,
    make_route_handler,
    postcondition_satisfied,
    structural_change,
)
from tests.browser_app.harness import require_chromium

_HOST = "app.pipedrive.com"
_IDP = "auth.pipedrive.com"
_EVIL = "attacker.example"
_PATTERNS = (_HOST, "*.pipedrive.com")

# --- Extended local test application ------------------------------------------
_APP: dict[str, str] = {
    # SPA: clicking replaces part of the DOM and pushes a new history URL.
    "/spa": (
        "<html><body><h1>Dashboard</h1><div id='view'>"
        "<button data-testid='open-api'>API keys</button></div>"
        "<script>document.querySelector('[data-testid=open-api]').onclick = () => {"
        "history.pushState({}, '', '/spa/api');"
        "document.getElementById('view').innerHTML = "
        "'<h2>API keys</h2><p>Your API token field label</p>';};</script>"
        "</body></html>"
    ),
    # iframe login: the password field lives in a same-origin reviewed frame.
    "/iframe-login": (
        f"<html><body><h1>Portal</h1>"
        f"<iframe name='loginframe' src='https://{_HOST}/frame-form'></iframe>"
        "</body></html>"
    ),
    # iframe login on an UNREVIEWED origin (must never receive a secret).
    "/iframe-evil": (
        f"<html><body><h1>Portal</h1>"
        f"<iframe name='evilframe' src='https://{_EVIL}/frame-form'></iframe>"
        "</body></html>"
    ),
    "/frame-form": (
        "<html><body><form action='/home' method='get'>"
        "<input type='email' name='email'>"
        "<input type='password' name='password'>"
        "<button type='submit' data-testid='frame-submit'>Sign in</button>"
        "</form></body></html>"
    ),
    # popup OAuth: opens a new page on an approved or unapproved host.
    "/popup-approved": (
        f"<html><body><button onclick=\"window.open('https://{_HOST}/oauth','_blank')\">"
        "Connect</button></body></html>"
    ),
    "/popup-evil": (
        f"<html><body><button onclick=\"window.open('https://{_EVIL}/oauth','_blank')\">"
        "Connect</button></body></html>"
    ),
    "/oauth": "<html><body><h1>Authorize</h1></body></html>",
    # duplicate button names -> ambiguity
    "/duplicate": (
        "<html><body><h1>Settings</h1><button>Manage</button><button>Manage</button></body></html>"
    ),
    # hidden and disabled controls must never become candidates
    "/hidden-disabled": (
        "<html><body><h1>Controls</h1>"
        "<button style='display:none'>API keys</button>"
        "<button disabled>API keys</button></body></html>"
    ),
    "/select": (
        "<html><body><h1>Plan</h1>"
        "<select name='plan' data-testid='plan'>"
        "<option value='basic'>Basic</option><option value='pro'>Pro</option>"
        "</select></body></html>"
    ),
    "/checkbox": (
        "<html><body><h1>Scopes</h1>"
        "<input type='checkbox' name='read' data-testid='read'> Read access"
        "</body></html>"
    ),
    "/confirm": (
        "<html><body><h1>Confirm</h1>"
        "<button data-testid='go' onclick=\"window.confirmed = confirm('Proceed?')\">Go</button>"
        "</body></html>"
    ),
    "/prompt": (
        "<html><body><h1>Prompt</h1>"
        "<button data-testid='go' onclick=\"window.answer = prompt('Name?')\">Go</button>"
        "</body></html>"
    ),
    "/download": (
        "<html><body><h1>Export</h1>"
        "<a data-testid='dl' href='/file.csv' download='export.csv'>Download</a>"
        "</body></html>"
    ),
    "/file.csv": "id,name\n1,test\n",
    # off-domain resource attempts (the guard must refuse these)
    "/offdomain": (
        f"<html><body><h1>Mixed</h1>"
        f"<img src='https://{_EVIL}/pixel.png'>"
        f"<script src='https://{_EVIL}/tracker.js'></script>"
        f"<script>fetch('https://{_EVIL}/collect').catch(()=>{{}});</script>"
        "</body></html>"
    ),
    "/slow": "<html><body><h1>Slow</h1></body></html>",
    "/home": "<html><body><h1>Welcome back</h1></body></html>",
}


async def _serve(page: Any, *, reached: list[str] | None = None) -> None:
    """Serve the app on the reviewed host; record/deny any other host."""

    async def _app(route: Any) -> None:
        url = route.request.url
        path = url.split(_HOST, 1)[1].split("?")[0] if _HOST in url else "/"
        if path == "/file.csv":
            await route.fulfill(
                status=200,
                content_type="text/csv",
                headers={"content-disposition": 'attachment; filename="export.csv"'},
                body=_APP["/file.csv"],
            )
            return
        if path == "/slow":
            await asyncio.sleep(1.0)
        if path == "/404":
            await route.fulfill(status=404, content_type="text/html", body="<h1>Not found</h1>")
            return
        if path == "/500":
            await route.fulfill(status=500, content_type="text/html", body="<h1>Server error</h1>")
            return
        body = _APP.get(path, "<html><body><h1>Unknown</h1></body></html>")
        await route.fulfill(status=200, content_type="text/html", body=body)

    await page.route(f"https://{_HOST}/**", _app)


def _launch(path: str, coro_factory: Any, *, guard: bool = False) -> Any:
    """Run ``coro_factory(page, reached)`` on a real page serving the test app.

    When ``guard`` is set, the production staged route handler is installed FIRST
    (context level) and a spy records anything that still reaches an off-host.
    """

    async def _main() -> Any:
        from playwright.async_api import async_playwright

        async with async_playwright() as p:
            try:
                browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
            except Exception as exc:  # pragma: no cover - no Chromium
                require_chromium(exc)
            context = await browser.new_context()
            reached: list[str] = []
            if guard:
                # Playwright consults the MOST RECENTLY registered route first, so
                # the spy is installed FIRST and the production guard SECOND. The
                # guard therefore runs first and anything the spy records is a
                # request the guard genuinely let through.
                async def _spy(route: Any) -> None:
                    reached.append(route.request.url)
                    await route.abort()

                await context.route(f"https://{_EVIL}/**", _spy)
                await context.route(
                    "**/*", make_route_handler(_PATTERNS, stage_provider=lambda: "pre_auth")
                )
            page = await context.new_page()
            await _serve(page)
            try:
                await page.goto(
                    f"https://{_HOST}{path}", wait_until="domcontentloaded", timeout=20_000
                )
                return await coro_factory(page, reached)
            finally:
                await browser.close()

    return asyncio.run(_main())


def _inspection(
    url: str, *, text: str = "", elements: tuple[SnapshotElement, ...] = (), fingerprint: str = "fp"
) -> PageInspection:
    return PageInspection(
        url=url,
        title="",
        visible_text=text,
        elements=elements,
        locators=(),
        fingerprint=fingerprint,
    )


# ===========================================================================
# 1. SPA checkpoint completes through a structural postcondition
# ===========================================================================
def test_spa_checkpoint_completes_through_structural_postcondition() -> None:
    async def _c(page: Any, _reached: list[str]) -> object:
        before_elements, _ = await build_ranked_snapshot(page, reviewed_patterns=_PATTERNS)
        before = _inspection(page.url, text=await page.inner_text("body"), elements=before_elements)
        await page.click("[data-testid=open-api]")
        after_elements, _ = await build_ranked_snapshot(page, reviewed_patterns=_PATTERNS)
        after = _inspection(page.url, text=await page.inner_text("body"), elements=after_elements)
        # The SPA pushed a new URL AND replaced part of the DOM.
        post = CandidatePostcondition(url_changed=True, text_appears=("API token",))
        return (
            postcondition_satisfied(post, before=before, after=after),
            structural_change(before, after) or before.url != after.url,
            "API token" in after.visible_text,
        )

    satisfied, changed, has_text = _launch("/spa", _c)
    assert satisfied is True
    assert changed is True
    assert has_text is True


# ===========================================================================
# 2/3. Frames: element resolves; unreviewed frame injection is blocked
# ===========================================================================
def test_iframe_element_is_resolved_with_frame_path() -> None:
    async def _c(page: Any, _reached: list[str]) -> object:
        # Give the child frame a moment to load before snapshotting.
        await page.wait_for_timeout(400)
        elements, _ = await build_ranked_snapshot(page, reviewed_patterns=_PATTERNS)
        framed = [e for e in elements if e.frame_path]
        submit = [e for e in framed if e.test_id == "frame-submit"]
        identity = (
            ElementIdentity(
                role=submit[0].role,
                name=submit[0].name,
                element_type=submit[0].element_type,
                frame_path=submit[0].frame_path,
                test_id=submit[0].test_id,
            )
            if submit
            else None
        )
        resolved = resolve_identity(identity, elements)[0] if identity is not None else "not_found"
        return len(framed) > 0, len(submit) == 1, framed[0].frame_path if framed else (), resolved

    has_framed, found_submit, frame_path, resolved = _launch("/iframe-login", _c)
    assert has_framed is True, "elements inside a reviewed frame must be collected"
    assert found_submit is True
    assert frame_path and _HOST in frame_path[0]
    # The framed element is re-resolvable by its frame-scoped identity.
    assert resolved == "resolved"


def test_unreviewed_frame_secret_injection_is_blocked() -> None:
    from ops.playwright_worker import _login_frames_are_reviewed

    async def _c(page: Any, _reached: list[str]) -> object:
        # The evil frame will fail to load (guard aborts it), so also assert the
        # pure policy check directly for an unreviewed host.
        return await _login_frames_are_reviewed(page, _PATTERNS)

    # A frame on an unreviewed origin must make the check fail closed.
    assert frame_path_is_reviewed((_EVIL,), _PATTERNS) is False
    assert frame_path_is_reviewed((_HOST,), _PATTERNS) is True
    assert frame_path_is_reviewed((), _PATTERNS) is True  # main frame handled separately
    # And with only reviewed frames present, injection is permitted.
    assert _launch("/iframe-login", _c, guard=True) is True


# ===========================================================================
# 4/5. Popups
# ===========================================================================
def test_approved_popup_becomes_active_and_unapproved_is_closed() -> None:
    async def _c(page: Any, _reached: list[str]) -> object:
        registry = BrowserPageRegistry(url_allowed=lambda url: url.startswith(f"https://{_HOST}"))
        original = registry.register(page, active=True)

        # Approved popup -> activated.
        async with page.context.expect_page() as info:
            await page.click("button")
        popup = await info.value
        try:
            await popup.wait_for_load_state("domcontentloaded", timeout=5_000)
        except Exception:
            pass
        decision = await registry.consider_popup(popup, opener_page_id=original)
        return decision.activated, decision.reason_code, registry.active_page_id != original

    approved, reason, switched = _launch("/popup-approved", _c)
    assert approved is True
    assert reason == "popup_activated"
    assert switched is True


def test_unapproved_popup_is_closed_and_original_stays_active() -> None:
    async def _c(page: Any, _reached: list[str]) -> object:
        registry = BrowserPageRegistry(url_allowed=lambda url: url.startswith(f"https://{_HOST}"))
        original = registry.register(page, active=True)
        async with page.context.expect_page() as info:
            await page.click("button")
        popup = await info.value
        decision = await registry.consider_popup(popup, opener_page_id=original)
        return (
            decision.activated,
            decision.reason_code,
            registry.active_page_id == original,
            registry.events,
        )

    activated, reason, stayed, events = _launch("/popup-evil", _c, guard=True)
    assert activated is False
    assert reason == "popup_blocked"
    assert stayed is True
    assert "popup_blocked" in events


# ===========================================================================
# 6. Duplicate target -> target_ambiguous
# ===========================================================================
def test_duplicate_target_returns_target_ambiguous() -> None:
    async def _c(page: Any, _reached: list[str]) -> object:
        elements, _ = await build_ranked_snapshot(page, reviewed_patterns=_PATTERNS)
        manage = [e for e in elements if e.name == "Manage"]
        identity = ElementIdentity(role=manage[0].role, name="Manage", element_type="")
        return len(manage), resolve_identity(identity, elements)[0]

    count, status = _launch("/duplicate", _c)
    assert count >= 2
    assert status == "ambiguous"


# ===========================================================================
# 7/8. select_option and checkbox postconditions
# ===========================================================================
def test_select_option_verifies_the_selected_value() -> None:
    async def _c(page: Any, _reached: list[str]) -> object:
        await page.select_option("[data-testid=plan]", "pro")
        value = await page.locator("[data-testid=plan]").input_value()
        return value

    assert _launch("/select", _c) == "pro"


def test_checkbox_verifies_checked_state() -> None:
    """The checked assertion must be bound to the checkbox that was acted on.

    A bare ``checked_state=True`` is deliberately NO LONGER sufficient: it used to
    be satisfied by any already-checked control anywhere on the page, so a no-op
    could be mistaken for a real transition.
    """

    async def _c(page: Any, _reached: list[str]) -> object:
        before_elements, _ = await build_ranked_snapshot(page, reviewed_patterns=_PATTERNS)
        before = _inspection(page.url, elements=before_elements)
        await page.check("[data-testid=read]")
        after_elements, _ = await build_ranked_snapshot(page, reviewed_patterns=_PATTERNS)
        after = _inspection(page.url, elements=after_elements, fingerprint="fp2")

        bound = CandidatePostcondition(target=ElementPredicate(test_id="read"), checked_state=True)
        untargeted = CandidatePostcondition(checked_state=True)
        return (
            await page.locator("[data-testid=read]").is_checked(),
            postcondition_satisfied(bound, before=before, after=after),
            postcondition_satisfied(untargeted, before=before, after=after),
        )

    checked, verified_bound, verified_untargeted = _launch("/checkbox", _c)
    assert checked is True
    # Bound to the acted-on element: verified.
    assert verified_bound is True
    # Unbound: refused, because it cannot prove WHICH element changed.
    assert verified_untargeted is False


# ===========================================================================
# 9. Dialogs
# ===========================================================================
def test_confirm_dialog_requires_hitl() -> None:
    async def _c(page: Any, _reached: list[str]) -> object:
        records: list[DialogRecord] = []
        install_dialog_handler(page, DialogPolicy(), records)
        await page.click("[data-testid=go]")
        await page.wait_for_timeout(300)
        # The dialog was answered (page not wedged) but flagged for a human.
        return [(r.kind, r.outcome, r.reason_code) for r in records], await page.evaluate(
            "() => window.confirmed"
        )

    records, confirmed = _launch("/confirm", _c)
    assert ("confirm", "requires_human", "confirm_requires_human") in records
    assert confirmed is False  # dismissed, never auto-accepted


def test_prompt_dialog_requires_hitl_and_page_is_not_wedged() -> None:
    async def _c(page: Any, _reached: list[str]) -> object:
        records: list[DialogRecord] = []
        install_dialog_handler(page, DialogPolicy(), records)
        await page.click("[data-testid=go]")
        await page.wait_for_timeout(300)
        # The page still responds -> the dialog did not wedge the browser.
        title = await page.title()
        return [(r.kind, r.outcome) for r in records], title is not None

    records, responsive = _launch("/prompt", _c)
    assert ("prompt", "requires_human") in records
    assert responsive is True


# ===========================================================================
# 10. Downloads blocked by default
# ===========================================================================
def test_download_blocked_by_default() -> None:
    async def _c(page: Any, _reached: list[str]) -> object:
        records: list[DownloadRecord] = []
        install_download_guard(page, DownloadPolicy(), records)
        try:
            await page.click("[data-testid=dl]")
        except Exception:
            pass
        await page.wait_for_timeout(600)
        return [(r.allowed, r.reason_code) for r in records]

    records = _launch("/download", _c)
    assert records, "a download event should have been observed"
    assert all(allowed is False for allowed, _ in records)
    assert any(reason == "download_blocked_by_policy" for _, reason in records)


def test_forbidden_filetypes_are_never_downloaded() -> None:
    policy = DownloadPolicy(allowed=True)
    for name in ("id_rsa", "key.pem", "installer.exe", "secrets.env", "vault.kdbx"):
        assert policy.forbidden_name.search(name), name
    assert policy.forbidden_name.search("report.csv") is None


# ===========================================================================
# 11/12/13/14. Staged egress policy
# ===========================================================================
def test_off_domain_fetch_and_script_are_blocked() -> None:
    async def _c(page: Any, _reached: list[str]) -> object:
        await page.wait_for_timeout(900)  # let the img/script/fetch attempts fire
        return list(_reached)

    reached = _launch("/offdomain", _c, guard=True)
    # The production guard aborts them, so the spy never sees an allowed request.
    assert reached == [], f"off-domain requests were not blocked: {reached}"


def test_reviewed_identity_provider_resources_allowed_only_while_authenticating() -> None:
    policy = build_egress_policy((_HOST,), identity_provider_hosts=(_IDP,))
    idp_url = f"https://{_IDP}/authorize"
    # PRE_AUTH: the IdP is not yet in play.
    assert policy.permits(url=idp_url, kind="document", stage=EgressStage.PRE_AUTH) is False
    # AUTHENTICATING: reviewed IdP resources are allowed.
    assert policy.permits(url=idp_url, kind="document", stage=EgressStage.AUTHENTICATING) is True
    assert policy.permits(url=idp_url, kind="script", stage=EgressStage.AUTHENTICATING) is True
    # AUTHENTICATED: the IdP is dropped again.
    assert policy.permits(url=idp_url, kind="document", stage=EgressStage.AUTHENTICATED) is False


def test_post_auth_policy_tightens_and_unknown_kinds_fail_closed() -> None:
    policy = build_egress_policy(
        (_HOST,), passive_asset_hosts=("cdn.pipedrive.com",), post_auth_hosts=("api.pipedrive.com",)
    )
    asset = "https://cdn.pipedrive.com/logo.png"
    # A passive asset host is fine pre-auth...
    assert policy.permits(url=asset, kind="image", stage=EgressStage.PRE_AUTH) is True
    # ...and refused once a credential may be on screen.
    assert policy.permits(url=asset, kind="image", stage=EgressStage.CREDENTIAL_SURFACE) is False
    # The vendor itself remains reachable at the tightest stage.
    assert (
        policy.permits(
            url=f"https://{_HOST}/settings/api",
            kind="document",
            stage=EgressStage.CREDENTIAL_SURFACE,
        )
        is True
    )
    # An unknown resource kind fails closed at every stage.
    for stage in EgressStage:
        assert (
            policy.permits(url=f"https://{_HOST}/x", kind="totally-unknown", stage=stage) is False
        )


def test_egress_stage_never_loosens() -> None:
    tracker = EgressStageTracker()
    tracker.advance_to(EgressStage.CREDENTIAL_SURFACE)
    assert tracker.advance_to(EgressStage.PRE_AUTH) is EgressStage.CREDENTIAL_SURFACE


# ===========================================================================
# 15. The LLM cannot create an unknown candidate
# ===========================================================================
def test_llm_cannot_create_an_unknown_candidate() -> None:
    with pytest.raises(ValueError, match="not in the generated policy set"):
        validate_choice(
            {"decision": "select_candidate", "candidate_id": "c_forged", "reason": ""},
            candidate_ids=["c_real"],
        )
    # ...and selection refuses an id the policy never produced.
    real = generate_candidates(
        elements=build_snapshot([{"tag": "button", "name": "API keys"}]),
        checkpoint_signals=("API",),
        checkpoint_order=1,
        trace_version="2.0",
        expected_postcondition="done",
    )
    with pytest.raises(ValueError):
        select_candidate(real, "c_forged")


# ===========================================================================
# 16. Provider timeout does not exhaust the browser deadline
# ===========================================================================
class _SlowBackend:
    name = "slow"

    def generate_json(self, prompt: str, schema: object) -> dict:
        time.sleep(5.0)  # far longer than the per-provider budget
        return {"decision": "report_hitl", "candidate_id": None, "reason": "late"}


class _FastBackend:
    name = "fast"

    def __init__(self) -> None:
        self.calls = 0

    def generate_json(self, prompt: str, schema: object) -> dict:
        self.calls += 1
        return {"decision": "report_hitl", "candidate_id": None, "reason": "ok"}


def test_provider_timeout_does_not_exhaust_the_browser_deadline() -> None:
    fast = _FastBackend()
    inference = JsonInference(
        [_SlowBackend(), fast],
        budget=DecisionBudget(total_seconds=3.0, provider_seconds=0.5, max_providers=3),
    )
    started = time.monotonic()
    result = inference.generate("prompt")
    elapsed = time.monotonic() - started
    # The slow provider was abandoned at its per-attempt cap and the next one won.
    assert result.provider == "fast"
    assert fast.calls == 1
    assert elapsed < 3.0, f"decision took {elapsed:.2f}s"
    assert "provider_timeout" in inference.last_reason_codes


def test_total_budget_is_enforced_and_reason_is_typed() -> None:
    inference = JsonInference(
        [_SlowBackend(), _SlowBackend(), _SlowBackend()],
        budget=DecisionBudget(total_seconds=1.2, provider_seconds=0.4, max_providers=3),
    )
    started = time.monotonic()
    with pytest.raises(DecisionFailed) as exc_info:
        inference.generate("prompt")
    elapsed = time.monotonic() - started
    assert exc_info.value.reason_code in {"provider_timeout", "all_providers_failed"}
    assert elapsed < 2.5, f"decision overran its total budget: {elapsed:.2f}s"


def test_programming_error_in_a_backend_propagates() -> None:
    class _Broken:
        name = "broken"

        def generate_json(self, prompt: str, schema: object) -> dict:
            raise TypeError("bad kwarg")

    inference = JsonInference([_Broken()], budget=DecisionBudget(total_seconds=2.0))
    with pytest.raises(TypeError):
        inference.generate("prompt")


# ===========================================================================
# Snapshot ranking + hidden/disabled controls
# ===========================================================================
def test_hidden_and_disabled_controls_never_become_candidates() -> None:
    async def _c(page: Any, _reached: list[str]) -> object:
        elements, _ = await build_ranked_snapshot(page, reviewed_patterns=_PATTERNS)
        candidates = generate_candidates(
            elements=elements,
            checkpoint_signals=("API keys",),
            checkpoint_order=1,
            trace_version="2.0",
            expected_postcondition="done",
        )
        return (
            [(e.name, e.visible, e.enabled) for e in elements if e.name == "API keys"],
            len(candidates),
        )

    states, candidate_count = _launch("/hidden-disabled", _c)
    assert states, "the controls should still be SEEN in the snapshot"
    assert all(not (visible and enabled) for _n, visible, enabled in states)
    assert candidate_count == 0, "a hidden/disabled control must not be actionable"


def test_ranking_puts_checkpoint_relevant_elements_first() -> None:
    raw = [
        {"role": "a", "name": "Careers", "visible": True, "enabled": True, "_top": 10.0},
        {"role": "button", "name": "API keys", "visible": True, "enabled": True, "_top": 900.0},
    ]
    ranked = rank_raw_elements(raw, checkpoint_signals=("API keys",), limit=2)
    assert ranked[0]["name"] == "API keys"  # relevance beats viewport position


# ===========================================================================
# Risk policy
# ===========================================================================
def _candidate(action: str, target: str, **kw: object) -> ActionCandidate:
    fields: dict[str, object] = {
        "candidate_id": "c_x",
        "action": action,
        "semantic_target": target,
        "identity": None,
        "risk": "low",
        "expected_postcondition": "done",
        "trace_version": "2.0",
        "checkpoint_order": 1,
    }
    fields.update(kw)
    return ActionCandidate(**fields)  # type: ignore[arg-type]


def _checkpoint(**kw: object) -> BrowserApiTraceStep:
    fields: dict[str, object] = {
        "order": 1,
        "instruction": "x",
        "expected_signals": ("API",),
        "completion": CheckpointPredicate(visible_text_contains=("API token",)),
    }
    fields.update(kw)
    return BrowserApiTraceStep(**fields)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "label",
    [
        "Create API key",
        "Generate token",
        "Save changes",
        "Authorize app",
        "Install integration",
        "Invite teammate",
        "Delete workspace",
        "Revoke key",
        "Upgrade plan",
        "I agree",
        "Reveal token",
    ],
)
def test_risk_policy_requires_hitl_for_consequential_verbs(label: str) -> None:
    decision = BrowserActionRiskPolicy().classify(
        candidate=_candidate("click", label), checkpoint=_checkpoint(), element=None
    )
    assert decision.autonomous_allowed is False
    assert decision.level == "irreversible"


def test_risk_policy_allows_ordinary_navigation_and_read_only() -> None:
    policy = BrowserActionRiskPolicy()
    nav = policy.classify(
        candidate=_candidate("click", "API keys"), checkpoint=_checkpoint(), element=None
    )
    assert nav.autonomous_allowed is True
    assert nav.level == "state_changing"

    read = policy.classify(
        candidate=_candidate("focus", "Create API key"), checkpoint=_checkpoint(), element=None
    )
    assert read.autonomous_allowed is True  # focusing changes nothing
    assert read.level == "read_only"


def test_risk_policy_refuses_a_value_ref_the_checkpoint_did_not_authorize() -> None:
    decision = BrowserActionRiskPolicy().classify(
        candidate=_candidate("fill", "Company", value_ref="company_name"),
        checkpoint=_checkpoint(allowed_value_refs=()),
        element=None,
    )
    assert decision.autonomous_allowed is False
    assert decision.reason_code == "value_ref_not_authorized_by_checkpoint"


def test_risk_policy_never_lets_the_agent_type_into_a_credential_field() -> None:
    secret = SnapshotElement(
        index=0, role="input", name="API token", element_type="password", secretish=True
    )
    decision = BrowserActionRiskPolicy().classify(
        candidate=_candidate("fill", "API token", value_ref="company_name"),
        checkpoint=_checkpoint(allowed_value_refs=("company_name",)),
        element=secret,
    )
    assert decision.autonomous_allowed is False


# ===========================================================================
# Identity resolution order
# ===========================================================================
def test_identity_prefers_test_id_then_frame_scoped_role_name() -> None:
    a = SnapshotElement(index=0, role="button", name="Manage", test_id="t1")
    b = SnapshotElement(index=1, role="button", name="Manage", test_id="t2")
    status, hit = resolve_identity(ElementIdentity("button", "Manage", test_id="t2"), (a, b))
    assert status == "resolved" and hit is not None and hit.index == 1


def test_identity_is_frame_scoped() -> None:
    main = SnapshotElement(index=0, role="button", name="Sign in")
    framed = SnapshotElement(index=1, role="button", name="Sign in", frame_path=(_HOST,))
    status, hit = resolve_identity(
        ElementIdentity("button", "Sign in", frame_path=(_HOST,)), (main, framed)
    )
    assert status == "resolved" and hit is not None and hit.index == 1


def test_identity_not_found_is_reported() -> None:
    status, hit = resolve_identity(ElementIdentity("button", "Nope"), ())
    assert status == "not_found" and hit is None


def test_element_predicate_matches_by_identity_not_selector() -> None:
    element = SnapshotElement(index=0, role="button", name="API keys", test_id="k")
    assert ElementPredicate(test_id="k").matches(element) is True
    assert ElementPredicate(role="button", name="API").matches(element) is True
    assert ElementPredicate(role="link", name="API").matches(element) is False
