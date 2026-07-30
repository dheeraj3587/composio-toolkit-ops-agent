"""Happy path for the operator-prompt counters (design LL-3.6, Requirement 11).

One walk through everything a run may be interrupted by. The run asks for
admission once and is refused a second ask; a legal-terms surface on an
allow-listed page is accepted with no prompt and the accepted document is
recorded as evidence; a cookie banner contributes nothing because it is not a
typed human action at all; and the CAPTCHA counter increments once per pause
until the budget answers with ``captcha_attempt_budget_exhausted`` and stops
prompting.

The phase-history store and the run ledger are the real SQLite ones in
``tmp_path`` — the at-most-once admission write and the durable prompt counts are
properties of their SQL — and the only fake is the paused session, whose
interesting property is that nothing here touches it.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from hashlib import sha256

import pytest

from ops.browser.host_policy import BrowserAllowedHosts
from ops.core.storage import OperationsStorage
from ops.onboarding.admission import AdmissionDecision
from ops.onboarding.driver import (
    CAPTCHA_BUDGET_EXHAUSTED,
    MAX_CAPTCHA_PAUSES,
    AuditTrailLegalEvidence,
    OperatorPrompts,
    PhaseStep,
    SQLitePhaseHistoryStore,
    accept_legal_terms,
    emit_admission_prompt,
    midflight_prompt_count,
    operator_prompts,
    pause_for_captcha,
)
from ops.onboarding.phase import OnboardingPhase, OnboardingReasonCode
from ops.providers.profile import (
    FieldEvidence,
    FlowSpec,
    ProviderProfile,
    compute_profile_digest,
)

RUN_ID = "run-prompts-001"
APP_SLUG = "example-provider"
OWNER = "owner-onboarding"
SESSION_ID = "browser-session-prompts-001"
TERMS_URL = "https://example.com/signup/terms?session=abc123"
TERMS_TEXT = "By creating an account you agree to the Example Provider terms of service."

# The walk that leaves the run durably at ``awaiting_admission``, which is the one
# phase the admission prompt may be emitted in.
_SEED_WALK: tuple[tuple[OnboardingPhase | None, OnboardingPhase, OnboardingReasonCode], ...] = (
    (None, "research", "profile_corroborated"),
    ("research", "vault_check", "profile_corroborated"),
    ("vault_check", "awaiting_admission", "credentials_missing"),
)


class _Session:
    """The bound session a pause holds open, plus a count of its releases."""

    def __init__(self) -> None:
        self.session_id = SESSION_ID
        self.releases = 0

    async def release(self) -> None:
        self.releases += 1


def _profile() -> ProviderProfile:
    evidence = FieldEvidence(
        field="signup_url",
        value="https://example.com/signup",
        source_url="https://example.com/docs",
        source_digest="a" * 64,
        adapters=("fake-discovery",),
        corroborations=2,
        confidence=0.9,
        extracted_at="2025-01-01T00:00:00Z",
    )
    profile = ProviderProfile(
        run_id=RUN_ID,
        provider_name="Example Provider",
        app_slug=APP_SLUG,
        registrable_domain="example.com",
        auxiliary_hosts=(),
        developer_portal_url="https://example.com/apps",
        signup_url="https://example.com/signup",
        login_url="https://example.com/login",
        developer_docs_url="https://example.com/docs",
        developer_app_flow=FlowSpec(
            kind="developer_app", supported=True, entry_url="https://example.com/apps"
        ),
        oauth_flow=FlowSpec(kind="oauth", supported=False, entry_url=None),
        api_key_flow=FlowSpec(kind="api_key", supported=False, entry_url=None),
        pat_flow=FlowSpec(kind="pat", supported=False, entry_url=None),
        approval_requirement="none",
        billing_requirement="none",
        evidence=(evidence,),
        confidence=0.9,
        adapters_engaged=("fake-discovery",),
        built_at="2025-01-01T00:00:00Z",
    )
    return replace(profile, profile_digest=compute_profile_digest(profile))


@pytest.fixture
def wired(tmp_path):
    db_path = tmp_path / "private" / "ops.db"
    ledger = OperationsStorage(db_path)
    ledger.create_run(
        run_id=RUN_ID,
        thread_id=f"thread-{RUN_ID}",
        app_name="Example Provider",
        app_slug=APP_SLUG,
    )
    phases = SQLitePhaseHistoryStore(db_path)
    profile = _profile()
    for from_phase, to_phase, reason_code in _SEED_WALK:
        assert phases.commit_phase(
            run_id=RUN_ID,
            from_phase=from_phase,
            to_phase=to_phase,
            reason_code=reason_code,
            profile_digest=profile.profile_digest,
            attempt=0,
            correlation_id=f"seed-{to_phase}",
        )
    return phases, ledger, profile


def test_admission_asks_once_terms_and_banners_ask_nothing_and_captcha_is_budgeted(
    wired,
) -> None:
    phases, ledger, profile = wired

    # --- the admission prompt: once, and only while it is due ----------------
    first = emit_admission_prompt(run_id=RUN_ID, app_name="Example Provider", prompts=phases)
    second = emit_admission_prompt(run_id=RUN_ID, app_name="Example Provider", prompts=phases)
    # Requirements 3.4 and 11.13: exactly one prompt, counted durably, and the
    # second ask is refused rather than duplicated.
    assert [request.type for request in first] == ["signup_authorization"]
    assert second == ()
    assert phases.admission_prompts(run_id=RUN_ID) == 1

    assert phases.commit_phase(
        run_id=RUN_ID,
        from_phase="awaiting_admission",
        to_phase="route_selected_signup",
        reason_code="operator_approved_signup",
        profile_digest=profile.profile_digest,
        attempt=0,
        correlation_id="seed-route_selected_signup",
    )
    # 11.13's second half: the prompt is scoped to ``awaiting_admission``, so a run
    # that has moved on cannot be asked even if the counter were zero.
    assert emit_admission_prompt(run_id=RUN_ID, app_name="Example Provider", prompts=phases) == ()

    # --- legal terms: accepted, promptless, and recorded as evidence ----------
    admission = AdmissionDecision(
        run_id=RUN_ID,
        profile_digest=profile.profile_digest,
        route="signup",
        reason_code="operator_approved_signup",
        decided_by="operator",
        actor_owner_id=OWNER,
        decided_at="2025-01-01T00:00:00Z",
    )
    allowed = BrowserAllowedHosts(
        app_slug=APP_SLUG,
        # The apex is an exact host and its subdomains are the vendor wildcard,
        # which is the shape the profile's own allow-list derivation produces.
        exact_hosts=(profile.registrable_domain,),
        vendor_wildcard_domains=(profile.registrable_domain,),
    )
    accepted = accept_legal_terms(
        run_id=RUN_ID,
        phase="signup",
        profile=profile,
        admission=admission,
        gate_url=TERMS_URL,
        document_text=TERMS_TEXT,
        allowed=allowed,
        evidence=AuditTrailLegalEvidence(ledger),
    )
    # Requirement 11.5: accepted under the run's own profile authority, no prompt.
    assert (accepted.accepted, accepted.authority, accepted.prompts) == (
        True,
        "profile_declared",
        0,
    )
    assert accepted.document is not None
    # Requirement 11.6: the accepted document is durable evidence — the digest of
    # the exact text, on a URL whose session-bearing query is gone, and no page
    # text copied into the row.
    events = [event for event in ledger.list_audit_events(RUN_ID) if "legal" in event["event_type"]]
    assert len(events) == 1
    payload = events[0]["payload"]
    assert payload["document_digest"] == sha256(TERMS_TEXT.encode("utf-8")).hexdigest()
    assert payload["url"] == "https://example.com/signup/terms"
    assert TERMS_TEXT not in str(payload)

    # A terms dialog rendered off the run's allow-list is not ours to accept, and
    # refusing it is still promptless (Requirement 11.14).
    off_list = accept_legal_terms(
        run_id=RUN_ID,
        phase="signup",
        profile=profile,
        admission=admission,
        gate_url="https://terms.other.test/agree",
        document_text=TERMS_TEXT,
        allowed=allowed,
        evidence=AuditTrailLegalEvidence(ledger),
    )
    assert (off_list.accepted, off_list.authority, off_list.prompts) == (False, "human_only", 0)

    # --- cookie banners: not a typed human action, so never a prompt ----------
    # Requirement 11.7: a dismissed banner is an ordinary observation, and the one
    # classification that costs a prompt is ``captcha``.
    assert midflight_prompt_count(None) == 0
    assert midflight_prompt_count("legal_acceptance") == 0
    assert midflight_prompt_count("captcha") == 1

    # --- the CAPTCHA counter and its budget ----------------------------------
    session = _Session()
    for pause in range(1, MAX_CAPTCHA_PAUSES + 1):
        assert asyncio.run(
            pause_for_captcha(
                run_id=RUN_ID, phase_at_pause="signup", session=session, pauses=phases
            )
        ) == PhaseStep.advance("captcha_paused", "captcha_detected")
        # Requirements 11.3 and 11.9: exactly one increment per pause.
        assert phases.captcha_pause(run_id=RUN_ID).prompts == pause

    exhausted = asyncio.run(
        pause_for_captcha(run_id=RUN_ID, phase_at_pause="signup", session=session, pauses=phases)
    )
    # Requirements 11.10 and 11.11: at the budget the run pauses without prompting,
    # and the count cannot creep past the bound.
    assert exhausted == PhaseStep.pause(CAPTCHA_BUDGET_EXHAUSTED)
    assert phases.captcha_pause(run_id=RUN_ID).prompts == MAX_CAPTCHA_PAUSES
    assert (session.session_id, session.releases) == (SESSION_ID, 0)

    # Requirement 11.15: the whole account, read from the durable counters.
    assert operator_prompts(run_id=RUN_ID, prompts=phases, pauses=phases) == OperatorPrompts(
        admission=1, captcha=MAX_CAPTCHA_PAUSES
    )
