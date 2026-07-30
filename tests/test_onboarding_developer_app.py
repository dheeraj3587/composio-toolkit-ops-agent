"""One happy path through the developer-application phase (LL-3.5, LL-4.2).

The path that matters: the profile's declared flows are supported and ungated, so
the phase derives a deterministic application name, reserves ``create_dev_app``
under it, drives the console page to ``done``, records the non-secret application
id as the effect receipt, and asks for ``credential_generation``
(Requirements 9.2, 9.4, 9.5, 9.6, 9.11). The two pauses that reserve nothing —
an unsupported flow and a gated provider — are checked on the same profile
(Requirements 9.7, 9.10).
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from dataclasses import replace

from ops.browser.candidates import ActionCandidate
from ops.browser.worker import BrowserObservation
from ops.core.effect_ledger import SQLiteEffectStore
from ops.onboarding.action_loop import LoopObservation
from ops.onboarding.driver import (
    DEVELOPER_APP_RECEIPT_KEY,
    DeveloperAppRequest,
    OnboardingDeps,
    developer_app_flows,
    developer_app_gate,
    developer_app_name,
    drive_developer_app,
)
from ops.onboarding.effects import EFFECT_PROVIDER, create_dev_app_key
from ops.onboarding.lease import Lease, deadline_after
from ops.onboarding.phase import OnboardingPhase
from ops.providers.profile import FieldEvidence, FlowSpec, ProviderProfile, compute_profile_digest

RUN_ID = "run-devapp-1"
OWNER = "owner-onboarding"
APP_ID = "app_42"

_RAW_ELEMENTS: tuple[Mapping[str, object], ...] = (
    {"role": "button", "name": "Create app", "visible": True, "enabled": True},
)


def _profile() -> ProviderProfile:
    profile = ProviderProfile(
        run_id=RUN_ID,
        provider_name="Example Provider",
        app_slug="example-provider",
        registrable_domain="example.com",
        auxiliary_hosts=(),
        developer_portal_url="https://console.example.com/apps",
        signup_url="https://example.com/signup",
        login_url="https://console.example.com/login",
        developer_docs_url="https://console.example.com/docs",
        developer_app_flow=FlowSpec(
            kind="developer_app",
            supported=True,
            entry_url="https://console.example.com/apps",
            steps=("Open the developer console", "Create app"),
        ),
        oauth_flow=FlowSpec(kind="oauth", supported=False, entry_url=None),
        api_key_flow=FlowSpec(
            kind="api_key",
            supported=True,
            entry_url="https://console.example.com/settings/api",
            produces=("api_key",),
        ),
        pat_flow=FlowSpec(kind="pat", supported=False, entry_url=None),
        approval_requirement="unknown",  # Requirement 9.9: unknown proceeds.
        billing_requirement="none",
        evidence=(
            FieldEvidence(
                field="developer_portal_url",
                value="https://console.example.com/apps",
                source_url="https://console.example.com/docs",
                source_digest="a" * 64,
                adapters=("fake-discovery",),
                corroborations=2,
                confidence=0.9,
                extracted_at="2025-01-01T00:00:00Z",
            ),
        ),
        confidence=0.9,
        adapters_engaged=("fake-discovery",),
        built_at="2025-01-01T00:00:00Z",
    )
    return replace(profile, profile_digest=compute_profile_digest(profile))


class _Session:
    """A two-step console: the create-app control, then the created app."""

    def __init__(self) -> None:
        self.acted: list[ActionCandidate] = []

    async def observe(self) -> LoopObservation:
        if self.acted:
            return LoopObservation(
                observation=BrowserObservation(
                    status="developer_console_ready",
                    current_url="https://console.example.com/apps/created",
                    page_title="App created",
                    developer_app_id=APP_ID,
                )
            )
        return LoopObservation(
            observation=BrowserObservation(
                status="developer_console_ready",
                current_url="https://console.example.com/apps",
                page_title="Apps",
            ),
            raw_elements=_RAW_ELEMENTS,
        )

    async def act(self, candidate: ActionCandidate) -> None:
        self.acted.append(candidate)


class _Sessions:
    def __init__(self, session: _Session) -> None:
        self.session = session
        self.opened: list[OnboardingPhase] = []

    async def session_for(self, *, run_id: str, phase: OnboardingPhase, lease: Lease) -> _Session:
        self.opened.append(phase)
        return self.session


class _Decider:
    """Picks the first id the schema offers, as a constrained backend would."""

    async def choose(self, prompt: str, *, schema: Mapping[str, object]) -> Mapping[str, object]:
        properties = schema["properties"]
        assert isinstance(properties, Mapping)
        candidate_id = properties["candidate_id"]
        assert isinstance(candidate_id, Mapping)
        ids = candidate_id["enum"]
        assert isinstance(ids, Sequence)
        return {"decision": "select_candidate", "candidate_id": ids[0], "reason": "next step"}


class _Telemetry:
    def denial(self, reason_code: str) -> None:
        return None

    def reject(self, reason_code: str) -> None:
        return None

    def dlp_refusal(self) -> None:
        return None

    def action(self, *, candidate_id: str, actions_executed: int) -> None:
        return None

    def model_call(self, *, model_calls: int) -> None:
        return None


def _deps(sessions: _Sessions) -> OnboardingDeps:
    """The driver's dep bundle, wired only where this phase reads it."""

    unused: object = object()
    return OnboardingDeps(
        leases=unused,  # type: ignore[arg-type]
        phases=unused,  # type: ignore[arg-type]
        profiles=unused,  # type: ignore[arg-type]
        queue=unused,  # type: ignore[arg-type]
        goals=unused,  # type: ignore[arg-type]
        sessions=sessions,
        decider=_Decider(),
        telemetry=_Telemetry(),
    )


def test_the_declared_flow_creates_one_application_and_advances(tmp_path) -> None:  # type: ignore[no-untyped-def]
    profile = _profile()
    request = DeveloperAppRequest(owner_id=OWNER, credential_kind="api_key")
    effects = SQLiteEffectStore(tmp_path / "private" / "effects.db")
    session = _Session()
    sessions = _Sessions(session)
    lease = Lease(
        run_id=RUN_ID, worker_id="worker-a", fencing_token=1, deadline=deadline_after(300)
    )

    step = asyncio.run(
        drive_developer_app(
            run_id=RUN_ID,
            profile=profile,
            request=request,
            lease=lease,
            effects=effects,
            deps=_deps(sessions),
        )
    )

    # Requirements 9.6, 9.11: the effect completed with the non-secret id first,
    # and the phase asks for credential_generation — which the driver commits.
    assert (step.kind, step.next_phase) == ("advance", "credential_generation")
    assert step.reason_code == "developer_app_created"
    assert sessions.opened == ["developer_app"]
    assert [candidate.action for candidate in session.acted] == ["click"]

    # Requirements 9.4, 9.5: the key is derived from the deterministic name, so a
    # second worker presenting it is told the application already exists.
    key = create_dev_app_key(RUN_ID, profile, developer_app_name(owner_id=OWNER, run_id=RUN_ID))
    reservation = effects.reserve(
        provider=EFFECT_PROVIDER, action="create_dev_app", idempotency_key=key
    )
    assert reservation.status == "completed"
    assert reservation.receipt == {DEVELOPER_APP_RECEIPT_KEY: APP_ID, "flow_kind": "developer_app"}


def test_an_unsupported_flow_and_a_gated_provider_reserve_nothing(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Requirements 9.7, 9.10: both answers are reached above the reservation."""

    profile = _profile()
    effects = SQLiteEffectStore(tmp_path / "private" / "effects.db")
    sessions = _Sessions(_Session())

    # The profile declares no supported PAT flow, so no application is created.
    unsupported = asyncio.run(
        drive_developer_app(
            run_id=RUN_ID,
            profile=profile,
            request=DeveloperAppRequest(owner_id=OWNER, credential_kind="personal_access_token"),
            lease=Lease(
                run_id=RUN_ID, worker_id="worker-a", fencing_token=1, deadline=deadline_after(300)
            ),
            effects=effects,
            deps=_deps(sessions),
        )
    )

    assert (unsupported.kind, unsupported.reason_code) == ("pause", "flow_unsupported")
    # No browser was opened and no key was reserved: a fresh presentation of the
    # key this run would have used is still unreserved.
    assert sessions.opened == []
    key = create_dev_app_key(RUN_ID, profile, developer_app_name(owner_id=OWNER, run_id=RUN_ID))
    assert (
        effects.reserve(
            provider=EFFECT_PROVIDER, action="create_dev_app", idempotency_key=key
        ).status
        == "reserved"
    )

    # An approval requirement the run cannot self-serve is a pause, while the
    # `unknown` requirement above was not (Requirement 9.9).
    gated = replace(profile, approval_requirement="manual_review")
    assert developer_app_gate(gated) == "developer_app_approval_required"
    assert developer_app_gate(profile) is None
    assert developer_app_flows(profile, credential_kind="api_key") is not None
    assert developer_app_flows(profile, credential_kind="client_credentials_pair") is None
