"""Happy path for the login route: references in, ``authenticated`` requested out.

One walk through what task 15.3 exists for. The run's recorded admission decision
carries two vault references, the handler mints one transient grant per reference,
the fake worker reports the provider accepted the submission, and the handler
returns the advancing step the driver commits (Requirements 8.1, 8.6, 8.8).

The broker, the worker, and the gate-resolution seam are fakes injected through
the module's own ports. The seam fails the test if it is consulted at all: an
accepted login has no gate to dispose of.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal, cast

import pytest

from ops.browser.login import (
    LOGIN_ACCEPTED,
    GateDisposition,
    LoginGrant,
    LoginObservation,
    LoginRouteContext,
    LoginRouteHandler,
)
from ops.browser.worker import HumanActionType
from ops.onboarding.admission import AdmissionDecision
from ops.onboarding.driver import OnboardingDeps
from ops.onboarding.lease import Lease, deadline_after

RUN_ID = "run-login-001"
APP_SLUG = "example-provider"
ACCOUNT_REF = "owner-onboarding:example-provider"
SESSION_ID = "bs_" + "0" * 32
EFFECT_IDENTITY = "eff-" + "1" * 16

_REFS: tuple[tuple[str, str], ...] = (
    ("login_email", f"vault://{APP_SLUG}/account_login_login_email/email-ref-0001"),
    ("login_password", f"vault://{APP_SLUG}/account_login_login_password/pass-ref-0001"),
)


class _FakeContextStore:
    """The durable login context, as the admission service recorded it."""

    def __init__(self, context: LoginRouteContext) -> None:
        self._context = context

    def login_context(self, *, run_id: str) -> LoginRouteContext | None:
        return self._context if run_id == self._context.decision.run_id else None


class _FakeBroker:
    """Records every grant reservation; resolves nothing, because it cannot."""

    def __init__(self) -> None:
        self.reservations: list[dict[str, object]] = []

    def reserve_browser_secret_grant(
        self,
        *,
        operation_key: str,
        run_id: str,
        session_id: str,
        app_slug: str,
        kind: str,
        action: Literal["consume", "capture"],
        reference: str | None = None,
        ttl_seconds: int = 900,
    ) -> str:
        self.reservations.append(
            {
                "operation_key": operation_key,
                "run_id": run_id,
                "session_id": session_id,
                "app_slug": app_slug,
                "kind": kind,
                "action": action,
                "reference": reference,
                "ttl_seconds": ttl_seconds,
            }
        )
        return f"bsg_grant_{len(self.reservations)}"


class _AcceptingWorker:
    """The trusted worker: consumes the grants in-process and gets an acceptance."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    async def submit_login(
        self,
        *,
        run_id: str,
        session_id: str,
        account_ref: str,
        grants: Sequence[LoginGrant],
    ) -> LoginObservation:
        self.calls.append(
            {
                "run_id": run_id,
                "session_id": session_id,
                "account_ref": account_ref,
                "grants": tuple(grants),
            }
        )
        return LoginObservation(accepted=True)


class _UnusedSeam:
    """An accepted login delegates nothing, so being called at all is a failure."""

    async def dispose(
        self,
        *,
        run_id: str,
        session_id: str,
        gate_type: HumanActionType,
        account_ref: str,
    ) -> GateDisposition:
        raise AssertionError("an accepted login must not consult the gate-resolution seam")


def _context() -> LoginRouteContext:
    decision = AdmissionDecision(
        run_id=RUN_ID,
        profile_digest="a" * 64,
        route="login",
        reason_code="credentials_present",
        decided_by="system",
        actor_owner_id="owner-onboarding",
        decided_at="2025-01-01T00:00:00+00:00",
        credential_refs=_REFS,
    )
    return LoginRouteContext(
        decision=decision,
        session_id=SESSION_ID,
        app_slug=APP_SLUG,
        account_ref=ACCOUNT_REF,
        effect_identity=EFFECT_IDENTITY,
    )


@pytest.mark.asyncio
async def test_accepted_login_requests_the_authenticated_boundary() -> None:
    """References reach the worker as grants, and acceptance advances the phase."""

    broker = _FakeBroker()
    worker = _AcceptingWorker()
    handler = LoginRouteHandler(
        context=_FakeContextStore(_context()),
        broker=broker,
        worker=worker,
        gates=_UnusedSeam(),
    )

    step = await handler(
        run_id=RUN_ID,
        phase="route_selected_login",
        profile=None,
        lease=Lease(
            run_id=RUN_ID,
            worker_id="worker-1",
            fencing_token=1,
            deadline=deadline_after(300),
        ),
        deps=cast(OnboardingDeps, None),
    )

    # Requirement 8.6: acceptance asks for the ``authenticated`` boundary, and
    # asks only — the handler commits nothing itself.
    assert step.kind == "advance"
    assert step.next_phase == "authenticated"
    assert step.reason_code == LOGIN_ACCEPTED

    # Requirement 8.1: one grant per reference, references only, no value.
    grants = cast(tuple[LoginGrant, ...], worker.calls[0]["grants"])
    assert [grant.field for grant in grants] == ["login_email", "login_password"]
    assert [grant.reference for grant in grants] == [reference for _, reference in _REFS]
    assert all(grant.grant.startswith("bsg_") for grant in grants)
    assert [reservation["action"] for reservation in broker.reservations] == ["consume", "consume"]

    # Requirement 8.8: the account binding the admission probe used, unchanged.
    assert worker.calls[0]["account_ref"] == ACCOUNT_REF
    assert worker.calls[0]["session_id"] == SESSION_ID
    assert {reservation["app_slug"] for reservation in broker.reservations} == {APP_SLUG}
