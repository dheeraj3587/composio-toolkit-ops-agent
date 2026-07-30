"""Session lifecycle policy: continuity keeps, only run release and the janitor end.

Requirements 15.3, 15.6, 15.7, 15.8 — a run's authenticated session survives every
continuity event, and it goes away only on a deliberate run release or under the
janitor's configured idle/max-age policy.
"""

from __future__ import annotations

import asyncio

from browser_service.session_manager import (
    SESSION_CONTINUITY_EVENTS,
    SessionManager,
)

OWNER = "assignment-owner"


def test_continuity_events_keep_the_session_and_cancel_releases_it() -> None:
    manager = SessionManager(
        max_sessions=1,
        inactivity_seconds=900,
        maximum_age_seconds=3600,
        drain_seconds=0.1,
    )

    async def scenario() -> None:
        session = manager.create(
            owner=OWNER,
            app_slug="pipedrive",
            live_view_mode="screenshot",
            run_id="run_1",
            account_ref="acct_1",
        )
        # Verification, CAPTCHA pause, navigation retry, worker restart, API restart,
        # and a live-view client disconnect all keep the bound session.
        for event in sorted(SESSION_CONTINUITY_EVENTS):
            assert manager.retain(session.session_id, event=event).lifecycle == "ACTIVE"
        assert manager.expired_session_ids() == ()
        assert manager.capacity_in_use == 1

        released = await manager.release_run("run_1", reason_code="run_cancelled", owner=OWNER)
        assert released == (session.session_id,)
        assert manager.get_if_present(session.session_id) is None
        assert manager.capacity_in_use == 0

    asyncio.run(scenario())
