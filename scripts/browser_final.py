"""One final real Browser Use v3 session for the selected fallback app (Pipedrive).

No Composio matrix and no Gemini call are run here. The verified official
Pipedrive developer URL is used directly. Exactly one session is created; it is
stopped at the end unless a human action is required (then it is kept alive for
owner interaction). No credentials are captured and no Gmail is sent.
"""

from __future__ import annotations

import asyncio

from ops.browser_worker import BrowserWorker
from ops.config import load_settings
from ops.p1_adapter import P1LookupFound, P1OperationalAdapter, to_operational_research

APP = "Pipedrive"
OFFICIAL_DEVELOPER_URL = "https://developers.pipedrive.com/"


def _line(text: str) -> None:
    print(text, flush=True)


async def main() -> None:
    settings = load_settings()
    if settings.browser_use_api_key is None or not settings.allow_live_browser:
        raise SystemExit("BROWSER_USE_API_KEY + ALLOW_LIVE_BROWSER are required")

    lookup = P1OperationalAdapter().lookup(APP)
    if not isinstance(lookup, P1LookupFound):
        raise SystemExit(f"{APP} not in P1 snapshot")
    research = to_operational_research(lookup.record)
    if not research.developer_portal_url:
        research = research.model_copy(update={"developer_portal_url": OFFICIAL_DEVELOPER_URL})

    worker = BrowserWorker(settings=settings)
    context = await worker.start(profile_id=None)
    live = worker.live_url(context.session_id)
    _line("Final real Browser Use v3 session:")
    _line(f"  app                 : {APP}")
    _line(f"  official_start_url  : {research.developer_portal_url}")
    _line(f"  session_id          : {context.session_id}")
    _line(f"  live_view_available : {context.live_view_available}")
    _line(f"  live_url            : {live or '(none)'}")

    try:
        observation = await worker.navigate_onboarding(context, research)
    except Exception as exc:  # noqa: BLE001 - report the concrete blocker
        _line(f"  navigation          : FAILED ({type(exc).__name__}: {exc})")
        _line(f"  stopping session {context.session_id} ...")
        try:
            await worker.stop(context)
            _line("  session stopped")
        except Exception as stop_exc:  # noqa: BLE001
            _line(f"  stop failed: {type(stop_exc).__name__}: {stop_exc}")
        return

    hitl = observation.status == "human_action_required"
    _line(f"  current_url         : {observation.current_url}")
    _line(f"  page_title          : {observation.page_title}")
    _line(f"  state               : {observation.status}")
    _line(f"  hitl_required       : {hitl} ({observation.human_action_type or 'none'})")
    if hitl:
        _line(f"  live_url (owner)    : {worker.live_url(context.session_id) or '(none)'}")
        _line(f"  session {context.session_id} kept ALIVE for owner interaction.")
        return
    await worker.stop(context)
    _line(f"  session {context.session_id} stopped (demo step complete).")


if __name__ == "__main__":
    asyncio.run(main())
