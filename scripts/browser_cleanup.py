"""Stop idle/created Browser Use sessions to reclaim credit. Read-then-stop only."""

from __future__ import annotations

import asyncio

from ops.config import load_settings


async def main() -> None:
    settings = load_settings()
    if settings.browser_use_api_key is None:
        raise SystemExit("BROWSER_USE_API_KEY missing")
    from browser_use_sdk.v3 import AsyncBrowserUse

    client = AsyncBrowserUse(api_key=settings.browser_use_api_key.get_secret_value(), timeout=30.0)
    listing = (await client.sessions.list()).model_dump(mode="json")
    sessions = listing.get("sessions", []) if isinstance(listing, dict) else []
    print(f"total sessions: {len(sessions)}")
    stopped = 0
    for item in sessions:
        if not isinstance(item, dict):
            continue
        sid = item.get("id")
        status = str(item.get("status"))
        if status in {"created", "idle", "running"} and isinstance(sid, str):
            try:
                await client.sessions.stop(sid)
                stopped += 1
                print(f"  stopped {sid} (was {status})")
            except Exception as exc:  # noqa: BLE001
                print(f"  stop failed {sid}: {type(exc).__name__}: {exc}")
    print(f"stopped {stopped} session(s)")


if __name__ == "__main__":
    asyncio.run(main())
