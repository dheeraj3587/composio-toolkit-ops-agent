"""Real, read-only Composio 10-app capability matrix.

Runs only Composio toolkit + ACTIVE connected-account lookups (no browser, no
Gmail, no connection creation, no credentials). Writes a sanitized table to
docs/live-10-app-matrix.json and docs/LIVE_10_APP_MATRIX.md.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

from ops.composio_capability import ComposioCapabilityPreflight
from ops.config import load_settings
from ops.p1_adapter import P1LookupFound, P1OperationalAdapter, to_operational_research

# 10 distinct apps covering every P1 route present in the snapshot
# (self_serve, approval_required, partner_gated, blocked; no hybrid/unknown exist).
APPS = [
    "HubSpot",
    "Pipedrive",
    "Attio",
    "Twenty",
    "Zendesk",
    "Google Ads",
    "WhatsApp Business",
    "Salesforce",
    "Close",
    "Sherlock",
]


def _resulting_action(p1_route: str, state: str) -> str:
    if state in {"composio_ready", "connection_required", "configuration_required"}:
        return {
            "composio_ready": "composio_ready",
            "connection_required": "composio_connection_required",
            "configuration_required": "configuration_required",
        }[state]
    # custom_auth_or_approval_required / toolkit_unavailable => P1 fallback route
    if p1_route in {"self_serve", "hybrid"}:
        return "browser_fallback"
    if p1_route in {"approval_required", "partner_gated"}:
        return "gated_outreach"
    return "configuration_required"


async def main() -> None:
    settings = load_settings()
    if settings.composio_api_key is None:
        raise SystemExit("COMPOSIO_API_KEY is required")
    adapter = P1OperationalAdapter()
    preflight = ComposioCapabilityPreflight(settings=settings)

    rows: list[dict[str, object]] = []
    for app in APPS:
        lookup = adapter.lookup(app)
        if not isinstance(lookup, P1LookupFound):
            raise SystemExit(f"{app} is not in the verified P1 snapshot")
        record = lookup.record
        p1_route = to_operational_research(record).access_route
        report = await preflight.evaluate(app_name=record.app, app_slug=record.slug)
        provider_error = (
            report.reason_code
            if report.capability_state == "configuration_required"
            and report.reason_code != "composio_not_configured"
            else None
        )
        rows.append(
            {
                "app_name": record.app,
                "app_slug": record.slug,
                "p1_access_route": p1_route,
                "composio_toolkit_slug": report.toolkit_slug,
                "toolkit_available": report.toolkit_available,
                "active_connection_available": report.active_connected_account,
                "capability_state": report.capability_state,
                "resulting_action": _resulting_action(p1_route, report.capability_state),
                "provider_error": provider_error,
                "external_action_taken": False,
            }
        )

    payload = {
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "composio_user_id": settings.composio_user_id,
        "app_count": len(rows),
        "external_action_taken": False,
        "results": rows,
    }
    docs = Path("docs")
    docs.mkdir(exist_ok=True)
    (docs / "live-10-app-matrix.json").write_text(json.dumps(payload, indent=2) + "\n")

    header = (
        "| App | Slug | P1 Route | Toolkit Slug | Toolkit Avail | Active Conn | "
        "Capability State | Resulting Action | Provider Error | External Action |"
    )
    sep = "| " + " | ".join(["---"] * 10) + " |"
    lines = [
        "# Live Composio 10-App Capability Matrix",
        "",
        f"Generated: {payload['generated_at']}",
        "",
        "Real, read-only Composio checks (toolkit lookup + ACTIVE connected-account "
        "lookup). No browser session, no Gmail, no connection creation, no credentials.",
        "",
        header,
        sep,
    ]
    for r in rows:
        lines.append(
            "| {app_name} | {app_slug} | {p1_access_route} | {composio_toolkit_slug} | "
            "{toolkit_available} | {active_connection_available} | {capability_state} | "
            "{resulting_action} | {provider_error} | {external_action_taken} |".format(**r)
        )
    (docs / "LIVE_10_APP_MATRIX.md").write_text("\n".join(lines) + "\n")

    for r in rows:
        print(
            f"{r['app_name']:<20} {r['p1_access_route']:<17} "
            f"slug={r['composio_toolkit_slug']} avail={r['toolkit_available']} "
            f"active={r['active_connection_available']} state={r['capability_state']} "
            f"action={r['resulting_action']} err={r['provider_error']}"
        )
    print("\nwrote docs/live-10-app-matrix.json and docs/LIVE_10_APP_MATRIX.md")


if __name__ == "__main__":
    asyncio.run(main())
