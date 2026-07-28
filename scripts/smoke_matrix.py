"""Offline-first smoke report for the canonical 50-app recipe matrix.

The default command only validates checked-in data. Public network probes are
available behind an explicit flag and send one unauthenticated HEAD or bounded
GET request to each reviewed Playwright login URL. This module never imports or
calls Browser Use, You.com, Composio, Gmail, or an authenticated vendor flow.
"""

from __future__ import annotations

import argparse
import json
import ssl
import sys
from dataclasses import asdict, dataclass
from http.client import HTTPException
from pathlib import Path
from typing import Literal, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

from ops.app_recipes import (  # noqa: E402 - repository root bootstrap for direct execution
    AppRecipe,
    load_app_recipe_catalog,
    recipes_for_route,
)

ProbeMethod = Literal["HEAD", "GET"]
ProbeOutcome = Literal["reachable", "redirect", "protected", "server_error", "unreachable"]
_USER_AGENT = "composio-ops-recipe-smoke/1.0"


class _NoRedirects(HTTPRedirectHandler):
    """Return redirect responses without following them to an unreviewed host."""

    def redirect_request(
        self,
        req: Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


@dataclass(frozen=True, slots=True)
class ProbeResult:
    app_slug: str
    method: ProbeMethod
    host: str
    status: int | None
    outcome: ProbeOutcome
    reason_code: str


def _probe(recipe: AppRecipe, method: ProbeMethod, timeout: float) -> ProbeResult:
    """Send one credential-free request to a checked-in public login entry."""

    if recipe.urls.login is None or recipe.browser is None:
        raise ValueError("a public-entry probe requires a reviewed browser recipe")
    parsed = urlsplit(recipe.urls.login)
    host = (parsed.hostname or "").casefold()
    if host not in recipe.browser.exact_hosts:
        raise ValueError("public-entry host is outside the reviewed recipe")
    headers = {"Accept": "text/html", "User-Agent": _USER_AGENT}
    if method == "GET":
        # Servers may ignore Range, but the response body is never read.
        headers["Range"] = "bytes=0-0"
    request = Request(recipe.urls.login, headers=headers, method=method)
    opener = build_opener(_NoRedirects())
    try:
        with opener.open(request, timeout=timeout) as response:
            status = int(response.status)
    except HTTPError as exc:
        status = int(exc.code)
    except (URLError, TimeoutError, ssl.SSLError, HTTPException):
        return ProbeResult(
            app_slug=recipe.app_slug,
            method=method,
            host=host,
            status=None,
            outcome="unreachable",
            reason_code="public_entry_transport_error",
        )

    if 200 <= status < 300:
        outcome: ProbeOutcome = "reachable"
        reason = "public_entry_responded"
    elif 300 <= status < 400:
        outcome = "redirect"
        reason = "public_entry_redirected_without_following"
    elif status in {401, 403, 405, 429}:
        outcome = "protected"
        reason = "public_entry_reachable_but_protected"
    elif status >= 500:
        outcome = "server_error"
        reason = "public_entry_server_error"
    else:
        outcome = "unreachable"
        reason = "public_entry_unexpected_status"
    return ProbeResult(
        app_slug=recipe.app_slug,
        method=method,
        host=host,
        status=status,
        outcome=outcome,
        reason_code=reason,
    )


def build_report(
    *,
    probe_method: ProbeMethod | None = None,
    timeout: float = 10.0,
) -> dict[str, object]:
    """Validate all recipes and optionally probe the 14 public browser entries."""

    catalog = load_app_recipe_catalog()
    route_counts = {
        "managed_auth": len(recipes_for_route("managed_auth")),
        "playwright": len(recipes_for_route("playwright")),
        "gated": len(recipes_for_route("gated")),
    }
    readiness_counts: dict[str, int] = {}
    for recipe in catalog.apps:
        readiness_counts[recipe.readiness_tier] = readiness_counts.get(recipe.readiness_tier, 0) + 1
    probes = (
        [_probe(recipe, probe_method, timeout) for recipe in recipes_for_route("playwright")]
        if probe_method is not None
        else []
    )
    failures = sum(item.outcome in {"server_error", "unreachable"} for item in probes)
    return {
        "catalog_id": catalog.catalog_id,
        "schema_version": catalog.schema_version,
        "app_count": len(catalog.apps),
        "route_counts": route_counts,
        "readiness_counts": dict(sorted(readiness_counts.items())),
        "network_used": probe_method is not None,
        "external_requests_sent": len(probes),
        "state_changing_actions_taken": False,
        "probe_method": probe_method,
        "probe_count": len(probes),
        "probe_failures": failures,
        "probes": [asdict(item) for item in probes],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate the canonical 50-app recipe matrix. Defaults to offline; "
            "public entry probes require an explicit method."
        )
    )
    parser.add_argument(
        "--probe-public-entries",
        choices=("HEAD", "GET"),
        help=(
            "Explicitly send one unauthenticated, no-redirect request to each "
            "reviewed Playwright login URL."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Per-request timeout in seconds for explicit probes (default: 10).",
    )
    parser.add_argument("--json", action="store_true", help="Print the full sanitized JSON report.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not 0.5 <= args.timeout <= 30.0:
        raise SystemExit("--timeout must be between 0.5 and 30 seconds")
    method: ProbeMethod | None = args.probe_public_entries
    report = build_report(probe_method=method, timeout=args.timeout)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            "catalog={catalog_id} apps={app_count} routes={route_counts} "
            "readiness={readiness_counts} network_used={network_used} "
            "external_requests_sent={external_requests_sent} "
            "state_changing_actions_taken={state_changing_actions_taken}".format(**report)
        )
        for item in cast(list[dict[str, object]], report["probes"]):
            print(
                "{app_slug:<16} {method:<4} {host:<32} status={status} "
                "outcome={outcome} reason={reason_code}".format(**item)
            )
    return 1 if report["probe_failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
