#!/usr/bin/env python3
"""Bounded, dry-run-first warming of verified P1 operational research.

The command uses the exact runtime ``OperationalResearchEnricher`` construction,
including You.com Search/Contents, Gemini extraction, current host policy, and the
shared SQLite cache.  It never starts a browser or sends an outreach message.

Examples:
    python scripts/warm_you_research.py --all
    python scripts/warm_you_research.py --app-slug pipedrive --execute
    python scripts/warm_you_research.py --all --execute --limit 5 --concurrency 2
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

# Running ``python scripts/warm_you_research.py`` puts scripts/ (not the project
# root) first on sys.path. Make the repository package import explicit.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ops.config import Settings  # noqa: E402
from ops.p1_adapter import (  # noqa: E402
    P1AppRecord,
    load_verified_snapshot,
    to_operational_research,
)
from ops.research_cache import SqliteResearchCache  # noqa: E402
from ops.run_service import RunService  # noqa: E402


class _ForceRefreshCache:
    """Bypass reads but retain normal keys/schema and write refreshed results.

    ``SqliteResearchCache`` remains the owner of locking and persistence.  This
    adapter is deliberately tiny: force-refresh means every normal runtime cache
    lookup is a miss for this invocation, while successful results overwrite their
    existing normal keys. It never stores secrets, prompts, or provider errors.
    """

    def __init__(self, delegate: SqliteResearchCache) -> None:
        self._delegate = delegate

    def get(self, key: str) -> Mapping[str, object] | None:
        del key
        return None

    def put(self, key: str, value: Mapping[str, object], *, expires_at: Any) -> None:
        self._delegate.put(key, value, expires_at=expires_at)

    def lock_for(self, key: str) -> Any:
        return self._delegate.lock_for(key)

    def close(self) -> None:
        self._delegate.close()


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    targets = parser.add_mutually_exclusive_group(required=True)
    targets.add_argument("--app-slug", help="one exact verified P1 app slug")
    targets.add_argument("--all", action="store_true", help="all verified P1 apps")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="permit bounded provider calls; without this flag the command is a dry run",
    )
    parser.add_argument("--limit", type=_positive_int, help="maximum selected app count")
    parser.add_argument(
        "--concurrency",
        type=_positive_int,
        default=1,
        help="maximum concurrent enrichments (default: 1; maximum: 5)",
    )
    parser.add_argument(
        "--force-refresh",
        action="store_true",
        help="bypass normal cache reads and refresh the same normal cache keys",
    )
    parser.add_argument(
        "--max-age-seconds",
        type=_positive_int,
        help="override the shared Contents/result-cache freshness window",
    )
    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="continue queued enrichments after an individual app failure",
    )
    parser.add_argument(
        "--output-summary",
        type=Path,
        help="write the sanitized final JSON summary to this path",
    )
    args = parser.parse_args(argv)
    if args.concurrency > 5:
        parser.error("--concurrency must be no greater than 5")
    return args


def _selected_records(args: argparse.Namespace) -> list[P1AppRecord]:
    snapshot = load_verified_snapshot()
    if args.all:
        records = list(snapshot.records)
    else:
        slug = str(args.app_slug).casefold()
        records = [record for record in snapshot.records if record.slug.casefold() == slug]
        if not records:
            raise ValueError("app_slug_not_in_verified_snapshot")
    if args.limit is not None:
        records = records[: args.limit]
    return records


def _summary_row(
    record: P1AppRecord,
    *,
    status: str,
    missing_fields: Sequence[str],
    verified_claim_count: int,
    reason_code: str = "",
) -> dict[str, object]:
    return {
        "app_slug": record.slug,
        "status": status,
        "reason_code": reason_code,
        "missing_fields": list(missing_fields),
        "missing_field_count": len(missing_fields),
        "verified_claim_count": verified_claim_count,
    }


def _dry_run(records: Sequence[P1AppRecord]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for record in records:
        baseline = to_operational_research(record)
        missing = _missing_fields(baseline.model_dump(mode="json"))
        rows.append(
            _summary_row(
                record,
                status="skipped",
                reason_code="dry_run",
                missing_fields=missing,
                verified_claim_count=len(baseline.operational_url_claims),
            )
        )
    return rows


def _missing_fields(research: Mapping[str, object]) -> list[str]:
    fields = (
        "api_base_url",
        "authorization_url",
        "token_url",
        "credential_fields",
        "credential_creation_instructions",
        "scopes",
        "developer_portal_url",
        "signup_url",
        "login_url",
        "credential_management_url",
    )
    return [name for name in fields if research.get(name) in (None, "", [], ())]


def _require_execute_configuration(settings: Settings) -> None:
    if settings.google_genai_api_key is None:
        raise ValueError("google_genai_api_key_required")
    if not settings.you_search_configured or not settings.you_contents_configured:
        raise ValueError("you_search_and_contents_must_be_enabled")


async def _execute(
    records: Sequence[P1AppRecord],
    *,
    settings: Settings,
    force_refresh: bool,
    concurrency: int,
    continue_on_error: bool,
) -> list[dict[str, object]]:
    _require_execute_configuration(settings)
    service = RunService.from_paths(db_path=settings.ops_db_path, settings=settings)
    if force_refresh:
        service._research_cache = _ForceRefreshCache(  # type: ignore[assignment]
            SqliteResearchCache(settings.research_cache_db_path)
        )
    enricher = service._build_research_enricher(settings)
    if enricher is None:  # defensive: configuration was checked above
        service.shutdown()
        raise ValueError("operational_research_enricher_unavailable")

    semaphore = asyncio.Semaphore(concurrency)
    stop_after_error = asyncio.Event()

    async def enrich_one(record: P1AppRecord) -> dict[str, object]:
        async with semaphore:
            if stop_after_error.is_set() and not continue_on_error:
                baseline = to_operational_research(record)
                return _summary_row(
                    record,
                    status="skipped",
                    reason_code="stopped_after_error",
                    missing_fields=_missing_fields(baseline.model_dump(mode="json")),
                    verified_claim_count=0,
                )
            baseline = to_operational_research(record)
            try:
                outcome = await enricher.enrich(
                    app_name=record.app,
                    p1_record=record.model_dump(mode="json"),
                    baseline=baseline,
                )
            except Exception:
                if not continue_on_error:
                    stop_after_error.set()
                return _summary_row(
                    record,
                    status="failed",
                    reason_code="enrichment_failed",
                    missing_fields=_missing_fields(baseline.model_dump(mode="json")),
                    verified_claim_count=0,
                )

            metrics = outcome.provider_metrics
            cache_hit = metrics.get("operational_research_cache") == "hit"
            if outcome.capability.status == "ready":
                status = "cache_hit" if cache_hit else "enriched"
                reason_code = "cache_hit" if cache_hit else "official_evidence_enriched"
            elif outcome.capability.status == "failed":
                status = "failed"
                reason_code = outcome.capability.reason_code
            else:
                status = "skipped"
                reason_code = outcome.capability.reason_code
            return _summary_row(
                record,
                status=status,
                reason_code=reason_code,
                missing_fields=outcome.missing_fields,
                verified_claim_count=len(outcome.research.operational_url_claims),
            )

    try:
        rows = await asyncio.gather(*(enrich_one(record) for record in records))
    finally:
        service.shutdown()
    return list(rows)


def _print_summary(*, execute: bool, rows: Sequence[Mapping[str, object]]) -> None:
    mode = "EXECUTE" if execute else "DRY RUN"
    print(f"{mode}: {len(rows)} verified P1 app(s)")
    if not execute:
        print("No You.com, Gemini, browser, or vendor calls were made.")
    for row in rows:
        missing = ",".join(str(item) for item in row["missing_fields"]) or "none"
        reason = str(row["reason_code"]) or "none"
        print(
            f"{row['app_slug']}: {row['status']} reason={reason} "
            f"missing={row['missing_field_count']}[{missing}] "
            f"verified_claims={row['verified_claim_count']}"
        )


def _write_summary(path: Path, *, execute: bool, rows: Sequence[Mapping[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"mode": "execute" if execute else "dry_run", "results": list(rows)}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        records = _selected_records(args)
        settings = Settings.from_env()
        if args.max_age_seconds is not None:
            settings = settings.model_copy(
                update={"you_contents_max_age_seconds": args.max_age_seconds}
            )
        rows = (
            asyncio.run(
                _execute(
                    records,
                    settings=settings,
                    force_refresh=args.force_refresh,
                    concurrency=args.concurrency,
                    continue_on_error=args.continue_on_error,
                )
            )
            if args.execute
            else _dry_run(records)
        )
    except ValueError as exc:
        # All expected operator/configuration errors are stable sanitized codes.
        print(f"configuration_error: {exc}", file=sys.stderr)
        return 2

    _print_summary(execute=args.execute, rows=rows)
    if args.output_summary is not None:
        _write_summary(args.output_summary, execute=args.execute, rows=rows)
    successful_statuses = {"cache_hit", "enriched"}
    if (
        args.execute
        and any(row["status"] == "failed" for row in rows)
        and not any(row["status"] in successful_statuses for row in rows)
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
