"""Local-only command line interface for the Phase 0/1/2 operations ledger.

The CLI exposes a narrow, sanitized view of verified P1 lookup and deterministic
routing. It does not invoke providers, send email, start browsers, or produce an
``IntegratorBundle``. Commands for those capabilities fail explicitly.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import httpx
from cryptography.fernet import Fernet
from pydantic import ValidationError

from ops.models import CompanyProfile, OperationsRequest
from ops.redaction import install_redacting_filter
from ops.run_service import RunService
from ops.storage import OperationsStorage

EXIT_OK = 0
EXIT_NOT_FOUND = 2
EXIT_PHASE_UNAVAILABLE = 3
EXIT_ERROR = 4

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE_PATH = REPOSITORY_ROOT / "private" / "operations.sqlite3"
SNAPSHOT_PATH = REPOSITORY_ROOT / "data" / "p1" / "SNAPSHOT.json"

_SENSITIVE_KEY = re.compile(
    r"(?:authorization|cookie|password|secret|token|api[_-]?key|private[_-]?key)",
    re.IGNORECASE,
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+\-/]+=*")


def _database_path(explicit: str | Path | None = None) -> Path:
    """Resolve the operations database without exposing configuration values."""

    if explicit is not None:
        return Path(explicit).expanduser().resolve()

    configured = os.getenv("OPS_DB_PATH") or os.getenv("OPERATIONS_DB_PATH")
    if configured:
        return Path(configured).expanduser().resolve()

    try:
        from ops.config import load_settings

        settings = load_settings()
        for field in ("ops_db_path", "operations_db_path", "database_path"):
            value = getattr(settings, field, None)
            if value:
                return Path(value).expanduser().resolve()
    except (AttributeError, ImportError, TypeError, ValueError):
        # The local dry-run ledger remains usable with the documented safe path.
        pass

    return DEFAULT_DATABASE_PATH


def _storage(db_path: str | Path | None = None) -> OperationsStorage:
    store = OperationsStorage(_database_path(db_path))
    store.initialize()
    return store


def _as_mapping(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        return dict(value)
    if hasattr(value, "model_dump"):
        dumped = value.model_dump(mode="json")
        return dict(dumped) if isinstance(dumped, Mapping) else {}
    if hasattr(value, "keys"):
        return {key: value[key] for key in value.keys()}
    if hasattr(value, "__dict__"):
        return dict(vars(value))
    return {}


def _redact_text(value: str) -> str:
    """Use the security core redactor, with a conservative local fallback."""

    try:
        from ops.redaction import redact_text

        return redact_text(value)
    except (ImportError, TypeError, ValueError):
        value = _BEARER.sub("Bearer [REDACTED]", value)
        return _JWT.sub("[REDACTED]", value)


def _safe_value(value: Any, *, key: str = "") -> Any:
    """Recursively sanitize values immediately before any terminal rendering."""

    if isinstance(value, str) and value.startswith("vault://"):
        return value
    if _SENSITIVE_KEY.search(key) and not key.endswith("_ref") and key != "credential_refs":
        return "[REDACTED]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, Mapping):
        return {
            str(item_key): _safe_value(item, key=str(item_key)) for item_key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_safe_value(item) for item in value]
    return _redact_text(str(value))


def _emit(payload: Mapping[str, Any], *, stream: Any = None) -> None:
    output = stream if stream is not None else sys.stdout
    print(json.dumps(_safe_value(payload), sort_keys=True), file=output)


def _run_service(db_path: str | Path | None = None) -> RunService:
    return RunService(storage=_storage(db_path))


def create_dry_run(
    request: OperationsRequest,
    *,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Create, verify, and deterministically route a local Phase 2 run."""

    return _run_service(db_path).create_run(request)


def get_run_status(run_id: str, *, db_path: str | Path | None = None) -> dict[str, Any] | None:
    return _run_service(db_path).get_run(run_id)


def get_run_timeline(run_id: str, *, db_path: str | Path | None = None) -> list[dict[str, Any]]:
    events = _run_service(db_path).get_timeline(run_id)
    timeline: list[dict[str, Any]] = []
    for event in events:
        source = _as_mapping(event)
        payload = source.get(
            "payload",
            source.get("sanitized_payload", source.get("sanitized_payload_json", {})),
        )
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                payload = {"status": "stored"}
        timeline.append(
            _safe_value(
                {
                    "event_type": source.get("event_type", "event"),
                    "payload": payload,
                    "created_at": source.get("created_at"),
                }
            )
        )
    return timeline


def get_run_output(run_id: str, *, db_path: str | Path | None = None) -> dict[str, Any] | None:
    return _run_service(db_path).get_output(run_id)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def doctor(*, db_path: str | Path | None = None) -> tuple[dict[str, Any], bool]:
    """Check readiness for the local dry-run slice without exposing env values."""

    checks: list[dict[str, Any]] = []
    manifest: dict[str, Any] = {}
    try:
        manifest = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
        checks.append({"name": "p1_snapshot_manifest", "status": "pass"})
    except (OSError, json.JSONDecodeError):
        checks.append({"name": "p1_snapshot_manifest", "status": "fail"})

    snapshot_files = {
        "results_sha256": REPOSITORY_ROOT / "data" / "p1" / "results.json",
        "coverage_sha256": REPOSITORY_ROOT / "data" / "p1" / "composio_coverage.json",
    }
    for manifest_key, path in snapshot_files.items():
        valid = path.is_file() and manifest.get(manifest_key) == _sha256(path)
        checks.append(
            {"name": manifest_key.removesuffix("_sha256"), "status": "pass" if valid else "fail"}
        )

    try:
        store = _storage(db_path)
        del store
        checks.append({"name": "operations_storage", "status": "pass"})
    except (OSError, RuntimeError, ValueError):
        checks.append({"name": "operations_storage", "status": "fail"})

    try:
        from ops.config import load_settings

        settings = load_settings()
        live_email = settings.allow_live_vendor_email
        if settings.secret_vault_key is None:
            vault_key_status = "not_configured"
        else:
            try:
                Fernet(settings.secret_vault_key.get_secret_value().encode("ascii"))
                vault_key_status = "configured"
            except (TypeError, UnicodeEncodeError, ValueError):
                vault_key_status = "fail"
    except (OSError, TypeError, ValueError):
        live_email = True
        vault_key_status = "fail"
    checks.append(
        {
            "name": "live_vendor_email_disabled",
            "status": "pass" if not live_email else "fail",
        }
    )
    checks.append(
        {
            "name": "secret_vault_key",
            "status": vault_key_status,
            "required_for": "future credential operations",
        }
    )

    ready = all(check["status"] != "fail" for check in checks)
    return (
        {
            "status": "ready_for_phase_2_local" if ready else "configuration_error",
            "phase": "0/1/2",
            "external_operations": "unavailable",
            "checks": checks,
        },
        ready,
    )


def research_app(app_name: str, *, provider: str = "you") -> dict[str, Any]:
    """Sanitized research-debug view of the PRODUCTION research pipeline.

    Exercises the same wiring ``RunService`` uses: You.com Search discovery,
    then You.com Contents for content extraction, with the guarded HTTP fetcher
    as a per-URL fallback. ``--provider auto`` also adds the Perplexity discovery
    fallback. Never runs Gemini extraction, never touches the browser, and never
    displays an API key, full document text, snippets, credentials, vault values,
    cookies, or a browser session.
    """

    from ops.config import load_settings
    from ops.operational_research import (
        OfficialEvidenceFetcher,
        PerplexitySearchDiscovery,
        _missing_fields,  # noqa: SLF001 - internal reuse within the same package
        _rich_candidate_urls,  # noqa: SLF001 - internal reuse within the same package
    )
    from ops.p1_adapter import lookup_p1_record, to_operational_research
    from ops.research_cache import SqliteResearchCache
    from ops.you_research import (
        CompositeEvidenceDiscovery,
        FallbackEvidenceContentFetcher,
        GuardedHTTPEvidenceFetcher,
        LegacyDiscoveryAdapter,
        ResearchHostPolicy,
        YouContentsFetcher,
        YouResearchMetrics,
        YouSearchDiscovery,
        use_metrics,
    )

    lookup = lookup_p1_record(app_name)
    if lookup.status != "found" or lookup.record is None:
        return {"error": "app_not_found", "app_name": app_name}

    record = lookup.record
    p1_record = record.model_dump(mode="json")
    baseline = to_operational_research(record)
    settings = load_settings()

    host_policy = ResearchHostPolicy.build(p1_record=p1_record, baseline=baseline)
    official_domains = host_policy.include_domains
    cache = SqliteResearchCache(settings.research_cache_db_path)

    providers: list[object] = []
    if provider in ("you", "auto") and settings.you_search_configured:
        providers.append(
            YouSearchDiscovery(
                settings.you_api_key,  # type: ignore[arg-type]
                count=settings.you_search_count,
                timeout_seconds=settings.you_search_timeout_seconds,
                max_calls=settings.you_max_search_calls_per_enrichment,
                cache=cache,
            )
        )
    if provider in ("perplexity", "auto") and settings.perplexity_api_key is not None:
        providers.append(
            LegacyDiscoveryAdapter(PerplexitySearchDiscovery(settings.perplexity_api_key))
        )

    if not providers:
        cache.close()
        return {
            "app_name": baseline.app_name,
            "app_slug": baseline.app_slug,
            "provider_requested": provider,
            "official_domains": list(official_domains),
            "error": "no_discovery_provider_configured",
        }

    composite = CompositeEvidenceDiscovery(providers)  # type: ignore[arg-type]
    effective_policy = host_policy.official_url_policy
    metrics = YouResearchMetrics()

    def _build_content_fetcher(http_client: httpx.AsyncClient) -> object:
        primary = YouContentsFetcher(
            settings.you_api_key,  # type: ignore[arg-type]
            policy=host_policy,
            max_age=settings.you_contents_max_age_seconds,
            request_timeout=settings.you_contents_timeout_seconds,
            max_pages=settings.you_max_contents_pages_per_enrichment,
            cache=cache,
        )
        if effective_policy is None:
            return primary
        fallback = GuardedHTTPEvidenceFetcher(
            OfficialEvidenceFetcher(http_client, effective_policy)
        )
        return FallbackEvidenceContentFetcher(primary=primary, fallback=fallback)

    async def _run() -> tuple[tuple[object, ...], list[dict[str, Any]], dict[str, float]]:
        latencies: dict[str, float] = {}
        with use_metrics(metrics):
            start = time.monotonic()
            found = await composite.discover(
                app_name=baseline.app_name,
                p1_record=p1_record,
                baseline=baseline,
                official_hosts=official_domains,
            )
            latencies["discovery_ms"] = round((time.monotonic() - start) * 1000, 1)

            docs_summary: list[dict[str, Any]] = []
            if found and settings.you_contents_configured and effective_policy is not None:
                candidate_urls = _rich_candidate_urls(p1_record, found, effective_policy)
                # This CLI owns the guarded fallback client, so it closes it here
                # rather than leaking its connections for the process lifetime.
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(15.0, connect=5.0), follow_redirects=False
                ) as http_client:
                    fetcher = _build_content_fetcher(http_client)
                    start = time.monotonic()
                    documents = await fetcher.fetch_many(candidate_urls)  # type: ignore[attr-defined]
                latencies["content_fetch_ms"] = round((time.monotonic() - start) * 1000, 1)
                docs_summary = [{"url": d.source_url, "title": d.title} for d in documents]
        return found, docs_summary, latencies

    try:
        candidates, documents_summary, latencies = asyncio.run(_run())
    finally:
        cache.close()

    return {
        "app_name": baseline.app_name,
        "app_slug": baseline.app_slug,
        "provider_requested": provider,
        "provider_used": metrics.discovery_provider_used
        or getattr(composite, "last_provider_used", None),
        "official_domains": list(official_domains),
        "candidates": [
            {
                "url": getattr(candidate, "source_url", ""),
                "category": getattr(candidate, "category", "unknown"),
                "provider": getattr(candidate, "provider", "unknown"),
            }
            for candidate in candidates
        ],
        "documents_fetched": documents_summary,
        "missing_baseline_fields": _missing_fields(baseline),
        "latencies_ms": latencies,
        "cache_hits": metrics.research_cache_hits,
        "cache_misses": metrics.research_cache_misses,
    }


def probe_you() -> dict[str, Any]:
    """Explicit, opt-in LIVE check: one cheap Search call, never run at startup.

    Returns only a sanitized success/failure reason — never the API key, the
    full response body, or a raw provider exception.
    """

    from ops.config import load_settings
    from ops.you_research import YouProviderError, YouSearchDiscovery

    settings = load_settings()
    if settings.you_api_key is None:
        return {"status": "not_configured", "detail": "YDC_API_KEY is not set."}
    if not settings.you_search_enabled:
        return {"status": "disabled", "detail": "YOU_SEARCH_ENABLED is false."}

    discovery = YouSearchDiscovery(settings.you_api_key, count=1, timeout_seconds=10.0, max_calls=1)

    async def _probe() -> tuple[bool, str, float]:
        start = time.monotonic()
        try:
            # One cheap, unfiltered Search call for reachability only.
            response = await discovery._search(  # noqa: SLF001
                query="you.com API documentation", provider_domains=()
            )
        except YouProviderError as exc:
            return False, exc.reason_code, round((time.monotonic() - start) * 1000, 1)
        del response  # the probe only needs success/failure, never the payload
        return True, "you_search_reachable", round((time.monotonic() - start) * 1000, 1)

    ok, reason, latency_ms = asyncio.run(_probe())
    return {
        "status": "ready" if ok else "failed",
        "reason_code": reason,
        "latency_ms": latency_ms,
    }


def _default_company(args: argparse.Namespace) -> CompanyProfile:
    from ops.config import load_settings

    settings = load_settings()
    return CompanyProfile(
        legal_name=args.legal_name or settings.company_legal_name or "Composio",
        website=args.website or settings.company_website or "https://composio.dev",
        work_email_ref=args.work_email_ref
        or settings.company_work_email_ref
        or "vault://company/work_email/unconfigured",
        use_case=args.use_case
        or settings.company_use_case
        or "Evaluate documented API access for integration readiness.",
        expected_volume=args.expected_volume or settings.company_expected_volume,
        callback_urls=args.callback_url or list(settings.oauth_callback_urls),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="composio-ops",
        description="Secure local operations ledger (Phase 0/1/2).",
    )
    parser.add_argument("--db-path", help=argparse.SUPPRESS)
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("doctor", help="Check local dry-run readiness.")

    run_parser = subparsers.add_parser("run", help="Create a local dry-run ledger entry.")
    run_parser.add_argument("app_name")
    run_parser.add_argument("--legal-name")
    run_parser.add_argument("--website")
    run_parser.add_argument("--work-email-ref")
    run_parser.add_argument("--use-case")
    run_parser.add_argument("--expected-volume")
    run_parser.add_argument("--callback-url", action="append", default=[])
    run_parser.add_argument(
        "--scope-policy",
        choices=("minimum", "recommended", "maximum"),
        default="maximum",
    )
    run_parser.add_argument(
        "--browser-provider",
        choices=("browser_use", "playwright"),
        default="browser_use",
        help="Freeze the browser engine for this run (default: browser_use).",
    )
    run_parser.add_argument(
        "--credential-creation-policy",
        choices=("reuse_only", "create_if_missing"),
        default="reuse_only",
        help="Reuse an existing developer credential or explicitly allow create-if-missing.",
    )

    for command, help_text in (
        ("status", "Show the sanitized local run status."),
        ("resume", "Report resume availability for a run."),
        ("poll-email", "Report email polling availability for a run."),
        ("show-output", "Show a validated IntegratorBundle when one exists."),
    ):
        command_parser = subparsers.add_parser(command, help=help_text)
        command_parser.add_argument("run_id")

    research_parser = subparsers.add_parser(
        "research-app",
        help="Sanitized You.com/Perplexity discovery diagnostic (no extraction, no browser).",
    )
    research_parser.add_argument("app_name")
    research_parser.add_argument("--provider", choices=("you", "perplexity", "auto"), default="you")

    subparsers.add_parser(
        "probe-you",
        help="Explicit, opt-in live You.com Search reachability check (spends one call).",
    )

    return parser


def _phase_unavailable(command: str, run_id: str) -> dict[str, Any]:
    return {
        "error": "phase_unavailable",
        "command": command,
        "run_id": run_id,
        "available_in": "a later implementation phase",
        "external_actions": False,
    }


def _validation_fields(exc: ValidationError) -> list[str]:
    company_fields = set(CompanyProfile.model_fields)
    fields: set[str] = set()
    for error in exc.errors():
        location = [str(part) for part in error["loc"]]
        if location and location[0] in company_fields:
            location.insert(0, "company")
        fields.add(".".join(location))
    return sorted(fields)


def main(argv: list[str] | None = None) -> int:
    # Frameworks and entry-point wrappers can attach handlers after importing
    # the package. Re-applying is idempotent and protects those late handlers.
    install_redacting_filter()
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "doctor":
            report, ready = doctor(db_path=args.db_path)
            _emit(report)
            return EXIT_OK if ready else EXIT_ERROR

        if args.command == "research-app":
            _emit(research_app(args.app_name, provider=args.provider))
            return EXIT_OK

        if args.command == "probe-you":
            result = probe_you()
            _emit(result)
            return EXIT_OK if result.get("status") == "ready" else EXIT_ERROR

        if args.command == "run":
            request = OperationsRequest(
                app_name=args.app_name,
                company=_default_company(args),
                requested_scope_policy=args.scope_policy,
                browser_provider=args.browser_provider,
                credential_creation_policy=args.credential_creation_policy,
                dry_run=True,
            )
            _emit({"run": create_dry_run(request, db_path=args.db_path)})
            return EXIT_OK

        status = get_run_status(args.run_id, db_path=args.db_path)
        if status is None:
            _emit({"error": "run_not_found", "run_id": args.run_id})
            return EXIT_NOT_FOUND

        if args.command == "status":
            _emit({"run": status, "timeline": get_run_timeline(args.run_id, db_path=args.db_path)})
            return EXIT_OK

        if args.command in {"resume", "poll-email"}:
            _emit(_phase_unavailable(args.command, args.run_id))
            return EXIT_PHASE_UNAVAILABLE

        if args.command == "show-output":
            output = get_run_output(args.run_id, db_path=args.db_path)
            if not output:
                _emit(_phase_unavailable(args.command, args.run_id))
                return EXIT_PHASE_UNAVAILABLE
            _emit({"run_id": args.run_id, "integrator_bundle": output})
            return EXIT_OK

    except ValidationError as exc:
        _emit(
            {"error": "invalid_request", "fields": _validation_fields(exc)},
            stream=sys.stderr,
        )
        return EXIT_ERROR
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        _emit(
            {"error": "operation_failed", "detail": _redact_text(str(exc))},
            stream=sys.stderr,
        )
        return EXIT_ERROR

    parser.error("unsupported command")
    return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover - exercised through module execution
    raise SystemExit(main())
