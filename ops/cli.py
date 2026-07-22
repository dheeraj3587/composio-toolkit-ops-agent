"""Local-only command line interface for the Phase 0/1 operations ledger.

The CLI deliberately exposes a narrow, sanitized view of persisted runs.  Phase
0/1 does not invoke providers, send email, start browsers, or produce an
``IntegratorBundle``.  Commands for those capabilities fail explicitly instead
of implying that work happened.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from cryptography.fernet import Fernet
from pydantic import ValidationError

from ops.models import CompanyProfile, IntegratorBundle, OperationsRequest
from ops.redaction import install_redacting_filter
from ops.storage import OperationsStorage

EXIT_OK = 0
EXIT_NOT_FOUND = 2
EXIT_PHASE_UNAVAILABLE = 3
EXIT_ERROR = 4

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE_PATH = REPOSITORY_ROOT / "private" / "operations.sqlite3"
SNAPSHOT_PATH = REPOSITORY_ROOT / "data" / "p1" / "SNAPSHOT.json"

_SAFE_RUN_FIELDS = (
    "run_id",
    "thread_id",
    "app_name",
    "app_slug",
    "status",
    "access_route",
    "created_at",
    "updated_at",
)
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


def _slugify(app_name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", app_name.strip().lower()).strip("-")
    return slug or "app"


def _public_run(record: Any) -> dict[str, Any]:
    source = _as_mapping(record)
    public = {
        field: source.get(field) for field in _SAFE_RUN_FIELDS if source.get(field) is not None
    }
    public["execution_mode"] = "local_dry_run"
    public["external_actions"] = False
    return cast(dict[str, Any], _safe_value(public))


def _append_event(
    store: OperationsStorage,
    run_id: str,
    event_type: str,
    payload: Mapping[str, Any],
) -> Any:
    safe_payload = _safe_value(payload)
    return store.append_audit_event(
        run_id=run_id,
        event_type=event_type,
        payload=safe_payload,
    )


def create_dry_run(
    request: OperationsRequest,
    *,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Create a local ledger entry and no external side effects."""

    if not request.dry_run:
        raise ValueError("Phase 0/1 accepts dry-run requests only")

    store = _storage(db_path)
    run_id = f"run_{uuid4().hex}"
    thread_id = f"local_{uuid4().hex}"
    created = store.create_run(
        run_id=run_id,
        thread_id=thread_id,
        app_name=request.app_name,
        app_slug=_slugify(request.app_name),
        status="created",
        access_route=None,
    )
    _append_event(
        store,
        run_id,
        "dry_run_created",
        {
            "status": "created",
            "scope_policy": request.requested_scope_policy,
            "execution_mode": "local_dry_run",
            "external_actions": False,
        },
    )
    return _public_run(created)


def get_run_status(run_id: str, *, db_path: str | Path | None = None) -> dict[str, Any] | None:
    record = _storage(db_path).get_run(run_id)
    return _public_run(record) if record else None


def get_run_timeline(run_id: str, *, db_path: str | Path | None = None) -> list[dict[str, Any]]:
    store = _storage(db_path)
    events = store.list_audit_events(run_id)
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
    record = _as_mapping(_storage(db_path).get_run(run_id))
    if not record:
        return None
    bundle = record.get("integrator_bundle", record.get("integrator_bundle_json"))
    if not bundle:
        return {}
    if isinstance(bundle, str):
        bundle = json.loads(bundle)
    validated = IntegratorBundle.model_validate(bundle)
    return cast(
        dict[str, Any],
        _safe_value(validated.model_dump(mode="json")),
    )


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
            "status": "ready_for_local_dry_run" if ready else "configuration_error",
            "phase": "0/1",
            "external_operations": "unavailable",
            "checks": checks,
        },
        ready,
    )


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
        description="Secure local operations ledger (Phase 0/1).",
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

    for command, help_text in (
        ("status", "Show the sanitized local run status."),
        ("resume", "Report resume availability for a run."),
        ("poll-email", "Report email polling availability for a run."),
        ("show-output", "Show a validated IntegratorBundle when one exists."),
    ):
        command_parser = subparsers.add_parser(command, help=help_text)
        command_parser.add_argument("run_id")

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

        if args.command == "run":
            request = OperationsRequest(
                app_name=args.app_name,
                company=_default_company(args),
                requested_scope_policy=args.scope_policy,
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
