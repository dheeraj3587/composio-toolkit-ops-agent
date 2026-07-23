"""Static regressions for frontend security and Next.js Server Action boundaries."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB_SOURCE = ROOT / "web" / "src"
SERVER_ACTION_FILES = (
    WEB_SOURCE / "app" / "runs" / "new" / "actions.ts",
    WEB_SOURCE / "app" / "runs" / "[runId]" / "actions.ts",
)

RUNTIME_EXPORT = re.compile(
    r"^export\s+(?!async\s+function\b|interface\b|type\b)",
    flags=re.MULTILINE,
)


def test_server_action_modules_export_only_async_functions_or_types() -> None:
    """Prevent Next runtime failures that its production build does not currently catch."""

    for path in SERVER_ACTION_FILES:
        source = path.read_text(encoding="utf-8")
        assert source.lstrip().startswith('"use server"')
        assert not RUNTIME_EXPORT.search(source), path


TEST_SOURCE_SUFFIXES = (".test.ts", ".test.tsx", ".spec.ts", ".spec.tsx")


def test_frontend_has_no_browser_storage_or_public_api_origin() -> None:
    # Scan real production TypeScript source only. Frontend test/spec files
    # legitimately reference these identifiers inside their own security
    # assertions and must be excluded from the production-source scan.
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in WEB_SOURCE.rglob("*")
        if path.is_file()
        and path.suffix in {".ts", ".tsx"}
        and not path.name.endswith(TEST_SOURCE_SUFFIXES)
    )

    assert "localStorage" not in source
    assert "sessionStorage" not in source
    assert "NEXT_PUBLIC_" not in source


def test_frontend_validates_success_envelopes_and_idempotency_keys() -> None:
    api_source = (WEB_SOURCE / "lib" / "api.ts").read_text(encoding="utf-8")
    schema_source = (WEB_SOURCE / "lib" / "api-schemas.ts").read_text(encoding="utf-8")

    assert "body as T" not in api_source
    assert "schema.safeParse(body)" in api_source
    assert "INVALID_API_RESPONSE" in api_source
    assert "Promise<ActionReceipt>" in api_source
    assert "^idem_[0-9a-f]{32}$" in api_source
    assert '"Idempotency-Key": idempotencyKey' in api_source
    # Semantic strictness: every response/envelope object rejects unknown keys.
    # Assert no lax `z.object(` remains rather than a brittle raw count.
    assert "z.object(" not in schema_source
    assert "z.strictObject(" in schema_source
    assert "vaultReference" in schema_source


def test_next_security_headers_and_standalone_assets_are_configured() -> None:
    next_config = (ROOT / "web" / "next.config.ts").read_text(encoding="utf-8")
    package = (ROOT / "web" / "package.json").read_text(encoding="utf-8")
    standalone_script = (ROOT / "web" / "scripts" / "prepare-standalone.mjs").read_text(
        encoding="utf-8"
    )

    for header in (
        "Content-Security-Policy",
        "Permissions-Policy",
        "Referrer-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
    ):
        assert header in next_config
    for directive in ("object-src 'none'", "frame-ancestors 'none'", "form-action 'self'"):
        assert directive in next_config

    assert '"postbuild": "node scripts/prepare-standalone.mjs"' in package
    assert '"start": "node .next/standalone/server.js"' in package
    assert 'join(root, "public")' in standalone_script
    assert 'join(root, ".next", "static")' in standalone_script


def test_container_runtime_has_one_writable_application_path() -> None:
    api_dockerfile = (ROOT / "Dockerfile.api").read_text(encoding="utf-8")
    requirements = (ROOT / "requirements-api.txt").read_text(encoding="utf-8").splitlines()

    assert "COPY requirements-api.txt ./" in api_dockerfile
    assert "--requirement requirements-api.txt" in api_dockerfile
    assert "COPY --chown=root:root api ./api" in api_dockerfile
    assert "COPY --chown=root:root ops ./ops" in api_dockerfile
    assert "COPY --chown=root:root data/p1 ./data/p1" in api_dockerfile
    assert "chmod 0555" in api_dockerfile
    assert "chmod 0444" in api_dockerfile
    assert "install -d -o ops -g ops -m 0700 /private" in api_dockerfile
    assert requirements == [
        "fastapi==0.139.2",
        "pydantic==2.13.4",
        "python-dotenv==1.2.2",
        "uvicorn[standard]==0.51.0",
    ]
