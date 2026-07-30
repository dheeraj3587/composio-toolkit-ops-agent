from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _environment_example() -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, value = line.split("=", maxsplit=1)
        values[key] = value
    return values


def _requirements(path: str) -> set[str]:
    return {
        line.strip().split("==", maxsplit=1)[0].split(">=", maxsplit=1)[0]
        for line in (ROOT / path).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith(("#", "-r "))
    }


def test_environment_example_contains_only_safe_live_action_defaults() -> None:
    values = _environment_example()

    for secret_name in {
        "PERPLEXITY_API_KEY",
        "GOOGLE_GENAI_API_KEY",
        "COMPOSIO_API_KEY",
        "BROWSER_USE_API_KEY",
        "LANGGRAPH_AES_KEY",
        "SECRET_VAULT_KEY",
    }:
        assert values[secret_name] == ""

    assert values["ALLOW_LIVE_BROWSER"] == "false"
    assert values["ALLOW_LIVE_VENDOR_EMAIL"] == "false"
    assert values["RUN_LIVE_TESTS"] == "0"
    assert "*" not in values["OPS_CORS_ORIGINS"]


def test_provider_sdks_are_isolated_from_the_core_requirement_group() -> None:
    core = _requirements("requirements.txt")
    providers = _requirements("requirements-providers.txt")

    expected_providers = {
        "browser-use-sdk",
        "composio",
        "google-genai",
        "langgraph",
        "langgraph-checkpoint-sqlite",
        "perplexityai",
        "playwright",
    }
    assert expected_providers <= providers
    assert expected_providers.isdisjoint(core)


def test_container_defaults_disable_live_actions_and_bind_host_ports_to_loopback() -> None:
    production = (ROOT / "compose.prod.yaml").read_text(encoding="utf-8")
    local = (ROOT / "compose.local.yaml").read_text(encoding="utf-8")
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()

    assert "ALLOW_LIVE_BROWSER: ${ALLOW_LIVE_BROWSER:-false}" in production
    assert "ALLOW_LIVE_VENDOR_EMAIL: ${ALLOW_LIVE_VENDOR_EMAIL:-false}" in production
    # These are configurable now, but every one of them still defaults to off, so
    # a deployment that says nothing gets no live provider.
    assert (
        "BROWSER_USE_COMPATIBILITY_ENABLED: ${BROWSER_USE_COMPATIBILITY_ENABLED:-false}"
        in production
    )
    assert "YOU_SEARCH_ENABLED: ${YOU_SEARCH_ENABLED:-false}" in production
    assert "YOU_CONTENTS_ENABLED: ${YOU_CONTENTS_ENABLED:-false}" in production
    assert "YOU_RESEARCH_ENABLED: ${YOU_RESEARCH_ENABLED:-false}" in production
    assert 'PLAYWRIGHT_MAX_SESSIONS: "${PLAYWRIGHT_MAX_SESSIONS:-2}"' in production
    assert "BROWSER_DISPLAY_SLOTS:" not in production
    assert "PLAYWRIGHT_DISABLE_SANDBOX: ${PLAYWRIGHT_DISABLE_SANDBOX:-false}" in production
    assert "ipc: host" not in production
    assert 'OPS_ENABLE_API_DOCS: "false"' in production
    assert 'RUN_LIVE_TESTS: "0"' in production
    assert '"127.0.0.1:${OPS_API_PORT:-8000}:8000"' in local
    assert '"127.0.0.1:${OPS_WEB_PORT:-3000}:3000"' in local
    for secret_name in {
        "BROWSER_USE_API_KEY",
        "COMPOSIO_API_KEY",
        "GOOGLE_GENAI_API_KEY",
        "LANGGRAPH_AES_KEY",
        "PERPLEXITY_API_KEY",
        "SECRET_VAULT_KEY",
    }:
        assignments = [
            line.split(":", maxsplit=1)[1].strip()
            for line in production.splitlines()
            if line.strip().startswith(f"{secret_name}:")
        ]
        # A service may deliberately receive an empty value when a secret is
        # outside its trust boundary (for example, browser credentials on the
        # API container). Every non-empty assignment must still be sourced from
        # the deployment environment rather than embedded in Compose.
        assert all(value in {"", '""', "''"} or value.startswith("${") for value in assignments)
    for private_pattern in {
        ".env",
        "*.db",
        "auth.json",
        "cookies.json",
        "private",
        "recordings",
        "screenshots",
        "storage_state.json",
        "web/node_modules",
    }:
        assert private_pattern in dockerignore


def test_production_proxy_keeps_fastapi_private_and_requires_internal_token() -> None:
    compose = (ROOT / "compose.prod.yaml").read_text(encoding="utf-8")
    caddyfile = (ROOT / "deploy" / "Caddyfile").read_text(encoding="utf-8")

    assert "OPS_INTERNAL_API_TOKEN:" in compose
    assert "X-Ops-Internal-Token" in compose
    assert "ALLOW_LIVE_BROWSER: ${ALLOW_LIVE_BROWSER:-false}" in compose
    assert 'ports:\n      - "80:80"\n      - "443:443"' in compose
    assert "8000:8000" not in compose
    assert "3000:3000" not in compose

    assert "handle /healthz" in caddyfile
    assert "Strict-Transport-Security" in caddyfile
    assert "reverse_proxy web:3000" in caddyfile
    assert "reverse_proxy /api/* api:8000" not in caddyfile
    assert "reverse_proxy api:8000" not in caddyfile
    assert "OPS_AUTH_SESSION_SECRET:" in compose
    assert "OPS_AUTH_TOTP_SECRET:" in compose


def test_security_gate_shell_is_syntactically_valid() -> None:
    for script in (
        "security_gate.sh",
        "deploy-droplet.sh",
        "backup-production-data.sh",
    ):
        result = subprocess.run(
            ["bash", "-n", str(ROOT / "scripts" / script)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"{script}: {result.stderr}"


def test_release_utilities_capture_and_verify_deployment_truth() -> None:
    deploy = (ROOT / "scripts" / "deploy-droplet.sh").read_text(encoding="utf-8")
    backup = (ROOT / "scripts" / "backup-production-data.sh").read_text(encoding="utf-8")
    entrypoint = (ROOT / "docker" / "browser-entrypoint.sh").read_text(encoding="utf-8")

    assert "PLAYWRIGHT_MAX_SESSIONS" in deploy
    assert 'DISPLAY_SLOTS="${BROWSER_DISPLAY_SLOTS:-${PLAYWRIGHT_MAX_SESSIONS:-1}}"' in entrypoint
    assert '"${origin}/healthz"' in deploy
    assert '"${origin}/system"' in deploy
    assert 'public_probes "$ROLLBACK_PUBLIC_ORIGIN"' in deploy
    assert "302|303|307|308" in deploy
    assert "/api/system/health" not in deploy

    assert "org.opencontainers.image.revision" in backup
    assert "runtime_config/deployed-sha.txt" in backup
    assert "runtime_config/compose.prod.yaml" in backup
    assert "runtime_config/deploy/Caddyfile" in backup
    assert "browser_profiles" in backup
    assert ".env.production" not in backup.split("tar czf", maxsplit=1)[1]
