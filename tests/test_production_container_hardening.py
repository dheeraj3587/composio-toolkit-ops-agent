from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
PLAYWRIGHT_SECCOMP_SHA256 = (
    "48f49fe40f3c2f66984b05a431d25f26280841590244e05e4aa574624d301d1d"  # pragma: allowlist secret
)


def _compose() -> dict[str, Any]:
    return yaml.safe_load((ROOT / "compose.prod.yaml").read_text(encoding="utf-8"))


def _production_env() -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in (ROOT / ".env.production.example").read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        name, value = line.split("=", maxsplit=1)
        values[name] = value
    return values


def test_reviewed_playwright_seccomp_profile_has_pinned_provenance() -> None:
    profile_path = ROOT / "deploy" / "chromium-seccomp.json"
    raw = profile_path.read_bytes()
    profile = json.loads(raw)

    assert hashlib.sha256(raw).hexdigest() == PLAYWRIGHT_SECCOMP_SHA256
    assert profile["defaultAction"] == "SCMP_ACT_ERRNO"
    namespace_rule = profile["syscalls"][0]
    assert namespace_rule == {
        "comment": "Allow create user namespaces",
        "names": ["clone", "setns", "unshare"],
        "action": "SCMP_ACT_ALLOW",
        "args": [],
        "includes": {},
        "excludes": {},
    }
    syscall_names = {name for rule in profile["syscalls"] for name in rule.get("names", [])}
    assert "chroot" in syscall_names
    requirements = (ROOT / "requirements-providers.txt").read_text(encoding="utf-8")
    operations = (ROOT / "docs" / "OPERATIONS.md").read_text(encoding="utf-8")
    assert "playwright==1.61.0" in requirements
    assert "playwright/blob/v1.61.0/utils/docker/seccomp_profile.json" in operations
    assert PLAYWRIGHT_SECCOMP_SHA256 in operations


def test_browser_compose_uses_profile_and_keeps_the_sandbox_boundary() -> None:
    service = _compose()["services"]["browser-worker"]

    assert service["user"] == "ops"
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert "ipc" not in service
    assert service["security_opt"] == [
        "no-new-privileges:true",
        "seccomp=./deploy/chromium-seccomp.json",
        "apparmor=composio-ops-browser-v1",
    ]
    assert service["environment"]["PLAYWRIGHT_DISABLE_SANDBOX"] == (
        "${PLAYWRIGHT_DISABLE_SANDBOX:-false}"
    )
    assert service["shm_size"] == "${BROWSER_SHM_SIZE:-2gb}"


def test_browser_apparmor_profile_preserves_docker_boundary_and_allows_chromium_userns() -> None:
    profile = (ROOT / "deploy" / "composio-ops-browser.apparmor").read_text(encoding="utf-8")

    assert "abi <abi/4.0>," in profile
    assert "profile composio-ops-browser-v1" in profile
    assert "userns," in profile
    assert "network unix," in profile
    assert "deny network alg," in profile
    assert "deny mount," in profile
    assert "deny @{PROC}/sysrq-trigger rwklx," in profile
    assert "deny /sys/kernel/security/** rwklx," in profile
    assert "flags=(unconfined)" not in profile


def test_all_production_services_are_revision_tagged_and_resource_bounded() -> None:
    services = _compose()["services"]
    expected = {
        "api": (
            "composio-ops-api:${APP_REVISION:-local-uncommitted}",
            "Dockerfile.api",
            "${API_MEM_LIMIT:-1536m}",
            "${API_CPUS:-1.0}",
        ),
        "browser-worker": (
            "composio-ops-browser:${APP_REVISION:-local-uncommitted}",
            "Dockerfile.browser",
            "${BROWSER_MEM_LIMIT:-4g}",
            "${BROWSER_CPUS:-2.0}",
        ),
        "web": (
            "composio-ops-web:${APP_REVISION:-local-uncommitted}",
            "web/Dockerfile",
            "${WEB_MEM_LIMIT:-1g}",
            "${WEB_CPUS:-0.75}",
        ),
        "caddy": (
            "composio-ops-edge:${APP_REVISION:-local-uncommitted}",
            "Dockerfile.caddy",
            "${CADDY_MEM_LIMIT:-512m}",
            "${CADDY_CPUS:-0.25}",
        ),
    }

    for name, (image, dockerfile, memory, cpus) in expected.items():
        service = services[name]
        assert service["image"] == image
        assert service["build"]["dockerfile"] == dockerfile
        assert service["build"]["args"]["APP_REVISION"] == ("${APP_REVISION:-local-uncommitted}")
        assert service["mem_limit"] == memory
        assert service["cpus"] == cpus

    environment = _production_env()
    expected_environment = {
        "API_MEM_LIMIT": "1536m",
        "API_CPUS": "1.0",
        "BROWSER_MEM_LIMIT": "4g",
        "BROWSER_CPUS": "2.0",
        "WEB_MEM_LIMIT": "1g",
        "WEB_CPUS": "0.75",
        "CADDY_MEM_LIMIT": "512m",
        "CADDY_CPUS": "0.25",
    }
    for name, value in expected_environment.items():
        assert environment[name] == value


def test_edge_runs_read_only_with_only_the_bind_service_capability() -> None:
    caddy = _compose()["services"]["caddy"]

    assert caddy["read_only"] is True
    assert caddy["pids_limit"] == 128
    assert caddy["cap_drop"] == ["ALL"]
    assert caddy["cap_add"] == ["NET_BIND_SERVICE"]
    assert caddy["security_opt"] == ["no-new-privileges:true"]
    assert caddy["tmpfs"] == ["/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777"]
    assert set(caddy["volumes"]) == {"caddy_data:/data", "caddy_config:/config"}


def test_api_does_not_receive_browser_only_credentials() -> None:
    environment = _compose()["services"]["api"]["environment"]

    for name in (
        "BROWSER_STORAGE_STATE_KEY",
        "CEREBRAS_API_KEY",
        "GROQ_API_KEY",
        # Mercury leads the browser-decision chain, so like the other decision
        # providers its key belongs to browser-worker, not the control plane.
        "MERCURY_API_KEY",
    ):
        assert environment[name] == ""

    # Browser Use is the exception: it executes in Browser Use Cloud rather than in
    # Chromium here, so its key can only live in the control plane. It stays empty
    # unless the deployment opts in, and deploy-droplet.sh refuses a key without
    # BROWSER_USE_COMPATIBILITY_ENABLED=true.
    assert environment["BROWSER_USE_API_KEY"] == "${BROWSER_USE_API_KEY:-}"
    assert (
        environment["BROWSER_USE_COMPATIBILITY_ENABLED"]
        == "${BROWSER_USE_COMPATIBILITY_ENABLED:-false}"
    )


def test_browser_decision_providers_reach_the_browser_worker() -> None:
    """The action loop cannot resolve an ambiguous page without a backend."""

    environment = _compose()["services"]["browser-worker"]["environment"]

    assert environment["MERCURY_API_KEY"] == "${MERCURY_API_KEY:-}"
    assert environment["MERCURY_MODEL"] == "${MERCURY_MODEL:-mercury-2}"
    assert environment["MERCURY_REASONING_EFFORT"] == "${MERCURY_REASONING_EFFORT:-low}"
    assert environment["GROQ_API_KEY"] == "${GROQ_API_KEY:-}"


def test_production_python_dependencies_use_the_hashed_transitive_lock() -> None:
    lock = (ROOT / "requirements-runtime.lock").read_text(encoding="utf-8")
    deploy = (ROOT / "scripts" / "deploy-droplet.sh").read_text(encoding="utf-8")
    operations = (ROOT / "docs" / "OPERATIONS.md").read_text(encoding="utf-8")

    assert "Resolved " not in lock
    assert "--python-platform x86_64-manylinux_2_36" in lock
    assert "--hash=sha256:" in lock
    assert '[ "$(uname -m)" = "x86_64" ]' in deploy
    assert "{{.Architecture}}" in deploy
    assert "Docker daemon must target amd64" in deploy
    assert "x86_64-manylinux_2_36" in operations
    for requirement in (
        "fastapi==0.139.2",
        "playwright==1.61.0",
        "composio==0.18.0",
        "google-genai==2.12.1",
    ):
        assert requirement in lock
    for dockerfile in ("Dockerfile.api", "Dockerfile.browser"):
        source = (ROOT / dockerfile).read_text(encoding="utf-8")
        assert (
            "COPY requirements-api.txt requirements-providers.txt requirements-runtime.lock ./"
            in source
        )
        assert "--require-hashes" in source
        assert "--requirement requirements-runtime.lock" in source


def test_security_gate_audits_the_exact_production_lock_without_resolving() -> None:
    gate = (ROOT / "scripts" / "security_gate.sh").read_text(encoding="utf-8")

    assert "--disable-pip" in gate
    assert "--require-hashes" in gate
    assert "-r requirements-runtime.lock" in gate
    assert "pip-audit" in gate


def test_api_uses_delayed_bounded_startup_automation_in_production() -> None:
    compose_environment = _compose()["services"]["api"]["environment"]
    template_environment = _production_env()

    assert compose_environment["OPS_STARTUP_AUTOMATION_ENABLED"] == "true"
    assert template_environment["OPS_STARTUP_AUTOMATION_ENABLED"] == "true"
    assert compose_environment["OPS_AUTOMATION_START_DELAY_SECONDS"] == (
        "${OPS_AUTOMATION_START_DELAY_SECONDS:-60}"
    )
    assert compose_environment["EMAIL_POLL_INTERVAL_SECONDS"] == (
        "${EMAIL_POLL_INTERVAL_SECONDS:-45}"
    )
    assert compose_environment["EMAIL_POLL_MAX_RUNS_PER_CYCLE"] == (
        "${EMAIL_POLL_MAX_RUNS_PER_CYCLE:-25}"
    )
    assert compose_environment["GMAIL_VERIFICATION_REQUIRE_AUTHENTICATED_SENDER"] == (
        "${GMAIL_VERIFICATION_REQUIRE_AUTHENTICATED_SENDER:-true}"
    )
    assert template_environment["GMAIL_VERIFICATION_REQUIRE_AUTHENTICATED_SENDER"] == "true"


def test_totp_secret_is_withheld_from_the_api_and_optional_for_web() -> None:
    services = _compose()["services"]
    template_environment = _production_env()

    # Containment is the durable rule: the secret is never available to the API
    # container, and no other service sees it at all.
    assert services["api"]["environment"]["OPS_AUTH_TOTP_SECRET"] == ""
    assert "OPS_AUTH_TOTP_SECRET" not in services["browser-worker"]["environment"]
    assert "OPS_AUTH_TOTP_SECRET" not in services["caddy"]["environment"]
    # The web passthrough is optional, so a deployment that omits the variable
    # renders and deploys exactly the same. The required `:?` form is refused.
    assert services["web"]["environment"].get("OPS_AUTH_TOTP_SECRET") in (
        None,
        "",
        "${OPS_AUTH_TOTP_SECRET:-}",
    )
    # cd5604f removed TOTP from production authentication, so the template no
    # longer ships the key at all. The containment rules above still apply to a
    # deployment carried over from before that change, which may still set it.
    assert "OPS_AUTH_TOTP_SECRET" not in template_environment


def test_ci_runs_browser_with_production_sandbox_posture_and_always_cleans_up() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    job = workflow.split("  browser-container-acceptance:", maxsplit=1)[1].split(
        "  production-compose-smoke:", maxsplit=1
    )[0]

    assert "--file Dockerfile.browser" in job
    assert "--user ops" in job
    assert "--read-only" in job
    assert "--memory 4g" in job
    assert "--cpus 2.0" in job
    assert "--cap-drop ALL" in job
    assert "--security-opt no-new-privileges:true" in job
    assert "--security-opt seccomp=deploy/chromium-seccomp.json" in job
    assert "--security-opt apparmor=composio-ops-browser-v1" in job
    assert "apparmor_parser -r -W /etc/apparmor.d/composio-ops-browser-v1" in job
    assert "--env PLAYWRIGHT_DISABLE_SANDBOX=false" in job
    assert "--env ALLOW_LIVE_BROWSER=true" in job
    assert "--env BROWSER_INTERACTIVE_HITL_ENABLED=true" in job
    assert "--env PLAYWRIGHT_MAX_SESSIONS=2" in job
    assert "--ipc=host" not in job
    assert "/internal/ready" in job
    assert "interactive_available" in job
    assert "for index in range(2)" in job
    assert "len({session_id for session_id, _ in sessions}) != 2" in job
    assert "for port in (5900, 5901, 5910, 5911)" in job
    assert 'if not {":99", ":100"}.issubset(chromium_displays)' in job
    assert "contextlib.ExitStack()" in job
    assert 'greeting.startswith(b"RFB ")' in job
    assert "openssl rand -hex 32" in job
    assert ".env.production" not in job
    log_capture = job.index('docker logs "${container_name}" >"${log_file}" 2>&1')
    log_scan = job.index('python scripts/assert_secret_free_log.py "${log_file}"')
    log_display = job.index('cat "${log_file}"')
    assert log_capture < log_scan < log_display
    assert 'BROWSER_SERVICE_TOKEN="${browser_token}"' in job
    assert "if: ${{ always() }}" in job
    assert "docker stop --time 10 composio-browser-acceptance" in job
    assert "docker rm --force composio-browser-acceptance" in job


def test_ci_accepts_the_complete_compose_topology_and_exact_images() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    job = workflow.split("  production-compose-smoke:", maxsplit=1)[1]

    assert "cp .env.production.example .env.production" in job
    assert "path.chmod(0o600)" in job
    assert '"${compose[@]}" config >/dev/null' in job
    assert '"${compose[@]}" build --pull' in job
    assert '"${compose[@]}" up --detach --wait --wait-timeout 360' in job
    assert "expected_id=" in job
    assert "actual_id=" in job
    assert '[ "${actual_id}" = "${expected_id}" ]' in job
    assert '[ "${revision}" = "${GITHUB_SHA}" ]' in job
    assert "OPS_DEPLOY_ACCEPTANCE_NONCE" in job
    assert "status != 503" in job
    assert '"deployment_not_accepted"' in job
    assert 'before.get("total") != 0' in job
    assert 'after.get("total") != 0' in job
    assert "write_deployment_acceptance_marker" in job
    assert '"execution_mode": "plan_only"' in job
    assert 'run.get("external_actions") is not False' in job
    assert '"${compose[@]}" restart api' in job
    assert "./scripts/backup-production-data.sh" in job
    assert "./scripts/restore-production-data.sh --dry-run" in job
    assert "http://127.0.0.1/healthz" in job
    assert "http://127.0.0.1/login" in job
    assert '"${compose[@]}" down --volumes --remove-orphans' in job
    assert "assert_secret_free_log.py" in job


def test_ci_scans_every_revisioned_production_image_with_pinned_trivy() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    production_job = workflow.split("  production-images:", maxsplit=1)[1].split(
        "  browser-container-acceptance:", maxsplit=1
    )[0]

    for image in ("api", "browser", "web", "edge"):
        assert f"- image: {image}" in production_job
    assert (
        "uses: aquasecurity/trivy-action@"
        "ed142fd0673e97e23eac54620cfb913e5ce36c25"  # pragma: allowlist secret
    ) in production_job
    assert "image-ref: composio-ops-${{ matrix.image }}:ci" in production_job
    assert "ignore-unfixed: true" in production_job
    assert "severity: HIGH,CRITICAL" in production_job
    assert 'exit-code: "1"' in production_job


def test_python_runtime_images_remove_build_only_packaging_tools() -> None:
    for dockerfile in ("Dockerfile.api", "Dockerfile.browser"):
        contents = (ROOT / dockerfile).read_text(encoding="utf-8")
        assert "python -m pip uninstall --yes setuptools wheel" in contents


def test_web_runtime_removes_build_only_npm_cli() -> None:
    dockerfile = (ROOT / "web" / "Dockerfile").read_text(encoding="utf-8")
    assert "rm -rf /usr/local/lib/node_modules/npm" in dockerfile
    assert "test ! -e /usr/local/bin/npm" in dockerfile
    assert "test ! -e /usr/local/bin/npx" in dockerfile


def test_edge_rebuilds_current_caddy_with_fixed_go_dependencies() -> None:
    dockerfile = (ROOT / "Dockerfile.caddy").read_text(encoding="utf-8")
    go_mod = (ROOT / "deploy" / "caddy-build" / "go.mod").read_text(encoding="utf-8")
    main = (ROOT / "deploy" / "caddy-build" / "main.go").read_text(encoding="utf-8")

    assert "golang:1.26.5-alpine3.24@sha256:" in dockerfile
    assert "github.com/caddyserver/caddy/v2 v2.11.4" in go_mod
    assert "golang.org/x/text v0.39.0" in go_mod
    assert "google.golang.org/grpc v1.82.1" in go_mod
    assert 'test "$(go list -m' in dockerfile
    assert "go version -m /out/caddy" in dockerfile
    assert "'c-ares>=1.34.8-r0'" in dockerfile
    assert "'curl>=8.20.0-r0'" in dockerfile
    assert "'libcurl>=8.20.0-r0'" in dockerfile
    assert 'caddycmd "github.com/caddyserver/caddy/v2/cmd"' in main
    assert '_ "github.com/caddyserver/caddy/v2/modules/standard"' in main


def test_ci_actions_are_full_sha_pinned_with_readable_release_comments() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "actions/checkout@v" not in workflow
    assert (
        workflow.count(
            "actions/checkout@"
            "11d5960a326750d5838078e36cf38b85af677262"  # pragma: allowlist secret
            " # v4.4.0"
        )
        == 6
    )
    assert (
        workflow.count(
            "actions/setup-python@"
            "a26af69be951a213d495a4c3e4e4022e16d87065"  # pragma: allowlist secret
            " # v5.6.0"
        )
        == 2
    )
    assert (
        workflow.count(
            "actions/setup-node@"
            "49933ea5288caeca8642d1e84afbd3f7d6820020"  # pragma: allowlist secret
            " # v4.4.0"
        )
        == 1
    )
