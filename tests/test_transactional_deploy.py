from __future__ import annotations

import fcntl
import os
import shlex
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_REVISION = "a" * 40
PREVIOUS_REVISION = "b" * 40

# OPS_AUTH_TOTP_SECRET is deliberately absent: the release validator no longer
# requires it, no longer checks its Base32 shape, and no longer checks it against
# the other secrets, so a production environment without it must still deploy.
_SECRETS = {
    "OPS_AUTH_PASSWORD": "auth-password-Q7p4v9K2m8N5s3W6",  # pragma: allowlist secret
    "OPS_AUTH_SESSION_SECRET": "auth-session-X4n8V2c6L9q3R7t5Y1p0",  # pragma: allowlist secret
    "OPS_INTERNAL_API_TOKEN": "internal-token-A1b2C3d4E5f6G7h8I9j0",  # pragma: allowlist secret
    "BROWSER_SERVICE_TOKEN": "browser-service-K9j8H7g6F5e4D3c2B1a0",  # pragma: allowlist secret
    "BROWSER_SECRET_BROKER_TOKEN": "broker-token-Z1x2C3v4B5n6M7k8J9h0",  # pragma: allowlist secret
    "BROWSER_SESSION_CAPABILITY_KEY": "capability-key-P0o9I8u7Y6t5R4e3W2q1",  # pragma: allowlist secret
    "SECRET_VAULT_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",  # pragma: allowlist secret
    "LANGGRAPH_AES_KEY": "0123456789abcdef0123456789abcdef",  # pragma: allowlist secret
}


def _write_executable(path: Path, content: str) -> None:
    path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")
    path.chmod(0o755)


def _fake_docker_script() -> str:
    return r"""
    #!/usr/bin/env bash
    set -euo pipefail

    # Compose is deliberately invoked through `env -i`; test controls live in a
    # repo-local fixture file so the fake does not require production code to
    # preserve arbitrary ambient variables.
    source "$PWD/.fake-deploy-controls"

    trace() { printf '%s\n' "$*" >> "$FAKE_TRACE"; }
    service_from_text() {
        case "$1" in
            *browser*) printf 'browser-worker' ;;
            *edge*|*caddy*) printf 'caddy' ;;
            *api*) printf 'api' ;;
            *web*) printf 'web' ;;
            *) return 1 ;;
        esac
    }
    current_revision() {
        state="$(cat "$FAKE_STATE")"
        if [ "$state" = "candidate" ]; then
            printf '%s' "$FAKE_CANDIDATE_REV"
        else
            printf '%s' "$FAKE_PREVIOUS_REV"
        fi
    }
    current_prefix() {
        state="$(cat "$FAKE_STATE")"
        if [ "$state" = "candidate" ]; then
            printf 'candidate'
        else
            printf 'previous'
        fi
    }

    if [ "${1:-}" = "info" ]; then
        if [ "${2:-}" = "--format" ]; then
            printf 'amd64\n'
        fi
        exit 0
    fi

    if [ "${1:-}" = "image" ]; then
        action="${2:-}"
        shift 2
        if [ "$action" = "tag" ]; then
            trace "TAG $1 $2"
            exit 0
        fi
        [ "$action" = "inspect" ]
        [ "${1:-}" = "--format" ]
        format="$2"
        reference="$3"
        service="$(service_from_text "$reference")"
        case "$format" in
            *'{{.Id}}'*) printf 'sha256:candidate-%s\n' "$service" ;;
            *org.opencontainers.image.revision*) printf '%s\n' "$FAKE_CANDIDATE_REV" ;;
            *) exit 2 ;;
        esac
        exit 0
    fi

    if [ "${1:-}" = "run" ]; then
        trace "BROWSER_HOST_PREFLIGHT"
        exit 0
    fi

    if [ "${1:-}" = "exec" ]; then
        exit 0
    fi

    if [ "${1:-}" = "rm" ]; then
        trace "BROWSER_HOST_PREFLIGHT_CLEANUP"
        exit 0
    fi

    if [ "${1:-}" = "logs" ]; then
        exit 0
    fi

    if [ "${1:-}" = "inspect" ]; then
        shift
        if [ "${1:-}" != "--format" ] \
            && [[ "${1:-}" == composio-browser-host-preflight-* ]]; then
            exit 1
        fi
        if [ "${1:-}" != "--format" ]; then
            python3 - "$FAKE_PREVIOUS_REV" "$@" <<'PY'
import json
import sys

revision = sys.argv[1]
containers = []
for container_id in sys.argv[2:]:
    service = container_id.removeprefix("cid-")
    environment = []
    if service == "api":
        environment = [
            f"APP_REVISION={revision}",
            "OPS_DEPLOY_ACCEPTANCE_NONCE=old-deployment-nonce-value-that-is-long-enough-123",  # pragma: allowlist secret
        ]
    elif service == "caddy":
        environment = ["DOMAIN=previous.ops.test.invalid"]
    containers.append(
        {
            "Config": {
                "Env": environment,
                "Labels": {
                    "com.docker.compose.project": "composio-ops-prod",
                    "com.docker.compose.service": service,
                },
                "StopTimeout": 30,
            },
            "HostConfig": {
                "LogConfig": {"Type": "json-file", "Config": {}},
                "Memory": 1024,
                "NanoCpus": 1_000_000_000,
                "PidsLimit": 128,
                "RestartPolicy": {"Name": "unless-stopped"},
                "ShmSize": 67_108_864,
            },
        }
    )
print(json.dumps(containers))
PY
            exit 0
        fi
        [ "${1:-}" = "--format" ]
        format="$2"
        cid="$3"
        service="${cid#cid-}"
        prefix="$(current_prefix)"
        revision="$(current_revision)"
        case "$format" in
            *'{{.Image}}'*)
                if [ "${FAKE_IDENTITY_MISMATCH:-}" = "$service" ] \
                    && [ "$prefix" = "candidate" ]; then
                    printf 'sha256:wrong-%s\n' "$service"
                else
                    printf 'sha256:%s-%s\n' "$prefix" "$service"
                fi
                ;;
            *'{{.Config.Image}}'*)
                suffix="$service"
                [ "$service" != "browser-worker" ] || suffix="browser"
                [ "$service" != "caddy" ] || suffix="edge"
                printf 'composio-ops-%s:%s\n' "$suffix" "$revision"
                ;;
            *org.opencontainers.image.revision*)
                printf '%s\n' "$revision"
                ;;
            *AppArmorProfile*)
                printf 'composio-ops-browser-v1\n'
                ;;
            *State.Running*)
                printf 'true\n'
                ;;
            *State.Health*)
                trace "HEALTH $service $prefix"
                if [ "${FAKE_FAIL_SERVICE:-}" = "$service" ] \
                    && [ "$prefix" = "candidate" ]; then
                    printf 'unhealthy\n'
                else
                    printf 'healthy\n'
                fi
                ;;
            *) exit 2 ;;
        esac
        exit 0
    fi

    [ "${1:-}" = "compose" ]
    shift
    while [ "$#" -gt 0 ]; do
        case "$1" in
            -f|--env-file|--project-name) shift 2 ;;
            *) break ;;
        esac
    done
    command="${1:-}"
    [ "$#" -eq 0 ] || shift
    case "$command" in
        version|config)
            if [ "$command" = "version" ]; then
                exit 0
            fi
            if [ "${FAKE_ASSERT_CLEAN_COMPOSE_ENV:-0}" = "1" ]; then
                for name in \
                    ALLOW_LIVE_BROWSER \
                    OPS_STARTUP_AUTOMATION_ENABLED \
                    COMPOSE_PROJECT_NAME; do
                    if [[ -v "$name" ]]; then
                        trace "AMBIENT_OVERRIDE $name"
                        exit 97
                    fi
                done
                [ "$APP_REVISION" = "$FAKE_CANDIDATE_REV" ] \
                    || [ "$APP_REVISION" = "$FAKE_PREVIOUS_REV" ]
                trace "CONFIG_ENV_CLEAN"
            fi
            if printf '%s\n' "$*" | grep -q -- '--format json'; then
                python3 - \
                    "$APP_REVISION" \
                    "${FAKE_RENDERED_STARTUP_AUTOMATION:-true}" \
                    "${FAKE_RENDERED_AUTOMATION_DELAY:-60}" \
                    "${FAKE_RENDERED_EMAIL_POLL_INTERVAL:-45}" \
                    "${FAKE_RENDERED_EMAIL_POLL_LIMIT:-25}" \
                    "${OPS_DEPLOY_ACCEPTANCE_NONCE:-manual-unaccepted}" <<'PY'
import json
import sys

revision = sys.argv[1]
startup_automation = sys.argv[2]
automation_delay = sys.argv[3]
email_poll_interval = sys.argv[4]
email_poll_limit = sys.argv[5]
acceptance_nonce = sys.argv[6]
print(json.dumps({
    "name": "composio-ops-prod",
    "services": {
        "api": {
            "image": f"composio-ops-api:{revision}",
            "environment": {
                "BROWSER_SERVICE_CLIENT_TIMEOUT_SECONDS": "315",
                "BROWSER_SESSION_CAPABILITY_KEY": "configured",
                "BROWSER_SERVICE_OWNER": "production-owner",
                "OPS_STARTUP_AUTOMATION_ENABLED": startup_automation,
                "OPS_AUTOMATION_START_DELAY_SECONDS": automation_delay,
                "EMAIL_POLL_INTERVAL_SECONDS": email_poll_interval,
                "EMAIL_POLL_MAX_RUNS_PER_CYCLE": email_poll_limit,
                "GMAIL_VERIFICATION_REQUIRE_AUTHENTICATED_SENDER": "true",
                "APP_REVISION": revision,
                "OPS_DEPLOY_ACCEPTANCE_NONCE": acceptance_nonce,
                "OPS_DEPLOY_ACCEPTANCE_MARKER_PATH": "/data/deploy-acceptance.json",
                # Operator credentials, including the TOTP secret, stay withheld
                # from the API container: that containment rule is retained.
                "OPS_AUTH_USERNAME": "",
                "OPS_AUTH_PASSWORD": "",
                "OPS_AUTH_SESSION_SECRET": "",
                "OPS_AUTH_TOTP_SECRET": "",
            },
        },
        "browser-worker": {
            "image": f"composio-ops-browser:{revision}",
            "environment": {
                "PLAYWRIGHT_MAX_SESSIONS": "2",
                "BROWSER_OPERATION_TIMEOUT_SECONDS": "300",
                "BROWSER_SERVICE_OWNER": "production-owner",
                # compose.prod.yaml gives this a default, so a real render always
                # carries it and the contract validator requires it.
                "MERCURY_MODEL": "mercury-2",
            },
        },
        # The web service carries no TOTP secret, which the release validator
        # must now admit: the variable is an optional passthrough, not a demand.
        "web": {
            "image": f"composio-ops-web:{revision}",
            "environment": {
                "OPS_RUN_ACTION_TIMEOUT_MS": "330000",
            },
        },
        "caddy": {
            "image": f"composio-ops-edge:{revision}",
            "environment": {"BROWSER_SERVICE_OWNER": "production-owner"},
        },
    }
}))
PY
            fi
            ;;
        ps)
            service="${@: -1}"
            if [ "$service" = "ps" ] || [[ "$service" == -* ]]; then
                trace "PS"
                exit 0
            fi
            if printf '%s\n' "$*" | grep -q -- '--all'; then
                [ "${FAKE_HAVE_PREVIOUS:-1}" = "1" ] || exit 0
            fi
            printf 'cid-%s\n' "$service"
            ;;
        build)
            trace "BUILD $APP_REVISION"
            ;;
        exec)
            method="${@: -1}"
            cat >/dev/null
            if [ "$method" = "-" ]; then
                trace "ACCEPT $APP_REVISION"
                if [ "$APP_REVISION" = "$FAKE_PREVIOUS_REV" ] \
                    && [ "${FAKE_ROLLBACK_ACCEPT_FAILURE:-0}" = "1" ]; then
                    exit 1
                fi
                exit 0
            fi
            trace "DRAIN $method"
            if [ "$method" = "POST" ] && [ "${FAKE_DRAIN_POST_FAILURE:-0}" = "1" ]; then
                exit 1
            fi
            case "$method" in
                DELETE) printf '1 0\n' ;;
                *)
                    if [ "${FAKE_DRAIN_STUCK:-0}" = "1" ]; then
                        printf '0 1\n'
                    else
                        printf '0 0\n'
                    fi
                    ;;
            esac
            ;;
        stop)
            trace "STOP $*"
            ;;
        up)
            trace "UP $APP_REVISION $*"
            if [ "$APP_REVISION" = "$FAKE_CANDIDATE_REV" ]; then
                printf 'candidate\n' > "$FAKE_STATE"
            else
                printf 'previous\n' > "$FAKE_STATE"
            fi
            ;;
        *)
            printf 'unsupported fake compose command: %s\n' "$command" >&2
            exit 2
            ;;
    esac
    """


def _make_fake_repo(tmp_path: Path) -> tuple[Path, dict[str, str], Path]:
    repo = tmp_path / "repo"
    scripts = repo / "scripts"
    deploy = repo / "deploy"
    fake_bin = tmp_path / "fake-bin"
    scripts.mkdir(parents=True)
    deploy.mkdir()
    fake_bin.mkdir()

    shutil.copy2(ROOT / "scripts" / "deploy-droplet.sh", scripts / "deploy-droplet.sh")
    (scripts / "deploy-droplet.sh").chmod(0o755)
    shutil.copy2(
        ROOT / "deploy" / "composio-ops-browser.apparmor",
        deploy / "composio-ops-browser.apparmor",
    )
    shutil.copy2(
        ROOT / "deploy" / "chromium-seccomp.json",
        deploy / "chromium-seccomp.json",
    )
    (repo / "compose.prod.yaml").write_text("services: {}\n", encoding="utf-8")

    env_lines = [
        "DOMAIN=ops.test.invalid",
        "OPS_AUTH_USERNAME=ops-admin",
        *[f"{name}={value}" for name, value in _SECRETS.items()],
        "COMPOSIO_GMAIL_SIGNUP_CONNECTED_ACCOUNT_ID=",
        "GMAIL_SIGNUP_ADDRESS=",
        "GMAIL_VERIFICATION_REQUIRE_BINDING=true",
        "MANAGED_AUTH_CALLBACK_BASE_URL=https://ops.test.invalid",
        "BROWSER_SERVICE_OWNER=production-owner",
        "DEPLOY_DRAIN_TIMEOUT_SECONDS=1",
        "DEPLOY_DRAIN_POLL_SECONDS=1",
    ]
    production_env = repo / ".env.production"
    production_env.write_text("\n".join(env_lines) + "\n", encoding="utf-8")
    production_env.chmod(0o600)

    _write_executable(
        scripts / "backup-production-data.sh",
        """
        #!/usr/bin/env bash
        set -euo pipefail
        source "$PWD/.fake-deploy-controls"
        printf 'BACKUP\\n' >> "$FAKE_TRACE"
        [ "${FAKE_BACKUP_FAILURE:-0}" = "0" ] || exit 1
        output="${@: -1}"
        mkdir -p "$output"
        archive="$output/production-state-20260729T000000Z.tar.gz"
        printf 'archive' > "$archive"
        printf 'checksum' > "$archive.sha256"
        """,
    )
    _write_executable(
        scripts / "restore-production-data.sh",
        """
        #!/usr/bin/env bash
        set -euo pipefail
        source "$PWD/.fake-deploy-controls"
        printf 'RESTORE %s\\n' "$*" >> "$FAKE_TRACE"
        [ "${FAKE_RESTORE_FAILURE:-0}" = "0" ] || exit 1
        """,
    )
    _write_executable(fake_bin / "docker", _fake_docker_script())
    # The release refuses to run unless it is root, because loading the browser
    # AppArmor policy needs it. Simulate that host fact rather than requiring the
    # whole suite to run as root; every privileged action itself is faked above.
    _write_executable(
        fake_bin / "id",
        """
        #!/usr/bin/env bash
        set -euo pipefail
        if [ "${1:-}" = "-u" ]; then
            printf '0\\n'
        else
            exec /usr/bin/id "$@"
        fi
        """,
    )
    # Simulating root has to be consistent on both sides of the ownership check:
    # the release compares `stat -c %u` on .env.production against `id -u`, and a
    # file the test wrote is owned by the real runner, not by the faked root. Only
    # that one query is answered; every other stat -- including the mode check on
    # the same file and the release lock's device:inode identity -- delegates to
    # the real tool, so the private-file guard is still genuinely exercised.
    _write_executable(
        fake_bin / "stat",
        """
        #!/usr/bin/env bash
        set -euo pipefail
        if [ "${1:-}" = "-c" ] && [ "${2:-}" = "%u" ]; then
            printf '0\\n'
        else
            exec /usr/bin/stat "$@"
        fi
        """,
    )
    _write_executable(
        fake_bin / "install",
        """
        #!/usr/bin/env bash
        set -euo pipefail
        source "$PWD/.fake-deploy-controls"
        printf 'APPARMOR_INSTALL\\n' >> "$FAKE_TRACE"
        """,
    )
    _write_executable(
        fake_bin / "apparmor_parser",
        """
        #!/usr/bin/env bash
        set -euo pipefail
        source "$PWD/.fake-deploy-controls"
        if printf '%s\\n' "$*" | grep -q -- '-Q'; then
            printf 'APPARMOR_VALIDATE\\n' >> "$FAKE_TRACE"
        else
            printf 'APPARMOR_LOAD\\n' >> "$FAKE_TRACE"
        fi
        """,
    )
    _write_executable(
        fake_bin / "trivy",
        """
        #!/usr/bin/env bash
        set -euo pipefail
        source "$PWD/.fake-deploy-controls"
        printf 'TRIVY %s\\n' "${@: -1}" >> "$FAKE_TRACE"
        [ "${FAKE_TRIVY_FAILURE:-0}" = "0" ]
        """,
    )
    _write_executable(
        fake_bin / "git",
        """
        #!/usr/bin/env bash
        set -euo pipefail
        case "${1:-}" in
          status) exit 0 ;;
          rev-parse) printf '%s\\n' "$FAKE_CANDIDATE_REV" ;;
          cat-file) exit 0 ;;
          show)
            [ "${FAKE_GIT_SHOW_FAILURE:-0}" = "0" ] || exit 1
            case "${2:-}" in
              *:compose.prod.yaml) printf 'services: {}\\n' ;;
              *:deploy/chromium-seccomp.json) printf '{}\\n' ;;
              *) exit 2 ;;
            esac
            ;;
          *) exit 2 ;;
        esac
        """,
    )
    _write_executable(
        fake_bin / "curl",
        r"""
        #!/usr/bin/env bash
        set -euo pipefail
        url="${@: -1}"
        path="/${url#*://*/}"
        authority="${url#*://}"
        authority="${authority%%/*}"
        printf 'CURL %s\n' "$path" >> "$FAKE_TRACE"
        printf 'CURL_HOST %s\n' "$authority" >> "$FAKE_TRACE"
        if [[ "$url" == */system ]]; then
            if [ "${FAKE_BAD_REDIRECT:-0}" = "1" ] \
                && [ "$(cat "$FAKE_STATE")" = "candidate" ]; then
                printf '307\thttps://attacker.invalid/login'
            else
                printf '307\thttps://%s/login?next=%%2Fsystem' "$authority"
            fi
        elif [ "${FAKE_ROLLBACK_PUBLIC_FAILURE:-0}" = "1" ] \
            && [ "$(cat "$FAKE_STATE")" = "previous" ]; then
            printf '503'
        elif [ "${FAKE_PUBLIC_FAILURE:-0}" = "1" ] \
            && [ "$(cat "$FAKE_STATE")" = "candidate" ]; then
            printf '503'
        else
            printf '200'
        fi
        """,
    )

    trace = tmp_path / "trace.log"
    state = tmp_path / "state"
    state.write_text("previous\n", encoding="utf-8")
    controls = repo / ".fake-deploy-controls"
    controls.write_text(
        "\n".join(
            (
                f"FAKE_TRACE={shlex.quote(str(trace))}",
                f"FAKE_STATE={shlex.quote(str(state))}",
                f"FAKE_CANDIDATE_REV={CANDIDATE_REVISION}",
                f"FAKE_PREVIOUS_REV={PREVIOUS_REVISION}",
                "FAKE_HAVE_PREVIOUS=1",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    environment = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "FAKE_TRACE": str(trace),
        "FAKE_STATE": str(state),
        "FAKE_CANDIDATE_REV": CANDIDATE_REVISION,
        "FAKE_PREVIOUS_REV": PREVIOUS_REVISION,
        "FAKE_HAVE_PREVIOUS": "1",
    }
    return repo, environment, trace


def _fake_backup_docker_script() -> str:
    return r"""
    #!/usr/bin/env bash
    set -euo pipefail
    # Production deliberately invokes Docker through `env -i`. Test controls
    # come from a repo-local fixture rather than ambient process variables.
    source "$PWD/.fake-backup-controls"
    trace() { printf '%s\n' "$*" >> "$FAKE_TRACE"; }

    if [ "${FAKE_ASSERT_CLEAN_DOCKER_ENV:-0}" = "1" ]; then
        for name in \
            ALLOW_LIVE_BROWSER \
            APP_REVISION \
            BACKUP_DRAIN_TIMEOUT_SECONDS \
            COMPOSE_FILE \
            COMPOSE_PROJECT_NAME \
            DOCKER_DEFAULT_PLATFORM \
            OPS_STARTUP_AUTOMATION_ENABLED; do
            if [[ -v "$name" ]]; then
                trace "AMBIENT_OVERRIDE $name"
                exit 97
            fi
        done
        [ "${DOCKER_HOST:-}" = "${FAKE_EXPECT_DOCKER_HOST:-}" ]
        trace "DOCKER_ENV_CLEAN"
    fi

    case "${1:-}" in
        info) exit 0 ;;
        image)
            [ "${2:-}" = "inspect" ]
            trace "HELPER_IMAGE ${3:-}"
            exit 0
            ;;
        volume)
            [ "${2:-}" = "inspect" ]
            exit 0
            ;;
        inspect)
            format="$3"
            cid="$4"
            service="${cid#cid-}"
            case "$format" in
                *org.opencontainers.image.revision*) printf '%s\n' "$FAKE_PREVIOUS_REV" ;;
                *State.Health*) printf 'healthy\n' ;;
                *) exit 2 ;;
            esac
            exit 0
            ;;
        run)
            shift
            archive=""
            output=""
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    -e)
                        case "$2" in ARCHIVE=*) archive="${2#ARCHIVE=}" ;; esac
                        shift 2
                        ;;
                    -v)
                        case "$2" in *:/backup) output="${2%:/backup}" ;; esac
                        shift 2
                        ;;
                    *) shift ;;
                esac
            done
            [ -n "$archive" ] && [ -n "$output" ]
            trace "ARCHIVE"
            printf 'archive' > "$output/$archive"
            printf 'checksum' > "$output/$archive.sha256"
            exit 0
            ;;
    esac

    [ "${1:-}" = "compose" ]
    shift
    while [ "$#" -gt 0 ]; do
        case "$1" in
            -f|--env-file) shift 2 ;;
            *) break ;;
        esac
    done
    command="${1:-}"
    [ "$#" -eq 0 ] || shift
    case "$command" in
        version) ;;
        ps)
            service="${@: -1}"
            printf 'cid-%s\n' "$service"
            ;;
        exec)
            method="${@: -1}"
            cat >/dev/null
            trace "DRAIN $method"
            case "$method" in
                DELETE) printf '1 0\n' ;;
                *)
                    if [ "${FAKE_DRAIN_STUCK:-0}" = "1" ]; then
                        printf '0 1\n'
                    else
                        printf '0 0\n'
                    fi
                    ;;
            esac
            ;;
        stop) trace "STOP $*" ;;
        start) trace "START $*" ;;
        *) exit 2 ;;
    esac
    """


def _make_fake_backup_repo(tmp_path: Path) -> tuple[Path, dict[str, str], Path, Path]:
    repo = tmp_path / "backup-repo"
    scripts = repo / "scripts"
    fake_bin = tmp_path / "backup-fake-bin"
    output = tmp_path / "backup-output"
    scripts.mkdir(parents=True)
    fake_bin.mkdir()
    output.mkdir()
    output.chmod(0o700)

    shutil.copy2(
        ROOT / "scripts" / "backup-production-data.sh",
        scripts / "backup-production-data.sh",
    )
    (scripts / "backup-production-data.sh").chmod(0o755)
    (repo / "compose.prod.yaml").write_text("services: {}\n", encoding="utf-8")
    production_env = repo / ".env.production"
    production_env.write_text(
        "\n".join(
            (
                *(f"{name}={value}" for name, value in _SECRETS.items()),
                "BACKUP_DRAIN_TIMEOUT_SECONDS=1",
                "BACKUP_DRAIN_POLL_SECONDS=1",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    production_env.chmod(0o600)

    _write_executable(fake_bin / "docker", _fake_backup_docker_script())
    _write_executable(
        fake_bin / "git",
        """
        #!/usr/bin/env bash
        set -euo pipefail
        case "${1:-}" in
          cat-file) exit 0 ;;
          show)
            case "${2:-}" in
              *compose.prod.yaml) printf 'services: {}\\n' ;;
              *deploy/Caddyfile) printf ':443 { respond "ok" }\\n' ;;
              *) exit 2 ;;
            esac
            ;;
          *) exit 2 ;;
        esac
        """,
    )
    trace = tmp_path / "backup-trace.log"
    controls = repo / ".fake-backup-controls"
    controls.write_text(
        "\n".join(
            (
                f"FAKE_TRACE={shlex.quote(str(trace))}",
                f"FAKE_PREVIOUS_REV={PREVIOUS_REVISION}",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    environment = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
    }
    return repo, environment, trace, output


def _run_deploy(
    tmp_path: Path, **overrides: str
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    repo, environment, trace = _make_fake_repo(tmp_path)
    fake_overrides = {name: value for name, value in overrides.items() if name.startswith("FAKE_")}
    if fake_overrides:
        with (repo / ".fake-deploy-controls").open("a", encoding="utf-8") as control_file:
            for name, value in fake_overrides.items():
                control_file.write(f"{name}={shlex.quote(value)}\n")
    environment.update(overrides)
    result = subprocess.run(
        [str(repo / "scripts" / "deploy-droplet.sh")],
        cwd=repo,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    lines = trace.read_text(encoding="utf-8").splitlines() if trace.exists() else []
    return result, lines


def _index(lines: list[str], prefix: str) -> int:
    return next(index for index, line in enumerate(lines) if line.startswith(prefix))


def _assert_no_secrets(result: subprocess.CompletedProcess[str]) -> None:
    rendered = result.stdout + result.stderr
    for secret in _SECRETS.values():
        assert secret not in rendered


def _run_deploy_with_production_env_value(
    tmp_path: Path,
    name: str,
    value: str,
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    repo, environment, trace = _make_fake_repo(tmp_path)
    _replace_production_env_value(repo, name, value)
    result = subprocess.run(
        [str(repo / "scripts" / "deploy-droplet.sh")],
        cwd=repo,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    lines = trace.read_text(encoding="utf-8").splitlines() if trace.exists() else []
    return result, lines


def _replace_production_env_value(repo: Path, name: str, value: str) -> None:
    path = repo / ".env.production"
    lines = path.read_text(encoding="utf-8").splitlines()
    prefix = f"{name}="
    matches = [index for index, line in enumerate(lines) if line.startswith(prefix)]
    assert len(matches) == 1
    lines[matches[0]] = f"{prefix}{value}"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o600)


@pytest.mark.parametrize(
    ("callback", "message"),
    [
        ("", "MANAGED_AUTH_CALLBACK_BASE_URL is required"),
        (
            "https://your-domain.example",
            "MANAGED_AUTH_CALLBACK_BASE_URL contains an example placeholder",
        ),
        (
            "https://localhost.invalid",
            "MANAGED_AUTH_CALLBACK_BASE_URL contains an example placeholder",
        ),
        (
            "https://example.com",
            "MANAGED_AUTH_CALLBACK_BASE_URL contains an example placeholder",
        ),
        (
            "https://callback.example",
            "MANAGED_AUTH_CALLBACK_BASE_URL contains an example placeholder",
        ),
        ("http://ops.test.invalid", "MANAGED_AUTH_CALLBACK_BASE_URL must use HTTPS"),
        (
            "https://auth.ops.test.invalid",
            "MANAGED_AUTH_CALLBACK_BASE_URL host must exactly match DOMAIN",
        ),
        (
            "https://ops.test.invalid/oauth/callback",
            "MANAGED_AUTH_CALLBACK_BASE_URL must be an HTTPS origin",
        ),
        (
            "https://ops.test.invalid:8443",
            "MANAGED_AUTH_CALLBACK_BASE_URL must use the standard HTTPS port",
        ),
        (
            "https://owner@ops.test.invalid",
            "MANAGED_AUTH_CALLBACK_BASE_URL must not contain credentials",
        ),
    ],
)
def test_deploy_rejects_unsafe_managed_auth_callback_before_build(
    tmp_path: Path,
    callback: str,
    message: str,
) -> None:
    result, trace = _run_deploy_with_production_env_value(
        tmp_path,
        "MANAGED_AUTH_CALLBACK_BASE_URL",
        callback,
    )

    assert result.returncode != 0
    assert message in result.stderr
    assert "BUILD" not in trace
    if callback:
        assert callback not in result.stdout + result.stderr
    _assert_no_secrets(result)


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        (
            "SECRET_VAULT_KEY",
            "not-a-fernet-key",
            "SECRET_VAULT_KEY must be a canonical URL-safe Fernet key",
        ),
        (
            "SECRET_VAULT_KEY",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "SECRET_VAULT_KEY must be a canonical URL-safe Fernet key",
        ),
        (
            "LANGGRAPH_AES_KEY",
            "too-short",
            "LANGGRAPH_AES_KEY must contain exactly 32 UTF-8 bytes",
        ),
        (
            "LANGGRAPH_AES_KEY",
            "replace-with-example-aes-key-123",
            "LANGGRAPH_AES_KEY contains an example placeholder",
        ),
    ],
)
def test_deploy_rejects_invalid_encryption_key_shapes_before_build(
    tmp_path: Path,
    name: str,
    value: str,
    message: str,
) -> None:
    result, trace = _run_deploy_with_production_env_value(tmp_path, name, value)

    assert result.returncode != 0
    assert message in result.stderr
    assert "BUILD" not in trace
    assert value not in result.stdout + result.stderr
    _assert_no_secrets(result)


def test_successful_release_has_transactional_order_and_secret_free_output(
    tmp_path: Path,
) -> None:
    result, trace = _run_deploy(tmp_path)

    assert result.returncode == 0, result.stderr
    scans = [line for line in trace if line.startswith("TRIVY ")]
    assert scans == [
        "TRIVY sha256:candidate-api",
        "TRIVY sha256:candidate-browser-worker",
        "TRIVY sha256:candidate-web",
        "TRIVY sha256:candidate-caddy",
    ]
    assert _index(trace, "APPARMOR_VALIDATE") < _index(trace, "APPARMOR_INSTALL")
    assert _index(trace, "APPARMOR_INSTALL") < _index(trace, "APPARMOR_LOAD")
    assert _index(trace, "APPARMOR_LOAD") < _index(trace, "BUILD")
    assert _index(trace, "BUILD") < _index(trace, "DRAIN POST")
    assert _index(trace, "TRIVY sha256:candidate-caddy") < _index(trace, "DRAIN POST")
    assert _index(trace, "TRIVY sha256:candidate-caddy") < _index(trace, "BROWSER_HOST_PREFLIGHT")
    assert _index(trace, "BROWSER_HOST_PREFLIGHT_CLEANUP") < _index(trace, "DRAIN POST")
    assert _index(trace, "DRAIN GET") < _index(trace, "STOP caddy")
    assert _index(trace, "STOP caddy") < _index(trace, "BACKUP")
    assert _index(trace, "BACKUP") < _index(trace, "RESTORE")
    assert _index(trace, f"UP {CANDIDATE_REVISION}") < _index(
        trace, "HEALTH browser-worker candidate"
    )
    assert _index(trace, "HEALTH web candidate") < _index(
        trace, f"UP {CANDIDATE_REVISION} -d --no-build caddy"
    )
    assert _index(trace, "HEALTH caddy candidate") < _index(trace, "CURL /healthz")
    assert _index(trace, "CURL /login") < _index(trace, f"ACCEPT {CANDIDATE_REVISION}")
    assert trace.count(f"ACCEPT {CANDIDATE_REVISION}") == 1
    assert "DRAIN DELETE" not in trace
    _assert_no_secrets(result)


def test_deploy_compose_ignores_conflicting_ambient_application_values(
    tmp_path: Path,
) -> None:
    poisoned_revision = "c" * 40
    result, trace = _run_deploy(
        tmp_path,
        FAKE_ASSERT_CLEAN_COMPOSE_ENV="1",
        ALLOW_LIVE_BROWSER="ambient-must-not-win",
        OPS_STARTUP_AUTOMATION_ENABLED="true",
        COMPOSE_PROJECT_NAME="ambient-project-must-not-win",
        APP_REVISION=poisoned_revision,
    )

    assert result.returncode == 0, result.stderr
    assert "CONFIG_ENV_CLEAN" in trace
    assert not any(line.startswith("AMBIENT_OVERRIDE ") for line in trace)
    assert f"BUILD {CANDIDATE_REVISION}" in trace
    assert all(poisoned_revision not in line for line in trace)
    _assert_no_secrets(result)


@pytest.mark.parametrize(
    ("first_name", "second_name", "message"),
    [
        (
            "OPS_AUTH_SESSION_SECRET",
            "OPS_AUTH_PASSWORD",
            "OPS_AUTH_PASSWORD must differ from OPS_AUTH_SESSION_SECRET",
        ),
        (
            "BROWSER_SERVICE_TOKEN",
            "OPS_INTERNAL_API_TOKEN",
            "OPS_INTERNAL_API_TOKEN must differ from BROWSER_SERVICE_TOKEN",
        ),
    ],
)
def test_deploy_rejects_reused_auth_and_control_secrets_before_build(
    tmp_path: Path,
    first_name: str,
    second_name: str,
    message: str,
) -> None:
    repo, environment, trace = _make_fake_repo(tmp_path)
    shared_value = "shared-security-value-long-enough-for-both-12345"
    _replace_production_env_value(repo, first_name, shared_value)
    _replace_production_env_value(repo, second_name, shared_value)

    result = subprocess.run(
        [str(repo / "scripts" / "deploy-droplet.sh")],
        cwd=repo,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )

    assert result.returncode != 0
    assert message in result.stderr
    assert not trace.exists() or "BUILD" not in trace.read_text(encoding="utf-8")
    _assert_no_secrets(result)


def test_deploy_requires_delayed_bounded_startup_maintenance_before_build(
    tmp_path: Path,
) -> None:
    result, trace = _run_deploy(
        tmp_path,
        FAKE_RENDERED_STARTUP_AUTOMATION="false",
    )

    assert result.returncode != 0
    assert "OPS_STARTUP_AUTOMATION_ENABLED must enable delayed" in result.stderr
    assert "BUILD" not in trace
    _assert_no_secrets(result)


@pytest.mark.parametrize(
    ("override", "value", "message"),
    [
        (
            "FAKE_RENDERED_AUTOMATION_DELAY",
            "59",
            "OPS_AUTOMATION_START_DELAY_SECONDS",
        ),
        (
            "FAKE_RENDERED_EMAIL_POLL_INTERVAL",
            "9",
            "EMAIL_POLL_INTERVAL_SECONDS",
        ),
        (
            "FAKE_RENDERED_EMAIL_POLL_LIMIT",
            "101",
            "EMAIL_POLL_MAX_RUNS_PER_CYCLE",
        ),
    ],
)
def test_deploy_rejects_unbounded_maintenance_configuration(
    tmp_path: Path,
    override: str,
    value: str,
    message: str,
) -> None:
    result, trace = _run_deploy(tmp_path, **{override: value})

    assert result.returncode != 0
    assert message in result.stderr
    assert "BUILD" not in trace
    _assert_no_secrets(result)


@pytest.mark.parametrize(
    ("overrides", "failure_marker"),
    [
        ({"FAKE_FAIL_SERVICE": "api"}, "api did not become healthy"),
        ({"FAKE_IDENTITY_MISMATCH": "api"}, "image identity does not match"),
        ({"FAKE_BACKUP_FAILURE": "1"}, "Pre-deploy backup failed"),
        ({"FAKE_RESTORE_FAILURE": "1"}, "archive validation failed"),
        ({"FAKE_BAD_REDIRECT": "1"}, "application-auth verification failed"),
    ],
)
def test_post_drain_failures_restore_exact_previous_images_and_remain_failed(
    tmp_path: Path,
    overrides: dict[str, str],
    failure_marker: str,
) -> None:
    result, trace = _run_deploy(tmp_path, **overrides)

    assert result.returncode != 0
    assert failure_marker in result.stderr
    assert any(
        line.startswith(f"UP {PREVIOUS_REVISION}")
        and "--force-recreate" in line
        and "--remove-orphans" in line
        and "browser-worker api web" in line
        for line in trace
    )
    assert any(
        line.startswith(f"UP {PREVIOUS_REVISION}") and "--force-recreate caddy" in line
        for line in trace
    )
    for service in ("api", "browser-worker", "web", "caddy"):
        assert any(line.startswith(f"TAG sha256:previous-{service}") for line in trace)
        assert f"HEALTH {service} previous" in trace
    activation_started = any(
        key in overrides
        for key in (
            "FAKE_FAIL_SERVICE",
            "FAKE_IDENTITY_MISMATCH",
            "FAKE_BAD_REDIRECT",
        )
    )
    confirmed_restores = [
        line for line in trace if line.startswith("RESTORE --confirm-restore --leave-stopped")
    ]
    if activation_started:
        assert len(confirmed_restores) == 1
        restore_position = _index(trace, "RESTORE --confirm-restore")
        assert any(
            position > restore_position
            for position, line in enumerate(trace)
            if line.startswith("TAG sha256:previous-api")
        )
        assert f"ACCEPT {PREVIOUS_REVISION}" in trace
        assert f"ACCEPT {CANDIDATE_REVISION}" not in trace
    else:
        assert confirmed_restores == []
    rollback_edge = max(
        index
        for index, line in enumerate(trace)
        if line.startswith(f"UP {PREVIOUS_REVISION}") and "--force-recreate caddy" in line
    )
    previous_acceptance = _index(trace, f"ACCEPT {PREVIOUS_REVISION}")
    rollback_login = max(index for index, line in enumerate(trace) if line == "CURL /login")
    assert rollback_edge < rollback_login < previous_acceptance
    assert "CURL_HOST previous.ops.test.invalid" in trace
    _assert_no_secrets(result)


def test_rollback_probes_the_frozen_previous_domain_not_candidate_domain(
    tmp_path: Path,
) -> None:
    result, trace = _run_deploy(tmp_path, FAKE_FAIL_SERVICE="api")

    assert result.returncode != 0
    rollback_edge = max(
        index
        for index, line in enumerate(trace)
        if line.startswith(f"UP {PREVIOUS_REVISION}") and "--force-recreate caddy" in line
    )
    previous_probe = _index(trace, "CURL_HOST previous.ops.test.invalid")
    previous_acceptance = _index(trace, f"ACCEPT {PREVIOUS_REVISION}")
    assert rollback_edge < previous_probe < previous_acceptance
    assert not any(
        line == "CURL_HOST ops.test.invalid"
        for line in trace[rollback_edge + 1 : previous_acceptance]
    )
    _assert_no_secrets(result)


@pytest.mark.parametrize(
    "rollback_failure",
    ["FAKE_ROLLBACK_PUBLIC_FAILURE", "FAKE_ROLLBACK_ACCEPT_FAILURE"],
)
def test_failed_rollback_acceptance_stops_every_service_after_edge_started(
    tmp_path: Path,
    rollback_failure: str,
) -> None:
    result, trace = _run_deploy(
        tmp_path,
        FAKE_FAIL_SERVICE="api",
        **{rollback_failure: "1"},
    )

    assert result.returncode == 70
    assert "every production service was ordered stopped" in result.stderr
    rollback_edge = max(
        index
        for index, line in enumerate(trace)
        if line.startswith(f"UP {PREVIOUS_REVISION}") and "--force-recreate caddy" in line
    )
    final_stops = [
        index
        for index, line in enumerate(trace)
        if line == "STOP caddy web api browser-worker" and index > rollback_edge
    ]
    # Both the frozen rollback configuration and the candidate configuration
    # independently order the fixed project closed.
    assert len(final_stops) == 2
    assert f"ACCEPT {CANDIDATE_REVISION}" not in trace
    if rollback_failure == "FAKE_ROLLBACK_PUBLIC_FAILURE":
        assert f"ACCEPT {PREVIOUS_REVISION}" not in trace
    else:
        assert _index(trace, f"ACCEPT {PREVIOUS_REVISION}") < final_stops[0]
    _assert_no_secrets(result)


def test_deploy_refuses_unfreezable_previous_topology_before_build_or_drain(
    tmp_path: Path,
) -> None:
    result, trace = _run_deploy(tmp_path, FAKE_GIT_SHOW_FAILURE="1")

    assert result.returncode != 0
    assert "freeze the exact previous rollback topology and runtime" in result.stderr
    assert "BUILD" not in trace
    assert "DRAIN POST" not in trace
    assert "BACKUP" not in trace
    assert not any(line.startswith("UP ") for line in trace)
    _assert_no_secrets(result)


def test_candidate_scan_failure_aborts_before_drain_or_volume_mutation(
    tmp_path: Path,
) -> None:
    result, trace = _run_deploy(tmp_path, FAKE_TRIVY_FAILURE="1")

    assert result.returncode != 0
    assert "Exact candidate image vulnerability scan failed" in result.stderr
    assert "DRAIN POST" not in trace
    assert "BACKUP" not in trace
    assert not any(line.startswith("UP ") for line in trace)
    _assert_no_secrets(result)


def test_deploy_refuses_a_concurrent_production_operation(tmp_path: Path) -> None:
    repo, environment, trace = _make_fake_repo(tmp_path)
    lock_dir = repo / "backups"
    lock_dir.mkdir()
    lock_path = lock_dir / ".production-operations.lock"
    with lock_path.open("w", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = subprocess.run(
            [str(repo / "scripts" / "deploy-droplet.sh")],
            cwd=repo,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )

    assert result.returncode != 0
    assert "production backup, restore, or deployment is already running" in result.stderr
    assert not trace.exists() or "BUILD" not in trace.read_text(encoding="utf-8")
    _assert_no_secrets(result)


def test_drain_timeout_aborts_before_backup_or_activation_and_undrains(
    tmp_path: Path,
) -> None:
    result, trace = _run_deploy(tmp_path, FAKE_DRAIN_STUCK="1")

    assert result.returncode != 0
    assert "Browser drain timed out" in result.stderr
    assert "BACKUP" not in trace
    assert not any(line.startswith(f"UP {CANDIDATE_REVISION}") for line in trace)
    assert "DRAIN DELETE" in trace
    _assert_no_secrets(result)


def test_ambiguous_drain_response_attempts_undrain(tmp_path: Path) -> None:
    result, trace = _run_deploy(tmp_path, FAKE_DRAIN_POST_FAILURE="1")

    assert result.returncode != 0
    assert "Could not establish browser drain" in result.stderr
    assert trace.count("DRAIN POST") == 1
    assert "DRAIN DELETE" in trace
    assert "BACKUP" not in trace
    _assert_no_secrets(result)


def test_deploy_refuses_group_readable_secret_file_before_build(tmp_path: Path) -> None:
    repo, environment, trace = _make_fake_repo(tmp_path)
    (repo / ".env.production").chmod(0o640)

    result = subprocess.run(
        [str(repo / "scripts" / "deploy-droplet.sh")],
        cwd=repo,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )

    assert result.returncode != 0
    assert "private regular file owned by the deploy user" in result.stderr
    assert not trace.exists() or "BUILD" not in trace.read_text(encoding="utf-8")
    _assert_no_secrets(result)


def test_standalone_backup_drains_before_stopping_and_restores_health(
    tmp_path: Path,
) -> None:
    repo, environment, trace, output = _make_fake_backup_repo(tmp_path)
    result = subprocess.run(
        [str(repo / "scripts" / "backup-production-data.sh"), str(output)],
        cwd=repo,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    lines = trace.read_text(encoding="utf-8").splitlines()

    assert result.returncode == 0, result.stderr
    assert _index(lines, "DRAIN POST") < _index(lines, "DRAIN GET")
    assert _index(lines, "DRAIN GET") < _index(lines, "STOP api")
    assert _index(lines, "STOP browser-worker") < _index(lines, "ARCHIVE")
    assert _index(lines, "ARCHIVE") < _index(lines, "START browser-worker")
    assert _index(lines, "START browser-worker") < _index(lines, "START api")
    assert list(output.glob("production-state-*.tar.gz"))
    _assert_no_secrets(result)


def test_standalone_backup_drain_timeout_mutates_no_writer_and_undrains(
    tmp_path: Path,
) -> None:
    repo, environment, trace, output = _make_fake_backup_repo(tmp_path)
    with (repo / ".fake-backup-controls").open("a", encoding="utf-8") as control_file:
        control_file.write("FAKE_DRAIN_STUCK=1\n")
    result = subprocess.run(
        [str(repo / "scripts" / "backup-production-data.sh"), str(output)],
        cwd=repo,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    lines = trace.read_text(encoding="utf-8").splitlines()

    assert result.returncode != 0
    assert "Browser drain timed out" in result.stderr
    assert not any(line.startswith("STOP ") for line in lines)
    assert "ARCHIVE" not in lines
    assert "DRAIN DELETE" in lines
    _assert_no_secrets(result)


def test_standalone_backup_rejects_non_private_output_before_drain(
    tmp_path: Path,
) -> None:
    repo, environment, trace, output = _make_fake_backup_repo(tmp_path)
    output.chmod(0o755)

    result = subprocess.run(
        [str(repo / "scripts" / "backup-production-data.sh"), str(output)],
        cwd=repo,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    lines = trace.read_text(encoding="utf-8").splitlines() if trace.exists() else []

    assert result.returncode != 0
    assert "backup output directory must be private" in result.stderr
    assert "DRAIN POST" not in lines
    assert "ARCHIVE" not in lines
    _assert_no_secrets(result)


def test_standalone_backup_ignores_conflicting_ambient_values(
    tmp_path: Path,
) -> None:
    repo, environment, trace, output = _make_fake_backup_repo(tmp_path)
    expected_docker_host = "unix:///trusted-test-docker.sock"
    with (repo / ".fake-backup-controls").open("a", encoding="utf-8") as control_file:
        control_file.write("FAKE_ASSERT_CLEAN_DOCKER_ENV=1\n")
        control_file.write(f"FAKE_EXPECT_DOCKER_HOST={shlex.quote(expected_docker_host)}\n")
    environment.update(
        {
            "ALLOW_LIVE_BROWSER": "ambient-must-not-win",
            "APP_REVISION": "ambient-must-not-win",
            "BACKUP_DRAIN_TIMEOUT_SECONDS": "invalid-ambient-value",
            "COMPOSE_FILE": "ambient-compose-must-not-win.yaml",
            "COMPOSE_PROJECT_NAME": "ambient-project-must-not-win",
            "DOCKER_DEFAULT_PLATFORM": "ambient-platform-must-not-win",
            "DOCKER_HOST": expected_docker_host,
            "OPS_STARTUP_AUTOMATION_ENABLED": "true",
        }
    )

    result = subprocess.run(
        [str(repo / "scripts" / "backup-production-data.sh"), str(output)],
        cwd=repo,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    lines = trace.read_text(encoding="utf-8").splitlines()

    assert result.returncode == 0, result.stderr
    assert "DOCKER_ENV_CLEAN" in lines
    assert not any(line.startswith("AMBIENT_OVERRIDE ") for line in lines)
    assert list(output.glob("production-state-*.tar.gz"))
    _assert_no_secrets(result)


def test_release_scripts_declare_drain_backup_and_immutable_helper_contracts() -> None:
    deploy = (ROOT / "scripts" / "deploy-droplet.sh").read_text(encoding="utf-8")
    backup = (ROOT / "scripts" / "backup-production-data.sh").read_text(encoding="utf-8")

    assert 'compose exec -T browser-worker python - "$method"' in deploy
    assert 'os.environ["BROWSER_SERVICE_TOKEN"]' in deploy
    assert "--leave-stopped" in deploy
    assert "compose up -d --no-build" in deploy
    assert "{{.Image}}" in deploy
    assert "BROWSER_SESSION_CAPABILITY_KEY must be independent" in deploy
    assert "BROWSER_SESSION_CAPABILITY_KEY must be API-only" in deploy
    assert "MANAGED_AUTH_CALLBACK_BASE_URL host must exactly match DOMAIN" in deploy
    assert "SECRET_VAULT_KEY must be a canonical URL-safe Fernet key" in deploy
    assert "LANGGRAPH_AES_KEY must contain exactly 32 UTF-8 bytes" in deploy
    assert "OPS_STARTUP_AUTOMATION_ENABLED must enable delayed" in deploy
    assert "OPS_AUTOMATION_START_DELAY_SECONDS must be between 60 and 300" in deploy
    assert "scan_candidate_images" in deploy
    assert "install_browser_apparmor_profile" in deploy
    assert "accept_browser_candidate_on_host" in deploy
    assert 'BROWSER_APPARMOR_PROFILE_NAME="composio-ops-browser-v1"' in deploy
    assert '--security-opt "apparmor=${BROWSER_APPARMOR_PROFILE_NAME}"' in deploy
    assert "PLAYWRIGHT_DISABLE_SANDBOX=false" in deploy
    assert "--confirm-restore --leave-stopped" in deploy
    assert "COMPOSIO_PRODUCTION_LOCK_FD" in deploy
    assert "uname -m" in deploy
    assert "env" in deploy
    assert "-i" in deploy
    assert "COMPOSE_*" in deploy
    # Chromium storage encryption and the removed cloud-browser key are what the
    # API container must still never hold. The inference credentials that used to
    # be listed alongside them are the control plane's own chain — the API plans,
    # composes outreach, extracts research and builds the operator's model catalog
    # on them — so the deploy gate no longer refuses them and no longer names them.
    for browser_only_name in (
        "BROWSER_STORAGE_STATE_KEY",
        "BROWSER_USE_API_KEY",
    ):
        assert browser_only_name in deploy
    assert "restore_previous_release" in deploy
    assert "prepare_previous_release_bundle" in deploy
    assert "snapshot_previous_runtime_override" in deploy
    assert "runtime.override.json" in deploy
    assert "/dev/shm/composio-ops-rollback." in deploy
    assert "ROLLBACK_PUBLIC_ORIGIN" in deploy
    assert "public-origin.txt" in deploy
    assert 'git show "${PREVIOUS_REVISION}:compose.prod.yaml"' in deploy
    assert '--project-name "$PROJECT"' in deploy
    assert "--force-recreate --remove-orphans" in deploy
    assert "mark_rollback_release_accepted" in deploy
    assert "stop_uncertain_rollback_stack" in deploy
    assert '[ ! -L "$ENV_FILE" ]' in deploy
    assert "permission_bits & 077" in deploy
    assert "compose logs" not in deploy

    drain_index = backup.index("begin_browser_drain ||")
    stop_index = backup.index('compose stop "$service"')
    archive_index = backup.index("docker_command run --rm")
    assert drain_index < stop_index < archive_index
    assert "--leave-stopped" in backup
    assert (
        "busybox:1.37.0@sha256:"
        "9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028"  # pragma: allowlist secret
        in backup
    )
    assert 'compose exec -T browser-worker python - "$method"' in backup
    assert "docker_command compose" in backup
    assert "BACKUP_DRAIN_TIMEOUT_SECONDS || printf '300'" in backup
    assert "COMPOSE_*" in backup
    assert '[ ! -L "$ENV_FILE" ]' in backup
    assert "permission_bits & 077" in backup
    assert "BACKUP_OWNER_UID" in backup
    assert "BACKUP_OWNER_GID" in backup
    assert 'chown "$BACKUP_OWNER_UID:$BACKUP_OWNER_GID"' in backup
    assert "private_output_file_ok" in backup
    assert "A backup already exists for this timestamp" in backup
    assert "compose logs" not in backup


def test_release_shell_scripts_are_syntactically_valid() -> None:
    for relative in ("scripts/deploy-droplet.sh", "scripts/backup-production-data.sh"):
        result = subprocess.run(
            ["bash", "-n", str(ROOT / relative)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
