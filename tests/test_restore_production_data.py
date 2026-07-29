"""Offline contract tests for the bounded production restore utility."""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import sqlite3
import subprocess
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "restore-production-data.sh"
ARCHIVE_NAME = "production-state-20260729T010203Z.tar.gz"


def _add_file(bundle: tarfile.TarFile, name: str, value: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(value)
    info.mode = 0o600
    bundle.addfile(info, io.BytesIO(value))


def _sqlite_bytes(directory: Path, name: str, statements: tuple[str, ...]) -> bytes:
    database = directory / name
    with sqlite3.connect(database) as connection:
        for statement in statements:
            connection.execute(statement)
    value = database.read_bytes()
    database.unlink()
    return value


def _make_archive(
    directory: Path,
    *,
    extra_member: tarfile.TarInfo | None = None,
    corrupt_ops_database: bool = False,
) -> Path:
    archive = directory / ARCHIVE_NAME
    ops_database = (
        b"not-a-sqlite-database"
        if corrupt_ops_database
        else _sqlite_bytes(
            directory,
            "ops-fixture.db",
            (
                "CREATE TABLE runs (id TEXT PRIMARY KEY)",
                "CREATE TABLE audit_events (id INTEGER PRIMARY KEY)",
            ),
        )
    )
    vault_database = _sqlite_bytes(
        directory,
        "vault-fixture.db",
        ("CREATE TABLE vault_entries (id TEXT PRIMARY KEY)",),
    )
    with tarfile.open(archive, "w:gz") as bundle:
        _add_file(bundle, "ops_data/ops.db", ops_database)
        _add_file(bundle, "credential_vault/credentials.db", vault_database)
        _add_file(
            bundle,
            "browser_profiles/storage-state/placeholder",
            b"encrypted-state-placeholder",
        )
        _add_file(
            bundle,
            "ops_data/deploy-acceptance.json",
            (
                b'{"schema_version":1,"revision":"'
                + b"a" * 40
                + b'","acceptance_digest":"'
                + b"b" * 64
                + b'"}\n'
            ),
        )
        _add_file(bundle, "runtime_config/deployed-sha.txt", b"a" * 40 + b"\n")
        _add_file(bundle, "runtime_config/compose.prod.yaml", b"name: evidence\n")
        _add_file(bundle, "runtime_config/deploy/Caddyfile", b"evidence.invalid {}\n")
        if extra_member is not None:
            payload = b"unexpected"
            extra_member.size = len(payload)
            bundle.addfile(extra_member, io.BytesIO(payload))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_name(archive.name + ".sha256").write_text(
        f"{digest}  {archive.name}\n",
        encoding="ascii",
    )
    archive.chmod(0o600)
    archive.with_name(archive.name + ".sha256").chmod(0o600)
    return archive


def _run(
    *arguments: str,
    env: dict[str, str] | None = None,
    script: Path = SCRIPT,
    cwd: Path = ROOT,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(script), *arguments],
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )


def test_dry_run_decrypt_validates_without_mutating_containers_or_volumes(
    tmp_path: Path,
) -> None:
    archive = _make_archive(tmp_path)
    repo, script, env, log = _confirmed_restore_repo(tmp_path)
    result = _run(
        "--dry-run",
        str(archive),
        env=env,
        script=script,
        cwd=repo,
    )

    assert result.returncode == 0, result.stderr
    assert "no containers or volumes were changed" in result.stdout
    assert "CREATE TABLE" not in result.stdout + result.stderr
    calls = log.read_text(encoding="utf-8")
    assert "run --rm --interactive" in calls
    assert "--network none" in calls
    assert " stop " not in f" {calls}"
    assert " start " not in f" {calls}"
    assert " volume " not in f" {calls}"


def test_dry_run_rejects_state_that_current_keys_cannot_decrypt(tmp_path: Path) -> None:
    archive = _make_archive(tmp_path)
    repo, script, env, log = _confirmed_restore_repo(
        tmp_path,
        controls={"FAIL_VALIDATION": "1"},
    )

    result = _run(
        "--dry-run",
        str(archive),
        env=env,
        script=script,
        cwd=repo,
    )

    assert result.returncode != 0
    assert "does not match the current private keys" in result.stderr
    calls = log.read_text(encoding="utf-8")
    assert "run --rm --interactive" in calls
    assert " stop " not in f" {calls}"
    assert " start " not in f" {calls}"


def test_dry_run_rejects_a_corrupt_sqlite_database(tmp_path: Path) -> None:
    archive = _make_archive(tmp_path, corrupt_ops_database=True)
    result = _run("--dry-run", str(archive), env={"PATH": os.environ["PATH"]})

    assert result.returncode != 0
    assert "database integrity validation failed" in result.stderr


def test_restore_requires_explicit_confirmation(tmp_path: Path) -> None:
    archive = _make_archive(tmp_path)
    result = _run(str(archive))

    assert result.returncode != 0
    assert "--confirm-restore" in result.stderr


def test_checksum_filename_and_digest_are_exact(tmp_path: Path) -> None:
    archive = _make_archive(tmp_path)
    checksum = archive.with_name(archive.name + ".sha256")
    checksum.write_text("0" * 64 + f"  {archive.name}\n", encoding="ascii")

    result = _run("--dry-run", str(archive))

    assert result.returncode != 0
    assert "checksum validation failed" in result.stderr


def test_restore_rejects_symlinked_or_non_private_input(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    archive = _make_archive(source)
    linked = tmp_path / "linked"
    linked.mkdir()
    archive_link = linked / archive.name
    archive_link.symlink_to(archive)
    shutil.copy2(
        archive.with_name(archive.name + ".sha256"),
        archive_link.with_name(archive_link.name + ".sha256"),
    )

    symlink_result = _run("--dry-run", str(archive_link))
    assert symlink_result.returncode != 0
    assert "private regular file" in symlink_result.stderr

    archive.chmod(0o640)
    permission_result = _run("--dry-run", str(archive))
    assert permission_result.returncode != 0
    assert "private regular file" in permission_result.stderr


@pytest.mark.parametrize("member_kind", ["traversal", "symlink", "environment"])
def test_archive_rejects_unsafe_paths_and_types(
    tmp_path: Path,
    member_kind: str,
) -> None:
    if member_kind == "traversal":
        member = tarfile.TarInfo("ops_data/../../escape")
    elif member_kind == "symlink":
        member = tarfile.TarInfo("ops_data/link")
        member.type = tarfile.SYMTYPE
        member.linkname = "/etc/passwd"
    else:
        member = tarfile.TarInfo("browser_profiles/.env.production")
    archive = _make_archive(tmp_path, extra_member=member)

    result = _run("--dry-run", str(archive))

    assert result.returncode != 0
    assert "structure validation failed" in result.stderr
    assert member.name not in result.stdout + result.stderr


def _fake_docker(directory: Path) -> tuple[Path, Path]:
    binary_dir = directory / "bin"
    binary_dir.mkdir()
    log = directory / "docker.log"
    fake = binary_dir / "docker"
    fake.write_text(
        """#!/bin/sh
set -eu
. "$PWD/.fake-restore-controls"
printf '%s\\n' "$*" >> "$DOCKER_LOG"
command_name="${1:-}"
shift || true
case "$command_name" in
  info) exit 0 ;;
  image)
    case "${1:-}" in
      inspect|pull) exit 0 ;;
    esac
    ;;
  volume) exit 0 ;;
  ps)
    case "$*" in
      *volume=*) exit 0 ;;
      *com.docker.compose.service=api*)
        printf '%s\\n' api123
        ;;
      *com.docker.compose.service=browser-worker*)
        printf '%s\\n' browser123
        ;;
      *com.docker.compose.service=web*)
        printf '%s\\n' web123
        ;;
      *com.docker.compose.service=caddy*)
        printf '%s\\n' caddy123
        ;;
    esac
    exit 0
    ;;
  inspect)
    format="${2:-}"
    container_id="${3:-}"
    service="${container_id%123}"
    [ "$service" != "browser" ] || service="browser-worker"
    case "$format" in
      *State.Running*)
        if [ -f "$DOCKER_STATE/${service}_stopped" ]; then
          printf 'false\\n'
        else
          printf 'true\\n'
        fi
        ;;
      *'{{.Image}}'*) printf 'sha256:api-image\\n' ;;
      *org.opencontainers.image.revision*)
        printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\n'
        ;;
      *State.Health*)
        if [ "${FAIL_HEALTH_SERVICE:-}" = "$service" ]; then
          printf 'unhealthy\\n'
        else
          printf 'healthy\\n'
        fi
        ;;
      *) exit 2 ;;
    esac
    exit 0
    ;;
  exec)
    cat >/dev/null
    if [ "${FAIL_ACCEPTANCE:-0}" = 1 ]; then
      exit 45
    fi
    exit 0
    ;;
  stop)
    case "${1:-}" in
      api123) : > "$DOCKER_STATE/api_stopped" ;;
      browser123) : > "$DOCKER_STATE/browser-worker_stopped" ;;
      web123) : > "$DOCKER_STATE/web_stopped" ;;
      caddy123) : > "$DOCKER_STATE/caddy_stopped" ;;
    esac
    exit 0
    ;;
  start)
    case "${1:-}" in
      api123) rm -f "$DOCKER_STATE/api_stopped" ;;
      browser123) rm -f "$DOCKER_STATE/browser-worker_stopped" ;;
      web123) rm -f "$DOCKER_STATE/web_stopped" ;;
      caddy123) rm -f "$DOCKER_STATE/caddy_stopped" ;;
    esac
    exit 0
    ;;
  run)
    safety_name=""
    safety_dir=""
    archive_name=""
    for item in "$@"; do
      case "$item" in
        SAFETY_NAME=*) safety_name="${item#SAFETY_NAME=}" ;;
        ARCHIVE_NAME=*) archive_name="${item#ARCHIVE_NAME=}" ;;
        *:/safety) safety_dir="${item%:/safety}" ;;
      esac
    done
    if [ -n "$safety_name" ]; then
      printf 'safety' > "$safety_dir/$safety_name"
      printf 'checksum' > "$safety_dir/$safety_name.sha256"
      exit 0
    fi
    case "$archive_name" in
      production-state-*)
        if [ "${FAIL_PRIMARY_RESTORE:-0}" = 1 ] \
          && [ ! -f "$DOCKER_STATE/primary_failed" ]; then
          : > "$DOCKER_STATE/primary_failed"
          exit 42
        fi
        ;;
      pre-restore-*)
        if [ "${FAIL_SAFETY_RESTORE:-0}" = 1 ]; then
          exit 43
        fi
        : > "$DOCKER_STATE/safety_restored"
        ;;
    esac
    if [ -z "$archive_name" ] && [ "${FAIL_VALIDATION:-0}" = 1 ]; then
      exit 44
    fi
    exit 0
    ;;
esac
exit 1
""",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    return binary_dir, log


def _confirmed_restore_repo(
    tmp_path: Path,
    *,
    controls: dict[str, str] | None = None,
) -> tuple[Path, Path, dict[str, str], Path]:
    repo = tmp_path / "restore-repo"
    scripts = repo / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy2(SCRIPT, scripts / SCRIPT.name)
    script = scripts / SCRIPT.name
    script.chmod(0o755)
    production_env = repo / ".env.production"
    production_env.write_text(
        "\n".join(
            (
                "SECRET_VAULT_KEY=test-only-key",
                "LANGGRAPH_AES_KEY=0123456789abcdef0123456789abcdef",  # pragma: allowlist secret
                "BROWSER_STORAGE_STATE_KEY=",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    production_env.chmod(0o600)
    binary_dir, log = _fake_docker(tmp_path)
    state = tmp_path / "docker-state"
    state.mkdir()
    values = {
        "DOCKER_LOG": str(log),
        "DOCKER_STATE": str(state),
        **(controls or {}),
    }
    (repo / ".fake-restore-controls").write_text(
        "\n".join(f"{name}={value!r}" for name, value in values.items()) + "\n",
        encoding="utf-8",
    )
    environment = {
        **os.environ,
        "PATH": f"{binary_dir}:{os.environ['PATH']}",
        "RESTORE_SAFETY_DIR": str(tmp_path / "safety"),
        "RESTORE_EVIDENCE_DIR": str(tmp_path / "evidence"),
    }
    return repo, script, environment, log


def test_confirmed_restore_quiesces_backs_up_restores_and_restarts(tmp_path: Path) -> None:
    archive = _make_archive(tmp_path)
    repo, script, env, log = _confirmed_restore_repo(tmp_path)

    result = _run(
        "--confirm-restore",
        str(archive),
        env=env,
        script=script,
        cwd=repo,
    )

    assert result.returncode == 0, result.stderr
    calls = log.read_text(encoding="utf-8")
    assert calls.index("stop caddy123") < calls.index("stop web123")
    assert calls.index("stop web123") < calls.index("stop api123")
    assert calls.index("stop api123") < calls.index("stop browser123")
    assert "SAFETY_NAME=pre-restore-" in calls
    assert f"ARCHIVE_NAME={archive.name}" in calls
    assert calls.index("start browser123") < calls.index("start api123")
    assert calls.index("start api123") < calls.index("start web123")
    assert calls.index("start web123") < calls.index("start caddy123")
    assert list((tmp_path / "safety").glob("pre-restore-*.tar.gz"))
    assert list((tmp_path / "evidence").glob("*"))


def test_confirmed_restore_rejects_non_private_recovery_output_before_stop(
    tmp_path: Path,
) -> None:
    archive = _make_archive(tmp_path)
    repo, script, env, log = _confirmed_restore_repo(tmp_path)
    safety = tmp_path / "safety"
    safety.mkdir()
    safety.chmod(0o755)

    result = _run(
        "--confirm-restore",
        str(archive),
        env=env,
        script=script,
        cwd=repo,
    )

    assert result.returncode != 0
    assert "Recovery output directories must be private" in result.stderr
    calls = log.read_text(encoding="utf-8")
    assert "\nstop " not in f"\n{calls}"
    assert "SAFETY_NAME=" not in calls


def test_failed_restore_rolls_back_safety_snapshot_and_keeps_edge_closed(
    tmp_path: Path,
) -> None:
    archive = _make_archive(tmp_path)
    repo, script, env, log = _confirmed_restore_repo(
        tmp_path,
        controls={"FAIL_PRIMARY_RESTORE": "1"},
    )

    result = _run(
        "--confirm-restore",
        str(archive),
        env=env,
        script=script,
        cwd=repo,
    )

    assert result.returncode != 0
    calls = log.read_text(encoding="utf-8")
    primary_position = calls.index(f"ARCHIVE_NAME={archive.name}")
    rollback_position = calls.index("ARCHIVE_NAME=pre-restore-", primary_position)
    assert rollback_position > primary_position
    assert "start browser123" not in calls
    assert "start api123" not in calls
    assert "start web123" not in calls
    assert "start caddy123" not in calls
    assert "all production services remain stopped" in result.stderr


def test_failed_safety_rollback_exits_fatal_and_keeps_everything_stopped(
    tmp_path: Path,
) -> None:
    archive = _make_archive(tmp_path)
    repo, script, env, log = _confirmed_restore_repo(
        tmp_path,
        controls={
            "FAIL_PRIMARY_RESTORE": "1",
            "FAIL_SAFETY_RESTORE": "1",
        },
    )

    result = _run(
        "--confirm-restore",
        str(archive),
        env=env,
        script=script,
        cwd=repo,
    )

    assert result.returncode == 70
    assert "automatic safety rollback or validation failed" in result.stderr
    assert "start " not in log.read_text(encoding="utf-8")


def test_running_release_refuses_an_archive_from_another_acceptance_nonce(
    tmp_path: Path,
) -> None:
    archive = _make_archive(tmp_path)
    repo, script, env, log = _confirmed_restore_repo(
        tmp_path,
        controls={"FAIL_ACCEPTANCE": "1"},
    )

    result = _run(
        "--confirm-restore",
        str(archive),
        env=env,
        script=script,
        cwd=repo,
    )

    assert result.returncode != 0
    assert "not accepted by the exact running release" in result.stderr
    calls = log.read_text(encoding="utf-8")
    assert "exec --interactive api123" in calls
    assert "stop " not in calls
    assert "SAFETY_NAME=" not in calls


def test_leave_stopped_validates_restore_without_reopening_services(
    tmp_path: Path,
) -> None:
    archive = _make_archive(tmp_path)
    repo, script, env, log = _confirmed_restore_repo(tmp_path)

    result = _run(
        "--confirm-restore",
        "--leave-stopped",
        str(archive),
        env=env,
        script=script,
        cwd=repo,
    )

    assert result.returncode == 0, result.stderr
    calls = log.read_text(encoding="utf-8")
    assert f"ARCHIVE_NAME={archive.name}" in calls
    assert "start " not in calls
    assert "remain stopped as requested" in result.stdout


def test_leave_stopped_allows_exact_recorded_revision_to_be_deployed_next(
    tmp_path: Path,
) -> None:
    archive = _make_archive(tmp_path)
    repo, script, env, log = _confirmed_restore_repo(
        tmp_path,
        controls={"FAIL_ACCEPTANCE": "1"},
    )

    result = _run(
        "--confirm-restore",
        "--leave-stopped",
        str(archive),
        env=env,
        script=script,
        cwd=repo,
    )

    assert result.returncode == 0, result.stderr
    calls = log.read_text(encoding="utf-8")
    assert "exec --interactive api123" not in calls
    assert "\nexec api123" not in calls
    assert "start " not in calls
    assert "remain stopped as requested" in result.stdout


def test_script_uses_private_keys_only_for_offline_validation_and_restores_data_only() -> None:
    source = SCRIPT.read_text(encoding="utf-8")

    assert '--env-file "$ENV_FILE"' in source
    assert "--network none" in source
    assert "Archived encrypted state does not match the current private keys." in source
    assert "deployment_payload_is_accepted" in source
    assert "deployment_is_accepted" in source
    assert "cp --reflink=auto" in source
    assert "Fernet(key)" in source
    assert "EncryptedSerializer.from_pycryptodome_aes" in source
    assert "all production services remain stopped" in source
    assert "SAFETY_OWNER_UID" in source
    assert "SAFETY_OWNER_GID" in source
    assert 'chown "$SAFETY_OWNER_UID:$SAFETY_OWNER_GID"' in source
    assert "Recovery output already exists for this timestamp" in source
    assert "docker compose" not in source
    assert "source .env" not in source
    restore_command = source.split("restore_volumes_from_archive()", maxsplit=1)[1]
    assert "ops_data credential_vault browser_profiles" in restore_command
    assert "runtime_config" not in restore_command.split("}", maxsplit=1)[0]
