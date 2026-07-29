"""Fail-closed production acceptance gate for autonomous maintenance.

Starting a candidate container is not release acceptance. Gmail polling and
browser reconciliation must remain inert until the transactional deploy has
verified exact image identities, internal health, and public routing. The deploy
then writes one owner-only marker whose digest binds both the immutable revision
and a fresh per-deploy nonce.

A stale marker cannot accept a same-revision redeploy because its nonce differs.
A manual ``docker compose up`` receives the inert sentinel nonce and therefore
waits forever. Backup and restore preserve the marker with the rest of
``ops_data`` so rollback can safely re-accept the verified previous release only
after its own health/public checks pass.

Acceptance is an admission check, not an in-flight transaction lock. For one
running release the marker is therefore monotonic (absent to accepted). Deploy
and restore orchestration must close public admission and stop the services
before replacing or revoking it for rollback.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import threading
from pathlib import Path
from typing import Protocol

from pydantic import SecretStr

_REVISION = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{43,128}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SCHEMA_VERSION = 1
_MANUAL_NONCE = "manual-unaccepted"
_MAX_MARKER_BYTES = 512


class AcceptanceSettings(Protocol):
    app_revision: str
    ops_deploy_acceptance_nonce: SecretStr | None
    ops_deploy_acceptance_marker_path: Path


def _nonce_value(value: SecretStr | None) -> str:
    return value.get_secret_value() if value is not None else ""


def _expected_digest(revision: str, nonce: str) -> str:
    return hashlib.sha256(f"{revision}\0{nonce}".encode()).hexdigest()


def _configuration(settings: AcceptanceSettings) -> tuple[str, str, Path] | None:
    try:
        revision = str(settings.app_revision)
        nonce = _nonce_value(settings.ops_deploy_acceptance_nonce)
        path = Path(settings.ops_deploy_acceptance_marker_path)
    except (AttributeError, TypeError, ValueError):
        return None
    if (
        _REVISION.fullmatch(revision) is None
        or _NONCE.fullmatch(nonce) is None
        or hmac.compare_digest(nonce, _MANUAL_NONCE)
        or not path.is_absolute()
    ):
        return None
    return revision, nonce, path


def deployment_payload_is_accepted(
    settings: AcceptanceSettings,
    payload: object,
) -> bool:
    """Validate an already-read marker against this exact runtime deployment."""

    configured = _configuration(settings)
    if configured is None:
        return False
    revision, nonce, _path = configured
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "revision",
        "acceptance_digest",
    }:
        return False
    marker_revision = payload.get("revision")
    marker_digest = payload.get("acceptance_digest")
    return bool(
        payload.get("schema_version") == _SCHEMA_VERSION
        and isinstance(marker_revision, str)
        and isinstance(marker_digest, str)
        and _DIGEST.fullmatch(marker_digest)
        and hmac.compare_digest(marker_revision, revision)
        and hmac.compare_digest(marker_digest, _expected_digest(revision, nonce))
    )


def deployment_is_accepted(settings: AcceptanceSettings) -> bool:
    """Return true only for the exact revision+nonce marker, without mutating it."""

    configured = _configuration(settings)
    if configured is None:
        return False
    _revision, _nonce, path = configured
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if not isinstance(no_follow, int) or no_follow == 0:
        # Production is Linux. On a platform that cannot guarantee a no-follow
        # open, do not fall back to a pathname check/read race.
        return False
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0),
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or info.st_size > _MAX_MARKER_BYTES
        ):
            return False
        encoded = bytearray()
        while len(encoded) <= _MAX_MARKER_BYTES:
            chunk = os.read(descriptor, _MAX_MARKER_BYTES + 1 - len(encoded))
            if not chunk:
                break
            encoded.extend(chunk)
        if len(encoded) > _MAX_MARKER_BYTES:
            return False
        payload = json.loads(bytes(encoded).decode("utf-8"))
    except (OSError, ValueError):
        return False
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return deployment_payload_is_accepted(settings, payload)


def wait_for_deployment_acceptance(
    settings: AcceptanceSettings,
    stop_event: threading.Event,
    *,
    poll_seconds: float = 1.0,
) -> bool:
    """Wait interruptibly until this exact deployment is accepted."""

    interval = max(0.05, min(float(poll_seconds), 5.0))
    while not stop_event.is_set():
        if deployment_is_accepted(settings):
            return True
        if stop_event.wait(interval):
            return False
    return False


def write_deployment_acceptance_marker(settings: AcceptanceSettings) -> None:
    """Atomically accept the exact configured release.

    This has no HTTP surface. The transactional deploy invokes it inside the API
    container only after public acceptance; ordinary application startup never
    calls it.
    """

    configured = _configuration(settings)
    if configured is None:
        raise ValueError("deployment_acceptance_configuration_invalid")
    revision, nonce, path = configured
    path.parent.mkdir(parents=True, exist_ok=True)
    parent_info = path.parent.lstat()
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or stat.S_ISLNK(parent_info.st_mode)
        or parent_info.st_uid != os.getuid()
        or stat.S_IMODE(parent_info.st_mode) & 0o077
    ):
        raise ValueError("deployment_acceptance_directory_not_private")
    payload = {
        "schema_version": _SCHEMA_VERSION,
        "revision": revision,
        "acceptance_digest": _expected_digest(revision, nonce),
    }
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


__all__ = [
    "deployment_is_accepted",
    "deployment_payload_is_accepted",
    "wait_for_deployment_acceptance",
    "write_deployment_acceptance_marker",
]
