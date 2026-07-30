"""Permission checks for application-owned SQLite database paths."""

from __future__ import annotations

import os
import stat
from pathlib import Path


def _require_owned_private_directory(path: Path) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise PermissionError("database parent must be a real directory")
    if info.st_uid != os.getuid():
        raise PermissionError("database parent must be owned by the current user")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise PermissionError("database parent must not grant group or other access")


def _require_owned_private_file(path: Path) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise PermissionError("database path must be a regular file")
    if info.st_uid != os.getuid():
        raise PermissionError("database file must be owned by the current user")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise PermissionError("database file must not grant group or other access")


def prepare_private_database(path: Path) -> bool:
    """Prepare a database path without mutating pre-existing permissions.

    Returns whether the database file already existed. Only a parent directory
    created by this call is chmodded; an existing permissive or foreign-owned
    directory is rejected rather than changed.
    """

    parent = path.parent
    try:
        parent.mkdir(parents=True, mode=0o700, exist_ok=False)
    except FileExistsError:
        pass
    else:
        parent.chmod(0o700)

    _require_owned_private_directory(parent)

    existed = path.exists() or path.is_symlink()
    if existed:
        _require_owned_private_file(path)
    return existed


def finalize_private_database(path: Path, *, existed: bool) -> None:
    """Lock down and validate a database created by SQLite."""

    if not existed:
        path.chmod(0o600)
    _require_owned_private_file(path)
