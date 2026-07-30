"""The durable checkpoint store, and validation of the values that address it.

Run state is a durable artifact that can contain operational detail, so the checkpoint
database is opened as a PRIVATE file and its serializer is locked down: strict JSON with
pickle and arbitrary module loading disabled, wrapped in AES encryption. Pickle
fallback in a checkpoint would mean a checkpoint could execute code on load, so it is
refused rather than merely discouraged.

The SQLite pragmas are chosen for the same reason: DELETE journalling and secure_delete
so overwritten state does not linger in a journal or in freed pages, and a long busy
timeout so a hundred sequential runs contending on one file wait instead of failing.

Thread ids and resume signals are validated because they address and mutate that
durable state: an unvalidated thread id could reach into another run's checkpoint, and
an unrecognized resume signal is rejected instead of being interpreted as a default.
"""

from __future__ import annotations

import asyncio
import importlib
import sqlite3
from pathlib import Path
from typing import Any

from pydantic import SecretStr

from ops.core.private_files import finalize_private_database, prepare_private_database


def _open_private_checkpoint(path: Path) -> sqlite3.Connection:
    existed = prepare_private_database(path)
    connection = sqlite3.connect(path, timeout=30, check_same_thread=False)
    try:
        finalize_private_database(path, existed=existed)
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA secure_delete = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection
    except Exception:
        connection.close()
        raise


def _build_saver(connection: sqlite3.Connection, key: bytes) -> object:
    json_module = importlib.import_module("langgraph.checkpoint.serde.jsonplus")
    encrypted_module = importlib.import_module("langgraph.checkpoint.serde.encrypted")
    sqlite_module = importlib.import_module("langgraph.checkpoint.sqlite")
    strict = json_module.JsonPlusSerializer(
        pickle_fallback=False,
        allowed_json_modules=None,
        allowed_msgpack_modules=None,
    )
    encrypted = encrypted_module.EncryptedSerializer.from_pycryptodome_aes(
        serde=strict,
        key=key,
    )
    saver = sqlite_module.SqliteSaver(connection, serde=encrypted)
    saver.setup()
    return saver


def _key_bytes(value: str | bytes | SecretStr) -> bytes:
    if isinstance(value, SecretStr):
        key = value.get_secret_value().encode("utf-8")
    elif isinstance(value, str):
        key = value.encode("utf-8")
    else:
        key = value
    if len(key) not in {16, 24, 32}:
        raise ValueError("LANGGRAPH_AES_KEY must contain exactly 16, 24, or 32 bytes")
    return key


def _config(thread_id: str) -> dict[str, dict[str, str]]:
    return {"configurable": {"thread_id": thread_id}}


def _validate_thread_id(value: str) -> None:
    if not value or len(value) > 200 or any(character in value for character in "\r\n\x00"):
        raise ValueError("thread_id is invalid")


def _resume_signal(value: object) -> str:
    if not isinstance(value, str) or value not in {"completed", "cancelled", "retry"}:
        raise ValueError("resume signal must be completed, cancelled, or retry")
    return value


def _run_async(awaitable: Any) -> Any:
    return asyncio.run(awaitable)
