"""An existing database must accept plan vocabularies that grew after it was made.

``CREATE TABLE IF NOT EXISTS`` leaves the first CHECK constraints in place forever
and SQLite cannot ALTER a CHECK, so a database created before ``source='profile'``
existed rejected every profile-sourced fallback plan at INSERT time.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from ops.core.storage import OperationsStorage


def _legacy_database(path: Path) -> None:
    """Create the table exactly as the previous release declared it."""

    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                thread_id TEXT UNIQUE NOT NULL,
                app_name TEXT NOT NULL,
                app_slug TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS onboarding_run_plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK (revision >= 1),
                status TEXT NOT NULL CHECK (status IN ('active', 'superseded')),
                source TEXT NOT NULL CHECK (source IN ('planner', 'recipe')),
                app_slug TEXT NOT NULL,
                catalog_id TEXT NOT NULL,
                recipe_version TEXT NOT NULL,
                surfaces_json TEXT NOT NULL,
                credential_host TEXT NOT NULL,
                credential_path TEXT NOT NULL,
                success_digest TEXT NOT NULL,
                reason_code TEXT NOT NULL,
                created_at TEXT NOT NULL,
                superseded_at TEXT,
                superseded_by INTEGER,
                UNIQUE (run_id, revision)
            );

            INSERT INTO onboarding_run_plans (
                run_id, revision, status, source, app_slug, catalog_id,
                recipe_version, surfaces_json, credential_host, credential_path,
                success_digest, reason_code, created_at
            ) VALUES (
                'run_legacy', 1, 'active', 'recipe', 'telegram', 'catalog-1',
                '1.0', '[]', 'example.com', '/keys', 'digest', 'host_in_app_policy',
                '2026-01-01T00:00:00Z'
            );
            """
        )
        connection.commit()
    finally:
        connection.close()


def _insert_profile_plan(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            INSERT INTO onboarding_run_plans (
                run_id, revision, status, source, app_slug, catalog_id,
                recipe_version, surfaces_json, credential_host, credential_path,
                success_digest, reason_code, created_at
            ) VALUES (
                'run_profile', 1, 'active', 'profile', 'telegram',
                'provider-profile-v1', 'digest', '[]', 'example.com', '/keys',
                'digest', 'host_in_app_policy', '2026-01-02T00:00:00Z'
            )
            """
        )
        connection.commit()
    finally:
        connection.close()


def test_a_legacy_database_rejects_a_profile_plan_before_migration(tmp_path: Path) -> None:
    """Establishes the failure the migration exists to remove."""

    db_path = tmp_path / "private" / "ops.db"
    _legacy_database(db_path)
    try:
        _insert_profile_plan(db_path)
    except sqlite3.IntegrityError:
        return
    raise AssertionError("the legacy CHECK was expected to reject source='profile'")


def test_initialize_migrates_the_legacy_check_and_preserves_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "private" / "ops.db"
    _legacy_database(db_path)

    OperationsStorage(db_path).initialize()

    # The pre-existing row survived the table rebuild.
    connection = sqlite3.connect(db_path)
    try:
        rows = connection.execute(
            "SELECT run_id, source FROM onboarding_run_plans ORDER BY id"
        ).fetchall()
    finally:
        connection.close()
    assert rows == [("run_legacy", "recipe")]

    # And the widened vocabulary is now accepted.
    _insert_profile_plan(db_path)
    connection = sqlite3.connect(db_path)
    try:
        sources = connection.execute(
            "SELECT source FROM onboarding_run_plans ORDER BY id"
        ).fetchall()
    finally:
        connection.close()
    assert sources == [("recipe",), ("profile",)]


def test_migration_is_idempotent(tmp_path: Path) -> None:
    db_path = tmp_path / "private" / "ops.db"
    _legacy_database(db_path)

    OperationsStorage(db_path).initialize()
    OperationsStorage(db_path).initialize()

    connection = sqlite3.connect(db_path)
    try:
        leftover = connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' AND name = 'onboarding_run_plans_superseded'"
        ).fetchone()
        rows = connection.execute("SELECT COUNT(*) FROM onboarding_run_plans").fetchone()
    finally:
        connection.close()
    assert leftover is None
    assert rows is not None and rows[0] == 1
