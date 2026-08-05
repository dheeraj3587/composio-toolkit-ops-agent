"""Researched signup routes, applied over the reviewed recipe catalog.

The catalog declares a signup policy for one app. Every other browser-ready app
had a complete reviewed recipe — hosts, login, credential surface, capture,
validation — and paused only because nobody had authored the two missing signup
fields. :mod:`ops.research.signup_agent` researches those two fields from the
app's own site; this module installs them.

What an overlay may change is deliberately tiny:

* ``urls.signup`` — a route the app's own official page links to.
* ``browser.signup`` — the entry paths and submit labels read off that route.

What it may NOT change is everything else, and in particular ``exact_hosts``.
An overlay is REFUSED unless the researched URL already sits on a host the
reviewed recipe navigates to. Research fills in a path inside an approved
origin; it never widens the browser allow-list. The result is re-validated by
``AppRecipe``'s own model validator, so an overlay that would produce an
invalid recipe is rejected rather than installed.

Findings are durable, and what is stored is the *finding*, never the overlaid
recipe. ``signup_overlays.db`` keeps the four researched fields plus their
evidence; the recipe is rebuilt by re-applying :func:`apply_signup_finding` to
whatever the reviewed catalog says today. So a catalog revision that moves a
host or drops a browser policy causes the stale finding to be refused on the
next read rather than resurrected — which a stored recipe blob could not do.

Durability is best-effort by design. A store that cannot be opened or read is
logged and skipped, because :func:`ops.recipes.app_recipes.get_app_recipe` is a
hot, synchronous, must-not-raise resolution used by the planner, the host
policy and the driver. Losing persistence costs one repeat research pass;
raising there would take down every route decision in the process.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

from ops.core.private_files import finalize_private_database, prepare_private_database
from ops.recipes.app_recipes import AppRecipe, SignupPolicy
from ops.research.signup_agent import SignupRouteFinding

LOGGER = logging.getLogger("composio_ops.signup_overlay")

# A separate file from ops.db, so ops/core/storage.py stays the only owner of the
# run ledger's schema and this module the only owner of the overlay schema.
SIGNUP_OVERLAY_DATABASE_NAME: Final = "signup_overlays.db"


def default_signup_overlays_db_path() -> Path:
    """Sit beside the run ledger, wherever this deployment put it.

    Read from the environment rather than from ``Settings``: the only caller is
    the process-wide registry that :func:`ops.recipes.app_recipes.get_app_recipe`
    consults, and building full settings there would make every route decision
    depend on a configuration load that can raise. ``OPS_DB_PATH`` is defaulted
    exactly as :mod:`ops.core.config` defaults it.

    Being a sibling of ``ops.db`` is what makes the overlay durable in
    production: Compose mounts that directory as the ``ops_data`` volume, so a
    path relative to the working directory would be discarded with the container
    and every restart would research every route again.
    """

    ledger = Path(os.environ.get("OPS_DB_PATH") or "./private/ops.db")
    return ledger.parent / SIGNUP_OVERLAY_DATABASE_NAME


_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS signup_overlays (
    app_slug          TEXT PRIMARY KEY,
    signup_url        TEXT NOT NULL,
    entry_path_prefix TEXT NOT NULL,
    submit_labels     TEXT NOT NULL,
    evidence_url      TEXT NOT NULL,
    scanned_pages     TEXT NOT NULL,
    researched_at     TEXT NOT NULL
);
"""

# Newline-separated, because a submit label is human page text that may contain
# any punctuation but never a line break.
_LIST_SEPARATOR: Final = "\n"


class SignupOverlayRefused(ValueError):
    """The researched route is not installable over this reviewed recipe."""


def _entry_matches(path: str, prefix: str) -> bool:
    normalized = prefix.rstrip("/") or "/"
    return path == normalized or (normalized != "/" and path.startswith(f"{normalized}/"))


def apply_signup_finding(recipe: AppRecipe, finding: SignupRouteFinding) -> AppRecipe:
    """Return ``recipe`` with the researched signup route installed.

    Raises :class:`SignupOverlayRefused` when the route is outside the recipe's
    reviewed navigation hosts, when the recipe declares no browser policy, or
    when the resulting recipe would not validate.
    """

    browser = recipe.browser
    if browser is None:
        raise SignupOverlayRefused("recipe declares no browser policy")
    if finding.app_slug != recipe.app_slug:
        raise SignupOverlayRefused("finding belongs to a different app")

    split = urlsplit(finding.signup_url)
    host = (split.hostname or "").casefold()
    if host not in browser.exact_hosts:
        # The one refusal that matters. A researched route on an unreviewed
        # origin would silently widen navigation, so it is dropped entirely
        # rather than accepted with the host appended.
        raise SignupOverlayRefused("researched signup host is not a reviewed navigation host")
    if not _entry_matches(split.path or "/", finding.entry_path_prefix):
        raise SignupOverlayRefused("researched entry path does not admit its own signup URL")
    if not finding.submit_labels:
        raise SignupOverlayRefused("researched signup route has no submit control")

    policy = SignupPolicy(
        flow="email_first",
        entry_path_prefixes=(finding.entry_path_prefix,),
        entry_submit_labels=finding.submit_labels,
        # A researched route cannot assert that submitting accepts terms on the
        # operator's behalf. Declaring it false keeps the reviewed meaning: only
        # a human-reviewed recipe may make that claim.
        entry_submit_implies_legal_acceptance=False,
    )
    payload = recipe.model_dump(mode="json")
    payload["urls"] = {**payload["urls"], "signup": finding.signup_url}
    payload["browser"] = {**payload["browser"], "signup": policy.model_dump(mode="json")}
    try:
        # Re-validated rather than ``model_copy``-ed: ``model_copy`` skips
        # validation, and the whole point of the overlay is that the recipe's
        # own signup invariants (host membership, entry-path match) still hold.
        return AppRecipe.model_validate(payload)
    except ValueError as error:
        raise SignupOverlayRefused(str(error)) from error


class SignupOverlayStore:
    """Durable researched signup findings, keyed by app slug."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        self._db_path = Path(db_path) if db_path is not None else default_signup_overlays_db_path()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        existed = prepare_private_database(self._db_path)
        connection = sqlite3.connect(self._db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        try:
            finalize_private_database(self._db_path, existed=existed)
            connection.executescript(_SCHEMA)
            yield connection
        finally:
            connection.close()

    def put(self, finding: SignupRouteFinding) -> None:
        """Persist one finding, replacing any earlier route for the same app."""

        now = datetime.now(UTC).isoformat()
        with self._connect() as connection, connection:
            connection.execute(
                """
                INSERT INTO signup_overlays (
                    app_slug, signup_url, entry_path_prefix,
                    submit_labels, evidence_url, scanned_pages, researched_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(app_slug) DO UPDATE SET
                    signup_url        = excluded.signup_url,
                    entry_path_prefix = excluded.entry_path_prefix,
                    submit_labels     = excluded.submit_labels,
                    evidence_url      = excluded.evidence_url,
                    scanned_pages     = excluded.scanned_pages,
                    researched_at     = excluded.researched_at
                """,
                (
                    finding.app_slug,
                    finding.signup_url,
                    finding.entry_path_prefix,
                    _LIST_SEPARATOR.join(finding.submit_labels),
                    finding.evidence_url,
                    _LIST_SEPARATOR.join(finding.scanned_pages),
                    now,
                ),
            )

    def load_all(self) -> tuple[SignupRouteFinding, ...]:
        """Every persisted finding. An unreadable store yields nothing."""

        if not self._db_path.exists():
            # Reading must never be what creates the file. Nothing has been
            # researched yet, and ``get_app_recipe`` — which reaches here on
            # every route decision — has no business writing to disk.
            return ()
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    """
                    SELECT app_slug, signup_url, entry_path_prefix,
                           submit_labels, evidence_url, scanned_pages
                    FROM signup_overlays
                    """
                ).fetchall()
        except (OSError, PermissionError, sqlite3.Error):
            LOGGER.warning("signup overlay store unreadable; researching again", exc_info=True)
            return ()
        return tuple(
            SignupRouteFinding(
                app_slug=row["app_slug"],
                signup_url=row["signup_url"],
                entry_path_prefix=row["entry_path_prefix"],
                submit_labels=_split(row["submit_labels"]),
                evidence_url=row["evidence_url"],
                scanned_pages=_split(row["scanned_pages"]),
            )
            for row in rows
        )


def _split(value: str) -> tuple[str, ...]:
    return tuple(part for part in value.split(_LIST_SEPARATOR) if part)


class SignupOverlayRegistry:
    """Researched findings for the process, hydrated from a durable store.

    Findings are held rather than recipes, and the overlaid recipe is rebuilt on
    every read against the reviewed recipe the caller passes in. That keeps the
    reviewed catalog authoritative: a finding that no longer fits today's recipe
    is refused at read time instead of shadowing it.
    """

    def __init__(self, store: SignupOverlayStore | None = None) -> None:
        self._findings: dict[str, SignupRouteFinding] = {}
        self._lock = threading.RLock()
        self._store = store
        self._hydrated = store is None

    def _hydrate_locked(self) -> None:
        if self._hydrated or self._store is None:
            return
        # Set before loading so a store that raises is not retried on every
        # single recipe resolution.
        self._hydrated = True
        for finding in self._store.load_all():
            self._findings.setdefault(finding.app_slug, finding)

    def overlay_for(self, reviewed: AppRecipe) -> AppRecipe | None:
        """The overlaid recipe for ``reviewed``, or ``None`` if none applies."""

        with self._lock:
            self._hydrate_locked()
            finding = self._findings.get(reviewed.app_slug)
        if finding is None:
            return None
        try:
            return apply_signup_finding(reviewed, finding)
        except SignupOverlayRefused as error:
            # A persisted route that the current catalog no longer admits. Drop
            # it so the next run researches afresh rather than retrying a route
            # that can never install.
            LOGGER.warning("discarding stale signup overlay for %s: %s", reviewed.app_slug, error)
            with self._lock:
                self._findings.pop(reviewed.app_slug, None)
            return None

    def put(self, finding: SignupRouteFinding) -> None:
        with self._lock:
            self._hydrate_locked()
            self._findings[finding.app_slug] = finding
        if self._store is None:
            return
        try:
            self._store.put(finding)
        except (OSError, PermissionError, sqlite3.Error):
            # In-memory install already succeeded, so this run proceeds; only a
            # restart pays for the lost write.
            LOGGER.warning(
                "signup overlay for %s kept in memory only", finding.app_slug, exc_info=True
            )

    def clear(self) -> None:
        with self._lock:
            self._findings.clear()
            self._hydrated = self._store is None


_REGISTRY: Final = SignupOverlayRegistry(SignupOverlayStore())


def shared_signup_overlays() -> SignupOverlayRegistry:
    """The process-wide overlay registry ``get_app_recipe`` consults."""

    return _REGISTRY


def install_signup_finding(recipe: AppRecipe, finding: SignupRouteFinding) -> AppRecipe:
    """Apply a finding, then persist it for later runs and later processes."""

    overlaid = apply_signup_finding(recipe, finding)
    _REGISTRY.put(finding)
    return overlaid


__all__ = [
    "SIGNUP_OVERLAY_DATABASE_NAME",
    "SignupOverlayRefused",
    "SignupOverlayRegistry",
    "SignupOverlayStore",
    "apply_signup_finding",
    "default_signup_overlays_db_path",
    "install_signup_finding",
    "shared_signup_overlays",
]
