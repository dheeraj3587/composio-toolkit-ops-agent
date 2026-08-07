"""Researched routes, applied over the reviewed recipe catalog.

The catalog declares a signup policy for one app. Every other browser-ready app
had a complete reviewed recipe — hosts, login, credential surface, capture,
validation — and paused only because nobody had authored the two missing signup
fields. :mod:`ops.research.signup_agent` researches those two fields from the
app's own site; this module installs them.

What an overlay may change is deliberately tiny:

* ``urls.signup`` — a route the app's own official page links to.
* ``browser.signup`` — the entry paths and submit labels read off that route.
* ``urls.login`` and ``urls.credential_management`` — the two operational
  routes :mod:`ops.research.operational_research` already discovers, promoted
  only into the *gaps* the reviewed recipe left (see
  :func:`apply_credential_finding`).

One known interlock, recorded here so the next reader does not mistake it for a
bug in this module: today every catalog route that lacks
``urls.credential_management`` is ``owner_submit_ready``, and
``AppRecipe._validate_playwright`` treats that URL as the *claim* that
credential capture is automated ("owner-submit route must not claim credential
automation"). So a researched console URL on such a route is refused by the
model validator, exactly as it should be — promoting it would silently convert
a human-gated owner-submit route into an automated capture, which no research
pass may authorize. Making those routes promotable needs a catalog-side change
(a destination-only credential URL that does not imply automation) in
``ops/recipes/app_recipes.py``; until then this arm installs only where the
reviewed contract already permits the URL.

What it may NOT change is everything else, and in particular ``exact_hosts``.
An overlay is REFUSED unless the researched URL already sits on a host the
reviewed recipe navigates to. Research fills in a path inside an approved
origin; it never widens the browser allow-list. The result is re-validated by
``AppRecipe``'s own model validator, so an overlay that would produce an
invalid recipe is rejected rather than installed.

Findings are durable, and what is stored is the *finding*, never the overlaid
recipe. ``signup_overlays.db`` keeps the researched fields plus their evidence
— signup routes in ``signup_overlays``, login/credential routes in
``credential_overlays`` — and the recipe is rebuilt by re-applying
:func:`apply_signup_finding` and :func:`apply_credential_finding` to whatever
the reviewed catalog says today. So a catalog revision that moves a host or
drops a browser policy causes the stale finding to be refused on the next read
rather than resurrected — which a stored recipe blob could not do.

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
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final
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

-- A sibling table rather than more columns on ``signup_overlays``: the two
-- findings are researched by different agents, arrive independently, and an app
-- may have either one alone. Widening the signup row would have forced every
-- credential write to carry a signup route it never learned (and would have
-- needed an ALTER migration on droplet databases that already hold signup rows).
-- Old databases simply do not have this table yet; ``CREATE TABLE IF NOT
-- EXISTS`` adds it on the next open, and the loaders below read by column NAME
-- so a row written by any earlier column set still loads.
CREATE TABLE IF NOT EXISTS credential_overlays (
    app_slug                  TEXT PRIMARY KEY,
    login_url                 TEXT NOT NULL DEFAULT '',
    credential_management_url TEXT NOT NULL DEFAULT '',
    evidence_url              TEXT NOT NULL DEFAULT '',
    scanned_pages             TEXT NOT NULL DEFAULT '',
    researched_at             TEXT NOT NULL DEFAULT ''
);
"""

# Newline-separated, because a submit label is human page text that may contain
# any punctuation but never a line break.
_LIST_SEPARATOR: Final = "\n"


class SignupOverlayRefused(ValueError):
    """The researched route is not installable over this reviewed recipe.

    Raised for credential-route findings too: refusal means the same thing for
    both, and :func:`ops.recipes.app_recipes.get_app_recipe` catches one type.
    """


@dataclass(frozen=True, slots=True)
class CredentialRouteFinding:
    """Login and credential-management routes researched from the app's site.

    A sibling of :class:`~ops.research.signup_agent.SignupRouteFinding` rather
    than more fields on it. The signup agent reads a registration *form* (entry
    path, submit labels); these two fields are plain operational URLs that
    :mod:`ops.research.operational_research` already produces without ever
    opening a form. Folding them together would have made every signup finding
    assert routes it did not research, and vice versa.

    Both URLs are optional because research routinely finds one and not the
    other. A finding with neither is inert and is refused at apply time.
    """

    app_slug: str
    #: The official page that evidenced these routes.
    evidence_url: str
    #: The app's sign-in page, if research found one.
    login_url: str | None = None
    #: The console page where an owner mints/reads API credentials.
    credential_management_url: str | None = None
    #: Every page read, in order, so the operator can retrace the research.
    scanned_pages: tuple[str, ...] = field(default=())


def _entry_matches(path: str, prefix: str) -> bool:
    normalized = prefix.rstrip("/") or "/"
    return path == normalized or (normalized != "/" and path.startswith(f"{normalized}/"))


def _host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").casefold()


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
    if (split.hostname or "").casefold() not in browser.exact_hosts:
        # The one refusal that matters. A researched route on an unreviewed
        # origin would silently widen navigation, so it is dropped entirely
        # rather than accepted with the host appended.
        raise SignupOverlayRefused("researched signup host is not a reviewed navigation host")
    if not _entry_matches(split.path or "/", finding.entry_path_prefix):
        raise SignupOverlayRefused("researched entry path does not admit its own signup URL")
    if not finding.submit_labels:
        raise SignupOverlayRefused("researched signup route has no submit control")

    policy = SignupPolicy(
        # Research reads a route, not a step ordering. Claiming ``email_first``
        # would assert that the page asks for an email alone first, which no
        # evidence here establishes -- and asserting it wrongly strands every
        # single-step registration form at ``signup_email_step_not_supported``.
        # ``dom_detected`` lets the driver read the form shape off the live page
        # under the same reviewed surface, host and human-gate rules.
        flow="dom_detected",
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


def apply_credential_finding(recipe: AppRecipe, finding: CredentialRouteFinding) -> AppRecipe:
    """Return ``recipe`` with researched login/credential routes installed.

    PRE: ``finding`` describes ``recipe.app_slug``; ``recipe`` is a reviewed
    recipe straight from the catalog.
    POST: the returned recipe differs from ``recipe`` in at most ``urls.login``
    and ``urls.credential_management``, each of which was ``None`` before and
    now points at a host the reviewed recipe already navigates to. No host list,
    no browser policy, no capture or validation contract is touched.

    Two refusal shapes, and they are deliberately different:

    * A researched URL on a host the reviewed recipe does not list is DROPPED —
      the other field may still install. Promoting it would make the overlay a
      way to widen navigation by writing a URL, which is the one thing this
      module exists to prevent.
    * A promotion that survives the host check but produces a recipe
      ``AppRecipe`` rejects raises :class:`SignupOverlayRefused` for the WHOLE
      finding, so the caller keeps the reviewed recipe rather than a
      half-applied one.

    Gap-fill ONLY: a field the reviewed catalog already authors is never
    replaced. That is not just caution about trust, it is what ``AppRecipe``
    already enforces — a Playwright route's first browser step must navigate to
    ``urls.login`` (ops/recipes/app_recipes.py:763), so an overlay that swapped
    the login URL without rewriting the reviewed step sequence could only ever
    produce a recipe the validator rejects. Rewriting reviewed browser steps
    from research output is a different, much larger promotion than this module
    is allowed to make.

    Pure: no I/O, no mutation of ``recipe``. Persistence is
    :meth:`SignupOverlayRegistry.put_credential_finding`'s job.
    """

    browser = recipe.browser
    if browser is None:
        # Without a reviewed browser policy there is no host list to check the
        # researched URLs against, so there is no safe way to accept them.
        raise SignupOverlayRefused("recipe declares no browser policy")
    if finding.app_slug != recipe.app_slug:
        raise SignupOverlayRefused("finding belongs to a different app")

    promoted: dict[str, str] = {}

    # Sign-in is a pre-auth, publicly linked page, and ``AppRecipe`` itself
    # requires a Playwright route's login host to be in ``exact_hosts``. Anything
    # else here would only be rejected by the model validator a few lines later.
    if finding.login_url is not None and recipe.urls.login is None:
        if _host_of(finding.login_url) in browser.exact_hosts:
            promoted["login"] = finding.login_url

    # The credential console is the one route that legitimately lives on the far
    # side of sign-in, which is exactly what ``post_auth_hosts`` reviews: entries
    # there are already top-level navigation destinations
    # (ops/browser/host_policy.py:257). Accepting them widens nothing — a URL on
    # a host in neither list would be blocked by the host policy at run time, so
    # promoting it would only manufacture a route that dead-ends.
    if finding.credential_management_url is not None and recipe.urls.credential_management is None:
        navigable = frozenset(browser.exact_hosts) | frozenset(browser.post_auth_hosts)
        if _host_of(finding.credential_management_url) in navigable:
            promoted["credential_management"] = finding.credential_management_url

    if not promoted:
        # Nothing installable: either both hosts were unreviewed, or the reviewed
        # catalog now authors these URLs itself. Refusing (rather than returning
        # the recipe unchanged) is what lets the registry drop the finding
        # instead of re-deriving the same no-op on every route decision.
        raise SignupOverlayRefused("no researched route is installable over this reviewed recipe")

    payload = recipe.model_dump(mode="json")
    payload["urls"] = {**payload["urls"], **promoted}
    try:
        # Same reason as ``apply_signup_finding``: re-validated, never
        # ``model_copy``-ed, so the recipe's own readiness contracts (a
        # browser-ready route needs validation + capture, an owner-submit route
        # must NOT claim credential automation) still decide the outcome.
        return AppRecipe.model_validate(payload)
    except ValueError as error:
        raise SignupOverlayRefused(str(error)) from error


class SignupOverlayStore:
    """Durable researched findings, keyed by app slug.

    One file, two tables: an app may have a signup route, a credential route, or
    both, and each is written by whichever agent found it without needing the
    other's fields.
    """

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

    def put_credential_finding(self, finding: CredentialRouteFinding) -> None:
        """Persist one credential-route finding, replacing the app's earlier one."""

        now = datetime.now(UTC).isoformat()
        with self._connect() as connection, connection:
            connection.execute(
                """
                INSERT INTO credential_overlays (
                    app_slug, login_url, credential_management_url,
                    evidence_url, scanned_pages, researched_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(app_slug) DO UPDATE SET
                    login_url                 = excluded.login_url,
                    credential_management_url = excluded.credential_management_url,
                    evidence_url              = excluded.evidence_url,
                    scanned_pages             = excluded.scanned_pages,
                    researched_at             = excluded.researched_at
                """,
                (
                    finding.app_slug,
                    # Stored as '' rather than NULL so the column stays NOT NULL
                    # and old readers never see an unexpected None.
                    finding.login_url or "",
                    finding.credential_management_url or "",
                    finding.evidence_url,
                    _LIST_SEPARATOR.join(finding.scanned_pages),
                    now,
                ),
            )

    def _rows(self, table: str) -> tuple[sqlite3.Row, ...]:
        """Every row of ``table``, or none at all if the store cannot be read.

        ``SELECT *`` rather than a column list, because this database may already
        exist on the droplet with a narrower schema: naming a column that an
        older writer never created raises ``OperationalError`` and would cost the
        process EVERY overlay, not just the outdated field. Callers read by name
        through :func:`_row_text`, which treats an absent column as empty.
        """

        if not self._db_path.exists():
            # Reading must never be what creates the file. Nothing has been
            # researched yet, and ``get_app_recipe`` — which reaches here on
            # every route decision — has no business writing to disk.
            return ()
        try:
            with self._connect() as connection:
                return tuple(connection.execute(f"SELECT * FROM {table}").fetchall())
        except (OSError, PermissionError, sqlite3.Error):
            LOGGER.warning("signup overlay store unreadable; researching again", exc_info=True)
            return ()

    def load_all(self) -> tuple[SignupRouteFinding, ...]:
        """Every persisted signup finding. An unreadable store yields nothing."""

        findings: list[SignupRouteFinding] = []
        for row in self._rows("signup_overlays"):
            app_slug = _row_text(row, "app_slug")
            signup_url = _row_text(row, "signup_url")
            if not app_slug or not signup_url:
                # A row from a schema that predates these two fields is not a
                # route at all. Dropping it costs one research pass; keeping it
                # would hand ``apply_signup_finding`` a slug-less finding.
                continue
            findings.append(
                SignupRouteFinding(
                    app_slug=app_slug,
                    signup_url=signup_url,
                    entry_path_prefix=_row_text(row, "entry_path_prefix"),
                    submit_labels=_split(_row_text(row, "submit_labels")),
                    evidence_url=_row_text(row, "evidence_url"),
                    scanned_pages=_split(_row_text(row, "scanned_pages")),
                )
            )
        return tuple(findings)

    def load_all_credential_findings(self) -> tuple[CredentialRouteFinding, ...]:
        """Every persisted credential-route finding, same best-effort contract."""

        findings: list[CredentialRouteFinding] = []
        for row in self._rows("credential_overlays"):
            app_slug = _row_text(row, "app_slug")
            login_url = _row_text(row, "login_url")
            management_url = _row_text(row, "credential_management_url")
            if not app_slug or not (login_url or management_url):
                continue
            findings.append(
                CredentialRouteFinding(
                    app_slug=app_slug,
                    evidence_url=_row_text(row, "evidence_url"),
                    # '' is how ``put_credential_finding`` writes "not found";
                    # the finding models that as ``None``.
                    login_url=login_url or None,
                    credential_management_url=management_url or None,
                    scanned_pages=_split(_row_text(row, "scanned_pages")),
                )
            )
        return tuple(findings)


def _split(value: str) -> tuple[str, ...]:
    return tuple(part for part in value.split(_LIST_SEPARATOR) if part)


def _row_text(row: Mapping[str, Any] | sqlite3.Row, key: str) -> str:
    """One column as text, tolerating a row written by an older schema."""

    try:
        value = row[key]
    except (IndexError, KeyError):
        return ""
    return value if isinstance(value, str) else ""


class SignupOverlayRegistry:
    """Researched findings for the process, hydrated from a durable store.

    Findings are held rather than recipes, and the overlaid recipe is rebuilt on
    every read against the reviewed recipe the caller passes in. That keeps the
    reviewed catalog authoritative: a finding that no longer fits today's recipe
    is refused at read time instead of shadowing it.
    """

    def __init__(self, store: SignupOverlayStore | None = None) -> None:
        self._findings: dict[str, SignupRouteFinding] = {}
        self._credentials: dict[str, CredentialRouteFinding] = {}
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
        for credential in self._store.load_all_credential_findings():
            self._credentials.setdefault(credential.app_slug, credential)

    def overlay_for(self, reviewed: AppRecipe) -> AppRecipe | None:
        """The overlaid recipe for ``reviewed``, or ``None`` if none applies.

        The two findings are applied in sequence and independently: a stale
        signup route does not cost the app its researched credential console,
        and vice versa. Each :func:`apply_*` call is all-or-nothing in itself,
        so what comes back is always a recipe ``AppRecipe`` validated.
        """

        with self._lock:
            self._hydrate_locked()
            finding = self._findings.get(reviewed.app_slug)
            credential = self._credentials.get(reviewed.app_slug)
        if finding is None and credential is None:
            return None
        overlaid = reviewed
        if finding is not None:
            try:
                overlaid = apply_signup_finding(overlaid, finding)
            except SignupOverlayRefused as error:
                # A persisted route that the current catalog no longer admits.
                # Drop it so the next run researches afresh rather than retrying
                # a route that can never install.
                LOGGER.warning(
                    "discarding stale signup overlay for %s: %s", reviewed.app_slug, error
                )
                with self._lock:
                    self._findings.pop(reviewed.app_slug, None)
        if credential is not None:
            try:
                overlaid = apply_credential_finding(overlaid, credential)
            except SignupOverlayRefused as error:
                LOGGER.warning(
                    "discarding stale credential overlay for %s: %s", reviewed.app_slug, error
                )
                with self._lock:
                    self._credentials.pop(reviewed.app_slug, None)
        return None if overlaid is reviewed else overlaid

    def put(self, finding: SignupRouteFinding) -> None:
        with self._lock:
            self._hydrate_locked()
            self._findings[finding.app_slug] = finding
        self._persist(finding.app_slug, lambda store: store.put(finding))

    def put_credential_finding(self, finding: CredentialRouteFinding) -> None:
        with self._lock:
            self._hydrate_locked()
            self._credentials[finding.app_slug] = finding
        self._persist(finding.app_slug, lambda store: store.put_credential_finding(finding))

    def _persist(self, app_slug: str, write: Callable[[SignupOverlayStore], None]) -> None:
        if self._store is None:
            return
        try:
            write(self._store)
        except (OSError, PermissionError, sqlite3.Error):
            # In-memory install already succeeded, so this run proceeds; only a
            # restart pays for the lost write.
            LOGGER.warning("overlay for %s kept in memory only", app_slug, exc_info=True)

    def clear(self) -> None:
        with self._lock:
            self._findings.clear()
            self._credentials.clear()
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


def install_credential_finding(recipe: AppRecipe, finding: CredentialRouteFinding) -> AppRecipe:
    """Apply a credential-route finding, then persist it.

    Persisting only after :func:`apply_credential_finding` returns is what keeps
    the store free of findings that can never install: a refusal propagates to
    the caller and nothing is written.
    """

    overlaid = apply_credential_finding(recipe, finding)
    _REGISTRY.put_credential_finding(finding)
    return overlaid


__all__ = [
    "SIGNUP_OVERLAY_DATABASE_NAME",
    "CredentialRouteFinding",
    "SignupOverlayRefused",
    "SignupOverlayRegistry",
    "SignupOverlayStore",
    "apply_credential_finding",
    "apply_signup_finding",
    "default_signup_overlays_db_path",
    "install_credential_finding",
    "install_signup_finding",
    "shared_signup_overlays",
]
