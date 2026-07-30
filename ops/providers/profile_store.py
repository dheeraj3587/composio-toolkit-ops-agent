"""Content-addressed persistence for the per-run provider profile.

A run's every later decision is justified by "the profile with digest D said so",
so the artifact behind that claim has to be immutable and retrievable by its
address. This module owns the port — :class:`ProviderProfileStore` — and its
SQLite implementation over ``provider_profiles.db``. The file is deliberately
*not* ``ops.db``: :mod:`ops.core.storage` owns every table in the run ledger, so the
profile schema lives here with its own file and its own single DDL owner.

Four decisions shape the code.

The stored body is the bytes the digest was taken of.
    ``put`` persists :func:`ops.providers.profile.canonical_profile_body_json`
    verbatim in ``body_json``, so "a *different* body under an existing digest"
    is a comparison against the same serialization the content address was
    computed from. A second notion of "the profile body" would eventually
    disagree with the digest and turn a rejection into a silent overwrite. The
    remaining columns (``signup_url``, ``approval_requirement``, ``confidence``,
    ``flows_json``, ...) are a read-only projection of that body, present so an
    operator can query the store and so the vocabularies carry database
    ``CHECK`` constraints.

Idempotence is by digest, and divergence raises rather than overwrites.
    Persisting the same profile twice writes one row and returns the same
    digest. A body that does not match the stored one under the same digest
    raises :class:`ProviderProfileConflictError` inside the write transaction,
    which rolls back, so the stored body is unchanged (Requirement 1.14).

Excerpts are never stored, only their attribution.
    ``provider_profile_evidence`` keeps ``source_url`` and the 64-hex
    ``source_digest`` of the cited excerpt. The excerpt itself is untrusted
    third-party page text; the digest preserves attribution and lets a re-fetch
    prove tampering without turning this store into a cache of arbitrary web
    content.

Tenancy is a property of the binding, not of the body.
    A profile body is a content address — two tenants who research the same
    provider to the same conclusions legitimately produce the same digest, so
    the body table carries no owner. ``provider_profile_runs`` is where tenancy
    and run scope live: it binds ``(owner, run_id) -> profile_digest``, and every
    read on this store is filtered through it, so a store constructed for one
    owner cannot read another owner's profile (Requirement 21.1). The store is
    therefore constructed *for* an owner rather than taking one per call, which
    also keeps the port's signatures free of a parameter a caller could forget.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Protocol, cast, get_args

from ops.browser.session_capability import validate_capability_owner
from ops.core.private_files import finalize_private_database, prepare_private_database
from ops.providers.profile import (
    APPROVAL_REQUIREMENTS,
    AUXILIARY_HOST_KINDS,
    BILLING_REQUIREMENTS,
    SOURCE_DIGEST_LENGTH,
    ApprovalRequirement,
    AuxiliaryHost,
    AuxiliaryHostKind,
    BillingRequirement,
    CredentialKind,
    FieldEvidence,
    FlowKind,
    FlowSpec,
    ProfileField,
    ProviderProfile,
    canonical_profile_body_json,
    compute_profile_digest,
)

LOGGER = logging.getLogger("composio_ops.provider_profile_store")

# A separate file from ops.db, so ops/core/storage.py stays the only owner of the run
# ledger's schema and this module the only owner of the profile schema.
DEFAULT_PROVIDER_PROFILES_DB_PATH: Final = Path("./private/provider_profiles.db")

PROFILE_DIGEST_LENGTH: Final = SOURCE_DIGEST_LENGTH
MAX_IDENTIFIER_LENGTH: Final = 200

# Runtime vocabularies for the values that arrive back from JSON, derived from
# the same ``Literal`` aliases the profile declares rather than restated, so a
# member added there is never missing here.
PROFILE_FIELDS: Final[frozenset[str]] = frozenset(get_args(ProfileField))
FLOW_KINDS: Final[frozenset[str]] = frozenset(get_args(FlowKind))
CREDENTIAL_KINDS: Final[frozenset[str]] = frozenset(get_args(CredentialKind))

# The four flow slots, in the order ``ProviderProfile.flows()`` reports them.
_FLOW_FIELDS: Final[tuple[str, ...]] = (
    "developer_app_flow",
    "oauth_flow",
    "api_key_flow",
    "pat_flow",
)

_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS provider_profiles (
    profile_digest        TEXT PRIMARY KEY,
    provider_name         TEXT NOT NULL,
    app_slug              TEXT NOT NULL,
    registrable_domain    TEXT NOT NULL,
    developer_portal_url  TEXT,
    signup_url            TEXT,
    login_url             TEXT,
    developer_docs_url    TEXT,
    approval_requirement  TEXT NOT NULL CHECK (
        approval_requirement IN ('none', 'manual_review', 'invite_only', 'unknown')
    ),
    billing_requirement   TEXT NOT NULL CHECK (
        billing_requirement IN ('none', 'card_required', 'paid_plan_required', 'unknown')
    ),
    flows_json            TEXT NOT NULL,
    auxiliary_hosts_json  TEXT NOT NULL,
    confidence            REAL NOT NULL CHECK (confidence BETWEEN 0.0 AND 1.0),
    adapters_engaged      TEXT NOT NULL,
    built_at              TEXT NOT NULL,
    body_json             TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS provider_profile_evidence (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_digest TEXT NOT NULL,
    field          TEXT NOT NULL,
    value          TEXT NOT NULL,
    source_url     TEXT NOT NULL,
    source_digest  TEXT NOT NULL,
    adapters       TEXT NOT NULL,
    corroborations INTEGER NOT NULL CHECK (corroborations >= 1),
    confidence     REAL NOT NULL CHECK (confidence BETWEEN 0.0 AND 1.0),
    extracted_at   TEXT NOT NULL,
    UNIQUE (profile_digest, field, value, source_digest),
    FOREIGN KEY (profile_digest) REFERENCES provider_profiles(profile_digest)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_profile_evidence_digest
ON provider_profile_evidence(profile_digest, field);

CREATE TABLE IF NOT EXISTS provider_profile_runs (
    run_id         TEXT PRIMARY KEY,
    owner          TEXT NOT NULL,
    profile_digest TEXT NOT NULL,
    bound_at       TEXT NOT NULL,
    FOREIGN KEY (profile_digest) REFERENCES provider_profiles(profile_digest)
);

CREATE INDEX IF NOT EXISTS idx_profile_runs_owner_digest
ON provider_profile_runs(owner, profile_digest);
"""


class ProviderProfileConflictError(RuntimeError):
    """A write that would contradict an already-stored, content-addressed profile.

    Carries a stable ``reason_code`` and the digest only: the rejected body is
    never echoed, because it is research output derived from third-party pages.
    """

    def __init__(self, *, reason_code: str, profile_digest: str) -> None:
        self.reason_code = reason_code
        self.profile_digest = profile_digest
        super().__init__(f"provider profile write refused for {profile_digest[:12]}: {reason_code}")


class ProviderProfileStore(Protocol):
    """Immutable, content-addressed profiles, scoped to one tenant owner."""

    def put(self, profile: ProviderProfile) -> str:
        """Persist immutably and return ``profile_digest``.

        PRE:  ``profile.profile_digest == compute_profile_digest(profile)``.
        POST: idempotent — persisting the same digest twice is a no-op that
              returns the same digest, and the run is bound to it. A DIFFERENT
              profile body under an existing digest raises
              :class:`ProviderProfileConflictError` and leaves the stored body
              unchanged; profiles are content-addressed and never mutated.
        """

    def get(self, *, profile_digest: str) -> ProviderProfile | None: ...

    def get_for_run(self, *, run_id: str) -> ProviderProfile | None: ...

    def evidence_for(self, *, profile_digest: str) -> tuple[FieldEvidence, ...]: ...


class SQLiteProviderProfileStore:
    """``provider_profiles.db``: one body per digest, reads scoped to one owner."""

    def __init__(self, db_path: str | Path, *, owner: str) -> None:
        self._path = Path(db_path)
        # The same normalization the browser capability applies to a tenant
        # namespace, so "owner" means one thing across the feature.
        self._owner = validate_capability_owner(owner)
        self.initialize()

    @property
    def owner(self) -> str:
        """The tenant namespace every row this store writes or reads belongs to."""

        return self._owner

    def initialize(self) -> None:
        """Create the profile schema if it is absent."""

        with self._connect() as connection:
            connection.executescript(_SCHEMA)

    def put(self, profile: ProviderProfile) -> str:
        """Persist the profile body once, bind the run to it, return the digest."""

        digest = _profile_digest(profile.profile_digest)
        if compute_profile_digest(profile) != digest:
            # The digest is the name of the body. A caller presenting one that
            # does not address the body it carries would make every later "this
            # decision is attributable to digest D" claim unverifiable.
            raise ValueError("profile digest does not address the profile body")
        run_id = _identifier(profile.run_id, field="run id")
        body_json = canonical_profile_body_json(profile)

        with self._write() as connection:
            stored = connection.execute(
                "SELECT body_json FROM provider_profiles WHERE profile_digest = ?",
                (digest,),
            ).fetchone()
            if stored is None:
                self._insert_profile(connection, profile, digest=digest, body_json=body_json)
            elif str(stored[0]) != body_json:
                # Rolled back by the write context, so the stored body is
                # byte-for-byte what it was before this call.
                raise ProviderProfileConflictError(
                    reason_code="profile_body_diverges_from_digest",
                    profile_digest=digest,
                )
            else:
                LOGGER.info("provider profile %s already stored; put is a no-op", digest[:12])
            self._bind_run(connection, run_id=run_id, digest=digest)
        return digest

    def get(self, *, profile_digest: str) -> ProviderProfile | None:
        """The profile at this address, or ``None`` if this owner has no run on it."""

        digest = _profile_digest(profile_digest)
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT p.body_json, p.built_at, p.adapters_engaged, r.run_id
                FROM provider_profiles AS p
                JOIN provider_profile_runs AS r ON r.profile_digest = p.profile_digest
                WHERE p.profile_digest = ? AND r.owner = ?
                ORDER BY r.bound_at ASC, r.run_id ASC
                LIMIT 1
                """,
                (digest, self._owner),
            ).fetchone()
            return self._profile_from_row(connection, row, digest=digest)

    def get_for_run(self, *, run_id: str) -> ProviderProfile | None:
        """The profile bound to this owner's run, or ``None`` if none is bound."""

        run = _identifier(run_id, field="run id")
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT p.body_json, p.built_at, p.adapters_engaged, r.run_id, p.profile_digest
                FROM provider_profile_runs AS r
                JOIN provider_profiles AS p ON p.profile_digest = r.profile_digest
                WHERE r.run_id = ? AND r.owner = ?
                """,
                (run, self._owner),
            ).fetchone()
            if row is None:
                return None
            return self._profile_from_row(connection, row, digest=str(row[4]))

    def evidence_for(self, *, profile_digest: str) -> tuple[FieldEvidence, ...]:
        """Every stored citation for this profile, in insertion order.

        Empty for a digest this owner has no run on, so the store does not
        answer "does profile D exist" for another tenant's profile.
        """

        digest = _profile_digest(profile_digest)
        with self._connect() as connection:
            if not self._owner_reaches(connection, digest):
                return ()
            rows = connection.execute(
                """
                SELECT field, value, source_url, source_digest, adapters,
                       corroborations, confidence, extracted_at
                FROM provider_profile_evidence
                WHERE profile_digest = ?
                ORDER BY id ASC
                """,
                (digest,),
            ).fetchall()
        return tuple(
            FieldEvidence(
                field=_profile_field(str(row[0])),
                value=str(row[1]),
                source_url=str(row[2]),
                source_digest=str(row[3]),
                adapters=_split_names(str(row[4])),
                corroborations=int(row[5]),
                confidence=float(row[6]),
                extracted_at=str(row[7]),
            )
            for row in rows
        )

    # --- writes ------------------------------------------------------------

    def _insert_profile(
        self,
        connection: sqlite3.Connection,
        profile: ProviderProfile,
        *,
        digest: str,
        body_json: str,
    ) -> None:
        """Write the immutable body, its queryable projection, and its citations."""

        body = _decode_body(body_json, digest=digest)
        connection.execute(
            """
            INSERT INTO provider_profiles (
                profile_digest, provider_name, app_slug, registrable_domain,
                developer_portal_url, signup_url, login_url, developer_docs_url,
                approval_requirement, billing_requirement, flows_json,
                auxiliary_hosts_json, confidence, adapters_engaged, built_at, body_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                digest,
                profile.provider_name,
                profile.app_slug,
                profile.registrable_domain,
                profile.developer_portal_url,
                profile.signup_url,
                profile.login_url,
                profile.developer_docs_url,
                profile.approval_requirement,
                profile.billing_requirement,
                # Projections of the body that was just hashed, not a re-derived
                # view of the object, so the columns cannot describe a profile
                # the digest does not name.
                _canonical_json([body[field] for field in _FLOW_FIELDS]),
                _canonical_json(body["auxiliary_hosts"]),
                profile.confidence,
                ",".join(profile.adapters_engaged),
                profile.built_at,
                body_json,
            ),
        )
        for evidence in _all_evidence(profile):
            connection.execute(
                """
                INSERT INTO provider_profile_evidence (
                    profile_digest, field, value, source_url, source_digest,
                    adapters, corroborations, confidence, extracted_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (profile_digest, field, value, source_digest) DO NOTHING
                """,
                (
                    digest,
                    evidence.field,
                    evidence.value,
                    # The excerpt is deliberately absent: attribution is the URL
                    # and the digest of what was read, never the page text.
                    evidence.source_url,
                    evidence.source_digest,
                    ",".join(evidence.adapters),
                    evidence.corroborations,
                    evidence.confidence,
                    evidence.extracted_at,
                ),
            )

    def _bind_run(self, connection: sqlite3.Connection, *, run_id: str, digest: str) -> None:
        """Bind ``(owner, run_id)`` to the digest, or refuse to rebind the run.

        A run builds exactly one profile, so a second digest under the same run
        id — or the same run id under a different owner — is a contradiction
        rather than an update.
        """

        row = connection.execute(
            "SELECT owner, profile_digest FROM provider_profile_runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            connection.execute(
                """
                INSERT INTO provider_profile_runs (run_id, owner, profile_digest, bound_at)
                VALUES (?, ?, ?, ?)
                """,
                (run_id, self._owner, digest, _utc_now()),
            )
            return
        if str(row[0]) != self._owner or str(row[1]) != digest:
            raise ProviderProfileConflictError(
                reason_code="profile_run_binding_conflict",
                profile_digest=digest,
            )

    # --- reads -------------------------------------------------------------

    def _owner_reaches(self, connection: sqlite3.Connection, digest: str) -> bool:
        row = connection.execute(
            "SELECT 1 FROM provider_profile_runs WHERE profile_digest = ? AND owner = ? LIMIT 1",
            (digest, self._owner),
        ).fetchone()
        return row is not None

    def _profile_from_row(
        self,
        connection: sqlite3.Connection,
        row: Sequence[object] | None,
        *,
        digest: str,
    ) -> ProviderProfile | None:
        """Rebuild a profile from its stored body and its per-run facts.

        The body carries everything the digest covers. ``run_id``, ``built_at``,
        ``adapters_engaged`` and each citation's ``extracted_at`` are excluded
        from the content address by design, so they are restored from the
        columns and the evidence rows that recorded them. The rebuilt profile
        therefore re-digests to the address it was read from.
        """

        if row is None:
            return None
        body = _decode_body(str(row[0]), digest=digest)
        return _profile_from_body(
            body,
            run_id=str(row[3]),
            built_at=str(row[1]),
            adapters_engaged=_split_names(str(row[2])),
            digest=digest,
            extracted_at=self._extraction_times(connection, digest),
        )

    @staticmethod
    def _extraction_times(
        connection: sqlite3.Connection,
        digest: str,
    ) -> Mapping[tuple[str, str, str], str]:
        """Citation timestamps keyed by the evidence identity the body carries."""

        rows = connection.execute(
            """
            SELECT field, value, source_digest, extracted_at
            FROM provider_profile_evidence
            WHERE profile_digest = ?
            """,
            (digest,),
        ).fetchall()
        return {(str(row[0]), str(row[1]), str(row[2])): str(row[3]) for row in rows}

    # --- connection handling ----------------------------------------------

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        """One immediate write transaction, committed or rolled back as a unit."""

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.rollback()
                raise
            connection.commit()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        existed = prepare_private_database(self._path)
        connection = sqlite3.connect(self._path, timeout=30, isolation_level=None)
        try:
            finalize_private_database(self._path, existed=existed)
            # Evidence and run bindings without their profile are meaningless, and
            # the cascade the schema declares only fires with this pragma on.
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA secure_delete = ON")
            yield connection
        finally:
            connection.close()


def _profile_from_body(
    body: Mapping[str, object],
    *,
    run_id: str,
    built_at: str,
    adapters_engaged: tuple[str, ...],
    digest: str,
    extracted_at: Mapping[tuple[str, str, str], str],
) -> ProviderProfile:
    """Rebuild the profile object from its canonical body.

    ``ProviderProfile.__post_init__`` re-checks every construction invariant on
    the way out, so a row edited outside this module cannot hand a consumer a
    profile whose URLs point off its registrable domain.
    """

    flows = tuple(
        _flow_from_body(_mapping(body, field), extracted_at=extracted_at, built_at=built_at)
        for field in _FLOW_FIELDS
    )
    return ProviderProfile(
        run_id=run_id,
        provider_name=_text(body, "provider_name"),
        app_slug=_text(body, "app_slug"),
        registrable_domain=_text(body, "registrable_domain"),
        auxiliary_hosts=tuple(
            _auxiliary_from_body(_as_mapping(item)) for item in _sequence(body, "auxiliary_hosts")
        ),
        developer_portal_url=_optional_text(body, "developer_portal_url"),
        signup_url=_optional_text(body, "signup_url"),
        login_url=_optional_text(body, "login_url"),
        developer_docs_url=_optional_text(body, "developer_docs_url"),
        developer_app_flow=flows[0],
        oauth_flow=flows[1],
        api_key_flow=flows[2],
        pat_flow=flows[3],
        approval_requirement=cast(
            ApprovalRequirement,
            _member(_text(body, "approval_requirement"), APPROVAL_REQUIREMENTS),
        ),
        billing_requirement=cast(
            BillingRequirement,
            _member(_text(body, "billing_requirement"), BILLING_REQUIREMENTS),
        ),
        evidence=_evidence_from_body(
            _sequence(body, "evidence"), extracted_at=extracted_at, built_at=built_at
        ),
        confidence=_number(body, "confidence"),
        adapters_engaged=adapters_engaged,
        built_at=built_at,
        profile_digest=digest,
    )


def _flow_from_body(
    body: Mapping[str, object],
    *,
    extracted_at: Mapping[tuple[str, str, str], str],
    built_at: str,
) -> FlowSpec:
    return FlowSpec(
        kind=cast(FlowKind, _member(_text(body, "kind"), FLOW_KINDS)),
        supported=_flag(body, "supported"),
        entry_url=_optional_text(body, "entry_url"),
        steps=tuple(_as_text(item) for item in _sequence(body, "steps")),
        produces=tuple(
            cast(CredentialKind, _member(_as_text(item), CREDENTIAL_KINDS))
            for item in _sequence(body, "produces")
        ),
        requires_approval=_flag(body, "requires_approval"),
        requires_billing=_flag(body, "requires_billing"),
        evidence=_evidence_from_body(
            _sequence(body, "evidence"), extracted_at=extracted_at, built_at=built_at
        ),
    )


def _evidence_from_body(
    items: Sequence[object],
    *,
    extracted_at: Mapping[tuple[str, str, str], str],
    built_at: str,
) -> tuple[FieldEvidence, ...]:
    """Rebuild citations, restoring the timestamps the content address excludes."""

    rebuilt: list[FieldEvidence] = []
    for item in items:
        body = _as_mapping(item)
        field = _profile_field(_text(body, "field"))
        value = _text(body, "value")
        source_digest = _text(body, "source_digest")
        rebuilt.append(
            FieldEvidence(
                field=field,
                value=value,
                source_url=_text(body, "source_url"),
                source_digest=source_digest,
                adapters=tuple(_as_text(name) for name in _sequence(body, "adapters")),
                corroborations=int(_number(body, "corroborations")),
                confidence=_number(body, "confidence"),
                # The build timestamp is the fallback: a citation whose row is
                # gone still has to produce a well-formed profile, and this field
                # is outside the digest, so the content address is unaffected.
                extracted_at=extracted_at.get((field, value, source_digest), built_at),
            )
        )
    return tuple(rebuilt)


def _auxiliary_from_body(body: Mapping[str, object]) -> AuxiliaryHost:
    return AuxiliaryHost(
        host=_text(body, "host"),
        kind=cast(AuxiliaryHostKind, _member(_text(body, "kind"), AUXILIARY_HOST_KINDS)),
        source_digest=_text(body, "source_digest"),
    )


def _all_evidence(profile: ProviderProfile) -> tuple[FieldEvidence, ...]:
    """Every citation the profile carries, profile-level and per-flow."""

    return (*profile.evidence, *(item for flow in profile.flows() for item in flow.evidence))


def _canonical_json(value: object) -> str:
    """Serialize a slice of an already-canonical body for a projection column."""

    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _decode_body(body_json: str, *, digest: str) -> Mapping[str, object]:
    decoded = json.loads(body_json)
    if not isinstance(decoded, dict):
        raise _malformed(digest)
    return cast(Mapping[str, object], decoded)


def _malformed(digest: str) -> RuntimeError:
    """A stored row that cannot be read back is a bug in this module, not input."""

    return RuntimeError(f"stored provider profile {digest[:12]} is malformed")


def _mapping(body: Mapping[str, object], key: str) -> Mapping[str, object]:
    return _as_mapping(body.get(key))


def _as_mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise RuntimeError("stored provider profile is malformed")
    return cast(Mapping[str, object], value)


def _sequence(body: Mapping[str, object], key: str) -> Sequence[object]:
    value = body.get(key, [])
    if not isinstance(value, list):
        raise RuntimeError("stored provider profile is malformed")
    return value


def _text(body: Mapping[str, object], key: str) -> str:
    return _as_text(body.get(key))


def _as_text(value: object) -> str:
    if not isinstance(value, str):
        raise RuntimeError("stored provider profile is malformed")
    return value


def _optional_text(body: Mapping[str, object], key: str) -> str | None:
    value = body.get(key)
    if value is None:
        return None
    return _as_text(value)


def _number(body: Mapping[str, object], key: str) -> float:
    value = body.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuntimeError("stored provider profile is malformed")
    return float(value)


def _flag(body: Mapping[str, object], key: str) -> bool:
    value = body.get(key)
    if not isinstance(value, bool):
        raise RuntimeError("stored provider profile is malformed")
    return value


def _member(value: str, vocabulary: frozenset[str]) -> str:
    if value not in vocabulary:
        raise RuntimeError("stored provider profile carries a value outside its vocabulary")
    return value


def _profile_field(value: str) -> ProfileField:
    return cast(ProfileField, _member(value, PROFILE_FIELDS))


def _split_names(value: str) -> tuple[str, ...]:
    """Read back a comma-joined name list, dropping the empty-string edge case."""

    return tuple(name for name in value.split(",") if name)


def _profile_digest(value: str) -> str:
    if len(value) != PROFILE_DIGEST_LENGTH:
        raise ValueError("profile digest must be a sha256 hex digest")
    return value


def _identifier(value: str, *, field: str, limit: int = MAX_IDENTIFIER_LENGTH) -> str:
    """Accept a bounded, single-line identifier and reject anything else."""

    if not value or len(value) > limit:
        raise ValueError(f"{field} is invalid")
    if any(character.isspace() or not character.isprintable() for character in value):
        raise ValueError(f"{field} is invalid")
    return value


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _port_conformance(store: SQLiteProviderProfileStore) -> ProviderProfileStore:
    """Typecheck-only proof that the SQLite store satisfies the port."""

    return store


__all__ = [
    "DEFAULT_PROVIDER_PROFILES_DB_PATH",
    "PROFILE_DIGEST_LENGTH",
    "ProviderProfileConflictError",
    "ProviderProfileStore",
    "SQLiteProviderProfileStore",
]
