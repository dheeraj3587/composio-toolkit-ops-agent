"""Verified, read-only adapter for the locked P1 research snapshot.

The P1 artifacts are canonical inputs.  This module validates their pinned
provenance and exact schema before exposing a record, then maps only fields
that P1 actually contains into :class:`OperationalResearch`.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import stat
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError, field_validator

from ops.models import OperationalResearch
from ops.state import AccessRoute

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_P1_ROOT = REPOSITORY_ROOT / "data" / "p1"

# These values deliberately duplicate the checked-in manifest.  A modified
# artifact and a modified manifest must not silently establish new provenance.
LOCKED_SOURCE_REPOSITORY = "dheeraj3587/composio-ai-product-ops"
LOCKED_SOURCE_COMMIT = (  # pragma: allowlist secret
    "d69549be542e00574ba2046eb7a498bc147fa756"  # pragma: allowlist secret
)
LOCKED_RESULTS_SHA256 = (  # pragma: allowlist secret
    "618c50441fc1f3a314f2c2a6684e5268862249cfe14056aacfd73781a24ec08c"  # pragma: allowlist secret
)
LOCKED_COVERAGE_SHA256 = (  # pragma: allowlist secret
    "f18ab33dad262dec8bbc47824ed979e5281c79fb421b52a1555e99ff510b49e8"  # pragma: allowlist secret
)

_MAX_MANIFEST_BYTES = 16 * 1024
_MAX_RESULTS_BYTES = 8 * 1024 * 1024
_MAX_COVERAGE_BYTES = 8 * 1024 * 1024


class SnapshotIntegrityError(RuntimeError):
    """The checked-in P1 snapshot failed provenance or schema verification."""


class P1RecordNotFoundError(LookupError):
    """A verified P1 snapshot does not contain the requested app."""

    def __init__(self, lookup: P1LookupNotFound) -> None:
        self.lookup = lookup
        super().__init__("the requested app is not present in the verified P1 snapshot")


class _LockedModel(BaseModel):
    """Strict immutable model used for canonical P1 bytes."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
        str_strip_whitespace=False,
    )


class P1AccessModel(_LockedModel):
    kind: Literal["Self-Serve", "Gated"]
    note: str = Field(min_length=1)


class P1AppRecord(_LockedModel):
    """The exact locked 19-field P1 ``AppRecord`` contract."""

    app: str = Field(min_length=1)
    category: str = Field(min_length=1)
    one_liner: str = Field(min_length=1)
    auth_methods: list[str] = Field(min_length=1)
    access_model: P1AccessModel
    api_type: Literal["REST", "GraphQL", "None"]
    api_breadth: Literal["Broad", "Moderate", "Narrow"]
    existing_mcp: Literal["Official", "Community", "None"]
    composio_toolkit: Literal["Yes", "No"]
    buildability: Literal["Easy", "Moderate", "Hard", "Blocked"]
    main_blocker: str
    recommended_next_action: Literal[
        "Build Now",
        "Needs Outreach",
        "Partner-Gated",
        "Blocked",
    ]
    evidence_urls: list[str] = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    verification_status: Literal["Auto", "Hand-Checked"]
    slug: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    primary_docs_url: str = Field(min_length=1)
    rate_limit_note: str = Field(min_length=1)
    last_verified: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")


class P1SnapshotProvenance(_LockedModel):
    source_repository: str
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    results_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    coverage_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    copied_at: str

    @field_validator("copied_at")
    @classmethod
    def copied_at_is_utc(cls, value: str) -> str:
        if not value.endswith("Z"):
            raise ValueError("copied_at must be an ISO 8601 UTC timestamp")
        # The strict suffix check plus fromisoformat rejects ambiguous or invalid dates.
        from datetime import datetime

        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("copied_at must be an ISO 8601 UTC timestamp") from exc
        offset = parsed.utcoffset()
        if offset is None or offset.total_seconds() != 0:
            raise ValueError("copied_at must be an ISO 8601 UTC timestamp")
        return value


class P1LookupFound(_LockedModel):
    status: Literal["found"] = "found"
    query: str
    normalized_query: str
    matched_by: Literal["app", "slug"]
    record: P1AppRecord
    provenance: P1SnapshotProvenance


class P1LookupNotFound(_LockedModel):
    status: Literal["not_found"] = "not_found"
    query: str
    normalized_query: str
    record: None = None
    provenance: P1SnapshotProvenance


P1LookupResult: TypeAlias = Annotated[
    P1LookupFound | P1LookupNotFound,
    Field(discriminator="status"),
]


@dataclass(frozen=True, slots=True)
class VerifiedP1Snapshot:
    """In-memory view produced only after all canonical files verify."""

    provenance: P1SnapshotProvenance
    records: tuple[P1AppRecord, ...]


_PROVENANCE_ADAPTER = TypeAdapter(P1SnapshotProvenance)
_RECORDS_ADAPTER = TypeAdapter(list[P1AppRecord])


def _read_regular_file(path: Path, *, max_bytes: int) -> bytes:
    """Atomically open and read a bounded regular file without following a symlink."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SnapshotIntegrityError("a required P1 snapshot file is unavailable") from exc

    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SnapshotIntegrityError("a required P1 snapshot file is not a regular file")
        if metadata.st_size > max_bytes:
            raise SnapshotIntegrityError("a P1 snapshot file exceeds its size limit")

        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise SnapshotIntegrityError("a P1 snapshot file exceeds its size limit")
        return data
    except OSError as exc:
        raise SnapshotIntegrityError("a required P1 snapshot file could not be read") from exc
    finally:
        os.close(descriptor)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_provenance(provenance: P1SnapshotProvenance) -> None:
    expected = (
        LOCKED_SOURCE_REPOSITORY,
        LOCKED_SOURCE_COMMIT,
        LOCKED_RESULTS_SHA256,
        LOCKED_COVERAGE_SHA256,
    )
    actual = (
        provenance.source_repository,
        provenance.source_commit,
        provenance.results_sha256,
        provenance.coverage_sha256,
    )
    if any(
        not hmac.compare_digest(value, locked)
        for value, locked in zip(actual, expected, strict=True)
    ):
        raise SnapshotIntegrityError("the P1 snapshot provenance does not match the locked release")


def load_verified_snapshot(snapshot_root: str | Path = DEFAULT_P1_ROOT) -> VerifiedP1Snapshot:
    """Verify pinned provenance and hashes, then strictly parse the P1 records."""

    root = Path(snapshot_root)
    manifest_bytes = _read_regular_file(root / "SNAPSHOT.json", max_bytes=_MAX_MANIFEST_BYTES)
    results_bytes = _read_regular_file(root / "results.json", max_bytes=_MAX_RESULTS_BYTES)
    coverage_bytes = _read_regular_file(
        root / "composio_coverage.json", max_bytes=_MAX_COVERAGE_BYTES
    )

    try:
        provenance = _PROVENANCE_ADAPTER.validate_json(manifest_bytes, strict=True)
    except ValidationError as exc:
        raise SnapshotIntegrityError("the P1 provenance manifest is invalid") from exc
    _validate_provenance(provenance)

    if not hmac.compare_digest(_sha256(results_bytes), provenance.results_sha256):
        raise SnapshotIntegrityError("the P1 results hash does not match its locked provenance")
    if not hmac.compare_digest(_sha256(coverage_bytes), provenance.coverage_sha256):
        raise SnapshotIntegrityError("the P1 coverage hash does not match its locked provenance")

    try:
        records = _RECORDS_ADAPTER.validate_json(results_bytes, strict=True)
    except ValidationError as exc:
        raise SnapshotIntegrityError(
            "the P1 results do not match the locked 19-field schema"
        ) from exc
    if not records:
        raise SnapshotIntegrityError("the P1 results contain no records")

    app_keys: set[str] = set()
    slug_keys: set[str] = set()
    for record in records:
        app_key = _normalize_lookup_key(record.app)
        slug_key = _normalize_lookup_key(record.slug)
        if app_key in app_keys or slug_key in slug_keys:
            raise SnapshotIntegrityError("the P1 results contain duplicate app or slug keys")
        app_keys.add(app_key)
        slug_keys.add(slug_key)

    return VerifiedP1Snapshot(provenance=provenance, records=tuple(records))


def _normalize_lookup_key(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value)
    return " ".join(normalized.split()).casefold()


def _p1_evidence_route(record: P1AppRecord) -> AccessRoute:
    """Map only explicit P1 classifications; do not infer operational URLs or approval facts."""

    if (
        record.api_type == "None"
        or record.buildability == "Blocked"
        or record.recommended_next_action == "Blocked"
    ):
        return "blocked"
    if record.access_model.kind == "Self-Serve":
        return "self_serve"
    if record.recommended_next_action == "Partner-Gated":
        return "partner_gated"
    if record.access_model.kind == "Gated":
        return "approval_required"
    return "unknown"


def to_operational_research(record: P1AppRecord) -> OperationalResearch:
    """Convert a P1 row without manufacturing fields absent from the snapshot."""

    return OperationalResearch(
        app_name=record.app,
        app_slug=record.slug,
        api_available=False if record.api_type == "None" else None,
        api_type=record.api_type,
        api_base_url=None,
        auth_methods=list(record.auth_methods),
        authorization_url=None,
        token_url=None,
        credential_fields=[],
        scopes=[],
        developer_portal_url=None,
        signup_url=None,
        access_route=_p1_evidence_route(record),
        production_approval_required=None,
        contact_email=None,
        contact_url=None,
        evidence_urls=list(record.evidence_urls),
        confidence=record.confidence,
    )


class P1OperationalAdapter:
    """Read-only adapter over a provenance-verified P1 snapshot."""

    def __init__(self, snapshot_root: str | Path = DEFAULT_P1_ROOT) -> None:
        self._snapshot_root = Path(snapshot_root)

    @property
    def snapshot_root(self) -> Path:
        """Return the configured immutable snapshot directory."""

        return self._snapshot_root

    def lookup(self, app_name_or_slug: str) -> P1LookupFound | P1LookupNotFound:
        """Return a typed exact app/slug match after verifying the snapshot."""

        snapshot = load_verified_snapshot(self._snapshot_root)
        normalized_query = _normalize_lookup_key(app_name_or_slug)

        for record in snapshot.records:
            if _normalize_lookup_key(record.app) == normalized_query:
                return P1LookupFound(
                    query=app_name_or_slug,
                    normalized_query=normalized_query,
                    matched_by="app",
                    record=record,
                    provenance=snapshot.provenance,
                )
        for record in snapshot.records:
            if _normalize_lookup_key(record.slug) == normalized_query:
                return P1LookupFound(
                    query=app_name_or_slug,
                    normalized_query=normalized_query,
                    matched_by="slug",
                    record=record,
                    provenance=snapshot.provenance,
                )
        return P1LookupNotFound(
            query=app_name_or_slug,
            normalized_query=normalized_query,
            provenance=snapshot.provenance,
        )

    async def get_operational_research(self, app_name: str) -> OperationalResearch:
        lookup = self.lookup(app_name)
        if isinstance(lookup, P1LookupNotFound):
            raise P1RecordNotFoundError(lookup)
        return to_operational_research(lookup.record)


def lookup_p1_record(app_name_or_slug: str) -> P1LookupFound | P1LookupNotFound:
    """Look up an app in the default locked snapshot."""

    return P1OperationalAdapter().lookup(app_name_or_slug)


async def get_operational_research(app_name: str) -> OperationalResearch:
    """Return the P1-derived operational baseline, with missing fields left unknown."""

    return await P1OperationalAdapter().get_operational_research(app_name)
