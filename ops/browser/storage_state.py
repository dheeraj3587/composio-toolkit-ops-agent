"""Encrypted persistence for authenticated browser state.

Playwright storage state contains session cookies and local-storage entries: it
is a bearer credential for the vendor account. Treated accordingly:

* **Encrypted at rest** with Fernet (the same primitive the secret vault uses).
  Without a key, state is simply NOT persisted — never persisted in the clear.
* **Owner-only filesystem permissions** (directory 0700, file 0600).
* **Bound to (app, account, owner)**: a blob saved for one triple can never be
  loaded for another, so state cannot leak sideways between runs or accounts.
* **Metadata tracked** (created/updated/expires) so stale state is refused.
* **Invalidated** on logout or an authentication failure.
* Never logged, never returned across an API boundary, never written into a test
  artifact, and (being under ``/browser-data``) never committed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

_DEFAULT_TTL_DAYS = 14
_MAX_BLOB_BYTES = 2 * 1024 * 1024


class StorageStateError(RuntimeError):
    """A typed failure; the message is a reason code, never state content."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class StorageStateBinding:
    """The identity a stored blob is bound to."""

    app_slug: str
    account_ref: str
    owner: str

    def fingerprint(self) -> str:
        """A stable, non-reversible id for this triple (used as the filename)."""

        digest = hashlib.sha256(
            "|".join((self.app_slug, self.account_ref, self.owner)).encode()
        ).hexdigest()
        return digest[:32]


@dataclass(frozen=True, slots=True)
class StorageStateMetadata:
    """Non-secret metadata about a stored blob."""

    app_slug: str
    created_at: str
    updated_at: str
    expires_at: str
    binding_fingerprint: str

    def is_expired(self, now: datetime | None = None) -> bool:
        try:
            expiry = datetime.fromisoformat(self.expires_at)
        except ValueError:
            return True
        return (now or datetime.now(UTC)) >= expiry


class EncryptedStorageStateStore:
    """Reads/writes Fernet-encrypted Playwright storage state on disk."""

    def __init__(self, directory: Path, key: str | None) -> None:
        self._directory = Path(directory)
        self._key = key

    @property
    def enabled(self) -> bool:
        """Persistence requires a key; without one nothing is written."""

        return bool(self._key)

    def _fernet(self) -> Any:
        if not self._key:
            raise StorageStateError("storage_state_key_missing")
        try:
            from cryptography.fernet import Fernet
        except ImportError:  # pragma: no cover - cryptography is a hard dependency
            raise StorageStateError("cryptography_unavailable") from None
        try:
            return Fernet(self._key.encode("ascii"))
        except (TypeError, ValueError, UnicodeEncodeError):
            raise StorageStateError("storage_state_key_invalid") from None

    def _path(self, binding: StorageStateBinding) -> Path:
        return self._directory / f"{binding.fingerprint()}.state"

    def _ensure_directory(self) -> None:
        self._directory.mkdir(parents=True, exist_ok=True)
        # Owner-only: no group/other access to authenticated session material.
        os.chmod(self._directory, 0o700)

    def save(
        self,
        binding: StorageStateBinding,
        storage_state: dict[str, object],
        *,
        ttl_days: int = _DEFAULT_TTL_DAYS,
    ) -> StorageStateMetadata:
        """Encrypt and persist state for one (app, account, owner) triple."""

        if not self.enabled:
            raise StorageStateError("storage_state_key_missing")
        payload = json.dumps(storage_state, sort_keys=True, separators=(",", ":")).encode()
        if len(payload) > _MAX_BLOB_BYTES:
            raise StorageStateError("storage_state_too_large")
        now = datetime.now(UTC)
        path = self._path(binding)
        previous_created = now.isoformat()
        existing = self._read_envelope(path)
        if existing is not None:
            previous_created = str(existing.get("created_at") or previous_created)
        envelope = {
            "app_slug": binding.app_slug,
            "binding_fingerprint": binding.fingerprint(),
            "created_at": previous_created,
            "updated_at": now.isoformat(),
            "expires_at": (now + timedelta(days=max(1, ttl_days))).isoformat(),
            # The secret part, encrypted. Never stored in the clear.
            "state": self._fernet().encrypt(payload).decode("ascii"),
        }
        self._ensure_directory()
        # Write via a private temp file then replace, so a reader never sees a
        # partially written blob and the mode is never briefly world-readable.
        temp_path = path.with_suffix(".tmp")
        descriptor = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(envelope, handle, sort_keys=True)
        finally:
            temp_path.replace(path)
            os.chmod(path, 0o600)
        return StorageStateMetadata(
            app_slug=binding.app_slug,
            created_at=str(envelope["created_at"]),
            updated_at=str(envelope["updated_at"]),
            expires_at=str(envelope["expires_at"]),
            binding_fingerprint=binding.fingerprint(),
        )

    def _read_envelope(self, path: Path) -> dict[str, object] | None:
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            return None
        try:
            value = json.loads(raw)
        except ValueError:
            return None
        return value if isinstance(value, dict) else None

    def metadata(self, binding: StorageStateBinding) -> StorageStateMetadata | None:
        """Non-secret metadata only; never decrypts."""

        envelope = self._read_envelope(self._path(binding))
        if envelope is None:
            return None
        return StorageStateMetadata(
            app_slug=str(envelope.get("app_slug") or ""),
            created_at=str(envelope.get("created_at") or ""),
            updated_at=str(envelope.get("updated_at") or ""),
            expires_at=str(envelope.get("expires_at") or ""),
            binding_fingerprint=str(envelope.get("binding_fingerprint") or ""),
        )

    def load(self, binding: StorageStateBinding) -> dict[str, object] | None:
        """Decrypt state for EXACTLY this binding, or None.

        Returns None (rather than raising) when nothing is stored or the blob is
        expired, so a caller simply proceeds with a fresh login.
        """

        if not self.enabled:
            return None
        envelope = self._read_envelope(self._path(binding))
        if envelope is None:
            return None
        # Binding check: refuse a blob that was written for a different triple.
        stored_fingerprint = str(envelope.get("binding_fingerprint") or "")
        if not hmac.compare_digest(stored_fingerprint, binding.fingerprint()):
            raise StorageStateError("storage_state_binding_mismatch")
        metadata = self.metadata(binding)
        if metadata is None or metadata.is_expired():
            self.invalidate(binding, reason_code="storage_state_expired")
            return None
        try:
            decrypted = self._fernet().decrypt(str(envelope.get("state") or "").encode("ascii"))
        except Exception:
            # A blob we cannot decrypt is treated as absent AND removed, so a
            # rotated key does not wedge the run forever.
            self.invalidate(binding, reason_code="storage_state_undecryptable")
            return None
        try:
            value = json.loads(decrypted)
        except ValueError:
            self.invalidate(binding, reason_code="storage_state_corrupt")
            return None
        return value if isinstance(value, dict) else None

    def invalidate(self, binding: StorageStateBinding, *, reason_code: str = "invalidated") -> str:
        """Delete stored state (after logout, auth failure, or expiry)."""

        del reason_code  # reason is for the caller's audit row, never persisted here
        path = self._path(binding)
        try:
            path.unlink(missing_ok=True)
        except OSError:
            return "storage_state_delete_failed"
        return "storage_state_invalidated"


__all__ = [
    "EncryptedStorageStateStore",
    "StorageStateBinding",
    "StorageStateError",
    "StorageStateMetadata",
]
