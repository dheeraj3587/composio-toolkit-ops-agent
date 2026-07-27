"""Browser sign-in secret handling: what crosses the wire, and what is remembered.

Three rules are enforced here and each one is the reason a separate method exists.

Nothing raw crosses an RPC boundary. In-process providers receive values directly
because there is no boundary to cross, but the browser SERVICE only ever receives a
transient, run-scoped, expiring ``vault://`` reference that it consumes once.

Durability is deliberately narrow. Only the reusable sign-in fields are remembered;
a one-time code or verification link is never persisted, and a partial pair is
treated as nothing stored because it would type an email and then stall.

Partial secret sets never reach a run. A vault write failure during transient
storage rolls back every reference created so far and fails the whole payload,
rather than proceeding with half the credentials or falling back to a raw value.
"""

from __future__ import annotations

import contextlib
from collections.abc import Mapping
from typing import Any, Protocol

from pydantic import SecretStr

from ops.browser_worker import BrowserWorker
from ops.config import Settings
from ops.provider_errors import ConfigurationRequiredError, ProviderOperationError
from ops.secret_store import REUSABLE_LOGIN_FIELDS, SQLiteSecretStore
from ops.state import BrowserProvider


class RunLoginSecretContext(Protocol):
    """Run-service state the login-secret helpers need."""

    _settings: Settings | None
    _secret_store: SQLiteSecretStore | None

    def _browser_worker_for(self, record: Any) -> BrowserWorker | None: ...


class RunLoginSecretService:
    """Resolve, remember and safely transport browser sign-in credentials."""

    def __init__(self, context: RunLoginSecretContext) -> None:
        self._context = context

    def browser_login_payload(
        self,
        *,
        provider: BrowserProvider,
        app_slug: str,
        scope_id: str,
        values: Mapping[str, SecretStr],
    ) -> dict[str, str]:
        """Build the credential payload for the ACTIVE browser provider.

        Browser Use receives raw values in-process, exactly as before. The browser
        SERVICE must never receive a raw value over RPC, so each permitted secret is
        first stored as a TRANSIENT (one-time, run-scoped, expiring) ``vault://``
        reference and only the reference travels; the service consumes it once.
        """

        raw = {name: secret.get_secret_value() for name, secret in values.items()}
        worker = self._context._browser_worker_for(provider)
        if getattr(worker, "provider_name", "") != "playwright":
            return raw
        if not callable(getattr(worker, "reconcile_session", None)):
            # In-process Playwright: same process, no RPC boundary to cross.
            return raw
        return self.store_transient_browser_secrets(
            app_slug=app_slug, scope_id=scope_id, values=raw
        )

    def remember_reusable_login(
        self, *, app_slug: str, values: Mapping[str, SecretStr]
    ) -> tuple[str, ...]:
        """Persist the owner's reusable sign-in credentials for this app.

        Only ``login_email``/``login_password`` are durable; a one-time OTP or
        verification link is deliberately never remembered. Returns the sanitized
        field names actually stored (never a value) so the caller can audit the
        act of remembering without recording the secret.

        A vault failure here must not break the run in progress: the credentials
        were already injected for THIS run, so failing to remember them only
        costs autonomy on a later run.
        """

        store = self._context._secret_store
        settings = self._context._settings or Settings.from_env()
        if store is None or not getattr(settings, "browser_login_credential_reuse", True):
            return ()
        remembered: list[str] = []
        for login_field in sorted(REUSABLE_LOGIN_FIELDS):
            secret = values.get(login_field)
            if secret is None:
                continue
            value = secret.get_secret_value()
            if not value:
                continue
            try:
                store.put_account_login(app_slug=app_slug, field=login_field, value=value)
            except Exception:
                continue  # sanitized: never log the value or the failure detail
            remembered.append(login_field)
        return tuple(remembered)

    def reusable_login_values(self, app_slug: str) -> dict[str, SecretStr]:
        """Load the remembered sign-in credentials for an app, if complete.

        A partial pair is useless to the deterministic login state machine (it
        would type an email and then stop at the password), so an incomplete set
        is treated as "nothing stored" and the run still asks the owner once.
        """

        store = self._context._secret_store
        settings = self._context._settings or Settings.from_env()
        if store is None or not getattr(settings, "browser_login_credential_reuse", True):
            return {}
        reader = getattr(store, "get_account_login", None)
        if not callable(reader):
            return {}
        values: dict[str, SecretStr] = {}
        for login_field in sorted(REUSABLE_LOGIN_FIELDS):
            try:
                value = reader(app_slug=app_slug, field=login_field)
            except Exception:
                return {}
            if not value:
                return {}
            values[login_field] = SecretStr(value)
        return values

    def store_transient_browser_secrets(
        self, *, app_slug: str, scope_id: str, values: Mapping[str, str]
    ) -> dict[str, str]:
        """Vault each permitted secret as a one-time, run-scoped reference.

        A field outside the reviewed set is refused. A vault-write failure is NOT
        suppressed: every reference created so far is rolled back (deleted) and the
        whole payload fails, so a run never proceeds with a partial secret set or a
        raw value on the wire.
        """

        from ops.browser_service_client import ALLOWED_BROWSER_SECRET_FIELDS

        store = self._context._secret_store
        if store is None:
            raise ConfigurationRequiredError(
                phase=5,
                capability="browser service secrets",
                reason_code="secret_vault_required_for_browser_service",
            )
        references: dict[str, str] = {}
        created: list[str] = []
        try:
            for name, value in values.items():
                if name not in ALLOWED_BROWSER_SECRET_FIELDS:
                    raise ProviderOperationError(
                        capability="browser service secrets",
                        reason_code="browser_secret_field_not_allowed",
                    )
                if not value:
                    continue
                reference = store.put_transient(
                    app_slug=app_slug,
                    # Namespaced so a browser-login secret is distinguishable from a
                    # captured integration credential in the vault.
                    kind=f"browser_login_{name}",
                    scope_id=scope_id,
                    value=value,
                    ttl_seconds=600,
                )
                references[name] = reference
                created.append(reference)
        except Exception:
            for reference in created:
                with contextlib.suppress(Exception):
                    store.delete(reference)
            raise ProviderOperationError(
                capability="browser service secrets",
                reason_code="browser_secret_store_failed",
            ) from None
        return references


__all__ = [
    "RunLoginSecretContext",
    "RunLoginSecretService",
]
