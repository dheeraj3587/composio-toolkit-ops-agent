"""Deterministic Playwright capture that emits vault references only."""

from __future__ import annotations

import importlib
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from ops.browser_worker import is_allowed_browser_url, validate_allowed_domains
from ops.models import validate_vault_reference
from ops.provider_errors import ConfigurationRequiredError, PhaseUnavailableError
from ops.secret_store import SecretStore, SecretStoreError

_FIELD_KIND = re.compile(r"^[a-z0-9][a-z0-9_-]{0,99}$")


class CredentialCapture:
    """Capture named values from one trusted page and encrypt them immediately."""

    def __init__(
        self,
        secret_store: SecretStore | None = None,
        *,
        allowed_domains: tuple[str, ...] = (),
        connect_timeout_ms: int = 30_000,
    ) -> None:
        self._secret_store = secret_store
        self._allowed_domains = (
            validate_allowed_domains(allowed_domains) if allowed_domains else ()
        )
        if not 1_000 <= connect_timeout_ms <= 120_000:
            raise ValueError("Playwright connection timeout is outside the supported range")
        self._connect_timeout_ms = connect_timeout_ms

    @property
    def allowed_domains(self) -> tuple[str, ...]:
        return self._allowed_domains

    @property
    def enforces_host_validation(self) -> bool:
        return bool(self._allowed_domains)

    async def capture_and_store(
        self,
        cdp_url: str,
        app_slug: str,
        field_selectors: dict[str, str],
    ) -> dict[str, str]:
        """Attach over CDP, capture once, close, and return exact references."""

        self._require_configuration()
        _validate_capture_request(cdp_url, app_slug, field_selectors)
        module = importlib.import_module("playwright.async_api")
        async_playwright = getattr(module, "async_playwright")
        browser: Any | None = None
        async with async_playwright() as playwright:
            try:
                browser = await playwright.chromium.connect_over_cdp(
                    cdp_url,
                    timeout=self._connect_timeout_ms,
                    is_local=False,
                )
                if not browser.contexts or not browser.contexts[0].pages:
                    raise RuntimeError("remote browser has no active page")
                page = browser.contexts[0].pages[0]
                return await self.capture_page_and_store(
                    page=page,
                    app_slug=app_slug,
                    field_selectors=field_selectors,
                )
            finally:
                if browser is not None:
                    await browser.close()

    async def execute(self, cdp_url: str) -> dict[str, str]:
        """TrustedRawBrowserOperation hook is provided by ``for_operation`` only."""

        del cdp_url
        raise RuntimeError("bind app and selector metadata with for_operation()")

    def for_operation(
        self,
        *,
        app_slug: str,
        field_selectors: Mapping[str, str],
    ) -> CredentialCaptureOperation:
        return CredentialCaptureOperation(
            capture=self,
            app_slug=app_slug,
            field_selectors=dict(field_selectors),
        )

    async def capture_page_and_store(
        self,
        *,
        page: Any,
        app_slug: str,
        field_selectors: Mapping[str, str],
    ) -> dict[str, str]:
        """Capture from an already-attached page; useful for controlled fixtures."""

        self._require_configuration()
        _validate_fields(app_slug, field_selectors)
        references: dict[str, str] = {}
        try:
            for kind, selector in field_selectors.items():
                current_url = getattr(page, "url", "")
                if not isinstance(current_url, str) or not is_allowed_browser_url(
                    current_url, self._allowed_domains
                ):
                    raise PermissionError("credential page host is outside the trusted adapter")
                locator = page.locator(selector)
                if await locator.count() != 1:
                    raise RuntimeError("credential selector did not resolve to exactly one element")
                raw_value = await locator.input_value(timeout=10_000)
                if not isinstance(raw_value, str) or not raw_value:
                    raise RuntimeError("credential selector returned no value")
                if self._secret_store is None:  # pragma: no cover - guarded above
                    raise RuntimeError("secret store is unavailable")
                reference = self._secret_store.put(
                    app_slug=app_slug,
                    kind=kind,
                    value=raw_value,
                )
                del raw_value
                references[kind] = validate_vault_reference(reference)
            return references
        except Exception:
            if self._secret_store is not None:
                for reference in references.values():
                    try:
                        self._secret_store.delete(reference)
                    except SecretStoreError:
                        pass
            raise

    def _require_configuration(self) -> None:
        if self._secret_store is None:
            raise ConfigurationRequiredError(
                phase=6,
                capability="Playwright credential capture",
                reason_code="secret_store_missing",
            )
        if not self._allowed_domains:
            raise ConfigurationRequiredError(
                phase=6,
                capability="Playwright credential capture",
                reason_code="trusted_domains_missing",
            )


class CredentialCaptureOperation:
    """App-bound trusted raw-browser operation with immutable selector metadata."""

    def __init__(
        self,
        *,
        capture: CredentialCapture,
        app_slug: str,
        field_selectors: dict[str, str],
    ) -> None:
        _validate_fields(app_slug, field_selectors)
        self._capture = capture
        self._app_slug = app_slug
        self._field_selectors = field_selectors.copy()

    @property
    def allowed_domains(self) -> tuple[str, ...]:
        return self._capture.allowed_domains

    @property
    def enforces_host_validation(self) -> bool:
        return self._capture.enforces_host_validation

    async def execute(self, cdp_url: str) -> dict[str, str]:
        return await self._capture.capture_and_store(
            cdp_url,
            self._app_slug,
            self._field_selectors,
        )


def _validate_capture_request(
    cdp_url: str,
    app_slug: str,
    field_selectors: Mapping[str, str],
) -> None:
    parsed = urlsplit(cdp_url)
    if parsed.scheme not in {"https", "wss"} or not parsed.hostname:
        raise ValueError("a remote HTTPS or WSS CDP capability URL is required")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("CDP capability URL user information is not allowed")
    _validate_fields(app_slug, field_selectors)


def _validate_fields(app_slug: str, field_selectors: Mapping[str, str]) -> None:
    if re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", app_slug) is None:
        raise ValueError("app_slug is invalid")
    if not field_selectors or len(field_selectors) > 20:
        raise ValueError("one to twenty credential selectors are required")
    for kind, selector in field_selectors.items():
        if _FIELD_KIND.fullmatch(kind) is None:
            raise ValueError("credential field kind is invalid")
        if not isinstance(selector, str) or not selector or len(selector) > 1_000:
            raise ValueError("credential selector is invalid")
        if "\x00" in selector or "script" in selector.casefold():
            raise ValueError("credential selector contains forbidden content")


__all__ = ["CredentialCapture", "CredentialCaptureOperation", "PhaseUnavailableError"]

