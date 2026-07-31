"""Reviewed contracts for deterministic, code-owned credential capture.

The browser may inspect only the exact provider page and selectors declared here.
Raw values are matched in code, written directly to the encrypted vault, and never
enter model context, screenshots, logs, or API responses.  A contract can contain
multiple fields because several providers issue credential pairs or bundles.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

CaptureSource = Literal["input_value", "text"]


@dataclass(frozen=True, slots=True)
class CredentialCaptureFieldSpec:
    """One named value inside a reviewed credential surface."""

    field_kind: str
    value_pattern: str
    selectors: tuple[str, ...]
    source: CaptureSource = "input_value"
    reveal_selector: str | None = None


@dataclass(frozen=True, slots=True)
class CredentialCaptureSpec:
    """A reviewed page plus one or more exact credential-field contracts.

    ``field_kind``/``value_pattern``/``selectors`` remain as a compatibility
    representation for older single-field profile contracts. New reviewed recipes
    use ``fields``. ``capture_fields`` is the only representation execution code
    should consume.
    """

    app_slug: str
    url: str
    vendor_domain: str
    field_kind: str | None = None
    value_pattern: str | None = None
    selectors: tuple[str, ...] = ()
    expected_path_prefix: str | None = None
    expected_heading: str | None = None
    reveal_selector: str | None = None
    fields: tuple[CredentialCaptureFieldSpec, ...] = ()

    @property
    def capture_fields(self) -> tuple[CredentialCaptureFieldSpec, ...]:
        if self.fields:
            return self.fields
        if self.field_kind and self.value_pattern:
            return (
                CredentialCaptureFieldSpec(
                    field_kind=self.field_kind,
                    value_pattern=self.value_pattern,
                    selectors=self.selectors,
                    reveal_selector=self.reveal_selector,
                ),
            )
        return ()

    def field(self, kind: str) -> CredentialCaptureFieldSpec | None:
        return next(
            (candidate for candidate in self.capture_fields if candidate.field_kind == kind),
            None,
        )


_SPECS: dict[str, CredentialCaptureSpec] = {
    # Compatibility fixture for direct callers. Canonical runs project the same
    # contract from the immutable AppRecipe snapshot.
    "pipedrive": CredentialCaptureSpec(
        app_slug="pipedrive",
        url="https://app.pipedrive.com/settings/api",
        vendor_domain="pipedrive.com",
        field_kind="api_token",
        value_pattern=r"[A-Fa-f0-9]{40}",
        selectors=(
            "input[name='api_token']",
            "input[data-testid='api-token']",
            "input[readonly][value]",
        ),
        expected_path_prefix="/settings/api",
        expected_heading="API",
    ),
}


def get_capture_spec(app_slug: str) -> CredentialCaptureSpec | None:
    """Return the deterministic capture spec for an app, if one is defined."""

    return _SPECS.get(app_slug)


__all__ = [
    "CaptureSource",
    "CredentialCaptureFieldSpec",
    "CredentialCaptureSpec",
    "get_capture_spec",
]
