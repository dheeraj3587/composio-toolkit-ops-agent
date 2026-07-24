"""Per-app specs for deterministic, hands-off credential capture over CDP.

After the AI agent autonomously signs in (its login state is persisted to a
Browser Use profile), a standalone browser is opened from that profile — already
logged in — and Playwright reads the credential value straight from the token
settings page over CDP. The LLM never reads the secret; the value is matched by
a strict pattern, written to the encrypted vault, and only a ``vault://``
reference leaves this boundary.

A spec is intentionally conservative: it names the exact settings URL, the
registrable domain the page must stay on, the credential field kind, and a
strict value pattern the captured input must match (so a wrong/empty field is
never mistaken for the credential).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CredentialCaptureSpec:
    app_slug: str
    url: str
    vendor_domain: str
    field_kind: str
    value_pattern: str


_SPECS: dict[str, CredentialCaptureSpec] = {
    # Pipedrive personal API token: a stable 40-hex value shown in a read-only
    # input at Settings -> Personal preferences -> API.
    "pipedrive": CredentialCaptureSpec(
        app_slug="pipedrive",
        url="https://app.pipedrive.com/settings/api",
        vendor_domain="pipedrive.com",
        field_kind="api_token",
        value_pattern=r"^[A-Fa-f0-9]{40}$",
    ),
}


def get_capture_spec(app_slug: str) -> CredentialCaptureSpec | None:
    """Return the deterministic capture spec for an app, if one is defined."""

    return _SPECS.get(app_slug)


__all__ = ["CredentialCaptureSpec", "get_capture_spec"]
