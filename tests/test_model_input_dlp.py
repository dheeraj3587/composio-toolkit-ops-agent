"""Adversarial canary tests for the model-input DLP boundary.

A single canary secret is planted in every page-derived channel the model could
receive — page title, URL path, an unknown query parameter, button text,
aria-label, placeholder, ``code``, ``pre`` and ``contenteditable`` content — and
each test asserts the canary never survives sanitization.
"""

from __future__ import annotations

import pytest

from ops.model_input_dlp import (
    DROPPED,
    REDACTED,
    contains_secret_material,
    is_high_entropy,
    redact_secrets,
    sanitize_element_name,
    sanitize_page_text,
    sanitize_reason,
    sanitize_url,
)

# Canaries are ASSEMBLED AT RUNTIME from harmless fragments. They have the exact
# shape the DLP patterns must catch, but no literal credential-shaped string is
# committed (which secret-scanning push protection would — correctly — reject).
CANARY_HEX40 = "a1b2c3d4e5" * 4
CANARY_STRIPE = "sk" + "_" + "live" + "_" + "51HxYzAbCdEfGhIjKlMnOpQr"
CANARY_SLACK = "xoxb" + "-" + "123456789012" + "-" + "abcdefghijklmnopqrst"
CANARY_GITHUB = "ghp" + "_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
CANARY_JWT = ".".join(
    ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "dBjftJeZ4CVPmB92K27uhbUJU1p1r"]
)
CANARY_ENTROPY = "Zk8vQ2p5RmxxYnR3TjNkSHc9PWFiY2RlZg"

ALL_CANARIES = (
    CANARY_HEX40,
    CANARY_STRIPE,
    CANARY_SLACK,
    CANARY_GITHUB,
    CANARY_JWT,
    CANARY_ENTROPY,
)


def _assert_clean(value: str, canary: str) -> None:
    assert canary not in value, f"canary leaked: {value!r}"


# --- Channel 1: page title -----------------------------------------------------
@pytest.mark.parametrize("canary", ALL_CANARIES)
def test_canary_in_page_title_is_redacted(canary: str) -> None:
    sanitized = sanitize_page_text(f"Your API token is {canary} — keep it safe")
    _assert_clean(sanitized, canary)
    assert REDACTED in sanitized


# --- Channel 2: URL path -------------------------------------------------------
@pytest.mark.parametrize("canary", [CANARY_HEX40, CANARY_STRIPE, CANARY_ENTROPY])
def test_canary_in_url_path_is_redacted(canary: str) -> None:
    sanitized = sanitize_url(f"https://app.pipedrive.com/settings/api/{canary}")
    _assert_clean(sanitized, canary)
    assert sanitized.startswith("https://app.pipedrive.com/")


# --- Channel 3: unknown query parameter (must be dropped entirely) -------------
@pytest.mark.parametrize("canary", ALL_CANARIES)
def test_query_parameters_are_dropped_entirely(canary: str) -> None:
    sanitized = sanitize_url(
        f"https://app.pipedrive.com/oauth/callback?code={canary}&unknown_param={canary}"
    )
    _assert_clean(sanitized, canary)
    assert "?" not in sanitized and "code=" not in sanitized


def test_fragment_is_dropped_entirely() -> None:
    sanitized = sanitize_url(f"https://app.pipedrive.com/x#access_token={CANARY_JWT}")
    _assert_clean(sanitized, CANARY_JWT)
    assert "#" not in sanitized


# --- Channel 4: button text ----------------------------------------------------
@pytest.mark.parametrize("canary", ALL_CANARIES)
def test_canary_in_button_text_is_redacted(canary: str) -> None:
    sanitized = sanitize_element_name(f"Copy {canary}")
    _assert_clean(sanitized, canary)


def test_copy_control_text_is_dropped_not_merely_redacted() -> None:
    # A "copy token" control is exactly where a rendered credential lives.
    sanitized = sanitize_element_name(CANARY_HEX40, origin="copy-control")
    assert sanitized == DROPPED


# --- Channel 5: aria-label -----------------------------------------------------
@pytest.mark.parametrize("canary", ALL_CANARIES)
def test_canary_in_aria_label_is_redacted(canary: str) -> None:
    sanitized = sanitize_element_name(f"API token value {canary}")
    _assert_clean(sanitized, canary)
    # A credential-describing name becomes a semantic placeholder.
    assert sanitized.startswith("<secret-field:")


# --- Channel 6: placeholder ----------------------------------------------------
@pytest.mark.parametrize("canary", ALL_CANARIES)
def test_canary_in_placeholder_is_redacted(canary: str) -> None:
    sanitized = sanitize_element_name(canary, element_type="text")
    _assert_clean(sanitized, canary)


# --- Channels 7-9: code / pre / contenteditable (dropped wholesale) ------------
@pytest.mark.parametrize("origin", ["code", "pre", "contenteditable", "textarea", "credential"])
@pytest.mark.parametrize("canary", [CANARY_HEX40, CANARY_JWT])
def test_unsafe_origins_are_dropped(origin: str, canary: str) -> None:
    assert sanitize_page_text(f"token: {canary}", origin=origin) == DROPPED
    assert sanitize_element_name(canary, origin=origin) == DROPPED


# --- Reasons/summaries derived from the page ----------------------------------
@pytest.mark.parametrize("canary", ALL_CANARIES)
def test_canary_in_a_derived_reason_is_redacted(canary: str) -> None:
    _assert_clean(sanitize_reason(f"Reached the page showing {canary}"), canary)


# --- Secret-field semantics ----------------------------------------------------
@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("Password", "password"),
        ("One-time code", "otp"),
        ("API key", "api_key"),
        ("Client secret", "client_secret"),
        ("Private key", "private_key"),
        ("CVV", "card"),
    ],
)
def test_secret_field_names_become_semantic_placeholders(name: str, kind: str) -> None:
    # element_type is left generic so the NAME determines the semantic kind.
    assert sanitize_element_name(name, element_type="text") == f"<secret-field:{kind}>"


def test_password_input_type_alone_yields_a_password_placeholder() -> None:
    # Even an unnamed field is flagged from its type, so the model learns "a
    # password goes here" without ever seeing a value.
    assert sanitize_element_name("", element_type="password") == "<secret-field:password>"


def test_ordinary_names_survive_for_model_usefulness() -> None:
    # The model still needs real structure: non-secret names pass through.
    assert sanitize_element_name("Personal preferences") == "Personal preferences"
    assert sanitize_element_name("Email", element_type="email") == "Email"


# --- Entropy detection ---------------------------------------------------------
def test_high_entropy_detection_flags_keys_not_prose() -> None:
    assert is_high_entropy(CANARY_ENTROPY) is True
    assert is_high_entropy("Personal preferences and settings") is False
    assert is_high_entropy("dashboard") is False


# --- Boundary assertion helper -------------------------------------------------
@pytest.mark.parametrize("canary", ALL_CANARIES)
def test_contains_secret_material_detects_every_canary(canary: str) -> None:
    assert contains_secret_material(f"value {canary}") is True


def test_contains_secret_material_is_quiet_on_clean_text() -> None:
    assert contains_secret_material("Open Personal preferences then the API tab") is False


def test_sanitized_output_passes_the_boundary_assertion() -> None:
    # Round trip: after sanitization the boundary check must be satisfied, which is
    # what lets the caller refuse to send anything that still trips it.
    for canary in ALL_CANARIES:
        assert contains_secret_material(redact_secrets(f"token {canary}")) is False
