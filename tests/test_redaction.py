from __future__ import annotations

import io
import json
import logging

from pydantic import SecretStr

from ops.redaction import (
    REDACTED,
    RedactingFilter,
    install_redacting_filter,
    redact_data,
    redact_text,
)


def test_redact_text_covers_required_secret_shapes() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature98765"  # pragma: allowlist secret
    private_key = "-----BEGIN PRIVATE KEY-----\nc2FuaXRpemVkLWZpeHR1cmUtb25seQ==\n-----END PRIVATE KEY-----"  # pragma: allowlist secret
    provider_key = "sk-test-abcdefghijklmnopqrstuv"  # pragma: allowlist secret
    source = (
        f"Authorization: Bearer super-sensitive-token\n"
        f"password=hunter-example client_secret: oauth-secret-value\n"
        f"jwt={jwt}\nkey={provider_key}\n{private_key}\n"
        "https://api.example.test/callback?code=one-time-code&safe=yes"
    )

    result = redact_text(source)

    for forbidden in (
        "super-sensitive-token",
        "hunter-example",
        "oauth-secret-value",
        jwt,
        provider_key,
        "c2FuaXRpemVkLWZpeHR1cmUtb25seQ==",
        "one-time-code",
    ):
        assert forbidden not in result
    assert "safe=yes" in result
    assert result.count(REDACTED) >= 7


def test_recursive_redaction_uses_keys_and_preserves_vault_references() -> None:
    payload = {
        "nested": [
            {"api_key": "plain-value", "status": "ready"},  # pragma: allowlist secret
            {"client_secret": "vault://example/client_secret/ref_123"},  # pragma: allowlist secret
        ],
        "authorization": "Basic dXNlcjpwYXNz",
        "safe_url": "https://example.test/path?token=temporary&view=compact",
        "secret_object": SecretStr("not-for-output"),
    }

    result = redact_data(payload)

    assert result["nested"][0]["api_key"] == REDACTED
    assert result["nested"][0]["status"] == "ready"
    assert result["nested"][1]["client_secret"] == (  # pragma: allowlist secret
        "vault://example/client_secret/ref_123"
    )
    assert result["authorization"] == REDACTED
    assert "temporary" not in result["safe_url"]
    assert result["secret_object"] == REDACTED


def test_logging_filter_sanitizes_format_args_and_extra_fields() -> None:
    record = logging.LogRecord(
        name="security-test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="request %s",
        args=("Authorization: Bearer log-token-value",),
        exc_info=None,
    )
    sensitive_field = "api_" + "key"
    setattr(record, sensitive_field, "standalone-secret")

    assert RedactingFilter().filter(record) is True

    rendered = record.getMessage()
    assert "log-token-value" not in rendered
    assert REDACTED in rendered
    assert getattr(record, sensitive_field) == REDACTED


def test_recursive_redaction_rejects_bare_secret_keys_and_unknown_objects() -> None:
    marker = "opaque credential material"
    key_marker = "opaque map key credential material"

    class OpaquePayload:
        def __str__(self) -> str:
            return marker

    class OpaqueKey:
        def __str__(self) -> str:
            return key_marker

    provider_key = "sk-test-abcdefghijklmnopqrstuv"  # pragma: allowlist secret
    result = redact_data(
        {
            "token": marker,
            "nested": {"secret": marker, "object": OpaquePayload()},
            provider_key: "safe label",
        }
    )
    serialized = json.dumps(result)
    opaque_key_result = redact_data({OpaqueKey(): "associated value"})

    assert marker not in serialized
    assert provider_key not in serialized
    assert key_marker not in json.dumps(opaque_key_result)
    assert result["token"] == REDACTED
    assert result["nested"]["object"] == REDACTED
    assert result["[REDACTED_KEY]"] == "safe label"
    assert opaque_key_result == {"[REDACTED_KEY]": REDACTED}


def test_redact_text_covers_oauth_tokens_and_private_key_variants() -> None:
    samples = {
        "oauth-secret-material": "oauth_secret=oauth-secret-material",
        "oauth-client-secret-material": ("oauth_client_secret=oauth-client-secret-material"),
        "session-token-material": (
            "https://example.test/callback?session_token=session-token-material"
        ),
        "identity-token-material": (
            "https://example.test/callback?id_token=identity-token-material"
        ),
        "auth-token-material": "https://example.test/callback?auth_token=auth-token-material",
        "encrypted-private-key-material": (
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"  # pragma: allowlist secret
            "encrypted-private-key-material\n"
            "-----END ENCRYPTED PRIVATE KEY-----"
        ),
        "dsa-private-key-material": (
            "-----BEGIN DSA PRIVATE KEY-----\n"  # pragma: allowlist secret
            "dsa-private-key-material\n"
            "-----END DSA PRIVATE KEY-----"
        ),
    }

    for marker, sample in samples.items():
        redacted = redact_text(sample)
        assert marker not in redacted
        assert REDACTED in redacted


def test_installed_logging_filter_redacts_exception_tracebacks() -> None:
    marker = "exception credential material"
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    logger = logging.getLogger("ops-redaction-exception-test")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)
    install_redacting_filter(logger)

    try:
        raise ValueError(f"Authorization: Bearer {marker}")
    except ValueError:
        logger.exception("provider request failed")

    rendered = stream.getvalue()
    assert marker not in rendered
    assert REDACTED in rendered
