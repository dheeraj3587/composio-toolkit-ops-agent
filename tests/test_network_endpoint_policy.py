"""NetworkEndpointPolicy: exact reviewed HTTPS endpoints for backend clients."""

from __future__ import annotations

import pytest

from ops.network_endpoint_policy import (
    NetworkEndpointError,
    get_network_policy,
    is_allowed_network_endpoint,
    normalize_endpoint,
    validation_endpoint,
)


def test_accepts_only_exact_reviewed_https_endpoints() -> None:
    # Exact reviewed endpoints are accepted.
    assert is_allowed_network_endpoint(
        "hubspot", "https://api.hubapi.com/account-info/2026-03/details"
    )
    assert is_allowed_network_endpoint("pipedrive", "https://api.pipedrive.com/v1/users/me")
    assert is_allowed_network_endpoint("pipedrive", "https://oauth.pipedrive.com/oauth/token")

    # A different path on the same host is rejected.
    assert not is_allowed_network_endpoint("pipedrive", "https://api.pipedrive.com/v1/deals")
    # Wrong host is rejected.
    assert not is_allowed_network_endpoint("hubspot", "https://evil.example/details")


def test_rejects_non_https_query_and_unknown_app() -> None:
    assert not is_allowed_network_endpoint(
        "pipedrive", "http://api.pipedrive.com/v1/users/me"
    )  # not https
    assert not is_allowed_network_endpoint(
        "pipedrive", "https://api.pipedrive.com/v1/users/me?api_token=x"
    )  # query string
    assert not is_allowed_network_endpoint("unknown-app", "https://api.pipedrive.com/v1/users/me")


def test_validation_endpoint_lookup() -> None:
    assert validation_endpoint("hubspot") == "https://api.hubapi.com/account-info/2026-03/details"
    assert validation_endpoint("pipedrive") == "https://api.pipedrive.com/v1/users/me"
    assert validation_endpoint("attio") is None  # backend does not call Attio


def test_normalize_endpoint_rejects_malformed() -> None:
    with pytest.raises(NetworkEndpointError):
        normalize_endpoint("http://api.pipedrive.com/v1/users/me")
    with pytest.raises(NetworkEndpointError):
        normalize_endpoint("https://api.pipedrive.com/v1/users/me?x=1")
    with pytest.raises(NetworkEndpointError):
        normalize_endpoint("https://user:pass@api.pipedrive.com/v1/users/me")


def test_network_policy_endpoints_are_all_normalizable() -> None:
    for slug in ("hubspot", "pipedrive"):
        policy = get_network_policy(slug)
        assert policy is not None
        # allowed_urls() will raise if any reviewed endpoint is malformed.
        assert policy.allowed_urls()
