from __future__ import annotations

import inspect

from browser_service.models import NavigateRequest, ResumeRequest
from ops.browser_provider import BrowserProvider
from ops.graph import WorkflowBrowser

_POLICY_NAMES = (
    "account_policy",
    "developer_app_policy",
    "credential_policy",
)


def _policy_signature(method: object) -> tuple[tuple[str, object], ...]:
    signature = inspect.signature(method)
    return tuple(
        (name, signature.parameters[name].default)
        for name in _POLICY_NAMES
    )


def test_browser_protocols_share_canonical_policy_keywords_and_defaults() -> None:
    assert _policy_signature(BrowserProvider.navigate_onboarding) == _policy_signature(
        WorkflowBrowser.navigate_onboarding
    )
    assert _policy_signature(BrowserProvider.resume_after_hitl) == _policy_signature(
        WorkflowBrowser.resume_after_hitl
    )
    assert _policy_signature(BrowserProvider.navigate_onboarding) == tuple(
        (name, "reuse_existing") for name in _POLICY_NAMES
    )


def test_browser_rpc_models_default_every_policy_to_reuse_existing() -> None:
    navigate = NavigateRequest(research={})
    resume = ResumeRequest(signal="completed")

    for model in (navigate, resume):
        assert model.account_policy == "reuse_existing"
        assert model.developer_app_policy == "reuse_existing"
        assert model.credential_policy == "reuse_existing"
