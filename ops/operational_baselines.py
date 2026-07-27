"""Reviewed operational baselines for evaluator-critical provider paths.

The immutable P1 snapshot remains the routing authority. These additive baselines
supply separately reviewed operational details that are absent from that snapshot,
so a production run does not depend on best-effort live research for known apps.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ops.models import OperationalResearch, ScopeRequirement


@dataclass(frozen=True, slots=True)
class ReviewedOperationalBaseline:
    """A versioned, code-reviewed overlay for one verified P1 app."""

    app_slug: str
    version: str
    values: dict[str, Any]


_PIPEDRIVE_API_REFERENCE = "https://developers.pipedrive.com/docs/api/v1"
_PIPEDRIVE_OAUTH_REFERENCE = "https://developers.pipedrive.com/docs/api/v1/Oauth"
_PIPEDRIVE_SCOPE_REFERENCE = (
    "https://pipedrive.readme.io/docs/marketplace-scopes-and-permissions-explanations"
)
_PIPEDRIVE_SUPPORT = "https://support.pipedrive.com/contact-us?ref=developers"

# This overlay is deliberately for the evaluator's reuse-only personal-token path.
# It documents OAuth as provider metadata, but it never authorizes creating an app,
# rotating a token, or accepting Marketplace/legal/billing prompts autonomously.
_PIPEDRIVE_REUSE_BASELINE = ReviewedOperationalBaseline(
    app_slug="pipedrive",
    version="pipedrive-reuse-v1-2026-07-25",
    values={
        "api_available": True,
        "api_base_url": "https://api.pipedrive.com/v1",
        "authorization_url": "https://oauth.pipedrive.com/oauth/authorize",
        "token_url": "https://oauth.pipedrive.com/oauth/token",
        "credential_fields": ["api_token"],
        "credential_creation_instructions": (
            "Sign in to the existing Pipedrive account and open Personal preferences > API.",
            "Reuse the existing personal API token; do not create, rotate, or delete a token.",
        ),
        "scopes": [
            ScopeRequirement(
                name="base",
                description=(
                    "Default OAuth scope for basic authorized-user settings; it includes the "
                    "read-only GET /users/me identity check."
                ),
                required=True,
                source_url=_PIPEDRIVE_SCOPE_REFERENCE,
            )
        ],
        "developer_portal_url": "https://developers.pipedrive.com/",
        "signup_url": "https://www.pipedrive.com/en/register",
        "login_url": "https://app.pipedrive.com/auth/login",
        "credential_management_url": "https://app.pipedrive.com/settings/api",
        # Personal API-token reuse is self-serve. Marketplace publication remains
        # outside this path and would need its own explicit approval policy.
        "production_approval_required": False,
        "contact_url": _PIPEDRIVE_SUPPORT,
    },
)

_REVIEWED_BASELINES: dict[str, ReviewedOperationalBaseline] = {
    _PIPEDRIVE_REUSE_BASELINE.app_slug: _PIPEDRIVE_REUSE_BASELINE,
}


def apply_reviewed_operational_baseline(
    research: OperationalResearch,
) -> tuple[OperationalResearch, str | None]:
    """Apply a reviewed overlay and return its version, if one exists.

    Re-validation is intentional: a malformed URL, scope, or field in a future
    baseline must fail at startup/tests rather than becoming durable run data.
    """

    baseline = _REVIEWED_BASELINES.get(research.app_slug)
    if baseline is None:
        return research, None

    payload = research.model_dump(mode="python")
    payload.update(baseline.values)
    payload["evidence_urls"] = list(
        dict.fromkeys(
            [
                *research.evidence_urls,
                _PIPEDRIVE_API_REFERENCE,
                _PIPEDRIVE_OAUTH_REFERENCE,
                _PIPEDRIVE_SCOPE_REFERENCE,
                _PIPEDRIVE_SUPPORT,
            ]
        )
    )
    return OperationalResearch.model_validate(payload), baseline.version


__all__ = ["ReviewedOperationalBaseline", "apply_reviewed_operational_baseline"]
