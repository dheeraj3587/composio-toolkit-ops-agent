"""Explainable deterministic routing for verified operational research."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Literal

from pydantic import Field

from ops.models import OperationalResearch, StrictModel
from ops.state import AccessRoute

MAX_UNKNOWN_PROBES: Literal[1] = 1

RoutingReasonCode = Literal[
    "api_unavailable",
    "production_approval_with_signup",
    "production_approval_without_signup",
    "contact_without_signup",
    "self_serve_portal",
    "verified_evidence_route",
    "insufficient_evidence_probe_available",
    "insufficient_evidence_after_probe",
]


class RoutingDecision(StrictModel):
    """Auditable final or bounded-intermediate result from the deterministic router."""

    route: AccessRoute
    reason_code: RoutingReasonCode
    explanation: str = Field(min_length=1)
    is_final: bool
    unknown_probe_attempts: int = Field(ge=0, le=MAX_UNKNOWN_PROBES)
    unknown_probe_remaining: int = Field(ge=0, le=MAX_UNKNOWN_PROBES)


UnknownRouteProbe = Callable[[OperationalResearch], Awaitable[OperationalResearch]]


def decide_access(
    research: OperationalResearch,
    *,
    unknown_probe_attempts: int = 0,
) -> RoutingDecision:
    """Apply fixed-priority routing rules and explain which verified signal won.

    Unknown research is allowed at most one enrichment probe.  The caller owns
    the probe implementation; this function only models the bounded state.
    """

    if unknown_probe_attempts not in (0, MAX_UNKNOWN_PROBES):
        raise ValueError("unknown_probe_attempts must be zero or one")

    if research.api_available is False:
        return _final(
            route="blocked",
            reason_code="api_unavailable",
            explanation="Verified operational research marks the API as unavailable.",
            attempts=unknown_probe_attempts,
        )

    if research.production_approval_required is True:
        if research.signup_url:
            return _final(
                route="hybrid",
                reason_code="production_approval_with_signup",
                explanation=(
                    "A self-service signup path exists, but verified production access requires "
                    "provider approval."
                ),
                attempts=unknown_probe_attempts,
            )
        return _final(
            route="approval_required",
            reason_code="production_approval_without_signup",
            explanation="Verified production access requires approval and no signup path is known.",
            attempts=unknown_probe_attempts,
        )

    if (research.contact_email or research.contact_url) and not research.signup_url:
        return _final(
            route="partner_gated",
            reason_code="contact_without_signup",
            explanation="Only a verified provider-contact path is available; no signup path is known.",
            attempts=unknown_probe_attempts,
        )

    if research.signup_url and research.developer_portal_url:
        return _final(
            route="self_serve",
            reason_code="self_serve_portal",
            explanation="Verified signup and developer-portal paths are both available.",
            attempts=unknown_probe_attempts,
        )

    # Operational signals above are authoritative.  In their absence, P1's
    # evidence-derived classification remains a legitimate, explicit input—not
    # a guessed operational URL or approval fact.
    if research.access_route != "unknown":
        return _final(
            route=research.access_route,
            reason_code="verified_evidence_route",
            explanation=(
                "No stronger operational signal contradicts the verified evidence-derived "
                "access classification."
            ),
            attempts=unknown_probe_attempts,
        )

    if unknown_probe_attempts == 0:
        return RoutingDecision(
            route="unknown",
            reason_code="insufficient_evidence_probe_available",
            explanation="Evidence is insufficient; exactly one bounded enrichment probe is allowed.",
            is_final=False,
            unknown_probe_attempts=0,
            unknown_probe_remaining=MAX_UNKNOWN_PROBES,
        )
    return RoutingDecision(
        route="unknown",
        reason_code="insufficient_evidence_after_probe",
        explanation="Evidence remains insufficient after the single allowed enrichment probe.",
        is_final=True,
        unknown_probe_attempts=MAX_UNKNOWN_PROBES,
        unknown_probe_remaining=0,
    )


def _final(
    *,
    route: AccessRoute,
    reason_code: RoutingReasonCode,
    explanation: str,
    attempts: int,
) -> RoutingDecision:
    return RoutingDecision(
        route=route,
        reason_code=reason_code,
        explanation=explanation,
        is_final=True,
        unknown_probe_attempts=attempts,
        unknown_probe_remaining=0,
    )


def classify_access(research: OperationalResearch) -> AccessRoute:
    """Preserve the plan's route-only public interface."""

    return decide_access(research).route


async def resolve_access(
    research: OperationalResearch,
    *,
    unknown_probe: UnknownRouteProbe | None = None,
) -> RoutingDecision:
    """Resolve a route, invoking an injected unknown probe no more than once."""

    initial = decide_access(research)
    if initial.route != "unknown" or initial.is_final or unknown_probe is None:
        return initial

    enriched = await unknown_probe(research)
    return decide_access(enriched, unknown_probe_attempts=MAX_UNKNOWN_PROBES)
