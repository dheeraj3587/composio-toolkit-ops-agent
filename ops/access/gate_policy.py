"""Declarative policy for which human gates the agent may resolve by itself.

This module is the single readable place that answers two questions for a paused
run: *may* this gate be resolved without a person, and if so *how*. It replaces
the previous empty ``_AUTO_ADVANCEABLE_GATES`` frozenset in ``ops.runs.advance``,
which made every gate human-only by construction.

The policy is deliberately fail-closed. A gate is human-only unless it appears in
``_AUTONOMOUS_RESOLUTION`` below, so a newly added ``HumanActionType`` pauses for
an owner until it is reviewed and classified here rather than silently becoming
autonomous.

Three gates are permanently human-only and must never be added:

``captcha``
    Resolving it autonomously means defeating an anti-bot control. Out of scope
    by policy, not by omission.
``phone_otp``
    Needs a programmable-number provider that this system does not have.
``device_approval``
    Only ever *avoided* by reusing previously approved encrypted storage state
    (see ``ops.browser.storage_state``); the agent never approves a device.

``billing`` is human-only because it spends money, and ``passkey`` /
``security_key`` are human-only because a hardware authenticator cannot be
satisfied by a headless session. ``provider_verification`` stays human-only
because it is ambiguous by construction: it can stand for a CAPTCHA, a device
check, a consent screen, or an account chooser, and auto-resuming it can turn a
solvable gate into a failed login before an operator can attach.

``signup_authorization`` joins them permanently: creating an account has legal
and billing consequences, so resolving it autonomously would mean the agent
authorizing contract acceptance and spending on the owner's behalf.

Two authority paths, never page text
------------------------------------
A gate that is autonomous only *conditionally* needs an authority saying so, and
this module admits exactly two. ``recipe_declared`` is a reviewed, versioned
assertion in the checked-in catalog. ``profile_declared`` is its runtime sibling
for a provider that has no catalog entry at all: the run's immutable,
content-addressed ``ops.providers.profile.ProviderProfile`` plus the operator's
recorded affirmative admission decision. Neither path ever consults the rendered
page — that is the whole point of naming them after their authority. The profile
path is additionally confined to the profile's single registrable domain, so an
authorization earned for one provider cannot travel to a page on another host.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

# The same authority the reviewed browser host policy and ``ProviderProfile``
# consult, including its conservative ``co.uk``-style suffix handling. Deriving
# domain confinement from a second implementation would let the boundaries drift.
from ops.browser.host_policy import registrable_domain as resolve_registrable_domain
from ops.recipes.app_recipes import get_app_recipe

# How a gate may be resolved. ``human_only`` is the fail-closed default.
GateResolution = Literal[
    "human_only",
    "reusable_login",
    "emailed_verification",
    "recipe_declared",
    "profile_declared",
]

# Gates the agent may resolve, mapped to the mechanism that resolves them. Every
# mechanism reuses machinery that already exists; none of them is a new provider
# boundary.
#
#   reusable_login       -> ops.runs.login_secrets reusable values, injected by
#                           the existing resume path.
#   emailed_verification -> ops.runs.verification.RunVerificationService, which
#                           already enforces recipient binding and authenticated
#                           sender evidence.
#   recipe_declared      -> a reviewed, versioned assertion in the recipe itself
#                           (never inferred from page text).
#   profile_declared     -> the run's immutable provider profile plus the
#                           operator's recorded admission decision, confined to
#                           the profile's registrable domain. The runtime
#                           stand-in for a recipe the provider does not have.
#
# The value stored here is the gate's *primary* authority. A gate whose primary
# authority does not apply may still resolve through a sibling authority, which
# is why ``resolve_gate`` re-derives the mechanism per run instead of returning
# this mapping's value directly for the declared gates.
_AUTONOMOUS_RESOLUTION: dict[str, GateResolution] = {
    "login_required": "reusable_login",
    "email_otp": "emailed_verification",
    "legal_acceptance": "recipe_declared",
}

# Gates that must never resolve without a person. Kept explicit rather than
# implied by absence so that the intent survives future edits to this file.
HUMAN_ONLY_GATES: frozenset[str] = frozenset(
    {
        "captcha",
        "phone_otp",
        "passkey",
        "security_key",
        "device_approval",
        "billing",
        "provider_verification",
        # Autonomous account choice needs a reviewed, unambiguous recipe selector.
        # No recipe declares one yet, so choosing would be a guess about which
        # tenant to onboard.
        "account_selection",
        # Creating an account has legal and billing consequences. Autonomous
        # resolution would mean the agent authorizing spending and contract
        # acceptance on the owner's behalf. Permanently human-only; must never be
        # added to ``_AUTONOMOUS_RESOLUTION``. Listed here as well as being
        # covered by the fail-closed default so the intent survives future edits.
        "signup_authorization",
    }
)

# Gates a per-run provider profile may authorize. Deliberately a single member:
# accepting the provider's own terms at the moment its signup form is submitted
# is the one consent the operator's affirmative admission decision already
# covers — approving account creation *is* approving the terms that creation is
# subject to. Nothing else belongs here, and ``signup_authorization`` least of
# all: a gate cannot supply its own authorization.
PROFILE_DECLARABLE_GATES: frozenset[str] = frozenset({"legal_acceptance"})

# A profile digest is a sha256 content address. Checking the shape refuses an
# empty or placeholder digest, which would otherwise let an uncommitted profile
# stand in for a committed one.
_PROFILE_DIGEST = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class ProfileGateAuthority:
    """The durable facts that let a run's own profile authorize a gate.

    Every field is a durable fact recorded before the gate was observed: the
    digest of the profile the run committed, that profile's single registrable
    domain, the page the gate appeared on, and the three attributable fields of
    the run's recorded admission decision. Page text is absent by construction —
    there is no field it could arrive in.

    The admission fields mirror ``AdmissionDecision`` (``route``, ``decided_by``,
    ``profile_digest``), which task 10.1 will define in
    ``ops/onboarding/admission.py``. They are accepted as primitives rather than
    as that record so this policy keeps no dependency on the admission service;
    the caller projects the recorded row onto this shape.

    Constructing one asserts nothing. Every check lives in :func:`resolve_gate`,
    which returns ``"human_only"`` rather than raising, so a malformed authority
    costs a run one pause instead of aborting the sweep that classified it.
    """

    profile_digest: str  # the run's committed ProviderProfile digest, 64 hex
    registrable_domain: str  # that profile's single primary registrable domain
    gate_url: str  # https URL of the page the gate was observed on
    admission_route: str  # AdmissionDecision.route: login | signup | cancelled
    admission_decided_by: str  # AdmissionDecision.decided_by: system | operator
    admission_profile_digest: str  # AdmissionDecision.profile_digest


def autonomous_gates() -> frozenset[str]:
    """Gate types that may resolve without a person, ignoring per-run conditions.

    Callers still have to consult :func:`resolve_gate`, because some gates are
    autonomous only when the run's recipe or the run's own profile authorizes it.
    """

    return frozenset(_AUTONOMOUS_RESOLUTION)


def _legal_acceptance_declared(app_slug: str) -> bool:
    """Whether the reviewed recipe states that entry submission accepts terms.

    Consent is a property of the reviewed recipe, never of the rendered page, so
    an app whose recipe omits the declaration keeps pausing for an owner.
    """

    recipe = get_app_recipe(app_slug)
    if recipe is None or recipe.browser is None:
        return False
    signup = recipe.browser.signup
    if signup is None:
        return False
    return bool(signup.entry_submit_implies_legal_acceptance)


def _within_profile_domain(url: str, domain: str) -> bool:
    """Whether ``url`` is an https URL inside the profile's registrable domain.

    ``domain`` must already be the registrable form of itself, which is the same
    invariant ``ProviderProfile`` enforces at construction: it refuses a host
    posing as a domain (``app.provider.com``) and a suffix-extension attempt
    (``provider.com.evil.io``, whose registrable form is ``evil.io``).

    Userinfo is refused for the same reason the reviewed browser host policy
    refuses it: ``https://provider.com@evil.io/`` reads as the vendor's domain to
    a person and resolves elsewhere.
    """

    if resolve_registrable_domain(domain) != domain:
        return False
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
    except ValueError:
        # A malformed URL is not a domain match. Fail closed rather than raise
        # into the classifier.
        return False
    if parsed.scheme != "https" or not hostname or parsed.username or parsed.password:
        return False
    return resolve_registrable_domain(hostname) == domain


def _profile_authorizes(action_type: str, authority: ProfileGateAuthority | None) -> bool:
    """Whether the run's profile and admission record authorize this gate.

    Every clause is required, and each one closes a different way the authority
    could be weaker than it looks:

    * the gate is one a profile may ever authorize;
    * the run committed a profile, evidenced by a well-formed content address;
    * the admission decision names *that* profile, so the authorization is
      attributable to the exact profile the operator saw rather than to a later
      re-research of the same provider;
    * a person made the decision and made it affirmatively — an operator's
      ``cancelled`` and the system's own ``login`` routing both fail here, so the
      only thing that grants this authority is a human approving account
      creation;
    * the gate was observed inside the profile's one registrable domain.
    """

    if authority is None:
        return False
    if action_type not in PROFILE_DECLARABLE_GATES:
        return False
    if _PROFILE_DIGEST.fullmatch(authority.profile_digest) is None:
        return False
    if authority.admission_profile_digest != authority.profile_digest:
        return False
    if authority.admission_route != "signup" or authority.admission_decided_by != "operator":
        return False
    return _within_profile_domain(authority.gate_url, authority.registrable_domain)


def resolve_gate(
    action_type: str | None,
    *,
    app_slug: str,
    profile_authority: ProfileGateAuthority | None = None,
) -> GateResolution:
    """Classify one paused gate into the mechanism allowed to resolve it.

    Returns ``"human_only"`` for an unknown, unclassified, or explicitly
    human-only gate, so an unrecognized value can never advance a run.

    ``profile_authority`` is the onboarding path's runtime stand-in for a
    reviewed recipe, and it is optional so that a caller with no profile — the
    recipe-driven sweep in ``ops.runs.advance`` — keeps its existing behavior
    exactly. Omitting it can only ever withhold autonomy.
    """

    if not action_type:
        return "human_only"
    if action_type in HUMAN_ONLY_GATES:
        # Checked before the autonomous table so a gate listed in both is
        # human-only, and a gate listed only here needs no second entry.
        return "human_only"
    resolution = _AUTONOMOUS_RESOLUTION.get(action_type)
    if resolution is None:
        return "human_only"
    if resolution == "recipe_declared":
        # Currently only legal acceptance is recipe-declared. Requiring the
        # declaration here keeps the authorization in the versioned catalog.
        if action_type == "legal_acceptance" and _legal_acceptance_declared(app_slug):
            return "recipe_declared"
        # A provider the repo has never seen has no catalog entry to declare
        # anything, which is why the profile path exists. The reviewed catalog
        # still wins when it speaks: this is only reached when it does not.
        if _profile_authorizes(action_type, profile_authority):
            return "profile_declared"
        return "human_only"
    return resolution


__all__ = [
    "HUMAN_ONLY_GATES",
    "PROFILE_DECLARABLE_GATES",
    "GateResolution",
    "ProfileGateAuthority",
    "autonomous_gates",
    "resolve_gate",
]
