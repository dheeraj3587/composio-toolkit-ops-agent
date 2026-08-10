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
    by policy, not by omission — and specifically NOT by buying the capability
    either: wiring a third-party solving service was considered and rejected by
    the owner, so a person solves every CAPTCHA and no code here should grow a
    ``solver_service`` resolution.

    Human-solved does not mean human-paced. The cost of this policy is bounded
    by ``ops.runs.takeover``, which watches every paused run and continues it as
    soon as it can *observe* that the gate is gone, so the agent takes the wheel
    back within one poll interval of the person finishing rather than whenever
    an operator next looks at the console. The complement is enforced in
    ``browser_service``: while the agent drives, human input is denied outright
    (see ``_take_exclusive_browser_control``), so the two never hold the same
    page at the same moment.
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

``signup_authorization`` is the one gate that moved. It was permanently human-only
on the reasoning that creating an account has legal and billing consequences, and
that reasoning still holds — what changed on 2026-08-09 is *when* the person
supplies the authorization, not whether one exists. The owner may now record a
standing, per-app, timestamped authorization (see
``ops.onboarding.standing_authorization``), and a run covered by one carries a
recorded ``AdmissionDecision(route="signup")`` naming that person before it ever
reaches a page. This gate therefore resolves ``profile_declared`` — against that
recorded decision, confined to the profile's own registrable domain — and stays
``human_only`` for every run without one, which is still the default.

The circularity objection this file used to raise ("a gate cannot supply its own
authorization") is answered rather than waived: the authority is not the gate and
not the page, it is a decision that predates the run. What would be circular, and
is still refused, is a signup the *system* decided — ``decided_by="system"`` is
rejected by ``AdmissionDecision`` construction and by the admission table's CHECK,
so no authority this module accepts can be one the software minted for itself.

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

# The deciders a stored signup route may name. Imported rather than restated so
# this policy and the record it reads cannot come to disagree about which
# authorities are human.
from ops.onboarding.admission import SIGNUP_DECIDERS
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
    # Resolvable only against the run's recorded signup decision — there is no
    # recipe path for it, because a checked-in catalog cannot record who
    # authorized creating an account and when. A run with no such decision gets
    # "human_only" from ``_profile_authorizes`` and pauses exactly as before.
    "signup_authorization": "profile_declared",
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
        # Granting one application access to an account is a scope decision about
        # someone else's data, not a terms acceptance, so it does not inherit
        # legal_acceptance's recipe-declared resolution. Phase 7B revisits this
        # for the managed-auth OAuth routes; until then it stays human-only.
        "oauth_grant",
        # Still human-only HERE, and deliberately so: by the time this gate is
        # raised, the one case that needs no judgement has already been handled
        # upstream. ``ops.browser.login.drive_login`` clicks a chooser entry when
        # its visible label contains the run's own sign-in address and no other
        # entry does -- an identity match against a value the run already holds,
        # not a choice. Anything that reaches this table is a chooser where that
        # match was absent or ambiguous, and picking one there would be a guess
        # about which tenant to onboard.
        "account_selection",
        # ``signup_authorization`` used to be listed here. It is not any more --
        # see the module docstring. It remains human-only for every run that
        # holds no recorded signup decision, which is the fail-closed default
        # rather than an entry in this set.
    }
)

# Gates a per-run provider profile may authorize. Both members are the same
# consent seen at two moments: the recorded affirmative admission decision IS the
# authorization to create the account, and approving account creation is
# approving the terms that creation is subject to. Nothing whose authority is a
# scope decision about someone else's data belongs here -- ``oauth_grant``
# notably does not.
PROFILE_DECLARABLE_GATES: frozenset[str] = frozenset({"legal_acceptance", "signup_authorization"})

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
      creation. Since 2026-08-09 that human may have approved it per run
      (``operator``) or in advance for this app (``standing_authorization``);
      ``system`` is still refused, and is the only value that could mean the
      software authorized itself;
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
    if authority.admission_route != "signup":
        return False
    if authority.admission_decided_by not in SIGNUP_DECIDERS:
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
    if resolution == "profile_declared":
        # A gate whose ONLY authority is the run's own profile. Unlike the branch
        # above there is no catalog fallback to try first, and returning the
        # mapping's value directly would grant the gate to every run — which is
        # precisely the bug the fail-closed default exists to prevent.
        return (
            "profile_declared"
            if _profile_authorizes(action_type, profile_authority)
            else "human_only"
        )
    return resolution


__all__ = [
    "HUMAN_ONLY_GATES",
    "PROFILE_DECLARABLE_GATES",
    "GateResolution",
    "ProfileGateAuthority",
    "autonomous_gates",
    "resolve_gate",
]
