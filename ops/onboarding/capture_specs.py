"""The capture contract for a provider that has no reviewed recipe.

``api.browser_secret_broker`` refuses a credential capture unless it can resolve
a contract naming the URL the value may be read from, the domain that URL must
stay on, and the exact shape the value must have. Today it resolves that
contract with ``ops.recipes.app_recipes.get_app_capture_spec(app_slug)``, which returns
``None`` for every provider outside the reviewed 50-app matrix — so autonomous
onboarding of a brand-new provider currently fails ``browser_capture_not_authorized``
at the last step. This module supplies the missing authority (design LL-1.6).

**The security property is unchanged; only the authority moves.** A reviewed
recipe and a run's committed profile answer different halves of the contract, and
the split is what makes the profile-derived path safe:

* *Where* the credential is minted comes from the run's immutable
  ``ProviderProfile`` — the matching ``FlowSpec.entry_url`` and the profile's
  single ``registrable_domain`` (Requirement 10.6). Both were corroborated at
  research time, content-addressed, and committed before any browser session
  existed, so neither can be influenced by the page the worker is standing on.
* *What a valid credential looks like* comes from checked-in code, keyed by
  credential kind and by nothing else — ``credential_value_pattern(kind)``
  (Requirement 10.5). Research never supplies a pattern. That accessor takes a
  credential kind and no other argument, so there is no parameter through which
  research output or page text could widen the contract.

**Selectors are deliberately absent.** A reviewed recipe names exact selectors
because a human read the page and a scan of every input could otherwise pick an
unrelated field that happens to match the pattern. A brand-new provider has no
reviewed page, and inventing selectors from research or from live DOM text would
put the untrusted page inside its own admission check. The profile-driven path
proves it is on the credential surface a different way: the action loop's
postcondition classification for the credential phase must hold in the final
observation before capture is reserved at all, and the broker independently
re-applies the checked-in ``value_pattern`` to whatever the worker sends. So the
contract returned here carries ``selectors=()`` and no ``expected_path_prefix``,
``expected_heading``, or ``reveal_selector`` — the absence is the design, not an
omission to be filled in later.

**The one refusal, and the code it carries.** When the profile declares no flow
that mints the requested kind, or the matching flow carries no ``entry_url``,
there is nothing to capture from and this module raises
:class:`CaptureContractUnavailable` with reason code ``capture_spec_unavailable``.
That is deliberately *not* ``flow_unsupported``: per task 3.2 the two codes ask
different things of an operator. ``flow_unsupported`` means the provider offers
no drivable flow for the kind (``FlowSpec.supported is False``) and is reported
much earlier, by the developer-application phase, which pauses before any
credential is generated. ``capture_spec_unavailable`` means a contract could not
be *constructed* for a flow the profile does declare — a re-researched or
corrected profile can make the same phase provable. This module never reports
the former, because a run whose flow was unsupported never reaches capture.
"""

from __future__ import annotations

from typing import Final, Literal, Protocol, cast

from ops.credentials.capture_specs import CredentialCaptureSpec
from ops.onboarding.credentials import credential_value_pattern, is_credential_kind
from ops.onboarding.phase import OnboardingReasonCode
from ops.providers.profile import FlowSpec, ProviderProfile, compute_profile_digest
from ops.providers.profile_store import ProviderProfileStore
from ops.recipes.app_recipes import get_app_capture_spec

# Why the contract is unbuildable. Stable, closed, and free of provider or page
# text, so it is safe to log next to the run id while the reason code the run
# pauses with stays the single member of the closed onboarding vocabulary.
CaptureContractDetail = Literal[
    "profile_store_unavailable",
    "profile_not_bound",
    "credential_kind_unknown",
    "profile_digest_mismatch",
    "flow_entry_url_absent",
]

# The attribute the run service exposes its profile store under. Both spellings
# are accepted because the run service's optional stores are private today
# (``_secret_store``, ``_effect_store``) while the composition task (25.1) binds
# ports by their public port name; resolving either keeps this module correct
# across that change instead of failing closed on a rename.
PROFILE_STORE_ATTRIBUTES: Final[tuple[str, ...]] = (
    "provider_profile_store",
    "_provider_profile_store",
)


class CaptureContractUnavailable(RuntimeError):
    """No capture contract could be built for this run and credential kind.

    Carries the closed onboarding ``reason_code`` the run pauses with, plus a
    bounded ``detail`` naming which precondition was missing. The provider's own
    strings — page text, research excerpts, credential material — never reach
    the message.
    """

    reason_code: Final[OnboardingReasonCode] = "capture_spec_unavailable"

    def __init__(self, *, run_id: str, detail: CaptureContractDetail) -> None:
        self.run_id = run_id
        self.detail = detail
        super().__init__(f"capture contract unavailable for run {run_id}: {detail}")


class ProfileCaptureCore(Protocol):
    """The one collaborator this module reads off the run service."""

    @property
    def provider_profile_store(self) -> ProviderProfileStore | None: ...


def profile_capture_contract(
    core: object,
    *,
    run_id: str,
    kind: str,
) -> CredentialCaptureSpec:
    """Build the run's capture contract from its committed profile.

    PRE:  ``run_id`` names a run whose profile is committed and bound, and
          ``kind`` is a member of the checked-in ``CredentialKind`` vocabulary.
    POST: returns a :class:`CredentialCaptureSpec` whose ``value_pattern`` came
          from checked-in code keyed by ``kind``, whose ``vendor_domain`` is the
          profile's single registrable domain, and whose ``url`` is the matching
          flow's entry URL — or raises :class:`CaptureContractUnavailable` with
          reason code ``capture_spec_unavailable``. Nothing is written, no
          credential material is read, and the returned contract carries no
          selectors (see the module docstring).

    ``core`` is the run service, typed structurally rather than imported, so the
    orchestrator stays out of this module's imports and the broker can keep
    passing the loosely typed service object it already holds.
    """

    store = _resolve_profile_store(core, run_id=run_id)
    if not is_credential_kind(kind):
        # Fail closed. The broker's request model bounds ``kind`` to a character
        # class, not to this vocabulary, so an unknown kind arrives here as
        # ordinary untrusted input rather than as a programming error.
        raise CaptureContractUnavailable(run_id=run_id, detail="credential_kind_unknown")

    # The run's stored ``profile_digest`` is the ``provider_profile_runs``
    # binding, and ``get_for_run`` resolves it in one owner-scoped read: a store
    # constructed for one tenant cannot load another tenant's profile.
    profile = store.get_for_run(run_id=run_id)
    if profile is None:
        raise CaptureContractUnavailable(run_id=run_id, detail="profile_not_bound")
    if compute_profile_digest(profile) != profile.profile_digest:
        # The body no longer addresses the digest the run recorded, so "this
        # capture is attributable to profile D" would be false. Refuse rather
        # than capture against an unattributable contract.
        raise CaptureContractUnavailable(run_id=run_id, detail="profile_digest_mismatch")

    flow = _minting_flow(profile, kind=kind)
    if flow is None or flow.entry_url is None:
        raise CaptureContractUnavailable(run_id=run_id, detail="flow_entry_url_absent")

    return CredentialCaptureSpec(
        app_slug=profile.app_slug,
        # Already proven to resolve to ``registrable_domain`` over HTTPS by
        # ``ProviderProfile.__post_init__``, which validates every flow entry
        # URL at construction, so this projection re-checks nothing.
        url=flow.entry_url,
        vendor_domain=profile.registrable_domain,
        # The broker compares ``field_kind`` against the requested kind, so the
        # credential kind is the field kind on this path; there is no reviewed
        # per-app field name to map onto.
        field_kind=kind,
        value_pattern=credential_value_pattern(kind),
        # Deliberately absent: the profile-driven path proves it is on the
        # credential surface through the action loop's postcondition
        # classification, not through a reviewed selector list.
        selectors=(),
    )


def resolve_capture_contract(
    core: object,
    *,
    app_slug: str,
    run_id: str,
    kind: str,
) -> CredentialCaptureSpec:
    """The capture contract for one run: reviewed recipe first, else the profile.

    THE AUTHORITY ORDER, in one place, for both transports that can capture — the
    production RPC path through ``api.browser_secret_broker`` and the local
    in-process path through ``ops.onboarding.adapters``. Two copies of this order
    could drift into two different answers about which contract governs a write.

    A checked-in recipe is the stronger authority, so it stays first: it was reviewed
    against a real page. :func:`profile_capture_contract` is the stand-in for every
    provider that has no reviewed recipe — which is the whole point of the
    off-catalog path, and exactly the set ``get_app_capture_spec`` returns ``None``
    for.

    POST: the returned ``value_pattern`` came from checked-in code on either branch.
          Research and page text never supply a pattern.
    """

    reviewed = get_app_capture_spec(app_slug)
    if reviewed is not None:
        return reviewed
    return profile_capture_contract(core, run_id=run_id, kind=kind)


def _resolve_profile_store(core: object, *, run_id: str) -> ProviderProfileStore:
    """The run service's profile store, or a fail-closed refusal."""

    for name in PROFILE_STORE_ATTRIBUTES:
        candidate = getattr(core, name, None)
        if candidate is not None and callable(getattr(candidate, "get_for_run", None)):
            return cast(ProviderProfileStore, candidate)
    raise CaptureContractUnavailable(run_id=run_id, detail="profile_store_unavailable")


def _minting_flow(profile: ProviderProfile, *, kind: str) -> FlowSpec | None:
    """The declared flow whose entry URL mints ``kind``, in a stable order.

    Supported flows are considered first because a supported flow is the one the
    developer-application phase actually drove. An unsupported flow that still
    carries an entry URL is not refused *here*: whether a flow may be driven at
    all is the developer-application phase's gate, and it pauses with
    ``flow_unsupported`` long before capture. Conflating the two would report the
    wrong code to the operator.
    """

    matches = tuple(flow for flow in profile.flows() if kind in flow.produces)
    ordered = (
        *(flow for flow in matches if flow.supported),
        *(flow for flow in matches if not flow.supported),
    )
    return next((flow for flow in ordered if flow.entry_url), None)


def _port_conformance(core: ProfileCaptureCore) -> object:
    """Typecheck-only proof that the structural core is what this module reads."""

    return core.provider_profile_store


__all__ = [
    "PROFILE_STORE_ATTRIBUTES",
    "CaptureContractDetail",
    "CaptureContractUnavailable",
    "ProfileCaptureCore",
    "profile_capture_contract",
    "resolve_capture_contract",
]
