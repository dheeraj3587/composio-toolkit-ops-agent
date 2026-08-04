"""The operation key a grant was reserved under, remembered in-process.

WHY THIS EXISTS. ``SQLiteSecretStore.consume_transient_with_grant`` requires
``expected_operation_key`` and re-validates the whole binding before it deletes the
one-time row. But ``ops.playwright.loop_session.GrantedSecretConsumer.consume``
receives only ``(reference, kind, grant)``. The key is not missing information — the
code that RESERVED the grant computed it (``ops.browser.signup`` for a signup fill,
``ops.onboarding.driver`` for a verification code). So the key is remembered at
reservation rather than recomputed at consumption, and rather than asking the vault
to divulge it.

WHAT THIS IS NOT. It is not a weakening of the grant binding. The vault still
validates every field and still deletes the row exactly once, so one-grant-one-use is
untouched. This only supplies the key the reserver already chose; a wrong or absent
entry produces a REFUSAL, never a bypass. Nor is it a secret store: it holds no
credential values, only bindings, whose grants this process already holds in
``SignupSecretFill``. The operation key itself is not secret — it is deterministic in
durable run facts — while the GRANT is the bearer, and the grant is what the vault
checks.

LIFETIME, AND WHY A RESTART NEEDS NOTHING FROM HERE. Reservation and consumption
happen inside ONE phase-handler call: ``stage_signup_credentials`` reserves and
``SignupSubmitter.submit_signup`` consumes; ``_stage_verification_code`` reserves and
``VerificationSession.inject_one_time_code`` consumes. Nothing spans a process
boundary, so this is a within-call handoff rather than durable state.

That is load-bearing for resume, and it holds for a reason worth stating: a resumed
run does not need its old entry back. ``put_transient`` mints its identifier with
``secrets.token_urlsafe``, and the reference is part of the grant's HMAC material, so
a re-staged secret yields a FRESH reference and therefore a FRESH grant — recorded on
the way through by ``RecordingSecretVault``. What survives a restart is the staged
signup PAIR, keyed by ``(app_slug, account_ref, run_id)``, so the identity the run
submits is stable while only the one-shot plumbing is regenerated.

Consequently a registry miss can only come from a wiring fault, never from a restart,
which is why refusing on a miss costs a correct run nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


@dataclass(frozen=True, slots=True)
class GrantBinding:
    """Exactly the fields the vault re-validates for one grant. No value, ever.

    Frozen because a binding describes a reservation that already happened: the vault
    minted a grant over these exact values, so mutating one afterwards could only
    make the registry disagree with the durable row.
    """

    operation_key: str
    run_id: str
    session_id: str
    app_slug: str
    kind: str
    action: Literal["consume", "capture"]
    reference: str | None


@dataclass(slots=True)
class RunGrantRegistry:
    """Grant -> the binding it was reserved under, for one run's walk.

    Deliberately two verbs and no delete. Retiring an entry after use would be
    redundant and misleading: the VAULT is what makes a grant single-use — it deletes
    the transient row inside ``consume_transient_with_grant`` — so a second
    consumption of a spent grant already fails there. Removing the entry here would
    turn that precise refusal into an indistinguishable "unknown grant" and imply
    this class enforces something it does not.
    """

    _bindings: dict[str, GrantBinding] = field(default_factory=dict)

    def record(self, grant: str, binding: GrantBinding) -> None:
        """Remember the binding one reservation was made under.

        An identical re-record is a replay rather than a conflict: re-reserving the
        same operation returns the same grant (the token is an HMAC over the binding),
        so a retried reservation legitimately arrives here twice with equal values.
        """

        self._bindings[grant] = binding

    def binding_for(self, grant: str) -> GrantBinding | None:
        """The recorded binding, or ``None`` — which the caller treats as a refusal."""

        return self._bindings.get(grant)


__all__ = ["GrantBinding", "RunGrantRegistry"]
