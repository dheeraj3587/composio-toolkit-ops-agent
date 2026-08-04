"""The in-process grant path: record at reservation, redeem at consumption.

Two collaborators, one purpose — let the local Playwright transport redeem a grant
without widening any port and without weakening the vault's binding check. See
``ops.onboarding.grant_registry`` for why the key is remembered rather than
recomputed, and why a restart needs nothing from the registry.

WHY THE LOCAL PATH NEEDS THIS AT ALL. The production RPC broker cannot serve an
onboarding run, for two independent structural reasons:

* ``api.browser_secret_broker._bound_active_run`` requires the run's phase to be
  ``credential_capture_reserved`` (capture) or ``authentication_submitted``
  (consume). Neither is an ``OnboardingPhase``; both are canonical-runtime phases.
* ``_current_operation_key`` recomposes the key from the run row's
  ``effect_identity``, and the onboarding path never writes that column.

So the in-process consumer is the only route for an onboarding run, which is what
``GrantedSecretConsumer`` already anticipates where it names the in-process case.

WHY NOTHING HERE PUTS A KEY ON A WIRE. ``GrantedSecretConsumer`` has no other
implementation and is passed to nothing else: the RPC session
(``ops.browser.service_client.BrowserServiceLoopSession``) exposes only ``act``,
``observe`` and ``session_id``, and the browser container redeems grants through its
own ``browser_service.secret_broker`` client, whose ``consume`` takes a different
argument list entirely. ``consume``'s signature is therefore left EXACTLY as it was.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from ops.browser.signup import SignupCredentialVault
from ops.core.secret_store import BrowserSecretGrantError
from ops.onboarding.driver import VerificationSecretVault
from ops.onboarding.grant_registry import GrantBinding, RunGrantRegistry


@dataclass(slots=True)
class RecordingSecretVault:
    """Delegates every vault verb verbatim, recording grant bindings in passing.

    Satisfies ``SignupCredentialVault`` and ``VerificationSecretVault``
    structurally — the two ports whose grants are later redeemed through
    :class:`InProcessGrantConsumer`. Every method forwards unchanged: this adds no
    verb, widens no signature, and makes no decision the wrapped store did not
    already make.

    Deliberately NOT used for the credential CAPTURE path. That path needs no
    registry because it already threads its operation key explicitly into
    ``ops.credentials.capture_boundary.capture_validated_credential``, and routing it
    through here would add a second, redundant source for a key it already holds.
    """

    store: Any
    registry: RunGrantRegistry

    def reserve_browser_secret_grant(
        self,
        *,
        operation_key: str,
        run_id: str,
        session_id: str,
        app_slug: str,
        kind: str,
        action: Literal["consume", "capture"],
        reference: str | None = None,
        ttl_seconds: int = 900,
    ) -> str:
        grant = str(
            self.store.reserve_browser_secret_grant(
                operation_key=operation_key,
                run_id=run_id,
                session_id=session_id,
                app_slug=app_slug,
                kind=kind,
                action=action,
                reference=reference,
                ttl_seconds=ttl_seconds,
            )
        )
        # Recorded only AFTER the vault accepted the reservation, so a binding the
        # vault rejected never enters the registry and a raised reservation records
        # nothing at all.
        self.registry.record(
            grant,
            GrantBinding(
                operation_key=operation_key,
                run_id=run_id,
                session_id=session_id,
                app_slug=app_slug,
                kind=kind,
                action=action,
                reference=reference,
            ),
        )
        return grant

    # --- forwarded verbatim; no behaviour of their own ------------------------
    def put_transient(
        self,
        *,
        app_slug: str,
        kind: str,
        scope_id: str,
        value: str,
        ttl_seconds: int = 600,
    ) -> str:
        return str(
            self.store.put_transient(
                app_slug=app_slug,
                kind=kind,
                scope_id=scope_id,
                value=value,
                ttl_seconds=ttl_seconds,
            )
        )

    def stage_signup_login_pair(
        self, *, app_slug: str, account_ref: str, run_id: str, email: str, password: str
    ) -> dict[str, str]:
        return dict(
            self.store.stage_signup_login_pair(
                app_slug=app_slug,
                account_ref=account_ref,
                run_id=run_id,
                email=email,
                password=password,
            )
        )

    def get_staged_signup_login_pair(
        self, *, app_slug: str, account_ref: str, run_id: str
    ) -> dict[str, str]:
        return dict(
            self.store.get_staged_signup_login_pair(
                app_slug=app_slug, account_ref=account_ref, run_id=run_id
            )
        )

    def promote_staged_signup_login_pair(
        self, *, app_slug: str, account_ref: str, run_id: str
    ) -> tuple[str, ...]:
        return tuple(
            self.store.promote_staged_signup_login_pair(
                app_slug=app_slug, account_ref=account_ref, run_id=run_id
            )
        )


@dataclass(slots=True)
class InProcessGrantConsumer:
    """``GrantedSecretConsumer`` for the local transport. Signature UNCHANGED.

    Redeems one grant by supplying the operation key the reserver recorded. Three
    refusals, all folded into the vault's own ``BrowserSecretGrantError`` so a caller
    cannot treat one as softer than another:

    * the grant is not in the registry — a wiring fault, never a restart (see
      ``ops.onboarding.grant_registry``);
    * it was reserved for ``capture`` rather than ``consume``;
    * the caller named a different reference or kind than the grant was reserved for.

    THE THIRD IS DEFENCE IN DEPTH, NOT THE ENFORCEMENT, and it is worth being precise
    because the reverse would be a comfortable thing to believe. The vault refuses a
    grant redeemed against a reference it was not reserved for on its own — verified
    by calling ``consume_transient_with_grant`` directly with a mismatched pair, which
    raises ``BrowserSecretGrantError`` without this class involved. So removing this
    check would not open a hole; it is a cheap early refusal that keeps a wiring bug
    from looking like a vault-level authorization failure.

    What actually authorizes the read is the vault re-validating the whole binding —
    operation key, run, session, app, kind, reference — and then deleting the one-time
    row. This class supplies the key; it does not decide anything.
    """

    store: Any
    registry: RunGrantRegistry

    def consume(self, *, reference: str, kind: str, grant: str) -> str:
        binding = self.registry.binding_for(grant)
        if binding is None or binding.action != "consume":
            # Fail closed. Guessing or reconstructing a key here would be precisely
            # the bypass this design exists to avoid.
            raise BrowserSecretGrantError("browser_secret_grant_unavailable")
        if binding.reference != reference or binding.kind != kind:
            raise BrowserSecretGrantError("browser_secret_grant_unavailable")
        # The value is produced here and returned to exactly one caller
        # (``PlaywrightLoopSession.fill_from_grant``), which passes it straight into
        # a single Playwright expression without binding it to a name.
        return str(
            self.store.consume_transient_with_grant(
                grant,
                reference,
                expected_app_slug=binding.app_slug,
                expected_kind=binding.kind,
                expected_scope_id=binding.run_id,
                expected_session_id=binding.session_id,
                expected_operation_key=binding.operation_key,
            )
        )


def _signup_vault_conformance(vault: RecordingSecretVault) -> SignupCredentialVault:
    """Typecheck-only proof that the wrapper satisfies the signup vault port."""

    return vault


def _verification_vault_conformance(vault: RecordingSecretVault) -> VerificationSecretVault:
    """Typecheck-only proof that the same wrapper satisfies the verification port."""

    return vault


__all__ = ["InProcessGrantConsumer", "RecordingSecretVault"]
