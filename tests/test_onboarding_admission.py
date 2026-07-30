"""Vault-first admission over a real vault, both routes in one walk.

The probe runs against a real ``SQLiteSecretStore`` in ``tmp_path`` rather than a
double, because the claim being checked is that a *stored* login pair routes the
run to login while an empty vault routes it to admission — a double would only
restate the test's own assumptions about what the vault holds.
"""

from __future__ import annotations

from cryptography.fernet import Fernet

from ops.core.secret_store import SQLiteSecretStore
from ops.onboarding.admission import (
    ADMISSION_GATE,
    admit_from_vault,
    decide_from_operator,
)

APP_SLUG = "acme-provider"
APP_NAME = "Acme Provider"
ACCOUNT_REF = "acct_" + "0" * 32
RUN_ID = "run_" + "1" * 32
OWNER_ID = "owner-1"
PROFILE_DIGEST = "a" * 64


def test_vault_presence_routes_to_login_and_absence_asks_once(tmp_path) -> None:
    store = SQLiteSecretStore(tmp_path / "vault.db", Fernet.generate_key())

    # Empty vault: no credential reference exists for this app and binding.
    absent = admit_from_vault(
        store,
        run_id=RUN_ID,
        profile_digest=PROFILE_DIGEST,
        app_slug=APP_SLUG,
        app_name=APP_NAME,
        account_ref=ACCOUNT_REF,
        owner_id=OWNER_ID,
    )

    assert absent.phase == "awaiting_admission"
    assert absent.reason_code == "signup_authorization_required"
    assert absent.probe.reason_code == "credentials_missing"
    assert absent.decision is None
    assert [prompt.type for prompt in absent.prompts] == [ADMISSION_GATE]

    # The operator authorizes account creation; only that path yields a signup route.
    approved = decide_from_operator(
        "create_account",
        run_id=RUN_ID,
        profile_digest=PROFILE_DIGEST,
        actor_owner_id=OWNER_ID,
    )
    assert (approved.route, approved.decided_by) == ("signup", "operator")
    assert approved.reason_code == "operator_approved_signup"

    # Signup stored a reusable login pair; a later run signs in with zero prompts.
    store.put_account_login_pair(
        app_slug=APP_SLUG,
        account_ref=ACCOUNT_REF,
        email="onboarding@example.invalid",
        password="generated-signup-password",  # pragma: allowlist secret
    )

    present = admit_from_vault(
        store,
        run_id=RUN_ID,
        profile_digest=PROFILE_DIGEST,
        app_slug=APP_SLUG,
        app_name=APP_NAME,
        account_ref=ACCOUNT_REF,
        owner_id=OWNER_ID,
    )

    assert present.phase == "route_selected_login"
    assert present.reason_code == "credentials_present"
    assert present.prompts == ()
    decision = present.decision
    assert decision is not None
    assert (decision.route, decision.decided_by) == ("login", "system")
    assert [field for field, _ in decision.credential_refs] == ["login_email", "login_password"]
    # References only: the email is a reference, never an address.
    for _, reference in decision.credential_refs:
        assert reference.startswith(f"vault://{APP_SLUG}/account_login_")
        assert "example.invalid" not in reference
