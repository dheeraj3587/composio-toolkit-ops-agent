# Autonomous signup submission authorization: Part 14

## Scope

Part 14 authorizes and dispatches one normal signup submission after Parts 12-13
have uniquely identified the submit control and verified every required field.

The implementation is separated by responsibility:

- `ops/signup_submission_gates.py` performs value-free human-gate detection.
- `ops/signup_submission_fields.py` re-verifies required live field values.
- `ops/signup_submission.py` owns authorization, effect reservation, and dispatch.
- `ops/browser_risk.py` owns the purpose-aware risk matrix.

This boundary does not classify the provider response. It records only that the
submit action was dispatched, or that the outcome is ambiguous. Account-created,
email-verification, CAPTCHA, existing-account, and provider-failure
classification remains Part 15.

## Research basis

The implementation follows primary browser and authorization guidance:

- Playwright locator actions are strict: an action targeting more than one
  element fails instead of selecting an arbitrary match:
  https://playwright.dev/python/docs/locators#strictness
- `Locator.click()` performs actionability checks and waits for navigation
  initiated by the click. `trial=True` performs the same actionability checks
  without dispatching the click:
  https://playwright.dev/python/docs/api/class-locator#locator-click
- Playwright discourages fixed sleeps and `networkidle` as generic readiness
  signals. This implementation relies on actionability and leaves result
  classification to deterministic Part 15 predicates:
  https://playwright.dev/python/docs/navigations
  https://playwright.dev/python/docs/api/class-page#page-wait-for-timeout
- OWASP transaction-authorization guidance recommends default-deny
  authorization, server-owned sequential state, and a final authorization check
  immediately before execution:
  https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html

## Explicit action purposes

`ops/browser_risk.py` now uses an explicit `ActionPurpose` instead of treating
every state-changing control as equivalent:

- `signup_submit`
- `login_submit`
- `create_workspace`
- `create_developer_app`
- `save_developer_app`
- `generate_credential`
- `reveal_credential`
- `rotate_credential`
- `revoke_credential`
- `delete_resource`
- `accept_legal_terms`
- `submit_payment`

The existing lexical safety rules remain active. Generic words such as
`create`, `generate`, `delete`, `revoke`, and `billing` were not removed from
the global risk policy.

The only narrow lexical exception is a control whose complete risk category is
normal creation and whose server-owned purpose is an already-authorized
`signup_submit`. A label that also indicates credentials, developer resources,
workspaces, legal acceptance, billing, deletion, or privilege changes remains
blocked or human-gated.

## Signup-submit authorization

The normal signup submit purpose is autonomous only when every condition is
true:

1. `AccountPolicy` is `create_if_missing`.
2. The automation contract is active and unexpired.
3. The contract explicitly supports signup.
4. Durable signup state is `signup_submission_ready`.
5. The form inspection and fill result use the same contract version.
6. Every required value is re-resolved and verified against the live DOM.
7. The exact code-generated submit token resolves to one visible, enabled
   control.
8. The current page and native form action remain on contract-authorized signup
   hosts.
9. No CAPTCHA, legal acceptance, billing, phone-verification, ownership, or
   administrator gate is visible.
10. The action is dispatched by deterministic code, never by the model.

A native GET signup form is rejected because it could place signup values in a
URL query. A native form targeting another browsing context is rejected.
JavaScript-only SPA submit buttons require the strongest reviewed-test-ID
identity strategy.

## Gate handling

Immediately before submission, Playwright performs a bounded, value-free scan
of visible controls. The scan reads accessibility and structural metadata but
never reads input values.

These findings require a human:

- active CAPTCHA challenge
- legal or terms acceptance
- billing or payment
- phone verification

Ownership or administrator changes and destructive credential/resource
purposes are blocked.

A control-inspection failure safe-stops. Dropping an unreadable control would
otherwise risk hiding a gate.

## TOCTOU and duplicate-submit protection

Submission uses a crash-safe sequence:

1. Validate the stable run/session/account/contract-version identity.
2. Reserve the external effect.
3. Replay an existing completed receipt without requiring the old form DOM.
4. For a new reservation, run full live authorization and Playwright
   `trial=True` actionability checks twice.
5. Dispatch exactly one real click.

The second live pass closes the normal check-to-use window: if the DOM,
contract, fields, control, page origin, or gates change after the first pass, no
click is sent.

The effect key is stable for the run, exact account binding, and contract version.
Outcomes are:

- completed reservation: validate the exact purpose, contract version, and
  account-binding receipt, then return it without clicking again;
- pending or unknown reservation: return `outcome_unknown` and require
  reconciliation;
- failed preflight before click: mark the reservation failed so a safe retry is
  possible;
- click exception or receipt-persistence failure: mark the outcome unknown and
  never blindly retry.

The result contains only status flags, semantic field names, gate categories,
and stable reason codes. It never contains an email address, password, vault
reference, selector, page text, form action, or full URL.

## Durable state

`AutonomousSignupFoundation.record_submission()` advances
`signup_submission_ready` to `signup_submitted` only for a completed or replayed
effect-ledger dispatch.

Authorization denials, configuration gaps, failures before dispatch, and
ambiguous outcomes do not claim submission. They leave the durable state ready
for Part 15 reconciliation or an explicitly authorized retry.

## Deliberate non-goals

Part 14 does not:

- classify signup success;
- mark an account created;
- fetch Gmail;
- solve CAPTCHA;
- accept legal terms;
- submit billing information;
- perform phone verification;
- rotate or revoke credentials;
- delete resources;
- change ownership or administrator roles.
