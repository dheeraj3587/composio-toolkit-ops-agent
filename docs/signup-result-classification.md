# Deterministic signup-result classification: Part 15

## Scope

Part 15 begins only after Part 14 has either dispatched the reviewed signup
submission or recovered a completed dispatch receipt. It classifies the browser
state that follows submission and persists an exact outcome and stable reason
code.

It does not:

- ask an LLM whether signup succeeded;
- fetch Gmail messages;
- enter an OTP;
- open an activation link;
- perform login fallback;
- claim success because the old form disappeared;
- retry an uncertain submission.

Gmail correlation begins in Part 16. Existing-account login fallback begins in
Part 20.

## Research basis

The implementation follows primary browser-platform guidance:

- Playwright locators are strict for single-element operations and its waiting
  model is based on observable actionability and page conditions, not positional
  guesses:
  https://playwright.dev/python/docs/locators
- Playwright documents that modern pages may continue updating after the load
  event. A result should therefore be tied to an expected URL or DOM condition,
  not merely to `load` or `networkidle`:
  https://playwright.dev/python/docs/navigations
- Playwright's assertions demonstrate the intended retry-until-condition model.
  Runtime code in this repository implements its own bounded equivalent because
  it returns a classification rather than asserting a test expectation:
  https://playwright.dev/python/docs/test-assertions
- HTML constraint-validation APIs expose whether a visible password input is
  natively invalid, but that fact proves only a client-side rejection. It cannot
  prove that an account was created:
  https://developer.mozilla.org/en-US/docs/Web/API/HTMLFormElement/checkValidity
  https://developer.mozilla.org/en-US/docs/Web/API/ValidityState

## Architecture

The implementation is separated into three responsibilities.

### `ops/signup_result.py`

A pure deterministic classifier. It accepts:

- one ephemeral, bounded `SignupResultObservation`;
- the same active `BrowserAutomationContract` used for submission;
- the value-free gate inspection.

It returns only `SignupResultClassification`, which contains:

- status;
- exact outcome;
- stable reason code;
- contract version;
- durable signup state;
- next workflow phase;
- HITL and retry facts;
- the contract group that supplied the proof.

The result never contains page text, URLs, selectors, input values, email
addresses, passwords, or vault references.

### `ops/playwright_signup_result.py`

A Playwright adapter that captures one atomic DOM observation using
`page.evaluate`. It reads:

- current URL for in-process origin and path validation;
- document title;
- bounded visible text;
- bounded alert/status/dialog and heading text;
- bounded accessible-facing names;
- a boolean indicating native password invalidity.

It never reads an input's `.value`.

Positive results require two equal observations by default. A transient redirect,
loading message, or temporary DOM failure therefore cannot immediately become
durable workflow truth. The observer does not wait for `networkidle`.

### `ops/signup_state_machine.py`

The existing SQLite state table remains the only source of truth. An additive
migration adds:

- `reason_code`;
- `outcome`.

Existing rows retain their state and revision. Existing same-state transitions
without new metadata remain idempotent no-ops.

## Contract predicate grammar

Part 15 interprets the existing contract predicate strings deterministically.
Supported forms are:

```text
url_path:/welcome
 title:welcome
 text:check your email
 accessible_name:dashboard
 status:account already exists
```

An unprefixed historical predicate is treated as `text:`.

`url_path` predicates must begin with `/` and cannot contain query strings or
fragments. Malformed predicates safe-stop the result classifier; they are not
silently skipped.

## Outcome proofs

### Account created and authenticated

This is the strongest result and requires both:

1. a signup `success_predicate`; and
2. a login `authentication_success_predicate`.

A redirect to a success-looking path without authentication proof remains
`signup_success_without_authentication_proof`.

### Email verification

A signup `verification_predicate` must match first. Only then may bounded
structural text specialize the result into:

- `otp_required`;
- `activation_link_required`;
- generic `email_verification_required`.

If both OTP and activation-link evidence appear, classification safe-stops as
ambiguous.

### Existing account

A matched `existing_account_predicate` produces
`account_already_exists` and routes to login. It never retries account creation.

### Password policy rejection

A rejection is accepted from either:

- a visible password field whose native validity state is invalid; or
- a visible alert/status/dialog containing a bounded password-rejection marker.

Ordinary password instructions in page prose are not enough.

### Human and approval gates

CAPTCHA, phone verification, legal acceptance, and billing route to HITL.
Provider approval requires both the contract's
`production_approval_required=true` fact and visible approval-status evidence.
Ownership or administrator changes safe-stop rather than selecting an automated
route.

### Generic failure

A generic failure requires either a contract authentication-failure predicate or
a visible browser feedback surface with a bounded failure marker.

A generic failure is subordinate to a more precise negative result such as an
existing account or verification requirement. It is never subordinate to a
success result: simultaneous success and failure evidence safe-stops as
ambiguous.

## Origin and ambiguity boundaries

Classification is allowed only on HTTPS hosts from the active contract's:

- vendor hosts;
- authentication hosts;
- email-verification hosts.

Prohibited and unknown hosts safe-stop.

Multiple distinct candidate outcomes safe-stop. The classifier has no priority
list that guesses which contradictory provider message should win.

## Durable routing

| Outcome | Durable state | Next phase |
| --- | --- | --- |
| account created and authenticated | `account_created` | authenticated |
| email verification / OTP / link | `email_verification_required` | Gmail coordinator |
| account already exists | `account_exists_detected` | login |
| password policy rejected | `signup_failed` | retry signup |
| CAPTCHA / phone / billing / legal | `signup_hitl_required` | HITL |
| provider approval | `provider_approval_required` | provider approval |
| generic failure | `signup_failed` | failed |
| unknown / ambiguous | `signup_submitted` | reconcile |

Unknown results stay at `signup_submitted`. That preserves the effect-ledger
boundary: the system may inspect again, but it may not blindly submit again.

## Next boundary

Part 16 creates a durable `VerificationExpectation` only after Part 15 proves
that email verification was requested. It will bind the Gmail lookup to the
current run, mailbox fingerprint, recipient, sender domains, request time,
purpose, browser session, and workflow generation.
