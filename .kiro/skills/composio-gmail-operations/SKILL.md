---
name: composio-gmail-operations
description: Implement or review controlled Composio Gmail send, fetch, sanitize, classify, reply, idempotency, connected-account selection, and live-test safety. Use for gated provider outreach workflows.
---

# Composio Gmail operations

- Inspect the installed Composio SDK and live tool schemas; do not guess signatures.
- Restrict execution to the approved Gmail tool allowlist.
- Pin the intended connected account and toolkit version.
- Validate identity with the profile tool before side effects.
- Track intended and actual recipients.
- Require a controlled override while live vendor email is disabled.
- Reserve each send/reply in the effect ledger.
- Reuse completed receipts; reconcile ambiguous outcomes.
- Preserve the Gmail thread ID and reply in the same thread.
- Fetch raw thread data only inside the Gmail boundary.
- Detect and vault credential-like values before persistence or model classification.
- Pass only `SanitizedGmailThread` to classifiers.
- Bound outreach rounds and unclear retries.
- Label fixture tests as fixture evidence, never live delivery.
