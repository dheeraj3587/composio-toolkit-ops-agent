---
inclusion: always
---
# Security invariants

Raw passwords, API keys, OAuth secrets, access/refresh tokens, auth codes, cookies, OTP/TOTP values, private keys, CDP URLs, and signed live-view URLs must never enter graph state, checkpoints, ledgers, logs, API responses, frontend state, screenshots, fixtures, prompts, or Git.

Public credentials are exact `vault://<app>/<kind>/<id>` references only.

No reveal-secret or export-secret interface. No CAPTCHA, OTP, passkey, device verification, billing, legal, or irreversible-action bypass. Use HITL.

All external URLs require explicit HTTP/HTTPS validation. Official-evidence fetches require official-host allowlisting, public DNS results, redirect revalidation, response-size limits, and content-type limits.

External actions require explicit policy flags, idempotency reservation, bounded retries, and truthful receipts. Ambiguous outcomes require reconciliation, not blind replay.
