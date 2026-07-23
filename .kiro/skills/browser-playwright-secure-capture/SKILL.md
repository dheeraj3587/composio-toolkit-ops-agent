---
name: browser-playwright-secure-capture
description: Reconcile Browser Use SDK contracts and implement safe domain-restricted navigation, HITL, deterministic Playwright CDP actions, and immediate vault capture. Use for developer portal onboarding or credential pages.
---

# Browser and Playwright secure capture

1. Inspect the installed Browser Use SDK signature and current official docs.
2. Permit agent navigation only when mandatory `allowed_domains` is supported and tested.
3. Never pass raw provider credentials to the browser agent.
4. Use Playwright or HITL for authentication and secret-sensitive steps.
5. Store browser/profile/session IDs and expiry metadata only; never persist CDP or signed live URLs.
6. Disable recording for credential workflows.
7. Validate the current HTTPS host immediately before every deterministic action.
8. Use app-owned immutable selectors for credential fields.
9. Require exactly one matching locator.
10. Store each raw value immediately with `SecretStore.put()`, delete local references, and return vault refs only.
11. Roll back partial vault writes on failure.
12. Stop remote sessions and close clients in `finally`.

Test domain attacks, private IPs, unsafe wildcards, expired sessions, HITL resume, selector ambiguity, partial capture cleanup, plaintext absence, and cleanup failures.
