# AGENTS.md

Read `PLAN.md` and `.kiro/steering/` before editing.

Use existing domain and security abstractions. Do not create parallel routers, run services, status enums, vaults, redactors, or provider clients without proving the current abstraction cannot be extended.

Never expose raw credentials, tokens, cookies, OTP/TOTP values, private keys, CDP URLs, or signed live links. Public credential material is exact `vault://...` references only.

Normal tests are offline-safe. Live provider actions require explicit user authorization, `RUN_LIVE_TESTS=1`, and provider-specific safety flags.

A feature is complete only when it is integrated through the public API, covered by tests, and truthfully represented in the frontend. File presence is not proof of working behavior.
