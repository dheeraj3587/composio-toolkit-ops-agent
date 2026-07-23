---
inclusion: always
---
# Project structure

- `ops/` is domain, workflow, storage, security, and provider-boundary code.
- `api/` is a sanitized FastAPI transport only.
- `web/` is the Next.js operator UI and server-only API client.
- `data/p1/` is immutable copied evidence.
- `tests/` contains offline-safe unit, integration, API, and boundary tests.
- `private/` contains local runtime state and is never committed.
- `.kiro/steering/` holds persistent project guidance.
- `.kiro/skills/` holds on-demand workflows.

Prefer one canonical application service. Do not create a second run service, router, redactor, vault, provider client, or status enum when one already exists. Keep provider SDK imports lazy and inside provider boundaries.
