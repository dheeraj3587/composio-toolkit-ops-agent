---
name: fastapi-contracts
description: Build or review strict sanitized FastAPI routes, request/response models, error envelopes, CORS, security headers, and lifecycle integration for the operations control plane.
---

# FastAPI contracts

- Use strict Pydantic request and response models with extras forbidden.
- Keep lifespan-managed services injectable for tests.
- Return sanitized declared models only.
- Never expose environment values, paths, provider payloads, checkpoint state, raw audit payloads, or secrets.
- Validation errors may expose approved field paths only, never rejected values.
- Use typed 404, 409, 422, and 500 envelopes.
- Configure CORS from an explicit exact-origin allowlist with no credentials unless required.
- Apply no-store, nosniff, frame, referrer, permissions, and CSP headers.
- Enable docs only in explicit local development.
- Validate idempotency keys and never echo malformed keys.

API tests must cover every route, lifecycle startup/shutdown, strict unknown fields, invalid paths, conflicts, sanitization, headers, and response schema.
