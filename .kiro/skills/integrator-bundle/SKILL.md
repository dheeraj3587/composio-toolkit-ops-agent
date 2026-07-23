---
name: integrator-bundle
description: Build and validate the final reference-only IntegratorBundle and readiness state from research, provider evidence, credential references, and read-only validation results.
---

# IntegratorBundle

- Accept only strict OperationalResearch, CompanyProfile, vault references, sanitized provider IDs, and CredentialValidationResult.
- Never infer credentials-ready from the presence of a developer app or provider account.
- `credentials_ready` requires at least one vault ref and validation status `valid`.
- Preserve waiting, human-action, configuration-required, blocked, and failed states.
- Include only verified URLs, scopes, callback URLs, evidence, non-secret IDs, validation summary, and operational notes.
- Validate the final model before persistence and before API return.
- Frontend may show reference count and readiness, never values.

Test every readiness branch, invalid reference, unsupported URL, missing validation, invalid credentials, provider unavailable, blocked route, and JSON round trip.
