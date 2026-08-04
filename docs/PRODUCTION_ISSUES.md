# Production issues log

Known, intentionally-not-yet-fixed issues discovered while working on the
P1 evidence domain guard (`fix(onboarding): drop foreign-host P1 evidence`,
commit 3d30810). Each entry names why it is out of scope for that change and
what a follow-up would need.

## Telegram research still stops at `research_no_evidence`

**Status: OUT OF SCOPE — separate blocker, not a domain-authority issue.**

After the P1 domain guard removed the `github.com/sparfenyuk/mcp-telegram`
MCP link from Telegram's research evidence, a live run with real provider
keys advances past `research_domain_disagreement` but then stops at
`research_no_evidence` with `model_calls: 0`.

Two distinct causes, both outside the domain guard:

1. **Production research composition does not wire an inference backend.**
   `MountedOnboardingRuntime.advance` extracts with
   `_InferenceProfileExtractor(self._ports.inference)`, and
   `build_onboarding_ports` leaves the research inference unwired (the
   `onboarding.autonomy_outcome` for the run reports `model_calls: 0`).
   Without a model, extraction is literal-link-only, which cannot produce
   the corroborated required-field claims a profile needs.

2. **Telegram is a login-only app with no signup URL.** Even with a model,
   the required-field corroboration (`signup_url`, `login_url`, each needing
   two distinct citing documents) may never be satisfiable for an app whose
   entry is a login/owner-submit-only flow. This would need a recipe-model
   decision about what evidence a login-only/entry-only route actually
   requires.

Fix would be: wire research inference in the production composition, and/or
reconsider required-field corroboration for login-only / owner-submit recipes.

## `neo4j` — genuine multi-zone provider (left as-is, flagged)

**Status: NO CODE CHANGE — intentionally preserved and logged.**

`neo4j` is a real multi-zone provider whose reviewed recipe authorizes two
registrable domains (`neo4j.com` and `neo4j.io`). The P1 evidence guard
deliberately does **not** collapse it to a single domain
(`tests/test_p1_evidence_domain_filter.py::test_filter_does_not_over_drop_reviewed_multi_zone_authority`).
If research ever disagrees on `neo4j`, it is a legitimate condition: the
profile resolver emits a `domain_disagreement` fact naming both domains and
the run blocks with `research_domain_disagreement` — a logged, auditable
state, not a silent failure. If it should ever proceed, the recipe needs a
human decision on which zone is the provider's authoritative signup/login
domain (or the resolver needs explicit multi-zone awareness).

## `composio.dev` in managed-auth recipe evidence — no split, and why

**Status: DOCUMENTED DECISION — not actioned.**

Managed-auth recipes carry `https://composio.dev/toolkits/<slug>` (Composio's
own platform documentation) in `evidence_urls` alongside the vendor's docs,
which put `composio.dev` in the derived provider registrable-domain authority.

This was NOT split into a separate "platform documentation" evidence category
because it has no runtime effect: `profile_onboarding` at
`ops/workflow/canonical_runtime.py:791-811` explicitly excludes
`route_kind == "managed_auth"` from the profile-mounting seam, so managed-auth
runs never reach `MountedOnboardingRuntime.advance` and never run the
profile/domain-disagreement research that the guard protects. Splitting it
would be dead special-casing of a single platform domain into core provider-
authority logic.

If managed-auth routes are ever moved onto the profile-mounting research seam,
revisit this: a clean approach would model `composio.dev` as a distinct
"platform documentation" evidence category (allowed in the evidence list, but
never counted toward the provider's registrable-domain authority and never
fetched as provider evidence), rather than an ad-hoc host exclusion.
