# Bootstrap decisions

These decisions apply to the secure runnable Phase 0/1 foundation created on 2026-07-22.

## Repository location

The approved local repository is
`/Users/dheerajjoshi/Desktop/composio-toolkit-ops-agent`, overriding the original sibling path under
`/Users/dheerajjoshi`. Hard-coded P2 paths in `PLAN.md` use the Desktop location. The P1 source
repository remains `/Users/dheerajjoshi/composio` and is not modified.

## Secure runnable depth

The first deliverable includes the Phase 0/1 security core plus a local dry-run CLI and early
Streamlit shell. This intentionally goes beyond the plan's bootstrap-only first commit and brings a
non-provider UI forward from Phase 7. The shell is an operations ledger, not a simulation of future
provider success: it exposes unavailable phases explicitly and contains no browser, email, model,
or paid API integration.

## P1 snapshot-only boundary

Only `out/results.json` and `out/composio_coverage.json` were copied from P1. Their source commit,
copy time, and SHA-256 digests are recorded in `data/p1/SNAPSHOT.json`. No P1 code, report assets,
hand-check material, transcripts, or meeting documents are included. Phase 0/1 never mutates or
operationally enriches these canonical files.

## Work-email reference correction

`.env.example` uses `COMPANY_WORK_EMAIL_REF` rather than the plan's plaintext
`COMPANY_WORK_EMAIL`. This aligns environment configuration with `CompanyProfile.work_email_ref`
and the non-negotiable rule that company/account credentials cross general application code only as
exact `vault://...` references.

## Provider isolation

Provider-facing modules are typed boundaries or explicit phase-unavailable stubs. They intentionally
do not import or call LangGraph, Browser Use, Playwright, Composio, Gemini, or Perplexity. This keeps
Gate A deterministic and prevents an innocent CLI/UI smoke test from creating network side effects.
Real providers are introduced only at their later phase gates with current SDK contracts and opt-in
live verification.

## Dependencies and deployment

The runtime set retains the versions locked in `PLAN.md` except for Pydantic. The resolver confirmed
that `composio==0.18.0` requires `pydantic>=2.13.4`, which conflicts with the plan's
`pydantic==2.12.5`; `requirements.txt` therefore uses the smallest compatible exact pin,
`pydantic==2.13.4`. Transitive locking is deferred until the first passing integration run, as
directed by the plan. The Dockerfile is included with an unprivileged runtime user, owner-only
`/private` mount, and no local-secret build context; image-build verification is deferred because
Docker is unavailable locally.
