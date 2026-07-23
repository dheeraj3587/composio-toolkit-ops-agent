---
name: secure-orchestration
description: Design or implement the canonical run application service, state machine, graph-ledger synchronization, retries, and side-effect idempotency. Use for FastAPI-to-LangGraph integration or runtime refactors.
---

# Secure orchestration workflow

- Establish one canonical run/status model shared by graph, storage, API, and frontend.
- Separate plan-only and explicit execution modes.
- Use one stable run/thread mapping.
- Project graph transitions into the sanitized ledger after every invocation.
- Validate legal predecessor and successor states.
- Reserve external effects before execution.
- Persist non-secret provider identifiers immediately after success.
- Mark ambiguous outcomes reconciliation-required.
- Never retry a side effect blindly after process failure.
- Ensure all public responses are rebuilt from sanitized storage, never raw checkpoint state.

Required tests:
- API-driven fake-provider end-to-end run;
- illegal transition rejection;
- duplicate create/resume/retry request;
- process restart;
- ambiguous external result;
- ledger/graph reconciliation;
- no secret leakage.
