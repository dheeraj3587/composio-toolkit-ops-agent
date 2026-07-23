---
name: repo-state-audit
description: Audit the Composio Toolkit Ops repository before planning or release. Use when reviewing current completion, recent commits, stale tests, architecture duplication, CI status, or implementation claims.
---

# Repository state audit

1. Record current branch, HEAD SHA, recent commits, and clean/dirty status.
2. Read PLAN.md, README.md, DECISIONS.md, dependency files, CI, Docker, API routes, graph, services, provider adapters, frontend pages, and tests.
3. Trace each public capability from UI to API to application service to graph/provider/storage.
4. Classify capability status as:
   - working end-to-end;
   - implemented but not integrated;
   - fixture-tested only;
   - configuration-gated;
   - stubbed;
   - unverified.
5. Search for stale bootstrap assertions and duplicate abstractions.
6. Verify claims using tests or runnable commands, not filenames.
7. Report critical integration gaps, security risks, and the next smallest vertical milestone.
8. Never edit during an audit unless explicitly asked.
