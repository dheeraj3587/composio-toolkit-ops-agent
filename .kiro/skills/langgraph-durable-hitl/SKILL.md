---
name: langgraph-durable-hitl
description: Implement and verify encrypted LangGraph persistence, interrupts, same-thread resume, process-restart recovery, and idempotent side effects. Use for graph nodes or human intervention flows.
---

# LangGraph durable HITL

Follow official LangGraph persistence and interrupt rules.

- Compile with a durable checkpointer and encrypted serializer.
- Require a stable `thread_id`.
- Interrupt payloads must be small JSON-safe sanitized contracts.
- Resume only with `Command(resume=...)` and the same thread ID.
- The interrupted node restarts from its beginning. Any work before `interrupt()` must be idempotent or side-effect free.
- Never wrap `interrupt()` in a broad try/except.
- Do not reorder or conditionally skip interrupt calls inside one node.
- Separate provider side effects into nodes before or after the interrupt.
- Persist provider IDs and effect receipts immediately.
- Enforce HITL count and session-expiry limits.

Proof test:
1. start run;
2. hit interrupt;
3. close graph and DB connection;
4. construct a new runtime;
5. resume same thread;
6. finish;
7. assert side-effect count is exactly one.
