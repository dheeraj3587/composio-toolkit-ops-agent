---
inclusion: always
---
# Technology stack

- Python 3.11
- FastAPI with strict Pydantic v2 contracts
- SQLite for owner-only local run, checkpoint, effect, and vault state
- LangGraph durable workflow with encrypted serializer and stable thread IDs
- Fernet exact-reference secret vault
- Composio Python SDK for controlled Gmail operations
- Perplexity for bounded discovery and Gemini structured output for official-evidence extraction
- Browser Use Cloud and Playwright for browser execution, with deterministic Playwright handling secret-sensitive steps
- Next.js App Router, React, TypeScript strict mode, Tailwind CSS, shadcn/ui, Radix, Zod, React Hook Form, TanStack Query, Vitest
- Ruff, mypy, pytest, detect-secrets, pip-audit, GitHub Actions, Docker Compose

Do not replace stack components unless a documented incompatibility is proven and recorded in DECISIONS.md.
