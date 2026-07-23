---
name: quality-release-gate
description: Run the final backend, frontend, security, dependency, CI, Docker, evidence, and truthfulness gates before a commit, pull request, demo, or release.
---

# Quality and release gate

1. Confirm branch, HEAD, clean tree, and private repository visibility.
2. Run full Python tests, Ruff, formatting, mypy, compileall, detect-secrets, pip-audit, and targeted leak scan.
3. Run npm clean install, lint, typecheck, tests, accessibility tests, and production build.
4. Review CI results; do not infer green status from workflow file presence.
5. Inspect dependency changes and lockfiles.
6. Build and start Docker Compose on a capable host; verify health, non-root users, read-only roots, private writable volume, and loopback bindings.
7. Inspect the full diff for unrelated edits, secrets, raw provider payloads, signed URLs, screenshots, and databases.
8. Execute local end-to-end fake-provider flow.
9. Execute approved live tests only with explicit flags and controlled accounts.
10. Produce a release report separating offline, fixture, local end-to-end, live controlled, and unverified evidence.
11. Never push if repository visibility is not private or any required gate failed.
