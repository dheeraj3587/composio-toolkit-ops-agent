---
inclusion: fileMatch
fileMatchPattern: "{ops,api,tests,web}/**/*"
---
# Testing standards

Add tests for behavior, failure, leakage, retries, and state transitions. Normal tests must be offline-safe and must not call paid or live providers.

Use injected fakes for provider behavior and sanitized fixtures for provider payloads. Label live tests and require `RUN_LIVE_TESTS=1` plus provider-specific safety flags.

A task is incomplete until focused tests and the affected full quality gate pass. Never suppress an audit or test failure merely to produce a green result.

Security boundaries require regression tests proving raw values are absent from database bytes, checkpoint bytes, logs, API payloads, frontend-rendered output, and snapshots.
