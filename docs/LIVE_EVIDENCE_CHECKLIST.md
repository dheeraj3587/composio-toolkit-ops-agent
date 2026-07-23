# Live Evidence Checklist

This checklist defines the proof required to claim the end-to-end flow works against
real providers, plus the screenshots to capture and an honest completion table.

Rules for evidence:

- Nothing here is marked verified until the exact action produced sanitized evidence. A
  configured key is not proof.
- Never capture or paste raw keys, tokens, cookies, OTP/TOTP values, private keys, CDP
  URLs, or signed live-view URLs. Public credential material appears only as
  `vault://<app>/<kind>/<id>` references.
- Placeholders (`<...>`) are to be filled by the backend agent that actually runs the
  live demo. Do not fabricate values.
- Redact freely. If a field cannot be shown safely, record its shape (for example,
  "returned N URLs") instead of the value.

Proof app for the reference run: **HubSpot**.

---

## 1. Required live proof

### 1.1 Real Perplexity response
- [ ] Command run: `PYTHONPATH=. .venv/bin/python scripts/live_smoke.py perplexity`
- [ ] Output line `perplexity: external_action=True sanitized_result_count=<n>`
- [ ] Discovered official-document URLs (HTTPS, official-host):
  - `<url_1>`
  - `<url_2>`
- [ ] Confirmed no secret or key was printed.

### 1.2 Real Gemini structured JSON
- [ ] Command run: `PYTHONPATH=. .venv/bin/python scripts/live_smoke.py gemini`
- [ ] Model id used: `<gemini_model>`
- [ ] `capability=<status> reason=<reason_code> documents=<n>`
- [ ] Sanitized structured fields present: `auth_methods=<...>`, `token_url=<...>`,
      `scopes=<...>`
- [ ] Confirmed extraction ran only over fetched official evidence.

### 1.3 Real Composio toolkit/account result
- [ ] Command run: `PYTHONPATH=. .venv/bin/python scripts/live_smoke.py composio`
- [ ] `toolkit_slug=<slug> toolkit_available=<bool>`
- [ ] `active_account=<bool> state=<capability_state> reason=<reason_code>`
- [ ] `external_action=False` (read-only preflight; no Gmail sent)

### 1.4 Browser Use session_id and live URL
- [ ] Preconditions: `BROWSER_USE_API_KEY` set and `ALLOW_LIVE_BROWSER=true`
- [ ] Command run: `PYTHONPATH=. .venv/bin/python scripts/live_smoke.py browser`
- [ ] `session_id=<session_id>`
- [ ] `live_view_available=<bool>` (signed live URL kept ephemeral; never printed,
      persisted, or screenshotted)
- [ ] Session explicitly stopped after the demo (paid resource).

### 1.5 vault:// references only
- [ ] Run request used `work_email_ref: vault://<app>/work_email/<id>` (no plaintext)
- [ ] IntegratorBundle `credential_refs` are all `vault://<app>/<kind>/<id>`
- [ ] No raw credential appears in any API response, log, timeline, or screenshot.

### 1.6 Real read-only validation
- [ ] Precondition: `SECRET_VAULT_KEY` set
- [ ] Validation reached a terminal state via the run (timeline event
      `credentials_validated` / `credential_validated`)
- [ ] Validation was read-only; no destructive or irreversible provider action.
- [ ] Result recorded: `<validation_outcome>`

### 1.7 IntegratorBundle from the API
- [ ] Command run: `curl -s "$API/api/runs/<RUN_ID>/output" | jq '.integrator_bundle'`
- [ ] `readiness=<credentials_ready|awaiting_provider|human_action_required|configuration_required|blocked|failed>`
- [ ] `access_route=<route>`, `auth_scheme=<scheme>`, `scopes=<...>`
- [ ] `credential_refs` are vault references only
- [ ] `evidence_urls=<...>` present and official-host

---

## 2. Screenshot checklist

Capture each screenshot with secrets redacted. Store under a private location; never
commit screenshots to Git.

- [ ] **Startup wiring audit** — output of `scripts/wiring_audit_demo.py` showing the
      `dependency | class | configured | runtime_wired` table (placeholder keys, no
      network calls).
- [ ] **Composio result** — sanitized `composio` smoke output (toolkit slug, toolkit
      availability, account state, reason code, `external_action=False`).
- [ ] **Gemini result** — sanitized `gemini` smoke output (model id, capability/reason,
      documents fetched, structured auth/scope fields).
- [ ] **Browser live session** — Browser Use dashboard or smoke output showing
      `session_id` and `live_view_available` (do NOT capture the signed live URL).
- [ ] **HITL screen** — the operator UI HITL/resume prompt for the run
      (`/runs/<RUN_ID>`), showing the human action request and resumable state.
- [ ] **Validation result** — run detail or timeline showing the read-only credential
      validation terminal state.
- [ ] **Final bundle** — `/api/runs/<RUN_ID>/output` (or UI output view) showing
      readiness and `vault://` credential references only.
- [ ] **Frontend run timeline** — `http://127.0.0.1:3000/runs/<RUN_ID>` showing phases,
      provider states, and the event timeline.

---

## 3. Honest completion table

Fill each row with the true state after the demo. Use exactly one status per capability
and cite the evidence (command output line, screenshot name, or timeline event). Do not
upgrade a row without evidence from that exact action.

Status legend:
- **live-verified** — a real provider action produced sanitized evidence this session.
- **runtime-wired-not-verified** — code path is integrated and reachable (e.g., wiring
  audit / configured key), but no live provider success was proven.
- **offline-tested** — covered by offline-safe tests / fixtures only.
- **blocked/missing** — cannot run: missing key, disabled policy flag, or unavailable
  provider.

| Capability | Status | Evidence / placeholder |
|---|---|---|
| Startup wiring audit | runtime-wired-not-verified | `wiring_audit_demo.py` table; no network calls by design |
| P1 snapshot lookup + research | offline-tested | `/api/apps/hubspot/research`; provenance verified |
| Deterministic access routing | offline-tested | run `route_decision` in `/api/runs/<RUN_ID>` |
| Perplexity discovery | `<live-verified | blocked/missing>` | `<smoke output / SKIPPED reason>` |
| Gemini structured extraction | `<live-verified | blocked/missing>` | `<smoke output / SKIPPED reason>` |
| Composio toolkit/account preflight | `<live-verified | blocked/missing>` | `<smoke output / SKIPPED reason>` |
| Browser Use live session + HITL | `<live-verified | blocked/missing>` | `<session_id / SKIPPED reason>` |
| Encrypted checkpoints + HITL resume | `<runtime-wired-not-verified | blocked/missing>` | `<LANGGRAPH_AES_KEY present? resume receipt>` |
| Live Gmail send | blocked/missing | Intentionally out of scope; `ALLOW_LIVE_VENDOR_EMAIL=false` |
| Email poll (read-only) | `<runtime-wired-not-verified | blocked/missing>` | `<poll-email receipt>` |
| Vault + read-only credential validation | `<live-verified | runtime-wired-not-verified | blocked/missing>` | `<timeline event / receipt>` |
| IntegratorBundle from API | `<live-verified | runtime-wired-not-verified>` | `<readiness value / phase_unavailable>` |
| FastAPI control plane | runtime-wired-not-verified | `/api/system/health` = `<healthy|degraded>` |
| Next.js operator UI | runtime-wired-not-verified | `/runs/<RUN_ID>` screenshot |
| Secret redaction / no raw secrets exposed | offline-tested | `security.raw_secrets_exposed=false`; boundary tests |

---

## 4. Sign-off

- [ ] Every claimed row cites real evidence; no fabricated results.
- [ ] No secrets, tokens, or signed live URLs appear in any artifact.
- [ ] Any paid Browser Use session was stopped.
- [ ] Local-only: no push, no deploy, no Gmail sent.

Runner: `<name>`  Date: `<YYYY-MM-DD>`  Commit: `<short_sha>`
