#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "${repo_root}"

if [[ -d "${repo_root}/.venv/bin" ]]; then
  export PATH="${repo_root}/.venv/bin:${PATH}"
fi

gate_scope="${1:-all}"
case "${gate_scope}" in
  all | backend | frontend) ;;
  *)
    echo "usage: $0 [all|backend|frontend]" >&2
    exit 64
    ;;
esac

required_commands=(git)
if [[ "${gate_scope}" == "all" || "${gate_scope}" == "backend" ]]; then
  required_commands+=(detect-secrets detect-secrets-hook ruff pytest mypy pip-audit python)
fi
if [[ "${gate_scope}" == "all" || "${gate_scope}" == "frontend" ]]; then
  required_commands+=(npm)
fi
for command_name in "${required_commands[@]}"; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "security gate: missing command ${command_name}" >&2
    exit 127
  fi
done

if [[ "${gate_scope}" == "all" || "${gate_scope}" == "backend" ]]; then
  grep_output="$(mktemp "${TMPDIR:-/tmp}/composio-ops-secret-grep.XXXXXX")"
  scan_output="$(mktemp "${TMPDIR:-/tmp}/composio-ops-detect-secrets.XXXXXX")"
  baseline_copy="$(mktemp "${TMPDIR:-/tmp}/composio-ops-secrets-baseline.XXXXXX")"
  audit_cache="${TMPDIR:-/tmp}/composio-ops-pip-audit-cache"
  mkdir -p "${audit_cache}"
  trap 'rm -f "${grep_output}" "${scan_output}" "${baseline_copy}"' EXIT

  if [[ ! -f .secrets.baseline ]]; then
    echo "security gate: .secrets.baseline is required" >&2
    echo "generate and audit it with detect-secrets before running this gate" >&2
    exit 1
  fi
  # detect-secrets refreshes line metadata while scanning and refuses a dirty
  # tracked baseline. Scan against an exact temporary copy so this gate is
  # read-only and works before the operator stages their reviewed changes.
  cp .secrets.baseline "${baseline_copy}"

  secret_scan_files=()
  while IFS= read -r -d '' candidate; do
    case "${candidate}" in
      .secrets.baseline | PLAN.md | data/p1/SNAPSHOT.json) continue ;;
    esac
    if [[ -f "${candidate}" ]]; then
      secret_scan_files+=("${candidate}")
    fi
  done < <(git ls-files -z --cached --others --exclude-standard)

  if (( ${#secret_scan_files[@]} > 0 )); then
    # The hook refreshes line metadata in the disposable baseline and returns 3
    # even when it found no new secret. That is safe here because the real
    # audited baseline remains read-only; exit 1 still means a new finding and
    # must fail the gate.
    set +e
    detect-secrets-hook --baseline "${baseline_copy}" "${secret_scan_files[@]}"
    hook_status=$?
    set -e
    case "${hook_status}" in
      0 | 3) ;;
      *) exit "${hook_status}" ;;
    esac
  fi
  # Run the required recursive scanner without printing candidate material. The audited
  # baseline hook above is the enforcing comparison for source-controlled files.
  detect-secrets scan --all-files \
    --exclude-files '(?:^|/)(?:\.git|\.venv|web/node_modules|web/\.next|private)(?:/|$)' \
    >"${scan_output}"

  ruff check .
  ruff format --check .
  for shell_script in scripts/*.sh docker/*.sh; do
    bash -n "${shell_script}"
  done
  # Provider/live and real-Chromium suites are explicit acceptance jobs. Keep
  # this repository gate deterministic and offline while still running the full
  # contract/state/security suite. Explicitly shadow every provider credential
  # and account binding with an empty process value: python-dotenv does not
  # override an existing variable, so an ignored developer .env cannot
  # accidentally turn a regression in a feature flag into a real provider call.
  ALLOW_LIVE_BROWSER=false \
    ALLOW_LIVE_VENDOR_EMAIL=false \
    ALLOW_LOCAL_CREDENTIAL_SUBMISSION=false \
    BROWSER_SERVICE_TOKEN= \
    BROWSER_SESSION_CAPABILITY_KEY= \
    BROWSER_SECRET_BROKER_TOKEN= \
    BROWSER_STORAGE_STATE_KEY= \
    CEREBRAS_API_KEY= \
    COMPOSIO_API_KEY= \
    COMPOSIO_GMAIL_API_KEY= \
    COMPOSIO_GMAIL_CONNECTED_ACCOUNT_ID= \
    COMPOSIO_GMAIL_SIGNUP_CONNECTED_ACCOUNT_ID= \
    COMPOSIO_GMAIL_USER_ID= \
    COMPOSIO_USER_ID= \
    GOOGLE_GENAI_API_KEY= \
    GMAIL_SIGNUP_ADDRESS= \
    GROQ_API_KEY= \
    INCEPTION_API_KEY= \
    MERCURY_API_KEY= \
    LANGGRAPH_AES_KEY= \
    OPENROUTER_API_KEY= \
    OUTREACH_RECIPIENT_OVERRIDE= \
    PERPLEXITY_API_KEY= \
    RUN_LIVE_TESTS=0 \
    SECRET_VAULT_KEY= \
    YDC_API_KEY= \
    YOU_API_KEY= \
    You_API_KEY= \
    YOU_CONTENTS_ENABLED=false \
    YOU_RESEARCH_ENABLED=false \
    YOU_SEARCH_ENABLED=false \
    pytest -q -m "not live and not browser"
  mypy ops api browser_service
  python -m compileall -q ops api browser_service
  # Audit the exact, hash-locked dependency graph installed in both production
  # Python images. Disabling pip prevents the audit from silently resolving a
  # different graph (or upgrading build tooling) before querying advisories.
  pip-audit \
    --cache-dir "${audit_cache}" \
    --progress-spinner off \
    --disable-pip \
    --require-hashes \
    -r requirements-runtime.lock

  git grep --untracked -nEI \
    '(client_secret|access_token|refresh_token|api[_-]?key|password|private[_-]?key|PRIVATE KEY|sk-|sk_live_|rk_live_|gh[pousr]_|github_pat_|AIza|xox[baprs]-|AKIA|ASIA|pplx-|gsk_|sk-or-v1-|ydc-sk-|bu_|ak_|csk-|SG\.)' \
    -- ':!PLAN.md' ':!.secrets.baseline' >"${grep_output}" || true

  python - "${grep_output}" <<'PY'
import re
import sys

quoted_assignment = re.compile(
    r"(?i)(?:client_secret|access_token|refresh_token|api[_-]?key|password)"
    r"\s*[:=]\s*['\"]([^'\"]+)['\"]"
)
shell_assignment = re.compile(
    r"(?<![A-Za-z0-9_])(?:export[ \t]+)?"
    r"(?:[A-Z0-9_]*API_KEY|[A-Z0-9_]*CLIENT_SECRET|[A-Z0-9_]*ACCESS_TOKEN|"
    r"[A-Z0-9_]*REFRESH_TOKEN|[A-Z0-9_]*PASSWORD|[A-Z0-9_]*PRIVATE_KEY|"
    r"SECRET_VAULT_KEY|LANGGRAPH_AES_KEY)"
    r"[ \t]*=[ \t]*(?!['\" \t])([^\s#;(){}\[\],]+)(?=[ \t]*(?:#|;|$))"
)
private_key_header = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
)
provider_key = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"sk-(?:live-|test-)?[A-Za-z0-9_-]{12,}|"
    r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{12,}|"
    r"gh[pousr]_[A-Za-z0-9]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"AIza[A-Za-z0-9_-]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"(?:AKIA|ASIA)[0-9A-Z]{16}|"
    r"pplx-[A-Za-z0-9_-]{12,}|"
    r"gsk_[A-Za-z0-9_-]{16,}|"
    r"sk-or-v1-[A-Za-z0-9_-]{16,}|"
    r"ydc-sk-[A-Za-z0-9_-]{16,}|"
    r"bu_[A-Za-z0-9_-]{16,}|"
    r"ak_[A-Za-z0-9_-]{16,}|"
    r"csk-[A-Za-z0-9_-]{16,}|"
    r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"
    r")(?![A-Za-z0-9])"
)
safe_prefixes = ("vault://", "[REDACTED", "${", "{")
suspicious: set[str] = set()

with open(sys.argv[1], encoding="utf-8") as handle:
    for raw_line in handle:
        parts = raw_line.split(":", 2)
        if len(parts) != 3:
            continue
        if "pragma: allowlist secret" in parts[2]:
            continue
        content = parts[2]
        location = f"{parts[0]}:{parts[1]}"
        quoted_match = quoted_assignment.search(content)
        shell_match = shell_assignment.search(content)
        assigned_values = (
            match.group(1) for match in (quoted_match, shell_match) if match is not None
        )
        if any(value and not value.startswith(safe_prefixes) for value in assigned_values):
            suspicious.add(location)
        if private_key_header.search(content) or provider_key.search(content):
            suspicious.add(location)

if suspicious:
    print("security gate: possible credential values at:", file=sys.stderr)
    for location in sorted(suspicious):
        print(f"  {location}", file=sys.stderr)
    raise SystemExit(1)
PY
fi

if [[ "${gate_scope}" == "all" || "${gate_scope}" == "frontend" ]]; then
  if [[ ! -f web/package-lock.json ]]; then
    echo "security gate: web/package-lock.json is required" >&2
    exit 1
  fi
  if [[ ! -d web/node_modules ]]; then
    echo "security gate: web dependencies are missing; run npm ci in web/" >&2
    exit 1
  fi

  (
    cd web
    # Runtime/production dependencies are the deployable attack surface. The
    # current ESLint 9 toolchain carries a dev-only brace-expansion advisory;
    # forcing ESLint 10 breaks eslint-config-next, so do not trade a functioning
    # quality gate for a non-runtime transitive package.
    npm audit --omit=dev --audit-level=high
    # Still fail on any critical advisory anywhere in the build toolchain.
    npm audit --audit-level=critical
    npm run lint
    npm run typecheck
    npm run test
    npm run build
  )
fi

echo "security gate (${gate_scope}): passed"
