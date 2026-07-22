#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "${repo_root}"

if [[ -d "${repo_root}/.venv/bin" ]]; then
  export PATH="${repo_root}/.venv/bin:${PATH}"
fi

required_commands=(detect-secrets detect-secrets-hook ruff pytest mypy pip-audit git python npm)
for command_name in "${required_commands[@]}"; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "security gate: missing command ${command_name}" >&2
    exit 127
  fi
done

grep_output="$(mktemp "${TMPDIR:-/tmp}/composio-ops-secret-grep.XXXXXX")"
trap 'rm -f "${grep_output}"' EXIT

if [[ ! -f .secrets.baseline ]]; then
  echo "security gate: .secrets.baseline is required" >&2
  echo "generate and audit it with detect-secrets before running this gate" >&2
  exit 1
fi

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
  detect-secrets-hook --baseline .secrets.baseline "${secret_scan_files[@]}"
fi

ruff check .
ruff format --check .
pytest -q
mypy api ops streamlit_app.py
python -m compileall -q api ops streamlit_app.py
pip-audit -r requirements.txt

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
  npm audit --audit-level=high
  npm run lint
  npm run typecheck
  npm run build
)

git grep --untracked -nEI \
  '(client_secret|access_token|refresh_token|api[_-]?key|password|private[_-]?key|PRIVATE KEY|sk-|sk_live_|rk_live_|gh[pousr]_|github_pat_|AIza|xox[baprs]-|AKIA|ASIA|pplx-|SG\.)' \
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

echo "security gate: passed"
