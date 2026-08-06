#!/usr/bin/env bash
#
# Collect everything this deployment knows about one run into a single bundle.
#
# When a run fails there are five places the explanation could be, and until now
# an operator had to know all five and reach each one by hand: the api container's
# stdout, the browser worker's stdout, the run row, the audit trail, and the
# onboarding telemetry tables. This gathers all of them for one run id, in the
# order they happened, and writes one file.
#
# Everything written passes through ops.core.redaction first. The audit payloads
# are already sanitized at write time and the container logs already pass through
# the RedactingFilter, so this is the third pass, not the first -- but a bundle is
# a file that gets copied around and pasted into issues, so it gets its own.
#
# Usage:
#   scripts/collect-run-logs.sh <run-id> [output-directory]
#   scripts/collect-run-logs.sh --last-failed [output-directory]
#
# The bundle is written 600 under backups/run-logs/ and its path is printed.
set -euo pipefail
umask 077

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

COMPOSE_FILE="compose.prod.yaml"
ENV_FILE=".env.production"
PROJECT="composio-ops-prod"
readonly -a SERVICES=(api browser-worker web caddy)
# Enough tail to cover a long browser run without pulling a container's whole
# retained history into memory for the grep.
readonly LOG_TAIL_LINES=20000
# How many bundles to keep. The host this runs on has been near 80% disk; a
# diagnostic tool that fills the disk is a worse outage than the one it explains.
readonly BUNDLE_RETENTION=20

log() { printf '\033[1;34m[run-logs]\033[0m %s\n' "$*" >&2; }
fail() {
	printf '\033[1;31m[run-logs] ERROR:\033[0m %s\n' "$*" >&2
	exit 1
}

compose() {
	docker compose -p "$PROJECT" -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"
}

[ -f "$COMPOSE_FILE" ] || fail "$COMPOSE_FILE is unavailable; run this from the deployment checkout."
[ -f "$ENV_FILE" ] || fail "$ENV_FILE is unavailable; compose cannot resolve its required variables without it."
command -v docker >/dev/null 2>&1 || fail "docker is unavailable."

# ---------------------------------------------------------------------------
# The database reader.
#
# Runs inside the api container, which already has the volume mounted and the
# interpreter installed, and opens the database read-only and immutable so a
# diagnostic read can never block or corrupt a live run's writes.
# ---------------------------------------------------------------------------
read_database() {
	local requested_run="$1"
	compose exec -T api python3 - "$requested_run" <<-'PYTHON'
		import json
		import sqlite3
		import sys

		run_id = sys.argv[1]
		connection = sqlite3.connect("file:/data/ops.db?mode=ro", uri=True)
		connection.row_factory = sqlite3.Row


		def table_exists(name: str) -> bool:
		    row = connection.execute(
		        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
		    ).fetchone()
		    return row is not None


		def dump(title: str, sql: str, parameters: tuple[object, ...]) -> None:
		    print(f"\n===== {title} =====")
		    try:
		        rows = connection.execute(sql, parameters).fetchall()
		    except sqlite3.Error as error:
		        print(f"(unreadable: {type(error).__name__})")
		        return
		    if not rows:
		        print("(no rows)")
		        return
		    for row in rows:
		        print(json.dumps({key: row[key] for key in row.keys()}, default=str, sort_keys=True))


		if run_id == "--last-failed":
		    row = connection.execute(
		        "SELECT run_id FROM runs WHERE status IN ('failed','blocked') "
		        "ORDER BY id DESC LIMIT 1"
		    ).fetchone()
		    if row is None:
		        print("RESOLVED_RUN_ID=")
		        sys.exit(0)
		    run_id = str(row["run_id"])

		print(f"RESOLVED_RUN_ID={run_id}")

		dump("run", "SELECT * FROM runs WHERE run_id = ?", (run_id,))
		dump(
		    "audit trail (oldest first)",
		    "SELECT id, created_at, event_type, sanitized_payload_json FROM audit_events "
		    "WHERE run_id = ? ORDER BY id ASC",
		    (run_id,),
		)
		# These three are the onboarding loop's own telemetry. They were empty on
		# every production run at the time this script was written, which is itself
		# a finding worth seeing in the bundle rather than discovering by hand.
		for table, order in (
		    ("onboarding_progress_events", "id ASC"),
		    ("onboarding_decision_attempts", "id ASC"),
		    ("onboarding_step_decisions", "id ASC"),
		    ("onboarding_phase_history", "id ASC"),
		):
		    if table_exists(table):
		        dump(table, f"SELECT * FROM {table} WHERE run_id = ? ORDER BY {order}", (run_id,))
		    else:
		        print(f"\n===== {table} =====\n(table absent from this schema)")
	PYTHON
}

# ---------------------------------------------------------------------------
# Argument handling. --last-failed is resolved by the database reader above, so
# an operator who just saw a run fail does not have to go find its id first.
# ---------------------------------------------------------------------------
[ "$#" -ge 1 ] || fail "usage: scripts/collect-run-logs.sh <run-id|--last-failed> [output-directory]"
REQUESTED_RUN="$1"
OUTPUT_DIR="${2:-$REPO_ROOT/backups/run-logs}"

# A run id reaches a SQL parameter and a grep pattern, so it is constrained to a
# bounded identifier here rather than trusted at either of those two places.
if [ "$REQUESTED_RUN" != "--last-failed" ]; then
	case "$REQUESTED_RUN" in
		*[!A-Za-z0-9._-]* | "")
			fail "a run id must be a bounded identifier: letters, digits, dot, underscore, dash."
			;;
	esac
fi

log "reading the database"
DATABASE_DUMP="$(read_database "$REQUESTED_RUN")" || fail "the database read failed; is the api container running?"

RUN_ID="$(printf '%s\n' "$DATABASE_DUMP" | sed -n 's/^RESOLVED_RUN_ID=//p' | head -n 1)"
[ -n "$RUN_ID" ] || fail "no run matched ${REQUESTED_RUN}."
log "run ${RUN_ID}"

mkdir -p "$OUTPUT_DIR"
chmod 700 "$OUTPUT_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BUNDLE="$OUTPUT_DIR/${RUN_ID}-${STAMP}.log"
RAW="$(mktemp)"
trap 'rm -f "$RAW"' EXIT

{
	printf '# run diagnostic bundle\n'
	printf 'run_id: %s\n' "$RUN_ID"
	printf 'collected_at: %s\n' "$STAMP"
	printf 'revision: %s\n' "$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"

	printf '\n\n##### container state #####\n'
	compose ps --format 'table {{.Service}}\t{{.Status}}\t{{.Image}}' 2>&1 || true

	printf '\n\n##### database #####\n'
	printf '%s\n' "$DATABASE_DUMP"

	# Container logs are split two ways per service on purpose. The run-scoped
	# grep is what an operator reads first; the unfiltered tail is what explains a
	# failure that happened before the run id was ever bound -- a crash at
	# startup, an OOM kill, a provider that refused every request.
	for service in "${SERVICES[@]}"; do
		printf '\n\n##### %s: lines carrying this run #####\n' "$service"
		compose logs --no-color --tail "$LOG_TAIL_LINES" "$service" 2>&1 |
			grep -F "$RUN_ID" || printf '(no lines mention this run)\n'

		printf '\n##### %s: last 200 lines, unfiltered #####\n' "$service"
		compose logs --no-color --timestamps --tail 200 "$service" 2>&1 || true
	done
} >"$RAW" 2>&1

# The redaction pass. Reused from the application rather than reimplemented in
# awk, so the bundle and the log stream can never disagree about what a secret
# looks like.
log "redacting"
if ! compose exec -T api python3 -c '
import sys
from ops.core.redaction import redact_text
sys.stdout.write(redact_text(sys.stdin.read()))
' <"$RAW" >"$BUNDLE"; then
	rm -f "$BUNDLE"
	fail "the redaction pass failed; refusing to write an unredacted bundle."
fi
chmod 600 "$BUNDLE"

# Prune oldest-first, by name: the timestamp is fixed-width and sorts
# lexicographically, so this needs no stat and behaves the same on BSD and GNU.
EXISTING=()
while IFS= read -r bundle_path; do
	EXISTING+=("$bundle_path")
done < <(find "$OUTPUT_DIR" -maxdepth 1 -type f -name '*.log' | sort)
if [ "${#EXISTING[@]}" -gt "$BUNDLE_RETENTION" ]; then
	remove_count=$((${#EXISTING[@]} - BUNDLE_RETENTION))
	for ((index = 0; index < remove_count; index++)); do
		rm -f "${EXISTING[index]}"
	done
	log "pruned ${remove_count} old bundle(s)"
fi

log "wrote $(wc -l <"$BUNDLE" | tr -d ' ') lines"
printf '%s\n' "$BUNDLE"
