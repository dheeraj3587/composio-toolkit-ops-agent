#!/usr/bin/env bash
#
# backup-production-data.sh — timestamped archive of the persistent SQLite state.
#
# Archives the contents of the ops_data volume (ops.db, checkpoints.db,
# secret_vault.db, provider_effects.db and their SQLite side files) into a
# gzipped tar under ./backups. It never prints database contents.
#
# CONSISTENCY NOTE:
#   SQLite databases in WAL mode can have in-flight writes. For an
#   application-consistent snapshot, briefly quiesce writers with --quiesce,
#   which stops the api service for the duration of the archive and restarts it
#   afterwards. Without --quiesce the backup is a live file copy that may capture
#   a checkpoint mid-write.
#
# Usage:
#   ./scripts/backup-production-data.sh [--quiesce] [output-dir]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

COMPOSE_FILE="compose.prod.yaml"
ENV_FILE=".env.production"
PROJECT="composio-ops-prod"
VOLUME="${PROJECT}_ops_data"

QUIESCE=0
OUT_DIR="$REPO_ROOT/backups"
for arg in "$@"; do
	case "$arg" in
		--quiesce) QUIESCE=1 ;;
		*)         OUT_DIR="$arg" ;;
	esac
done

log()  { printf '\033[1;34m[backup]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[backup] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "Docker is not installed or not on PATH."

# Fail if the persistent data volume is missing.
docker volume inspect "$VOLUME" >/dev/null 2>&1 || fail "Data volume '$VOLUME' does not exist. Nothing to back up."

mkdir -p "$OUT_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARCHIVE="ops-data-${STAMP}.tar.gz"

compose() { docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"; }

restart_api=0
if [ "$QUIESCE" -eq 1 ]; then
	if [ -f "$ENV_FILE" ] && compose ps -q api >/dev/null 2>&1 && [ -n "$(compose ps -q api 2>/dev/null)" ]; then
		log "Quiescing: stopping 'api' for a consistent snapshot..."
		compose stop api >/dev/null
		restart_api=1
	else
		log "Quiesce requested but 'api' is not running; proceeding with a live copy."
	fi
fi

log "Archiving volume '$VOLUME' -> $OUT_DIR/$ARCHIVE"
# A throwaway root container reads the ops:0700 files and writes only the tar.
if ! docker run --rm \
	-v "${VOLUME}:/data:ro" \
	-v "${OUT_DIR}:/backup" \
	busybox sh -c "tar czf /backup/${ARCHIVE} -C /data . && chmod 0600 /backup/${ARCHIVE}"; then
	[ "$restart_api" -eq 1 ] && { log "Restarting 'api' after failed backup..."; compose start api >/dev/null || true; }
	fail "Backup archive creation failed."
fi

if [ "$restart_api" -eq 1 ]; then
	log "Restarting 'api'..."
	compose start api >/dev/null
fi

log "Backup complete: $OUT_DIR/$ARCHIVE"
log "Restore procedure is documented in DEPLOY_DIGITALOCEAN.md."
