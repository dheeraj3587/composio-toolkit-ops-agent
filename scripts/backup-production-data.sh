#!/usr/bin/env bash
#
# Create one application-consistent production archive containing:
#   - canonical/legacy SQLite state from the ops_data volume
#   - encrypted credential-vault database and metadata from credential_vault
#   - the deployed Git SHA and its non-secret Compose/Caddy configuration
#
# Both writers (api and browser-worker) are stopped before the read-only volume
# copy and restarted on every exit path. Database contents and environment
# values are never printed.
#
# Usage:
#   ./scripts/backup-production-data.sh [--quiesce] [output-directory]
#
# --quiesce is retained for compatibility; safe quiescing is always enabled.
set -euo pipefail
umask 077

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

COMPOSE_FILE="compose.prod.yaml"
ENV_FILE=".env.production"
PROJECT="composio-ops-prod"
DATA_VOLUME="${PROJECT}_ops_data"
VAULT_VOLUME="${PROJECT}_credential_vault"
OUT_DIR="$REPO_ROOT/backups"
OUTPUT_SEEN=0

log() { printf '\033[1;34m[backup]\033[0m %s\n' "$*"; }
fail() {
	printf '\033[1;31m[backup] ERROR:\033[0m %s\n' "$*" >&2
	exit 1
}

for arg in "$@"; do
	case "$arg" in
		--quiesce)
			# Compatibility flag. Quiescing cannot be disabled.
			;;
		--help|-h)
			printf 'Usage: %s [--quiesce] [output-directory]\n' "$0"
			exit 0
			;;
		-*)
			fail "Unknown option: $arg"
			;;
		*)
			[ "$OUTPUT_SEEN" -eq 0 ] || fail "Only one output directory may be supplied."
			OUT_DIR="$arg"
			OUTPUT_SEEN=1
			;;
	esac
done

command -v docker >/dev/null 2>&1 || fail "Docker is not installed or not on PATH."
command -v git >/dev/null 2>&1 || fail "Git is not installed or not on PATH."
docker compose version >/dev/null 2>&1 || fail "The Docker Compose plugin is unavailable."
docker info >/dev/null 2>&1 || fail "Cannot communicate with the Docker daemon."
[ -f "$COMPOSE_FILE" ] || fail "$COMPOSE_FILE is unavailable."
[ -f "$ENV_FILE" ] || fail "$ENV_FILE is unavailable."

for volume in "$DATA_VOLUME" "$VAULT_VOLUME"; do
	docker volume inspect "$volume" >/dev/null 2>&1 \
		|| fail "Required volume '$volume' does not exist."
done

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd -P)"
case "$OUT_DIR" in
	*:*|*$'\n'*) fail "Output directory contains unsupported characters." ;;
esac
chmod 0700 "$OUT_DIR"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARCHIVE="production-state-${STAMP}.tar.gz"
CHECKSUM="${ARCHIVE}.sha256"
BACKUP_TMP="$OUT_DIR/.${ARCHIVE}.tmp"
CONFIG_TMP=""

compose() {
	docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"
}

DEPLOYED_REVISION=""
for service in api browser-worker web; do
	cid="$(compose ps --all --quiet "$service" 2>/dev/null || true)"
	[ -n "$cid" ] || fail "Cannot identify the deployed $service container."
	service_revision="$(docker inspect --format \
		'{{index .Config.Labels "org.opencontainers.image.revision"}}' "$cid")"
	[ -n "$service_revision" ] || fail "$service container has no deployed revision label."
	if [ -z "$DEPLOYED_REVISION" ]; then
		DEPLOYED_REVISION="$service_revision"
	elif [ "$service_revision" != "$DEPLOYED_REVISION" ]; then
		fail "Production services do not share one deployed revision."
	fi
done
git cat-file -e "${DEPLOYED_REVISION}^{commit}" 2>/dev/null \
	|| fail "Deployed revision is not available in the local Git object database."

RUNNING_SERVICES=()
for service in api browser-worker; do
	if [ -n "$(compose ps --status running -q "$service" 2>/dev/null || true)" ]; then
		RUNNING_SERVICES+=("$service")
	fi
done

restore_services() {
	local status=$?
	trap - EXIT INT TERM
	rm -f "$BACKUP_TMP"
	if [ -n "$CONFIG_TMP" ] && [ -d "$CONFIG_TMP" ]; then
		rm -rf "$CONFIG_TMP"
	fi
	if [ "${#RUNNING_SERVICES[@]}" -gt 0 ]; then
		log "Restarting services that were running before the backup..."
		for service in browser-worker api; do
			if [[ " ${RUNNING_SERVICES[*]} " == *" $service "* ]]; then
				if ! compose start "$service" >/dev/null; then
					printf '\033[1;31m[backup] ERROR:\033[0m failed to restart %s\n' \
						"$service" >&2
					status=1
				fi
			fi
		done
	fi
	exit "$status"
}
trap restore_services EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "${#RUNNING_SERVICES[@]}" -gt 0 ]; then
	log "Quiescing SQLite and vault writers..."
	# Stop the API first so it cannot request new browser work while the worker exits.
	for service in api browser-worker; do
		if [[ " ${RUNNING_SERVICES[*]} " == *" $service "* ]]; then
			compose stop "$service" >/dev/null
		fi
	done
else
	log "Writers are already stopped; creating a consistent archive."
fi

CONFIG_TMP="$(mktemp -d "$OUT_DIR/.production-config-${STAMP}.XXXXXX")"
mkdir -p "$CONFIG_TMP/deploy"
printf '%s\n' "$DEPLOYED_REVISION" > "$CONFIG_TMP/deployed-sha.txt"
git show "${DEPLOYED_REVISION}:compose.prod.yaml" > "$CONFIG_TMP/compose.prod.yaml" \
	|| fail "Deployed Compose configuration is unavailable at $DEPLOYED_REVISION."
git show "${DEPLOYED_REVISION}:deploy/Caddyfile" > "$CONFIG_TMP/deploy/Caddyfile" \
	|| fail "Deployed Caddy configuration is unavailable at $DEPLOYED_REVISION."
chmod -R go-rwx "$CONFIG_TMP"

log "Archiving production state, vault metadata, deployed SHA, and safe configuration..."
docker run --rm \
	-e "ARCHIVE=$ARCHIVE" \
	-v "${DATA_VOLUME}:/source/ops_data:ro" \
	-v "${VAULT_VOLUME}:/source/credential_vault:ro" \
	-v "${CONFIG_TMP}:/source/runtime_config:ro" \
	-v "${OUT_DIR}:/backup" \
	busybox sh -eu -c '
		umask 077
		test -f /source/ops_data/ops.db
		test -f /source/credential_vault/credentials.db
		tmp="/backup/.${ARCHIVE}.tmp"
		rm -f "$tmp"
		tar czf "$tmp" -C /source ops_data credential_vault runtime_config
		tar tzf "$tmp" | grep -q "^ops_data/ops.db$"
		tar tzf "$tmp" | grep -q "^credential_vault/credentials.db$"
		tar tzf "$tmp" | grep -q "^runtime_config/deployed-sha.txt$"
		tar tzf "$tmp" | grep -q "^runtime_config/compose.prod.yaml$"
		tar tzf "$tmp" | grep -q "^runtime_config/deploy/Caddyfile$"
		mv "$tmp" "/backup/$ARCHIVE"
		chmod 0600 "/backup/$ARCHIVE"
		cd /backup
		sha256sum "$ARCHIVE" > "$ARCHIVE.sha256"
		chmod 0600 "$ARCHIVE.sha256"
	'

[ -s "$OUT_DIR/$ARCHIVE" ] || fail "Backup archive is empty."
[ -s "$OUT_DIR/$CHECKSUM" ] || fail "Backup checksum is empty."

log "Backup complete: $OUT_DIR/$ARCHIVE"
log "Checksum: $OUT_DIR/$CHECKSUM"
log "Encryption keys are intentionally excluded; retain them in the production secret manager."
