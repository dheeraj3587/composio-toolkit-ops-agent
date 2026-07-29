#!/usr/bin/env bash
#
# Create one application-consistent production archive containing:
#   - canonical/legacy SQLite state from the ops_data volume
#   - encrypted credential-vault database and metadata from credential_vault
#   - encrypted browser storage-state from browser_profiles
#   - the deployed Git SHA and its non-secret Compose/Caddy configuration
#
# New browser admissions are blocked and active sessions must reach zero before
# both writers (api and browser-worker) are stopped for the read-only volume
# copy. Database contents and environment values are never printed.
#
# Usage:
#   ./scripts/backup-production-data.sh [--quiesce] [--leave-stopped] [output-directory]
#
# --quiesce is retained for compatibility; safe quiescing is always enabled.
# --leave-stopped is for the transactional deploy helper only: on SUCCESS it
# leaves writers stopped so no new work can race candidate activation. Failures
# always restore the services that were originally running.
set -euo pipefail
umask 077

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

COMPOSE_FILE="compose.prod.yaml"
ENV_FILE=".env.production"
PROJECT="composio-ops-prod"
DATA_VOLUME="${PROJECT}_ops_data"
VAULT_VOLUME="${PROJECT}_credential_vault"
BROWSER_VOLUME="${PROJECT}_browser_profiles"
OUT_DIR="$REPO_ROOT/backups"
RELEASE_LOCK_PATH="$REPO_ROOT/backups/.production-operations.lock"
RELEASE_LOCK_FD=9
OUTPUT_SEEN=0
LEAVE_STOPPED=0
DRAIN_ESTABLISHED=0
BROWSER_STOPPED=0
HELPER_IMAGE="busybox:1.37.0@sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028"
BACKUP_DRAIN_TIMEOUT_SECONDS=""
BACKUP_DRAIN_POLL_SECONDS=""

log() { printf '\033[1;34m[backup]\033[0m %s\n' "$*"; }
fail() {
	printf '\033[1;31m[backup] ERROR:\033[0m %s\n' "$*" >&2
	exit 1
}

read_env_value() {
	local requested_key="$1" line value first last
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in
			"${requested_key}="*)
				value="${line#*=}"
				if [ "${#value}" -ge 2 ]; then
					first="${value:0:1}"
					last="${value: -1}"
					if { [ "$first" = '"' ] && [ "$last" = '"' ]; } \
						|| { [ "$first" = "'" ] && [ "$last" = "'" ]; }; then
						value="${value:1:${#value}-2}"
					fi
				fi
				printf '%s' "$value"
				return 0
				;;
		esac
	done < "$ENV_FILE"
	return 1
}

private_env_file_ok() {
	local owner_uid current_uid mode permission_bits
	[ -f "$ENV_FILE" ] && [ ! -L "$ENV_FILE" ] && [ -r "$ENV_FILE" ] || return 1
	owner_uid="$(stat -c '%u' -- "$ENV_FILE")" || return 1
	current_uid="$(id -u)" || return 1
	[ "$owner_uid" = "$current_uid" ] || return 1
	mode="$(stat -c '%a' -- "$ENV_FILE")" || return 1
	[[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
	permission_bits=$((8#$mode))
	[ $((permission_bits & 077)) -eq 0 ]
}

private_directory_ok() {
	local path="$1" owner_uid current_uid mode permission_bits
	[ -d "$path" ] && [ ! -L "$path" ] || return 1
	owner_uid="$(stat -c '%u' -- "$path")" || return 1
	current_uid="$(id -u)" || return 1
	[ "$owner_uid" = "$current_uid" ] || return 1
	mode="$(stat -c '%a' -- "$path")" || return 1
	[[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
	permission_bits=$((8#$mode))
	[ $((permission_bits & 077)) -eq 0 ]
}

private_output_file_ok() {
	local path="$1" owner_uid current_uid mode permission_bits
	[ -f "$path" ] && [ ! -L "$path" ] && [ -r "$path" ] || return 1
	owner_uid="$(stat -c '%u' -- "$path")" || return 1
	current_uid="$(id -u)" || return 1
	[ "$owner_uid" = "$current_uid" ] || return 1
	mode="$(stat -c '%a' -- "$path")" || return 1
	[[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
	permission_bits=$((8#$mode))
	[ $((permission_bits & 077)) -eq 0 ]
}

acquire_release_lock() {
	local inherited_fd="${COMPOSIO_PRODUCTION_LOCK_FD:-}" lock_identity fd_identity
	command -v flock >/dev/null 2>&1 || fail "flock is required for production operations."
	mkdir -p "$(dirname "$RELEASE_LOCK_PATH")"
	chmod 0700 "$(dirname "$RELEASE_LOCK_PATH")"
	touch "$RELEASE_LOCK_PATH"
	chmod 0600 "$RELEASE_LOCK_PATH"

	if [ -n "$inherited_fd" ]; then
		[ "$inherited_fd" = "$RELEASE_LOCK_FD" ] \
			|| fail "The inherited production-operation lock is invalid."
		[ -e "/proc/$$/fd/$RELEASE_LOCK_FD" ] \
			|| fail "The inherited production-operation lock descriptor is unavailable."
		lock_identity="$(stat -Lc '%d:%i' -- "$RELEASE_LOCK_PATH")" || return 1
		fd_identity="$(stat -Lc '%d:%i' -- "/proc/$$/fd/$RELEASE_LOCK_FD")" || return 1
		[ "$lock_identity" = "$fd_identity" ] \
			|| fail "The inherited production-operation lock does not match this repository."
		flock -n "$RELEASE_LOCK_FD" \
			|| fail "Another production backup, restore, or deployment is already running."
		return 0
	fi

	exec 9>"$RELEASE_LOCK_PATH"
	flock -n "$RELEASE_LOCK_FD" \
		|| fail "Another production backup, restore, or deployment is already running."
	export COMPOSIO_PRODUCTION_LOCK_FD="$RELEASE_LOCK_FD"
}

isolated_command() {
	local name
	local -a clean_environment=(
		env
		-i
		"PATH=$PATH"
	)
	if [ "${COMPOSIO_PRODUCTION_LOCK_FD:-}" = "$RELEASE_LOCK_FD" ]; then
		clean_environment+=(
			"COMPOSIO_PRODUCTION_LOCK_FD=$COMPOSIO_PRODUCTION_LOCK_FD"
		)
	fi
	# Retain only Docker daemon/context selection. COMPOSE_*, application,
	# provider, feature-flag, and backup-control values from the caller cannot
	# override the private .env.production inputs.
	for name in \
		DOCKER_HOST \
		DOCKER_CONTEXT \
		DOCKER_CONFIG \
		DOCKER_CERT_PATH \
		DOCKER_TLS_VERIFY; do
		if [[ -v "$name" ]]; then
			clean_environment+=("$name=${!name}")
		fi
	done
	"${clean_environment[@]}" "$@"
}

docker_command() {
	isolated_command docker "$@"
}

for arg in "$@"; do
	case "$arg" in
		--quiesce)
			# Compatibility flag. Quiescing cannot be disabled.
			;;
		--leave-stopped)
			LEAVE_STOPPED=1
			;;
		--help|-h)
			printf 'Usage: %s [--quiesce] [--leave-stopped] [output-directory]\n' "$0"
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

acquire_release_lock

command -v docker >/dev/null 2>&1 || fail "Docker is not installed or not on PATH."
command -v git >/dev/null 2>&1 || fail "Git is not installed or not on PATH."
docker_command compose version >/dev/null 2>&1 \
	|| fail "The Docker Compose plugin is unavailable."
docker_command info >/dev/null 2>&1 || fail "Cannot communicate with the Docker daemon."
[ -f "$COMPOSE_FILE" ] || fail "$COMPOSE_FILE is unavailable."
private_env_file_ok \
	|| fail ".env.production must be a private regular file owned by the deploy user."
BACKUP_DRAIN_TIMEOUT_SECONDS="$(
	read_env_value BACKUP_DRAIN_TIMEOUT_SECONDS || printf '300'
)"
BACKUP_DRAIN_POLL_SECONDS="$(
	read_env_value BACKUP_DRAIN_POLL_SECONDS || printf '2'
)"
[[ "$BACKUP_DRAIN_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] \
	&& [ "$BACKUP_DRAIN_TIMEOUT_SECONDS" -ge 1 ] \
	&& [ "$BACKUP_DRAIN_TIMEOUT_SECONDS" -le 3600 ] \
	|| fail "BACKUP_DRAIN_TIMEOUT_SECONDS must be between 1 and 3600."
[[ "$BACKUP_DRAIN_POLL_SECONDS" =~ ^[0-9]+$ ]] \
	&& [ "$BACKUP_DRAIN_POLL_SECONDS" -ge 1 ] \
	&& [ "$BACKUP_DRAIN_POLL_SECONDS" -le 30 ] \
	|| fail "BACKUP_DRAIN_POLL_SECONDS must be between 1 and 30."
docker_command image inspect "$HELPER_IMAGE" >/dev/null 2>&1 \
	|| docker_command pull "$HELPER_IMAGE" >/dev/null \
	|| fail "The immutable backup helper image is unavailable."

for volume in "$DATA_VOLUME" "$VAULT_VOLUME" "$BROWSER_VOLUME"; do
	docker_command volume inspect "$volume" >/dev/null 2>&1 \
		|| fail "Required volume '$volume' does not exist."
done

if [ -e "$OUT_DIR" ] || [ -L "$OUT_DIR" ]; then
	private_directory_ok "$OUT_DIR" \
		|| fail "The backup output directory must be private and owned by the backup user."
else
	mkdir -p -m 0700 -- "$OUT_DIR"
fi
OUT_DIR="$(cd "$OUT_DIR" && pwd -P)"
case "$OUT_DIR" in
	*:*|*$'\n'*) fail "Output directory contains unsupported characters." ;;
esac
chmod 0700 "$OUT_DIR"
private_directory_ok "$OUT_DIR" \
	|| fail "The resolved backup output directory is not private."

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARCHIVE="production-state-${STAMP}.tar.gz"
CHECKSUM="${ARCHIVE}.sha256"
BACKUP_TMP="$OUT_DIR/.${ARCHIVE}.tmp"
CONFIG_TMP=""
BACKUP_OWNER_UID="$(id -u)"
BACKUP_OWNER_GID="$(id -g)"
[[ "$BACKUP_OWNER_UID" =~ ^[0-9]+$ ]] && [[ "$BACKUP_OWNER_GID" =~ ^[0-9]+$ ]] \
	|| fail "Could not determine the backup owner identity."
[ ! -e "$OUT_DIR/$ARCHIVE" ] && [ ! -L "$OUT_DIR/$ARCHIVE" ] \
	&& [ ! -e "$OUT_DIR/$CHECKSUM" ] && [ ! -L "$OUT_DIR/$CHECKSUM" ] \
	|| fail "A backup already exists for this timestamp; retry after the current second."

compose() {
	docker_command compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"
}

browser_drain_call() {
	local method="$1"
	# Read the token and owner only inside browser-worker. Neither value crosses
	# the host argv/log boundary.
	compose exec -T browser-worker python - "$method" <<'PY'
import json
import os
import sys
import urllib.request

try:
    method = sys.argv[1]
    if method not in {"GET", "POST", "DELETE"}:
        raise ValueError
    request = urllib.request.Request(
        "http://127.0.0.1:8081/internal/drain",
        method=method,
        headers={
            "X-Browser-Service-Token": os.environ["BROWSER_SERVICE_TOKEN"],
            "X-Browser-Session-Owner": os.environ["BROWSER_SERVICE_OWNER"],
        },
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=10) as response:
        payload = json.load(response)
    accepting = payload.get("accepting_new_sessions")
    capacity = payload.get("capacity_in_use")
    if not isinstance(accepting, bool) or type(capacity) is not int or capacity < 0:
        raise ValueError
    print("1" if accepting else "0", capacity)
except Exception:
    print("browser_drain_request_failed", file=sys.stderr)
    raise SystemExit(1)
PY
}

read_drain_snapshot() {
	local method="$1" snapshot accepting capacity extra
	snapshot="$(browser_drain_call "$method")" || return 1
	read -r accepting capacity extra <<< "$snapshot"
	[ -z "${extra:-}" ] || return 1
	case "$accepting" in 0|1) ;; *) return 1 ;; esac
	[[ "$capacity" =~ ^[0-9]+$ ]] || return 1
	printf '%s %s' "$accepting" "$capacity"
}

begin_browser_drain() {
	local snapshot accepting _capacity
	# A response can be lost after the worker accepted the request. Arm cleanup
	# before POST so every ambiguous failure attempts DELETE.
	DRAIN_ESTABLISHED=1
	snapshot="$(read_drain_snapshot POST)" || return 1
	read -r accepting _capacity <<< "$snapshot"
	[ "$accepting" -eq 0 ] || return 1
}

wait_for_browser_zero() {
	local elapsed=0 snapshot accepting capacity
	while :; do
		snapshot="$(read_drain_snapshot GET)" || return 1
		read -r accepting capacity <<< "$snapshot"
		[ "$accepting" -eq 0 ] || return 1
		[ "$capacity" -ne 0 ] || return 0
		[ "$elapsed" -lt "$BACKUP_DRAIN_TIMEOUT_SECONDS" ] || return 2
		sleep "$BACKUP_DRAIN_POLL_SECONDS"
		elapsed=$((elapsed + BACKUP_DRAIN_POLL_SECONDS))
	done
}

cancel_browser_drain() {
	local snapshot accepting _capacity
	snapshot="$(read_drain_snapshot DELETE)" || return 1
	read -r accepting _capacity <<< "$snapshot"
	[ "$accepting" -eq 1 ]
}

wait_for_service_health() {
	local service="$1" timeout="$2" waited=0 cid health
	while :; do
		cid="$(compose ps --quiet "$service" 2>/dev/null || true)"
		if [ -n "$cid" ]; then
			health="$(
				docker_command inspect --format \
					'{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
					"$cid" 2>/dev/null || printf 'unknown'
			)"
			case "$health" in
				healthy) return 0 ;;
				unhealthy|dead|exited) return 1 ;;
			esac
		fi
		[ "$waited" -lt "$timeout" ] || return 1
		sleep 3
		waited=$((waited + 3))
	done
}

DEPLOYED_REVISION=""
for service in api browser-worker web caddy; do
	cid="$(compose ps --all --quiet "$service" 2>/dev/null || true)"
	[ -n "$cid" ] || fail "Cannot identify the deployed $service container."
	service_revision="$(docker_command inspect --format \
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
	local restart_required=0
	trap - EXIT INT TERM
	rm -f "$BACKUP_TMP"
	if [ -n "$CONFIG_TMP" ] && [ -d "$CONFIG_TMP" ]; then
		rm -rf "$CONFIG_TMP"
	fi
	if [ "$status" -ne 0 ] || [ "$LEAVE_STOPPED" -eq 0 ]; then
		restart_required=1
	fi
	if [ "$restart_required" -eq 1 ] && [ "${#RUNNING_SERVICES[@]}" -gt 0 ]; then
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
		if [ "$BROWSER_STOPPED" -eq 1 ]; then
			# A restarted worker begins in normal accepting mode.
			DRAIN_ESTABLISHED=0
		fi
		for service in browser-worker api; do
			if [[ " ${RUNNING_SERVICES[*]} " == *" $service "* ]] \
				&& ! wait_for_service_health "$service" 180; then
				printf '\033[1;31m[backup] ERROR:\033[0m restarted %s is not healthy.\n' \
					"$service" >&2
				status=1
			fi
		done
	fi
	if [ "$DRAIN_ESTABLISHED" -eq 1 ] && [ "$BROWSER_STOPPED" -eq 0 ]; then
		if ! cancel_browser_drain >/dev/null; then
			printf '\033[1;31m[backup] ERROR:\033[0m failed to cancel browser drain.\n' >&2
			status=1
		fi
	fi
	exit "$status"
}
trap restore_services EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ " ${RUNNING_SERVICES[*]} " == *" browser-worker "* ]]; then
	log "Blocking new browser sessions and waiting for active work to finish..."
	begin_browser_drain || fail "Could not establish browser drain."
	DRAIN_STATUS=0
	wait_for_browser_zero || DRAIN_STATUS=$?
	case "$DRAIN_STATUS" in
		0) ;;
		2) fail "Browser drain timed out; no writers were stopped." ;;
		*) fail "Browser drain status could not be verified." ;;
	esac
fi

if [ "${#RUNNING_SERVICES[@]}" -gt 0 ]; then
	log "Quiescing SQLite and vault writers..."
	# Stop the API first so it cannot request new browser work while the worker exits.
	for service in api browser-worker; do
		if [[ " ${RUNNING_SERVICES[*]} " == *" $service "* ]]; then
			compose stop "$service" >/dev/null
			if [ "$service" = "browser-worker" ]; then
				BROWSER_STOPPED=1
			fi
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
docker_command run --rm \
	-e "ARCHIVE=$ARCHIVE" \
	-e "BACKUP_OWNER_UID=$BACKUP_OWNER_UID" \
	-e "BACKUP_OWNER_GID=$BACKUP_OWNER_GID" \
	-v "${DATA_VOLUME}:/source/ops_data:ro" \
	-v "${VAULT_VOLUME}:/source/credential_vault:ro" \
	-v "${BROWSER_VOLUME}:/source/browser_profiles:ro" \
	-v "${CONFIG_TMP}:/source/runtime_config:ro" \
	-v "${OUT_DIR}:/backup" \
	"$HELPER_IMAGE" sh -eu -c '
		umask 077
		test -f /source/ops_data/ops.db
		test -f /source/credential_vault/credentials.db
		tmp="/backup/.${ARCHIVE}.tmp"
		rm -f "$tmp"
		tar czf "$tmp" -C /source ops_data credential_vault browser_profiles runtime_config
		tar tzf "$tmp" | grep -q "^ops_data/ops.db$"
		tar tzf "$tmp" | grep -q "^credential_vault/credentials.db$"
		tar tzf "$tmp" | grep -q "^browser_profiles/$"
		tar tzf "$tmp" | grep -q "^runtime_config/deployed-sha.txt$"
		tar tzf "$tmp" | grep -q "^runtime_config/compose.prod.yaml$"
		tar tzf "$tmp" | grep -q "^runtime_config/deploy/Caddyfile$"
		mv "$tmp" "/backup/$ARCHIVE"
		chmod 0600 "/backup/$ARCHIVE"
		cd /backup
		sha256sum "$ARCHIVE" > "$ARCHIVE.sha256"
		chmod 0600 "$ARCHIVE.sha256"
		chown "$BACKUP_OWNER_UID:$BACKUP_OWNER_GID" "$ARCHIVE" "$ARCHIVE.sha256"
	'

[ -s "$OUT_DIR/$ARCHIVE" ] || fail "Backup archive is empty."
[ -s "$OUT_DIR/$CHECKSUM" ] || fail "Backup checksum is empty."
private_output_file_ok "$OUT_DIR/$ARCHIVE" \
	|| fail "Backup archive ownership or permissions are unsafe."
private_output_file_ok "$OUT_DIR/$CHECKSUM" \
	|| fail "Backup checksum ownership or permissions are unsafe."

log "Backup complete: $OUT_DIR/$ARCHIVE"
log "Checksum: $OUT_DIR/$CHECKSUM"
log "Encryption keys are intentionally excluded; retain them in the production secret manager."
if [ "$LEAVE_STOPPED" -eq 1 ] && [ "${#RUNNING_SERVICES[@]}" -gt 0 ]; then
	log "Writers remain stopped for transactional deployment."
fi
