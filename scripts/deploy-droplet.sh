#!/usr/bin/env bash
#
# Transactional single-Droplet production deployment.
#
# The running revision stays online while the candidate is validated and built.
# Existing browser work is then drained, a restorable backup is verified, public
# traffic is stopped, and the exact pre-built candidate images are activated.
# Any failure after quiescing restores the previous image identities and remains
# a failed deployment.
#
# Environment values, rendered Compose configuration, credentials, and browser
# session identifiers are never printed or written to release artifacts.
set -euo pipefail
umask 077

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

COMPOSE_FILE="compose.prod.yaml"
ENV_FILE=".env.production"
PROJECT="composio-ops-prod"
RELEASE_LOCK_PATH="$REPO_ROOT/backups/.production-operations.lock"
RELEASE_LOCK_FD=9
readonly -a RELEASE_SERVICES=(api browser-worker web caddy)
readonly -a INTERNAL_SERVICES=(browser-worker api web)

declare -A PREVIOUS_IMAGE_ID=()
declare -A PREVIOUS_IMAGE_REF=()
declare -A PREVIOUS_CONTAINER_ID=()
declare -A CANDIDATE_IMAGE_ID=()
declare -A CONFIG_IMAGE_REF=()
declare -A ROLLBACK_IMAGE_REF=()

PREVIOUS_STACK=0
PREVIOUS_REVISION=""
DRAIN_ESTABLISHED=0
ROLLBACK_REQUIRED=0
RELEASE_COMPLETE=0
PREDEPLOY_ARCHIVE=""
CANDIDATE_ACTIVATION_STARTED=0
DEPLOY_ACCEPTANCE_NONCE=""
ROLLBACK_BUNDLE_DIR=""
ROLLBACK_PUBLIC_ORIGIN=""
# Never inherit an APP_REVISION from the deploy shell. It is populated from the
# verified Git commit below and is the sole non-Docker value deliberately passed
# through the sanitized Compose environment.
APP_REVISION=""

log() { printf '\033[1;34m[deploy]\033[0m %s\n' "$*"; }
fail() {
	printf '\033[1;31m[deploy] ERROR:\033[0m %s\n' "$*" >&2
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

validate_production_security_shapes() {
	local public_domain="$1"
	local managed_auth_callback="$2"
	local secret_vault_key="$3"
	local langgraph_aes_key="$4"

	# Feed secret material over stdin rather than argv or the process
	# environment. The validator emits only a fixed, value-free error message.
	printf '%s\0%s\0%s\0%s' \
		"$public_domain" \
		"$managed_auth_callback" \
		"$secret_vault_key" \
		"$langgraph_aes_key" |
		python3 -c '
import base64
import re
import sys
from urllib.parse import urlsplit


def reject(message: str) -> None:
    print(message)
    raise SystemExit(1)


parts = sys.stdin.buffer.read().split(b"\0")
if len(parts) != 4:
    reject("Production security configuration could not be validated.")
domain_bytes, callback_bytes, vault_bytes, aes_bytes = parts

try:
    domain = domain_bytes.decode("ascii")
    callback = callback_bytes.decode("utf-8")
except UnicodeDecodeError:
    reject("MANAGED_AUTH_CALLBACK_BASE_URL must be a valid HTTPS origin.")

if not callback:
    reject("MANAGED_AUTH_CALLBACK_BASE_URL is required.")
if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in callback):
    reject("MANAGED_AUTH_CALLBACK_BASE_URL must not contain whitespace or controls.")

normalized_callback = callback.casefold().rstrip("/")
if normalized_callback in {
    "https://your-domain.example",
    "https://localhost.invalid",
} or any(
    marker in normalized_callback
    for marker in ("replace-with", "change-me", "placeholder")
):
    reject("MANAGED_AUTH_CALLBACK_BASE_URL contains an example placeholder.")

try:
    parsed = urlsplit(callback)
except ValueError:
    reject("MANAGED_AUTH_CALLBACK_BASE_URL must be a valid HTTPS origin.")
if parsed.scheme.casefold() != "https":
    reject("MANAGED_AUTH_CALLBACK_BASE_URL must use HTTPS.")
if parsed.username is not None or parsed.password is not None:
    reject("MANAGED_AUTH_CALLBACK_BASE_URL must not contain credentials.")
try:
    hostname = parsed.hostname
    port = parsed.port
except ValueError:
    reject("MANAGED_AUTH_CALLBACK_BASE_URL must be a valid HTTPS origin.")
if hostname is None or not parsed.netloc:
    reject("MANAGED_AUTH_CALLBACK_BASE_URL must be a valid HTTPS origin.")
normalized_hostname = hostname.casefold()
if normalized_hostname in {"example.com", "example.net", "example.org"} or (
    normalized_hostname == "example" or normalized_hostname.endswith(".example")
):
    reject("MANAGED_AUTH_CALLBACK_BASE_URL contains an example placeholder.")
if port not in {None, 443}:
    reject("MANAGED_AUTH_CALLBACK_BASE_URL must use the standard HTTPS port.")
if parsed.path not in {"", "/"} or "?" in callback or "#" in callback:
    reject(
        "MANAGED_AUTH_CALLBACK_BASE_URL must be an HTTPS origin without a path, "
        "query, or fragment."
    )
if normalized_hostname != domain.casefold():
    reject("MANAGED_AUTH_CALLBACK_BASE_URL host must exactly match DOMAIN.")

try:
    vault_key = vault_bytes.decode("ascii")
except UnicodeDecodeError:
    reject("SECRET_VAULT_KEY must be a canonical URL-safe Fernet key.")
if re.fullmatch(r"[A-Za-z0-9_-]{43}=", vault_key) is None:
    reject("SECRET_VAULT_KEY must be a canonical URL-safe Fernet key.")
try:
    decoded_vault_key = base64.urlsafe_b64decode(vault_key.encode("ascii"))
except (ValueError, TypeError):
    reject("SECRET_VAULT_KEY must be a canonical URL-safe Fernet key.")
if (
    len(decoded_vault_key) != 32
    or base64.urlsafe_b64encode(decoded_vault_key).decode("ascii") != vault_key
):
    reject("SECRET_VAULT_KEY must be a canonical URL-safe Fernet key.")

try:
    aes_key = aes_bytes.decode("utf-8")
except UnicodeDecodeError:
    reject("LANGGRAPH_AES_KEY must contain exactly 32 UTF-8 bytes.")
if len(aes_bytes) != 32:
    reject("LANGGRAPH_AES_KEY must contain exactly 32 UTF-8 bytes.")
if any(
    marker in aes_key.casefold()
    for marker in ("replace-with", "change-me", "placeholder", "example")
):
    reject("LANGGRAPH_AES_KEY contains an example placeholder.")
'
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
		"APP_REVISION=$APP_REVISION"
	)
	if [ -n "${DEPLOY_ACCEPTANCE_NONCE:-}" ]; then
		clean_environment+=(
			"OPS_DEPLOY_ACCEPTANCE_NONCE=$DEPLOY_ACCEPTANCE_NONCE"
		)
	fi
	if [ "${COMPOSIO_PRODUCTION_LOCK_FD:-}" = "$RELEASE_LOCK_FD" ]; then
		clean_environment+=(
			"COMPOSIO_PRODUCTION_LOCK_FD=$COMPOSIO_PRODUCTION_LOCK_FD"
		)
	fi
	# Retain only Docker daemon/context selection. In particular, COMPOSE_* and
	# application/provider variables from the caller are excluded so they cannot
	# take precedence over the already-validated .env.production file.
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

compose() {
	docker_command compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"
}

rollback_compose() {
	[ -n "$ROLLBACK_BUNDLE_DIR" ] || return 1
	docker_command compose \
		--project-name "$PROJECT" \
		-f "$ROLLBACK_BUNDLE_DIR/compose.prod.yaml" \
		-f "$ROLLBACK_BUNDLE_DIR/runtime.override.json" \
		--env-file "$REPO_ROOT/$ENV_FILE" \
		"$@"
}

cleanup_rollback_bundle() {
	if [ -n "$ROLLBACK_BUNDLE_DIR" ] \
		&& [[ "$ROLLBACK_BUNDLE_DIR" == /dev/shm/composio-ops-rollback.* ]] \
		&& [ -d "$ROLLBACK_BUNDLE_DIR" ]; then
		rm -rf -- "$ROLLBACK_BUNDLE_DIR"
	fi
	ROLLBACK_BUNDLE_DIR=""
	ROLLBACK_PUBLIC_ORIGIN=""
}

single_container_id() {
	local service="$1" ids count
	ids="$(compose ps --all --quiet "$service" 2>/dev/null || true)"
	[ -n "$ids" ] || return 1
	count="$(printf '%s\n' "$ids" | awk 'NF { count += 1 } END { print count + 0 }')"
	[ "$count" -eq 1 ] || return 2
	printf '%s' "$ids"
}

load_config_image_refs() {
	local rendered service image extra
	rendered="$(
		compose config --format json | python3 -c '
import json
import re
import sys

services = json.load(sys.stdin).get("services", {})
for name in sys.argv[1:]:
    image = services.get(name, {}).get("image")
    if not isinstance(image, str) or not image or re.search(r"[\t\r\n]", image):
        raise SystemExit(f"missing immutable image reference for {name}")
    print(f"{name}\t{image}")
' "${RELEASE_SERVICES[@]}"
	)" || return 1
	CONFIG_IMAGE_REF=()
	while IFS=$'\t' read -r service image extra; do
		[ -n "$service" ] && [ -n "$image" ] && [ -z "${extra:-}" ] || return 1
		CONFIG_IMAGE_REF["$service"]="$image"
	done <<< "$rendered"
	for service in "${RELEASE_SERVICES[@]}"; do
		[ -n "${CONFIG_IMAGE_REF[$service]:-}" ] || return 1
	done
}

load_rollback_image_refs() {
	local rendered service image extra
	rendered="$(
		rollback_compose config --format json | python3 -c '
import json
import re
import sys

services = json.load(sys.stdin).get("services", {})
for name in sys.argv[1:]:
    image = services.get(name, {}).get("image")
    if not isinstance(image, str) or not image or re.search(r"[\t\r\n]", image):
        raise SystemExit(f"missing rollback image reference for {name}")
    print(f"{name}\t{image}")
' "${RELEASE_SERVICES[@]}"
	)" || return 1
	ROLLBACK_IMAGE_REF=()
	while IFS=$'\t' read -r service image extra; do
		[ -n "$service" ] && [ -n "$image" ] && [ -z "${extra:-}" ] || return 1
		ROLLBACK_IMAGE_REF["$service"]="$image"
	done <<< "$rendered"
	for service in "${RELEASE_SERVICES[@]}"; do
		[ -n "${ROLLBACK_IMAGE_REF[$service]:-}" ] || return 1
	done
}

capture_previous_stack() {
	local service cid found=0 revision image_id image_ref
	for service in "${RELEASE_SERVICES[@]}"; do
		if cid="$(single_container_id "$service")"; then
			found=$((found + 1))
			image_id="$(docker_command inspect --format '{{.Image}}' "$cid")" || return 1
			image_ref="$(docker_command inspect --format '{{.Config.Image}}' "$cid")" || return 1
			revision="$(
				docker_command inspect --format \
					'{{index .Config.Labels "org.opencontainers.image.revision"}}' "$cid"
			)" || return 1
			[ -n "$image_id" ] && [ -n "$image_ref" ] && [ -n "$revision" ] || return 1
			PREVIOUS_CONTAINER_ID["$service"]="$cid"
			PREVIOUS_IMAGE_ID["$service"]="$image_id"
			PREVIOUS_IMAGE_REF["$service"]="$image_ref"
			if [ -z "$PREVIOUS_REVISION" ]; then
				PREVIOUS_REVISION="$revision"
			elif [ "$revision" != "$PREVIOUS_REVISION" ]; then
				return 3
			fi
		else
			case "$?" in
				1) ;;
				*) return 2 ;;
			esac
		fi
	done
	if [ "$found" -eq 0 ]; then
		PREVIOUS_STACK=0
		return 0
	fi
	[ "$found" -eq "${#RELEASE_SERVICES[@]}" ] || return 4
	[[ "$PREVIOUS_REVISION" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || return 5
	git cat-file -e "${PREVIOUS_REVISION}^{commit}" 2>/dev/null || return 6
	PREVIOUS_STACK=1
	for service in "${RELEASE_SERVICES[@]}"; do
		# Preserve a revision-unique rollback tag before candidate builds can move
		# the Compose-facing tag. Image IDs remain the final identity authority.
		docker_command image tag \
			"${PREVIOUS_IMAGE_ID[$service]}" \
			"composio-ops-rollback-${service}:${PREVIOUS_REVISION}" >/dev/null || return 7
	done
}

snapshot_previous_runtime_override() {
	local output="$ROLLBACK_BUNDLE_DIR/runtime.override.json"
	local origin_output="$ROLLBACK_BUNDLE_DIR/public-origin.txt"
	local -a container_ids=()
	local service
	for service in "${RELEASE_SERVICES[@]}"; do
		container_ids+=("${PREVIOUS_CONTAINER_ID[$service]}")
	done
	docker_command inspect "${container_ids[@]}" \
		| python3 -c '
import json
import os
import pathlib
import re
import sys

output = pathlib.Path(sys.argv[1])
origin_output = pathlib.Path(sys.argv[2])
project = sys.argv[3]
services = sys.argv[4:]
containers = json.load(sys.stdin)
if not isinstance(containers, list) or len(containers) != len(services):
    raise SystemExit(1)
rendered = {"services": {}}
rollback_domain = None
for service, container in zip(services, containers, strict=True):
    config = container.get("Config") or {}
    host = container.get("HostConfig") or {}
    labels = config.get("Labels") or {}
    if (
        labels.get("com.docker.compose.project") != project
        or labels.get("com.docker.compose.service") != service
    ):
        raise SystemExit(1)
    environment = {}
    for entry in config.get("Env") or []:
        if not isinstance(entry, str) or "=" not in entry:
            raise SystemExit(1)
        name, value = entry.split("=", 1)
        if not name or name in environment:
            raise SystemExit(1)
        # These two values belong to the deploy transaction, not the prior
        # container. The previous Compose contract must render the exact
        # rollback revision and this deployment fresh nonce.
        if service == "api" and name in {
            "APP_REVISION",
            "OPS_DEPLOY_ACCEPTANCE_NONCE",
        }:
            continue
        environment[name] = value
    if service == "caddy":
        rollback_domain = environment.get("DOMAIN")
    override = {
        "environment": environment,
        "mem_limit": int(host.get("Memory") or 0),
        "pids_limit": int(host.get("PidsLimit") or 0),
        "shm_size": int(host.get("ShmSize") or 0),
    }
    nano_cpus = int(host.get("NanoCpus") or 0)
    if nano_cpus:
        override["cpus"] = nano_cpus / 1_000_000_000
    restart = (host.get("RestartPolicy") or {}).get("Name")
    if isinstance(restart, str) and restart:
        override["restart"] = restart
    stop_timeout = config.get("StopTimeout")
    if type(stop_timeout) is int and stop_timeout > 0:
        override["stop_grace_period"] = f"{stop_timeout}s"
    log_config = host.get("LogConfig") or {}
    log_driver = log_config.get("Type")
    log_options = log_config.get("Config")
    if isinstance(log_driver, str) and log_driver:
        override["logging"] = {
            "driver": log_driver,
            "options": log_options if isinstance(log_options, dict) else {},
        }
    rendered["services"][service] = override
temporary = output.with_suffix(".tmp")
temporary.write_text(
    json.dumps(rendered, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
os.chmod(temporary, 0o600)
os.replace(temporary, output)
if (
    not isinstance(rollback_domain, str)
    or "." not in rollback_domain
    or re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]",
        rollback_domain,
    )
    is None
):
    raise SystemExit(1)
origin_temporary = origin_output.with_suffix(".tmp")
origin_temporary.write_text(
    f"https://{rollback_domain}\n",
    encoding="ascii",
)
os.chmod(origin_temporary, 0o600)
os.replace(origin_temporary, origin_output)
' "$output" "$origin_output" "$PROJECT" "${RELEASE_SERVICES[@]}" \
		|| return 1
	[ -s "$output" ] || return 1
	[ -s "$origin_output" ] || return 1
	chmod 0600 "$output"
	chmod 0600 "$origin_output"
	IFS= read -r ROLLBACK_PUBLIC_ORIGIN < "$origin_output" || return 1
	[[ "$ROLLBACK_PUBLIC_ORIGIN" =~ ^https://[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$ ]] \
		&& [[ "$ROLLBACK_PUBLIC_ORIGIN" == *.* ]] \
		|| return 1
}

prepare_previous_release_bundle() {
	[ "$PREVIOUS_STACK" -eq 1 ] || return 0
	[ -d /dev/shm ] && [ -w /dev/shm ] || return 1
	ROLLBACK_BUNDLE_DIR="$(
		mktemp -d "/dev/shm/composio-ops-rollback.XXXXXX"
	)" || return 1
	chmod 0700 "$ROLLBACK_BUNDLE_DIR"
	git show "${PREVIOUS_REVISION}:compose.prod.yaml" \
		> "$ROLLBACK_BUNDLE_DIR/compose.prod.yaml" || return 1
	chmod 0400 "$ROLLBACK_BUNDLE_DIR/compose.prod.yaml"
	if git cat-file -e \
		"${PREVIOUS_REVISION}:deploy/chromium-seccomp.json" 2>/dev/null; then
		mkdir -m 0700 "$ROLLBACK_BUNDLE_DIR/deploy"
		git show "${PREVIOUS_REVISION}:deploy/chromium-seccomp.json" \
			> "$ROLLBACK_BUNDLE_DIR/deploy/chromium-seccomp.json" || return 1
		chmod 0400 "$ROLLBACK_BUNDLE_DIR/deploy/chromium-seccomp.json"
	fi
	# The base file may declare env_file: .env.production. Keep it empty so no
	# current candidate-only variables bleed into rollback containers; the
	# private override below contains the exact previous runtime environment.
	: > "$ROLLBACK_BUNDLE_DIR/.env.production"
	chmod 0400 "$ROLLBACK_BUNDLE_DIR/.env.production"
	snapshot_previous_runtime_override || return 1
	(
		APP_REVISION="$PREVIOUS_REVISION"
		export APP_REVISION
		rollback_compose config --format json \
			| python3 -c '
import json
import re
import sys

configuration = json.load(sys.stdin)
expected_project = sys.argv[2]
if configuration.get("name") != expected_project:
    raise SystemExit(1)
services = configuration.get("services", {})
expected = {"api", "browser-worker", "web", "caddy"}
if set(services) != expected:
    raise SystemExit(1)
revision = sys.argv[1]
for name, service in services.items():
    image = service.get("image")
    if not isinstance(image, str) or not image.endswith(f":{revision}"):
        raise SystemExit(1)
    if service.get("configs") or service.get("secrets"):
        raise SystemExit(1)
    for mount in service.get("volumes") or []:
        if isinstance(mount, dict) and mount.get("type") == "bind":
            raise SystemExit(1)
api = services["api"].get("environment") or {}
nonce = api.get("OPS_DEPLOY_ACCEPTANCE_NONCE", "")
if (
    api.get("APP_REVISION") != revision
    or api.get("OPS_DEPLOY_ACCEPTANCE_MARKER_PATH")
    != "/data/deploy-acceptance.json"
    or re.fullmatch(r"[A-Za-z0-9_-]{43,128}", nonce) is None
    or nonce == "manual-unaccepted"
):
    raise SystemExit(1)
' "$PREVIOUS_REVISION" "$PROJECT"
	) || return 1
}

capture_candidate_images() {
	local service image_ref image_id revision
	load_config_image_refs || return 1
	for service in "${RELEASE_SERVICES[@]}"; do
		image_ref="${CONFIG_IMAGE_REF[$service]}"
		case "$image_ref" in
			*":${APP_REVISION}") ;;
			*) return 2 ;;
		esac
		image_id="$(docker_command image inspect --format '{{.Id}}' "$image_ref")" || return 3
		revision="$(
			docker_command image inspect --format \
				'{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image_ref"
		)" || return 4
		[ -n "$image_id" ] && [ "$revision" = "$APP_REVISION" ] || return 5
		CANDIDATE_IMAGE_ID["$service"]="$image_id"
	done
}

scan_candidate_images() {
	local service cache_dir status=0
	cache_dir="$(mktemp -d "${TMPDIR:-/tmp}/composio-ops-trivy.XXXXXX")" || return 1
	chmod 0700 "$cache_dir"
	for service in "${RELEASE_SERVICES[@]}"; do
		log "Scanning exact candidate image for '$service'..."
		if ! isolated_command trivy image \
			--cache-dir "$cache_dir" \
			--scanners vuln \
			--severity HIGH,CRITICAL \
			--exit-code 1 \
			--no-progress \
			"${CANDIDATE_IMAGE_ID[$service]}"; then
			status=1
			break
		fi
	done
	rm -rf -- "$cache_dir"
	return "$status"
}

browser_drain_call() {
	local method="$1"
	# The Python process runs INSIDE browser-worker and reads its own environment.
	# The service token and owner therefore never appear in the host process argv,
	# shell trace, Compose output, or this helper's stdout/stderr.
	compose exec -T browser-worker python - "$method" <<'PY'
import json
import os
import sys
import urllib.request

try:
    method = sys.argv[1]
    if method not in {"GET", "POST", "DELETE"}:
        raise ValueError
    token = os.environ["BROWSER_SERVICE_TOKEN"]
    owner = os.environ["BROWSER_SERVICE_OWNER"]
    request = urllib.request.Request(
        "http://127.0.0.1:8081/internal/drain",
        method=method,
        headers={
            "X-Browser-Service-Token": token,
            "X-Browser-Session-Owner": owner,
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
	local snapshot accepting capacity
	# Arm cancellation BEFORE the request: a lost response may still mean the
	# worker accepted the drain, so every failure path must attempt to reopen it.
	DRAIN_ESTABLISHED=1
	snapshot="$(read_drain_snapshot POST)" || return 1
	read -r accepting capacity <<< "$snapshot"
	[ "$accepting" -eq 0 ] || return 1
	printf '%s' "$capacity"
}

wait_for_browser_zero() {
	local timeout="$1" poll="$2" elapsed=0 snapshot accepting capacity
	while :; do
		snapshot="$(read_drain_snapshot GET)" || return 1
		read -r accepting capacity <<< "$snapshot"
		[ "$accepting" -eq 0 ] || return 1
		if [ "$capacity" -eq 0 ]; then
			return 0
		fi
		if [ "$elapsed" -ge "$timeout" ]; then
			return 2
		fi
		sleep "$poll"
		elapsed=$((elapsed + poll))
	done
}

cancel_browser_drain() {
	local snapshot accepting _capacity
	snapshot="$(read_drain_snapshot DELETE)" || return 1
	read -r accepting _capacity <<< "$snapshot"
	[ "$accepting" -eq 1 ]
}

wait_for_health() {
	local service="$1" timeout="$2" waited=0 cid status
	log "Waiting for '$service' health (timeout ${timeout}s)..."
	while :; do
		cid="$(compose ps --quiet "$service" 2>/dev/null || true)"
		if [ -n "$cid" ]; then
			status="$(
				docker_command inspect --format \
					'{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
					"$cid" 2>/dev/null || printf 'unknown'
			)"
			case "$status" in
				healthy)
					log "'$service' is healthy."
					return 0
					;;
				unhealthy|dead|exited)
					return 1
					;;
			esac
		fi
		[ "$waited" -lt "$timeout" ] || return 2
		sleep 3
		waited=$((waited + 3))
	done
}

verify_running_identity() {
	local service="$1" expected_id="$2" expected_revision="$3"
	local cid actual_id actual_revision
	cid="$(compose ps --quiet "$service" 2>/dev/null || true)"
	[ -n "$cid" ] || return 1
	actual_id="$(docker_command inspect --format '{{.Image}}' "$cid")" || return 1
	actual_revision="$(
		docker_command inspect --format \
			'{{index .Config.Labels "org.opencontainers.image.revision"}}' "$cid"
	)" || return 1
	[ "$actual_id" = "$expected_id" ] && [ "$actual_revision" = "$expected_revision" ]
}

public_probes() {
	local origin="${1:-$PUBLIC_ORIGIN}"
	local health_status redirect_probe unauthenticated_status redirect_url extra login_status
	health_status="$(
		curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
			--max-time 20 "${origin}/healthz"
	)" || return 1
	[ "$health_status" = "200" ] || return 1
	redirect_probe="$(
		curl --silent --show-error --output /dev/null \
			--write-out $'%{http_code}\t%{redirect_url}' \
			--max-time 20 "${origin}/system"
	)" || return 1
	IFS=$'\t' read -r unauthenticated_status redirect_url extra <<< "$redirect_probe"
	[ -z "${extra:-}" ] || return 1
	case "$unauthenticated_status" in 302|303|307|308) ;; *) return 1 ;; esac
	python3 - "$origin" "$redirect_url" <<'PY' || return 1
import sys
from urllib.parse import parse_qs, urlsplit

origin = urlsplit(sys.argv[1])
redirect = urlsplit(sys.argv[2])
if (
    redirect.scheme != origin.scheme
    or redirect.netloc != origin.netloc
    or redirect.path != "/login"
    or redirect.fragment
):
    raise SystemExit(1)
query = parse_qs(redirect.query, keep_blank_values=True)
if query and query != {"next": ["/system"]}:
    raise SystemExit(1)
PY
	login_status="$(
		curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
			--max-time 20 "${origin}/login"
	)" || return 1
	[ "$login_status" = "200" ]
}

mark_current_release_accepted() {
	# The nonce remains inside the API container environment. Only its
	# revision-bound SHA-256 digest is persisted, atomically and owner-only.
	compose exec -T api python - <<'PY'
from ops.config import Settings
from ops.deploy_acceptance import (
    deployment_is_accepted,
    write_deployment_acceptance_marker,
)

settings = Settings.from_env(dotenv_path=None)
write_deployment_acceptance_marker(settings)
if not deployment_is_accepted(settings):
    raise SystemExit(1)
PY
}

mark_rollback_release_accepted() {
	rollback_compose exec -T api python - <<'PY'
from ops.config import Settings
from ops.deploy_acceptance import (
    deployment_is_accepted,
    write_deployment_acceptance_marker,
)

settings = Settings.from_env(dotenv_path=None)
write_deployment_acceptance_marker(settings)
if not deployment_is_accepted(settings):
    raise SystemExit(1)
PY
}

restore_previous_release() {
	local service expected_ref
	log "Restoring the previous exact image identities..."
	compose stop caddy >/dev/null 2>&1 || true

	if [ "$PREVIOUS_STACK" -eq 0 ]; then
		# First-deploy failure has no prior release. Return to a closed edge while
		# preserving named data volumes for diagnosis/retry.
		compose stop caddy web api browser-worker >/dev/null 2>&1 || true
		return 0
	fi

	if [ "$CANDIDATE_ACTIVATION_STARTED" -eq 1 ]; then
		[ -n "$PREDEPLOY_ARCHIVE" ] && [ -s "$PREDEPLOY_ARCHIVE" ] \
			&& [ -s "$PREDEPLOY_ARCHIVE.sha256" ] || return 1
		log "Restoring the exact verified pre-deploy data snapshot..."
		isolated_command \
			./scripts/restore-production-data.sh \
			--confirm-restore --leave-stopped "$PREDEPLOY_ARCHIVE" \
			|| return 1
	fi

	APP_REVISION="$PREVIOUS_REVISION"
	export APP_REVISION
	load_rollback_image_refs || return 1
	for service in "${RELEASE_SERVICES[@]}"; do
		expected_ref="${ROLLBACK_IMAGE_REF[$service]}"
		docker_command image tag \
			"${PREVIOUS_IMAGE_ID[$service]}" "$expected_ref" >/dev/null || return 1
		if [ "${PREVIOUS_IMAGE_REF[$service]}" != "$expected_ref" ]; then
			docker_command image tag \
				"${PREVIOUS_IMAGE_ID[$service]}" \
				"${PREVIOUS_IMAGE_REF[$service]}" >/dev/null || return 1
		fi
	done

	rollback_compose up -d --no-build --force-recreate --remove-orphans \
		"${INTERNAL_SERVICES[@]}" >/dev/null || return 1
	wait_for_health browser-worker 180 || return 1
	wait_for_health api 150 || return 1
	wait_for_health web 150 || return 1
	for service in "${INTERNAL_SERVICES[@]}"; do
		verify_running_identity \
			"$service" "${PREVIOUS_IMAGE_ID[$service]}" "$PREVIOUS_REVISION" || return 1
	done

	rollback_compose up -d --no-build --force-recreate caddy >/dev/null || return 1
	wait_for_health caddy 90 || return 1
	verify_running_identity \
		caddy "${PREVIOUS_IMAGE_ID[caddy]}" "$PREVIOUS_REVISION" || return 1
	public_probes "$ROLLBACK_PUBLIC_ORIGIN" || return 1
	mark_rollback_release_accepted || return 1
	log "Previous revision restored and verified."
}

stop_uncertain_rollback_stack() {
	# Both configurations address the same fixed Compose project. Invoke both so
	# a render failure in either the candidate or frozen rollback contract cannot
	# leave an unaccepted edge—or an uncertain writer—running.
	rollback_compose stop caddy web api browser-worker >/dev/null 2>&1 || true
	compose stop caddy web api browser-worker >/dev/null 2>&1 || true
}

release_exit() {
	local status=$?
	trap - EXIT INT TERM
	if [ "$status" -ne 0 ] && [ "$RELEASE_COMPLETE" -eq 0 ]; then
		if [ "$ROLLBACK_REQUIRED" -eq 1 ]; then
			if ! restore_previous_release; then
				stop_uncertain_rollback_stack
				printf '\033[1;31m[deploy] FATAL:\033[0m automatic rollback failed; every production service was ordered stopped.\n' >&2
				status=70
			fi
		elif [ "$DRAIN_ESTABLISHED" -eq 1 ]; then
			if ! cancel_browser_drain >/dev/null; then
				printf '\033[1;31m[deploy] ERROR:\033[0m failed to cancel browser drain.\n' >&2
				status=70
			fi
		fi
	fi
	cleanup_rollback_bundle
	exit "$status"
}

# ── Host/configuration preconditions ─────────────────────────────────────────
command -v docker >/dev/null 2>&1 || fail "Docker is not installed or not on PATH."
command -v git >/dev/null 2>&1 || fail "Git is not installed or not on PATH."
command -v curl >/dev/null 2>&1 || fail "curl is required for public checks."
command -v python3 >/dev/null 2>&1 || fail "python3 is required for rendered checks."
command -v trivy >/dev/null 2>&1 \
	|| fail "Trivy is required to scan the exact production candidate images."
command -v flock >/dev/null 2>&1 || fail "flock is required for production operations."
[ "$(uname -m)" = "x86_64" ] \
	|| fail "This release lock is compiled for an x86_64/amd64 production host."
acquire_release_lock
docker_command compose version >/dev/null 2>&1 \
	|| fail "The Docker Compose plugin is unavailable."
docker_command info >/dev/null 2>&1 || fail "Cannot communicate with the Docker daemon."
DOCKER_ARCHITECTURE="$(
	docker_command info --format '{{.Architecture}}'
)" || fail "Could not determine the Docker daemon architecture."
[ "$DOCKER_ARCHITECTURE" = "x86_64" ] || [ "$DOCKER_ARCHITECTURE" = "amd64" ] \
	|| fail "The Docker daemon must target amd64 for requirements-runtime.lock."
[ -f "$COMPOSE_FILE" ] || fail "$COMPOSE_FILE is unavailable."
private_env_file_ok \
	|| fail ".env.production must be a private regular file owned by the deploy user."
[ -x scripts/backup-production-data.sh ] || fail "The production backup helper is unavailable."
[ -x scripts/restore-production-data.sh ] || fail "The production restore validator is unavailable."

PUBLIC_DOMAIN="$(read_env_value DOMAIN || true)"
APP_AUTH_USERNAME_VALUE="$(read_env_value OPS_AUTH_USERNAME || true)"
APP_AUTH_PASSWORD_VALUE="$(read_env_value OPS_AUTH_PASSWORD || true)"
APP_AUTH_SESSION_SECRET_VALUE="$(read_env_value OPS_AUTH_SESSION_SECRET || true)"
APP_AUTH_TOTP_SECRET_VALUE="$(read_env_value OPS_AUTH_TOTP_SECRET || true)"
INTERNAL_API_TOKEN_VALUE="$(read_env_value OPS_INTERNAL_API_TOKEN || true)"
BROWSER_SERVICE_TOKEN_VALUE="$(read_env_value BROWSER_SERVICE_TOKEN || true)"
BROWSER_SECRET_BROKER_TOKEN_VALUE="$(read_env_value BROWSER_SECRET_BROKER_TOKEN || true)"
BROWSER_SESSION_CAPABILITY_KEY_VALUE="$(
	read_env_value BROWSER_SESSION_CAPABILITY_KEY || true
)"
BROWSER_SERVICE_OWNER_VALUE="$(read_env_value BROWSER_SERVICE_OWNER || true)"
SECRET_VAULT_KEY_VALUE="$(read_env_value SECRET_VAULT_KEY || true)"
LANGGRAPH_AES_KEY_VALUE="$(read_env_value LANGGRAPH_AES_KEY || true)"
MANAGED_AUTH_CALLBACK_BASE_URL_VALUE="$(
	read_env_value MANAGED_AUTH_CALLBACK_BASE_URL || true
)"
SIGNUP_GMAIL_ACCOUNT_VALUE="$(
	read_env_value COMPOSIO_GMAIL_SIGNUP_CONNECTED_ACCOUNT_ID || true
)"
SIGNUP_GMAIL_ADDRESS_VALUE="$(read_env_value GMAIL_SIGNUP_ADDRESS || true)"
GMAIL_REQUIRE_BINDING_VALUE="$(read_env_value GMAIL_VERIFICATION_REQUIRE_BINDING || true)"
GMAIL_SIGNUP_PREFLIGHT_TIMEOUT_VALUE="$(
	read_env_value GMAIL_SIGNUP_PREFLIGHT_TIMEOUT_SECONDS || printf '10'
)"
DRAIN_TIMEOUT_VALUE="$(
	read_env_value DEPLOY_DRAIN_TIMEOUT_SECONDS || printf '300'
)"
DRAIN_POLL_VALUE="$(
	read_env_value DEPLOY_DRAIN_POLL_SECONDS || printf '2'
)"

[ -n "$PUBLIC_DOMAIN" ] || fail "DOMAIN is required for public TLS verification."
[ "$PUBLIC_DOMAIN" != "your-domain.example" ] || fail "DOMAIN still contains the example value."
[[ "$PUBLIC_DOMAIN" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$ ]] \
	|| fail "DOMAIN must be a DNS hostname without a scheme or path."
[[ "$PUBLIC_DOMAIN" == *.* ]] || fail "DOMAIN must be a public DNS hostname."
[ -n "$APP_AUTH_USERNAME_VALUE" ] || fail "OPS_AUTH_USERNAME is required."
[ "${#APP_AUTH_PASSWORD_VALUE}" -ge 20 ] || fail "OPS_AUTH_PASSWORD must be at least 20 characters."
[ "${#APP_AUTH_SESSION_SECRET_VALUE}" -ge 32 ] \
	|| fail "OPS_AUTH_SESSION_SECRET must be at least 32 characters."
APP_AUTH_TOTP_NORMALIZED="${APP_AUTH_TOTP_SECRET_VALUE// /}"
APP_AUTH_TOTP_NORMALIZED="${APP_AUTH_TOTP_NORMALIZED^^}"
[ "${#APP_AUTH_TOTP_NORMALIZED}" -ge 16 ] \
	&& [ "${#APP_AUTH_TOTP_NORMALIZED}" -le 128 ] \
	&& [[ "$APP_AUTH_TOTP_NORMALIZED" =~ ^[A-Z2-7]+={0,6}$ ]] \
	|| fail "OPS_AUTH_TOTP_SECRET must be a valid Base32 secret of 16 to 128 characters."
[ "${#INTERNAL_API_TOKEN_VALUE}" -ge 32 ] \
	|| fail "OPS_INTERNAL_API_TOKEN must be at least 32 characters."
[ "${#BROWSER_SERVICE_TOKEN_VALUE}" -ge 32 ] \
	|| fail "BROWSER_SERVICE_TOKEN must be at least 32 characters."
[ "${#BROWSER_SECRET_BROKER_TOKEN_VALUE}" -ge 32 ] \
	|| fail "BROWSER_SECRET_BROKER_TOKEN must be at least 32 characters."
[ "${#BROWSER_SESSION_CAPABILITY_KEY_VALUE}" -ge 32 ] \
	|| fail "BROWSER_SESSION_CAPABILITY_KEY must be at least 32 characters."
[[ "$BROWSER_SERVICE_OWNER_VALUE" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$ ]] \
	|| fail "BROWSER_SERVICE_OWNER must be an explicit safe owner identifier."
[ -n "$SECRET_VAULT_KEY_VALUE" ] || fail "SECRET_VAULT_KEY is required."
[ -n "$LANGGRAPH_AES_KEY_VALUE" ] || fail "LANGGRAPH_AES_KEY is required."
PRODUCTION_SECURITY_ERROR=""
if ! PRODUCTION_SECURITY_ERROR="$(
	validate_production_security_shapes \
		"$PUBLIC_DOMAIN" \
		"$MANAGED_AUTH_CALLBACK_BASE_URL_VALUE" \
		"$SECRET_VAULT_KEY_VALUE" \
		"$LANGGRAPH_AES_KEY_VALUE"
)"; then
	fail "${PRODUCTION_SECURITY_ERROR:-Production security configuration is invalid.}"
fi
unset PRODUCTION_SECURITY_ERROR

for other_value in \
	"$APP_AUTH_PASSWORD_VALUE" \
	"$INTERNAL_API_TOKEN_VALUE" \
	"$BROWSER_SERVICE_TOKEN_VALUE" \
	"$BROWSER_SECRET_BROKER_TOKEN_VALUE" \
	"$APP_AUTH_SESSION_SECRET_VALUE"; do
	[ "$BROWSER_SESSION_CAPABILITY_KEY_VALUE" != "$other_value" ] \
		|| fail "BROWSER_SESSION_CAPABILITY_KEY must be independent from every internal/browser token."
done
[ "$APP_AUTH_TOTP_SECRET_VALUE" != "$APP_AUTH_PASSWORD_VALUE" ] \
	|| fail "OPS_AUTH_TOTP_SECRET must differ from OPS_AUTH_PASSWORD."
[ "$APP_AUTH_TOTP_SECRET_VALUE" != "$APP_AUTH_SESSION_SECRET_VALUE" ] \
	|| fail "OPS_AUTH_TOTP_SECRET must differ from OPS_AUTH_SESSION_SECRET."
[ "$APP_AUTH_PASSWORD_VALUE" != "$APP_AUTH_SESSION_SECRET_VALUE" ] \
	|| fail "OPS_AUTH_PASSWORD must differ from OPS_AUTH_SESSION_SECRET."
for other_value in \
	"$INTERNAL_API_TOKEN_VALUE" \
	"$BROWSER_SERVICE_TOKEN_VALUE" \
	"$BROWSER_SECRET_BROKER_TOKEN_VALUE" \
	"$BROWSER_SESSION_CAPABILITY_KEY_VALUE" \
	"$SECRET_VAULT_KEY_VALUE" \
	"$LANGGRAPH_AES_KEY_VALUE"; do
	[ "$APP_AUTH_TOTP_SECRET_VALUE" != "$other_value" ] \
		|| fail "OPS_AUTH_TOTP_SECRET must be independent from application and encryption secrets."
done
[ "$BROWSER_SECRET_BROKER_TOKEN_VALUE" != "$INTERNAL_API_TOKEN_VALUE" ] \
	|| fail "BROWSER_SECRET_BROKER_TOKEN must differ from OPS_INTERNAL_API_TOKEN."
[ "$BROWSER_SECRET_BROKER_TOKEN_VALUE" != "$BROWSER_SERVICE_TOKEN_VALUE" ] \
	|| fail "BROWSER_SECRET_BROKER_TOKEN must differ from BROWSER_SERVICE_TOKEN."
[ "$INTERNAL_API_TOKEN_VALUE" != "$BROWSER_SERVICE_TOKEN_VALUE" ] \
	|| fail "OPS_INTERNAL_API_TOKEN must differ from BROWSER_SERVICE_TOKEN."
case "$(
	printf '%s' \
		"$APP_AUTH_PASSWORD_VALUE $APP_AUTH_SESSION_SECRET_VALUE " \
		"$APP_AUTH_TOTP_SECRET_VALUE " \
		"$INTERNAL_API_TOKEN_VALUE $BROWSER_SERVICE_TOKEN_VALUE " \
		"$BROWSER_SECRET_BROKER_TOKEN_VALUE $BROWSER_SESSION_CAPABILITY_KEY_VALUE" |
		tr '[:upper:]' '[:lower:]'
)" in
	*replace-with*|*change-me*|*placeholder*|*example*)
		fail "One or more security values still contain an example placeholder."
		;;
esac
if [ -n "$SIGNUP_GMAIL_ACCOUNT_VALUE" ] || [ -n "$SIGNUP_GMAIL_ADDRESS_VALUE" ]; then
	[ -n "$SIGNUP_GMAIL_ACCOUNT_VALUE" ] \
		|| fail "COMPOSIO_GMAIL_SIGNUP_CONNECTED_ACCOUNT_ID is required with GMAIL_SIGNUP_ADDRESS."
	[ -n "$SIGNUP_GMAIL_ADDRESS_VALUE" ] \
		|| fail "GMAIL_SIGNUP_ADDRESS is required with the signup Gmail account."
	[[ "$SIGNUP_GMAIL_ADDRESS_VALUE" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] \
		|| fail "GMAIL_SIGNUP_ADDRESS must be a valid email address."
	[ "${GMAIL_REQUIRE_BINDING_VALUE,,}" = "true" ] \
		|| fail "GMAIL_VERIFICATION_REQUIRE_BINDING must be true for signup Gmail."
fi
[[ "$GMAIL_SIGNUP_PREFLIGHT_TIMEOUT_VALUE" =~ ^(([1-9]|[12][0-9])(\.[0-9]+)?|30(\.0+)?)$ ]] \
	|| fail "GMAIL_SIGNUP_PREFLIGHT_TIMEOUT_SECONDS must be between 1 and 30."
[[ "$DRAIN_TIMEOUT_VALUE" =~ ^[0-9]+$ ]] \
	&& [ "$DRAIN_TIMEOUT_VALUE" -ge 1 ] \
	&& [ "$DRAIN_TIMEOUT_VALUE" -le 3600 ] \
	|| fail "DEPLOY_DRAIN_TIMEOUT_SECONDS must be between 1 and 3600."
[[ "$DRAIN_POLL_VALUE" =~ ^[0-9]+$ ]] \
	&& [ "$DRAIN_POLL_VALUE" -ge 1 ] \
	&& [ "$DRAIN_POLL_VALUE" -le 30 ] \
	|| fail "DEPLOY_DRAIN_POLL_SECONDS must be between 1 and 30."
PUBLIC_ORIGIN="https://${PUBLIC_DOMAIN}"

[ -z "$(git status --porcelain)" ] \
	|| fail "Working tree is not clean. Commit the reviewed candidate before deployment."
APP_REVISION="$(git rev-parse --verify 'HEAD^{commit}')"
[[ "$APP_REVISION" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] \
	|| fail "Git returned an invalid deployment revision."
export APP_REVISION
DEPLOY_ACCEPTANCE_NONCE="$(
	python3 -c 'import secrets; print(secrets.token_urlsafe(48))'
)" || fail "Could not generate the deployment acceptance nonce."
[[ "$DEPLOY_ACCEPTANCE_NONCE" =~ ^[A-Za-z0-9_-]{43,128}$ ]] \
	|| fail "The deployment acceptance nonce generator returned an invalid value."
export OPS_DEPLOY_ACCEPTANCE_NONCE="$DEPLOY_ACCEPTANCE_NONCE"
log "Preparing exact revision: $APP_REVISION"

trap release_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

log "Validating Compose and rendered security contracts..."
compose config >/dev/null || fail "Compose configuration is invalid."
compose config --format json | python3 -c '
import json
import re
import sys

configuration = json.load(sys.stdin)
services = configuration["services"]
expected_owner = sys.argv[1]
expected_revision = sys.argv[2]
expected_project = sys.argv[3]
if configuration.get("name") != expected_project:
    raise SystemExit("Compose project name must remain stable")
browser = services["browser-worker"]["environment"]
api = services["api"]["environment"]
web = services["web"]["environment"]

try:
    capacity = int(browser["PLAYWRIGHT_MAX_SESSIONS"])
    worker_timeout = float(browser["BROWSER_OPERATION_TIMEOUT_SECONDS"])
    client_timeout = float(api["BROWSER_SERVICE_CLIENT_TIMEOUT_SECONDS"])
    web_timeout = float(web["OPS_RUN_ACTION_TIMEOUT_MS"]) / 1000
    automation_delay = float(api["OPS_AUTOMATION_START_DELAY_SECONDS"])
    email_poll_interval = int(api["EMAIL_POLL_INTERVAL_SECONDS"])
    email_poll_limit = int(api["EMAIL_POLL_MAX_RUNS_PER_CYCLE"])
except (KeyError, TypeError, ValueError):
    raise SystemExit("invalid browser, timeout, or maintenance configuration")
if not 1 <= capacity <= 10:
    raise SystemExit("PLAYWRIGHT_MAX_SESSIONS must be between 1 and 10")
if worker_timeout < 60 or not worker_timeout < client_timeout < web_timeout < 345:
    raise SystemExit("invalid nested browser timeout configuration")
for name in (
    "OPS_AUTH_USERNAME",
    "OPS_AUTH_PASSWORD",
    "OPS_AUTH_SESSION_SECRET",
    "OPS_AUTH_TOTP_SECRET",
):
    if api.get(name):
        raise SystemExit(f"{name} must not be available to the API container")
for name in (
    "BROWSER_STORAGE_STATE_KEY",
    "BROWSER_USE_API_KEY",
    "CEREBRAS_API_KEY",
    "GROQ_API_KEY",
):
    if api.get(name):
        raise SystemExit(f"{name} must not be available to the API container")
if not api.get("BROWSER_SESSION_CAPABILITY_KEY"):
    raise SystemExit("BROWSER_SESSION_CAPABILITY_KEY must be available to API")
if not web.get("OPS_AUTH_TOTP_SECRET"):
    raise SystemExit("OPS_AUTH_TOTP_SECRET must be available to web")
if api.get("OPS_STARTUP_AUTOMATION_ENABLED") != "true":
    raise SystemExit("OPS_STARTUP_AUTOMATION_ENABLED must enable delayed production maintenance")
if not 60 <= automation_delay <= 300:
    raise SystemExit("OPS_AUTOMATION_START_DELAY_SECONDS must be between 60 and 300")
if not 10 <= email_poll_interval <= 900:
    raise SystemExit("EMAIL_POLL_INTERVAL_SECONDS must be between 10 and 900")
if not 1 <= email_poll_limit <= 100:
    raise SystemExit("EMAIL_POLL_MAX_RUNS_PER_CYCLE must be between 1 and 100")
if api.get("GMAIL_VERIFICATION_REQUIRE_AUTHENTICATED_SENDER") != "true":
    raise SystemExit("GMAIL_VERIFICATION_REQUIRE_AUTHENTICATED_SENDER must be true")
if api.get("APP_REVISION") != expected_revision:
    raise SystemExit("API APP_REVISION must match the exact candidate revision")
acceptance_nonce = api.get("OPS_DEPLOY_ACCEPTANCE_NONCE", "")
if (
    re.fullmatch(r"[A-Za-z0-9_-]{43,128}", acceptance_nonce) is None
    or acceptance_nonce == "manual-unaccepted"
):
    raise SystemExit("OPS_DEPLOY_ACCEPTANCE_NONCE must be a fresh deploy nonce")
if api.get("OPS_DEPLOY_ACCEPTANCE_MARKER_PATH") != "/data/deploy-acceptance.json":
    raise SystemExit("OPS_DEPLOY_ACCEPTANCE_MARKER_PATH must use the ops_data volume")
for service_name in ("browser-worker", "web", "caddy"):
    if services[service_name].get("environment", {}).get("BROWSER_SESSION_CAPABILITY_KEY"):
        raise SystemExit("BROWSER_SESSION_CAPABILITY_KEY must be API-only")
    if services[service_name].get("environment", {}).get("OPS_DEPLOY_ACCEPTANCE_NONCE"):
        raise SystemExit("OPS_DEPLOY_ACCEPTANCE_NONCE must be API-only")
for service_name in ("api", "browser-worker", "caddy"):
    owner = services[service_name].get("environment", {}).get("BROWSER_SERVICE_OWNER")
    if owner != expected_owner or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", owner or "") is None:
        raise SystemExit("BROWSER_SERVICE_OWNER must match across API, worker, and Caddy")
if browser.get("GMAIL_SIGNUP_ADDRESS"):
    raise SystemExit("GMAIL_SIGNUP_ADDRESS must not be ambient browser configuration")
for forbidden in (
    "SECRET_VAULT_KEY",
    "SECRET_VAULT_DB_PATH",
    "OPS_INTERNAL_API_TOKEN",
    "BROWSER_SESSION_CAPABILITY_KEY",
):
    if browser.get(forbidden):
        raise SystemExit(f"{forbidden} must not be available to browser-worker")
' "$BROWSER_SERVICE_OWNER_VALUE" "$APP_REVISION" "$PROJECT" \
	|| fail "Rendered deployment contract is invalid."

CAPTURE_STATUS=0
capture_previous_stack || CAPTURE_STATUS=$?
case "$CAPTURE_STATUS" in
	0) ;;
	2) fail "Multiple containers exist for a production service." ;;
	3) fail "The previous production stack contains mixed revisions." ;;
	4) fail "The previous production stack is partial; refusing an ambiguous rollout." ;;
	*) fail "Could not verify the previous production image identities." ;;
esac
prepare_previous_release_bundle \
	|| fail "Could not freeze the exact previous rollback topology and runtime."

log "Building revision-tagged candidate images while the current stack remains live..."
compose build --pull || fail "Candidate image build failed."
capture_candidate_images || fail "Candidate image identity or revision-label verification failed."
scan_candidate_images || fail "Exact candidate image vulnerability scan failed."

if [ "$PREVIOUS_STACK" -eq 1 ]; then
	log "Blocking new browser sessions and waiting for active work to finish..."
	begin_browser_drain >/dev/null || fail "Could not establish browser drain."
	DRAIN_STATUS=0
	wait_for_browser_zero "$DRAIN_TIMEOUT_VALUE" "$DRAIN_POLL_VALUE" || DRAIN_STATUS=$?
	case "$DRAIN_STATUS" in
		0) ;;
		2) fail "Browser drain timed out; the current release was left active." ;;
		*) fail "Browser drain status could not be verified." ;;
	esac
	# From this point, any error must verify the frozen previous release. Close
	# public admission BEFORE either SQLite writer is stopped so no operator
	# mutation can race the snapshot boundary.
	ROLLBACK_REQUIRED=1
	log "Closing the public edge before the recovery snapshot..."
	compose stop caddy >/dev/null || fail "Could not close the public edge."

	BACKUP_STAMP="$(date -u +%Y%m%dT%H%M%SZ)-$$"
	BACKUP_DIR="$REPO_ROOT/backups/predeploy-${APP_REVISION}-${BACKUP_STAMP}"
	mkdir -p "$BACKUP_DIR"
	chmod 0700 "$BACKUP_DIR"
	log "Creating a unique pre-deploy recovery archive..."
	isolated_command \
		./scripts/backup-production-data.sh --leave-stopped "$BACKUP_DIR" \
		|| fail "Pre-deploy backup failed."
	DRAIN_ESTABLISHED=0
	shopt -s nullglob
	BACKUP_ARCHIVES=("$BACKUP_DIR"/production-state-*.tar.gz)
	shopt -u nullglob
	[ "${#BACKUP_ARCHIVES[@]}" -eq 1 ] \
		|| fail "Pre-deploy backup did not produce exactly one archive."
	[ -s "${BACKUP_ARCHIVES[0]}.sha256" ] \
		|| fail "Pre-deploy backup checksum is unavailable."
	log "Validating that the pre-deploy archive is restorable..."
	isolated_command \
		./scripts/restore-production-data.sh --dry-run "${BACKUP_ARCHIVES[0]}" \
		|| fail "Pre-deploy archive validation failed."
	PREDEPLOY_ARCHIVE="${BACKUP_ARCHIVES[0]}"
else
	log "No previous stack exists; this is a first deployment."
	ROLLBACK_REQUIRED=1
fi

log "Ensuring the public edge is closed before candidate activation..."
compose stop caddy >/dev/null || fail "Could not close the public edge."

log "Activating pre-built internal candidate images..."
CANDIDATE_ACTIVATION_STARTED=1
compose up -d --no-build --remove-orphans "${INTERNAL_SERVICES[@]}" \
	|| fail "Internal candidate activation failed."
wait_for_health browser-worker 180 || fail "browser-worker did not become healthy."
wait_for_health api 150 || fail "api did not become healthy."
wait_for_health web 150 || fail "web did not become healthy."
for service in "${INTERNAL_SERVICES[@]}"; do
	verify_running_identity "$service" "${CANDIDATE_IMAGE_ID[$service]}" "$APP_REVISION" \
		|| fail "$service running image identity does not match the candidate."
done

log "Starting the verified candidate edge..."
compose up -d --no-build caddy || fail "Candidate edge activation failed."
wait_for_health caddy 90 || fail "caddy did not become healthy."
verify_running_identity caddy "${CANDIDATE_IMAGE_ID[caddy]}" "$APP_REVISION" \
	|| fail "caddy running image identity does not match the candidate."

log "Verifying public TLS and the application-auth boundary..."
public_probes || fail "Public TLS or application-auth verification failed."

log "Accepting the exact release for autonomous maintenance..."
mark_current_release_accepted \
	|| fail "Could not persist and verify the exact deployment acceptance marker."

unset APP_AUTH_PASSWORD_VALUE APP_AUTH_SESSION_SECRET_VALUE APP_AUTH_TOTP_SECRET_VALUE
unset APP_AUTH_TOTP_NORMALIZED
unset INTERNAL_API_TOKEN_VALUE BROWSER_SERVICE_TOKEN_VALUE
unset BROWSER_SECRET_BROKER_TOKEN_VALUE BROWSER_SESSION_CAPABILITY_KEY_VALUE
unset SECRET_VAULT_KEY_VALUE LANGGRAPH_AES_KEY_VALUE
unset MANAGED_AUTH_CALLBACK_BASE_URL_VALUE
unset OPS_DEPLOY_ACCEPTANCE_NONCE DEPLOY_ACCEPTANCE_NONCE

RELEASE_COMPLETE=1
ROLLBACK_REQUIRED=0
cleanup_rollback_bundle
trap - EXIT INT TERM
log "Service status:"
if ! compose ps; then
	log "Deployment is accepted, but the final status display was unavailable."
fi
log "Deployment complete at exact revision $APP_REVISION."
