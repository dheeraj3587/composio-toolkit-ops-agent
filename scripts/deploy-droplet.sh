#!/usr/bin/env bash
#
# deploy-droplet.sh — first-time / repeatable production bring-up on a Droplet.
#
# Idempotent: safe to re-run. It validates configuration, builds images and
# (re)starts services with Docker Compose, then waits for health checks.
#
# It never prints environment values or database contents.
#
# Usage:
#   ./scripts/deploy-droplet.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

COMPOSE_FILE="compose.prod.yaml"
ENV_FILE=".env.production"

log()  { printf '\033[1;34m[deploy]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[deploy] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

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

# ── Preconditions ─────────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || fail "Docker is not installed or not on PATH."
command -v git >/dev/null 2>&1 || fail "Git is not installed or not on PATH."
command -v curl >/dev/null 2>&1 || fail "curl is required for the public TLS/auth checks."
command -v python3 >/dev/null 2>&1 || fail "python3 is required for rendered capacity checks."
docker compose version >/dev/null 2>&1 || fail "The Docker Compose plugin is not available."
docker info >/dev/null 2>&1 || fail "Cannot talk to the Docker daemon (is it running / do you have permission?)."
[ -f "$COMPOSE_FILE" ] || fail "$COMPOSE_FILE not found in $REPO_ROOT."
[ -f "$ENV_FILE" ] || fail "$ENV_FILE not found. Copy .env.production.example to .env.production and fill it in."

PUBLIC_DOMAIN="$(read_env_value DOMAIN || true)"
BASIC_AUTH_USER_VALUE="$(read_env_value OPS_BASIC_AUTH_USER || true)"
BASIC_AUTH_PASSWORD_VALUE="$(read_env_value OPS_BASIC_AUTH_PASSWORD || true)"
[ -n "$PUBLIC_DOMAIN" ] || fail "DOMAIN is required for public TLS verification."
[ "$PUBLIC_DOMAIN" != "your-domain.example" ] || fail "DOMAIN still contains the example value."
[[ "$PUBLIC_DOMAIN" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$ ]] \
	|| fail "DOMAIN must be a DNS hostname without a scheme or path."
[[ "$PUBLIC_DOMAIN" == *.* ]] || fail "DOMAIN must be a public DNS hostname."
[ -n "$BASIC_AUTH_USER_VALUE" ] || fail "OPS_BASIC_AUTH_USER is required."
[ -n "$BASIC_AUTH_PASSWORD_VALUE" ] \
	|| fail "OPS_BASIC_AUTH_PASSWORD is required for the authenticated deployment probe."
PUBLIC_ORIGIN="https://${PUBLIC_DOMAIN}"

if [ -n "$(git status --porcelain)" ]; then
	fail "Working tree is not clean. Commit the reviewed candidate before production deployment."
fi
APP_REVISION="$(git rev-parse HEAD)"
export APP_REVISION
log "Deploying exact revision: $APP_REVISION"

compose() { docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"; }

# ── Validate configuration (does not start anything) ──────────────────────────
log "Validating Compose configuration..."
compose config >/dev/null || fail "Compose configuration is invalid."
rendered_capacity="$(compose config --format json | python3 -c '
import json
import sys

environment = json.load(sys.stdin)["services"]["browser-worker"]["environment"]
print(environment.get("PLAYWRIGHT_MAX_SESSIONS"), environment.get("BROWSER_DISPLAY_SLOTS"))
')"
[ "$rendered_capacity" = "1 1" ] \
	|| fail "Production must enforce exactly one Playwright session and one display slot."

# ── Build images ──────────────────────────────────────────────────────────────
log "Building images..."
compose build

# ── Start / update services ───────────────────────────────────────────────────
log "Starting services..."
compose up -d --remove-orphans

# ── Wait for health ───────────────────────────────────────────────────────────
wait_for_health() {
	local service="$1" timeout="${2:-120}" waited=0 cid status
	log "Waiting for '$service' to become healthy (timeout ${timeout}s)..."
	while :; do
		cid="$(compose ps -q "$service" 2>/dev/null || true)"
		if [ -n "$cid" ]; then
			status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || echo unknown)"
			case "$status" in
				healthy|running) log "'$service' is ${status}."; return 0 ;;
				unhealthy)       fail "'$service' reported unhealthy. Check: docker compose -f $COMPOSE_FILE logs $service" ;;
			esac
		fi
		[ "$waited" -ge "$timeout" ] && fail "'$service' did not become healthy within ${timeout}s."
		sleep 3; waited=$((waited + 3))
	done
}

wait_for_health api 150
wait_for_health browser-worker 180
wait_for_health web 150
wait_for_health caddy 90

for service in api browser-worker web; do
	cid="$(compose ps -q "$service")"
	deployed_revision="$(docker inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$cid")"
	[ "$deployed_revision" = "$APP_REVISION" ] || fail "$service image revision does not match $APP_REVISION."
done

# ── Public TLS and Basic Auth acceptance ─────────────────────────────────────
log "Verifying public TLS and Basic Auth..."
health_status="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
	--max-time 20 "${PUBLIC_ORIGIN}/healthz")" \
	|| fail "Public TLS health probe failed."
[ "$health_status" = "200" ] || fail "Public /healthz returned HTTP $health_status."

unauthenticated_status="$(curl --silent --show-error --output /dev/null \
	--write-out '%{http_code}' --max-time 20 "${PUBLIC_ORIGIN}/system")" \
	|| fail "Unauthenticated Basic Auth probe failed."
[ "$unauthenticated_status" = "401" ] \
	|| fail "Protected page must reject unauthenticated requests with HTTP 401."

curl_auth_pair="${BASIC_AUTH_USER_VALUE}:${BASIC_AUTH_PASSWORD_VALUE}"
curl_auth_pair="${curl_auth_pair//\\/\\\\}"
curl_auth_pair="${curl_auth_pair//\"/\\\"}"
printf 'user = "%s"\n' "$curl_auth_pair" \
	| curl --config - --fail --silent --show-error --location --max-time 30 \
		"${PUBLIC_ORIGIN}/system" >/dev/null \
	|| fail "Authenticated public page probe failed."
unset curl_auth_pair
unset BASIC_AUTH_PASSWORD_VALUE

# ── Sanitized status ──────────────────────────────────────────────────────────
log "Service status:"
compose ps

log "Deployment complete at exact revision $APP_REVISION."
log "Public TLS, unauthenticated rejection, and authenticated /system checks passed."
