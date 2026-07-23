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

# ── Preconditions ─────────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || fail "Docker is not installed or not on PATH."
docker compose version >/dev/null 2>&1 || fail "The Docker Compose plugin is not available."
docker info >/dev/null 2>&1 || fail "Cannot talk to the Docker daemon (is it running / do you have permission?)."
[ -f "$COMPOSE_FILE" ] || fail "$COMPOSE_FILE not found in $REPO_ROOT."
[ -f "$ENV_FILE" ] || fail "$ENV_FILE not found. Copy .env.production.example to .env.production and fill it in."

compose() { docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"; }

# ── Validate configuration (does not start anything) ──────────────────────────
log "Validating Compose configuration..."
compose config >/dev/null || fail "Compose configuration is invalid."

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
wait_for_health web 150
wait_for_health caddy 90

# ── Sanitized status ──────────────────────────────────────────────────────────
log "Service status:"
compose ps

log "Deployment complete. Public entry point is the reverse proxy on :80/:443."
log "Verify the API health path via the proxy: curl -fsS https://<your-domain>/api/system/health"
