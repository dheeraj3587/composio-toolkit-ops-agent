#!/usr/bin/env bash
#
# update-droplet.sh — pull the latest code and roll out an updated build.
#
# Idempotent and non-destructive: it never removes named volumes, so persistent
# SQLite state and Caddy certificates are preserved across updates.
#
# Usage:
#   ./scripts/update-droplet.sh [git-branch]     # default branch: main
#
# ROLLBACK (documented, not automatic):
#   Redeploy a known-good revision, then rebuild without touching volumes:
#       git fetch --tags origin
#       git checkout <previous-good-tag-or-commit>
#       docker compose -f compose.prod.yaml --env-file .env.production up -d --build
#   Persistent data in the ops_data / caddy_data volumes is unaffected.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BRANCH="${1:-main}"
COMPOSE_FILE="compose.prod.yaml"
ENV_FILE=".env.production"

log()  { printf '\033[1;34m[update]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[update] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

command -v git >/dev/null 2>&1 || fail "git is not installed."
command -v docker >/dev/null 2>&1 || fail "Docker is not installed or not on PATH."
docker compose version >/dev/null 2>&1 || fail "The Docker Compose plugin is not available."
[ -f "$COMPOSE_FILE" ] || fail "$COMPOSE_FILE not found in $REPO_ROOT."
[ -f "$ENV_FILE" ] || fail "$ENV_FILE not found. Nothing to update against."

compose() { docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"; }

CURRENT_REV="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
log "Current revision: $CURRENT_REV"

log "Fetching origin/$BRANCH..."
git fetch --prune origin "$BRANCH"

log "Checking out and fast-forwarding $BRANCH..."
git checkout "$BRANCH"
git pull --ff-only origin "$BRANCH"

NEW_REV="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
log "Updated to revision: $NEW_REV"

log "Validating Compose configuration..."
compose config >/dev/null || fail "Compose configuration is invalid; not rolling out."

log "Building updated images..."
compose build

log "Rolling out (volumes are preserved)..."
compose up -d --remove-orphans

log "Service status:"
compose ps

log "Update complete ($CURRENT_REV -> $NEW_REV). If health is degraded, roll back per the header of this script."
