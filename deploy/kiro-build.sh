#!/bin/bash
# Deploy helper for the single-droplet production stack.
#
# Builds and recreates ONLY the services affected by a change, with BuildKit
# disabled: the daemon on this host refuses BuildKit's parallel connections
# ("only one connection allowed"), so classic builds are used deliberately.
#
# Usage: kiro-build.sh [service ...]   (default: api browser-worker web)
set -u

cd /root/composio-toolkit-ops-agent || exit 1

SERVICES=${*:-"api browser-worker web"}

COMPOSE=(docker compose
  --project-directory /root/composio-toolkit-ops-agent
  --env-file /root/composio-toolkit-ops-agent/.env.production
  --env-file /root/composio-toolkit-ops-agent/.env.assignment
  -p composio-ops-prod
  -f /root/composio-toolkit-ops-agent/compose.prod.yaml
  -f /root/composio-toolkit-ops-agent/compose.assignment.yaml
  -f /root/composio-toolkit-ops-agent/compose.interactive.yaml)

export DOCKER_BUILDKIT=0
export COMPOSE_DOCKER_CLI_BUILD=0
export COMPOSE_PARALLEL_LIMIT=1

echo "=== commit ==="
git rev-parse HEAD

for service in $SERVICES; do
  echo "=== build ${service} ==="
  "${COMPOSE[@]}" build "$service" || { echo "BUILD_FAILED ${service}"; exit 1; }
done

for service in $SERVICES; do
  echo "=== recreate ${service} ==="
  "${COMPOSE[@]}" up -d --force-recreate "$service" || { echo "UP_FAILED ${service}"; exit 1; }
done

echo "=== health ==="
for _ in $(seq 1 30); do
  states=$(docker inspect -f '{{.Name}} {{.State.Health.Status}}' \
    composio-ops-prod-api-1 composio-ops-prod-browser-worker-1 composio-ops-prod-web-1 2>/dev/null)
  echo "$states"
  unhealthy=$(echo "$states" | grep -cv " healthy")
  [ "$unhealthy" -eq 0 ] && break
  sleep 10
done

echo "BUILD_SCRIPT_DONE"
