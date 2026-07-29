# syntax=docker/dockerfile:1

# Docker Hub official-image index digest for node:22.23.1-bookworm-slim,
# reviewed 2026-07-29. All stages share one immutable runtime/toolchain base.
FROM node:26.5.0-bookworm-slim@sha256:2d49d876e96237d76de412761cf05dbfe5aee325cc4406a4d41d5824c5bb8beb AS dependencies

ENV NEXT_TELEMETRY_DISABLED=1
WORKDIR /app

COPY web/package.json web/package-lock.json web/.npmrc ./
# Third-party dependency lifecycle scripts are disabled. The reviewed
# application build remains an explicit command in the next stage.
RUN npm ci --ignore-scripts --no-audit --no-fund

FROM node:26.5.0-bookworm-slim@sha256:2d49d876e96237d76de412761cf05dbfe5aee325cc4406a4d41d5824c5bb8beb AS builder

ENV NEXT_TELEMETRY_DISABLED=1
WORKDIR /app

COPY --from=dependencies /app/node_modules ./node_modules
COPY web/ ./
RUN npm run build

FROM node:26.5.0-bookworm-slim@sha256:2d49d876e96237d76de412761cf05dbfe5aee325cc4406a4d41d5824c5bb8beb AS runner

ARG APP_REVISION=local-uncommitted
LABEL org.opencontainers.image.revision=$APP_REVISION

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    HOSTNAME=0.0.0.0 \
    PORT=3000

WORKDIR /app

COPY --from=builder --chown=node:node /app/.next/standalone ./
# Next.js standalone output intentionally excludes static/public assets. Copy
# them explicitly or a clean image either fails the assertion below or serves
# the UI without fonts, icons, and compiled client chunks.
COPY --from=builder --chown=node:node /app/public ./public
COPY --from=builder --chown=node:node /app/.next/static ./.next/static
# npm is required in the two build stages but the production process only
# executes the generated Node server. Remove npm and npx from the final image so
# their package-management and archive-extraction dependency trees are not part
# of the remotely reachable runtime.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx \
    && test -f /app/server.js \
    && test -d /app/public \
    && test -d /app/.next/static \
    && test ! -e /usr/local/lib/node_modules/npm \
    && test ! -e /usr/local/bin/npm \
    && test ! -e /usr/local/bin/npx

USER node
EXPOSE 3000
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/health').then(async r=>{const p=await r.json();if(!r.ok||p.status!=='ok')process.exit(1)}).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
