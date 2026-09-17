# syntax=docker/dockerfile:1.7
# Build from the repo root: docker build -f apps/server/Dockerfile .

ARG NODE_IMAGE=node:22-trixie-slim

FROM ${NODE_IMAGE} AS build
ENV PNPM_HOME=/pnpm PATH=/pnpm:$PATH CI=true
RUN npm install -g pnpm@10.34.5
WORKDIR /repo

# Fetch from the lockfile alone so dependency layers survive source edits.
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json .npmrc ./
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store pnpm fetch --frozen-lockfile

COPY . .
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
    pnpm install --offline --frozen-lockfile --filter d3auth-server... --filter d3auth-console...
RUN pnpm --filter d3auth-server build && pnpm --filter d3auth-console build
# The release-age policy gates *resolving* new versions, which happens at `pnpm install` on a
# developer's machine. This step reproduces a lockfile that already passed it, so the check is off
# here and only here. `--legacy`: the server has no workspace dependencies to inject.
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
    pnpm --filter d3auth-server deploy --prod --legacy --config.minimum-release-age=0 /out

FROM ${NODE_IMAGE} AS runtime
# pg_dump takes the pre-migration dump at boot (REQ-121) and the backup bundle (ADR-004); pg_restore
# puts either back. The client must be the server's major version: a newer pg_dump reads an older
# server, but a newer pg_restore writes settings the older server refuses (Postgres 17 emits
# `SET transaction_timeout`, which 16 rejects). Found by the first production restore drill.
# Debian's own package follows the distribution (17 on trixie), so this comes from PGDG, whose
# signing key ships inside Debian's postgresql-common — no key is fetched over the network.
ARG POSTGRES_MAJOR=16
RUN apt-get update \
    && apt-get install -y --no-install-recommends postgresql-common ca-certificates \
    && /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y \
    && apt-get install -y --no-install-recommends postgresql-client-${POSTGRES_MAJOR} \
    && rm -rf /var/lib/apt/lists/* \
    && pg_dump --version | grep -q " ${POSTGRES_MAJOR}\." \
    && pg_restore --version | grep -q " ${POSTGRES_MAJOR}\."
ENV NODE_ENV=production PORT=3000 CONSOLE_DIST=/app/public BACKUP_DIR=/backups
WORKDIR /app
# Code stays root-owned so the service user cannot modify it; only /backups is writable.
COPY --from=build /out ./
COPY --from=build /repo/apps/console/dist ./public
RUN mkdir -p /backups && chown node:node /backups
USER node
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=6 \
  CMD ["node", "dist/healthcheck.js"]
CMD ["node", "dist/index.js"]
