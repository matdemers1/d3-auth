# syntax=docker/dockerfile:1.7
# Build from the repo root: docker build -f apps/server/Dockerfile .

ARG NODE_IMAGE=node:22-trixie-slim

FROM ${NODE_IMAGE} AS build
ENV PNPM_HOME=/pnpm PATH=/pnpm:$PATH CI=true
RUN npm install -g pnpm@9.15.9
WORKDIR /repo

# Fetch from the lockfile alone so dependency layers survive source edits.
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json .npmrc ./
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store pnpm fetch --frozen-lockfile

COPY . .
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
    pnpm install --offline --frozen-lockfile --filter d3auth-server...
RUN pnpm --filter d3auth-server build
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
    pnpm --filter d3auth-server deploy --prod /out

FROM ${NODE_IMAGE} AS runtime
ENV NODE_ENV=production PORT=3000
WORKDIR /app
# Code stays root-owned so the service user cannot modify it; only /backups is writable.
COPY --from=build /out ./
RUN mkdir -p /backups && chown node:node /backups
USER node
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=6 \
  CMD ["node", "dist/healthcheck.js"]
CMD ["node", "dist/index.js"]
