# Standalone image for the example relying party. Deliberately not part of the pnpm workspace:
# an example should be copyable into someone else's project without inheriting this repo's build.
FROM node:22-trixie-slim

# Published by CI as ghcr.io/matdemers1/d3-auth/demo:sha-<40hex>; the label lets a deployer check
# that the image it runs is the commit it verified.
ARG REVISION=unknown
LABEL org.opencontainers.image.revision=$REVISION

ENV NODE_ENV=production PORT=4000
WORKDIR /app

# The source is ESM with top-level await, so the image needs its own module type; without it
# tsx transforms to CommonJS and the app will not start.
RUN printf '{\n  "name": "d3auth-express-demo",\n  "private": true,\n  "type": "module"\n}\n' > package.json

# Pinned, and installed directly rather than from the workspace lockfile.
RUN npm install --no-fund --no-audit --no-package-lock \
      express@5.2.1 \
      openid-client@6.8.8 \
      @d3cloudio/auth-client@0.1.1 \
      tsx@4.23.13 \
    && npm cache clean --force

COPY src ./src

USER node
EXPOSE 4000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=5 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:4000/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
CMD ["npx", "tsx", "src/index.ts"]
