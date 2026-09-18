# Express example

A relying party in about a hundred lines: discovery, authorization code + PKCE with `state` and
`nonce`, identity by `(iss, sub)`, its own session cookie, and RP-initiated logout. It is what the
[consumer contract](../../docs/) asks every app to do, written out longhand. Phase 3 replaces the
hand-rolled parts with `@d3cloudio/auth-client`.

## Against the local dev stack

```bash
pnpm dev:up                      # D3 Auth on localhost:3000, seeded with a dev client
pnpm --filter d3auth-express start
open http://localhost:4000
```

## Against a deployed D3 Auth

Register a client first (until the console can, that is the seed CLI on the host), then:

```bash
cp .env.example .env             # issuer, client id and secret, and this app's own base URL
docker compose -f docker-compose.demo.yml up -d --build
```

The app needs a public URL of its own, because the redirect URI must be an exact `https` match for
a confidential client.

| Variable | What it is |
|---|---|
| `D3AUTH_ISSUER` | `https://auth.d3cloud.io` |
| `D3AUTH_CLIENT_ID` | the client id you registered |
| `D3AUTH_CLIENT_SECRET` | shown once when the client was created |
| `BASE_URL` | where this app is reachable, e.g. `https://demo.d3cloud.io` |
