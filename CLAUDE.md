# CLAUDE.md — D3 Auth

Self-hosted OpenID Connect provider with one console for users, apps, groups and per-app roles. Optional "Sign in with D3 Auth" for D3 Cloud apps; Bindery is the reference relying party. Read this file, then the vault, before writing code.

## Where the plan lives
All planning is in the Obsidian vault: `../D3 Cloud Vault/D3 Auth/`.
- **Scope of Work.md** — phases P0–P7, every task with REQ ids; check tasks off as they land.
- **Requirements Register.md** — REQ-001…REQ-140, the traceability spine.
- **Architecture.md**, **Data Model.md**, **API Contract.md**, **UX Flows & Screen Inventory.md**, **Glossary.md**.
- **ADR-001** — why `oidc-provider` on Node 22, not Python/Authlib.
- **ADR-002** — conformance profile: test-only PKCE exemption; `SameSite=Lax` kept over POST authorization; expected-results register.
- **Risk Register.md**, **Test Strategy.md**, **Phase Plans/** — open the phase plan before starting a phase.
Start a session with `/start-development d3-auth`.

## Stack (locked)
Node 22 (ESM, TypeScript strict) · Express · `oidc-provider` 9.x · Prisma + PostgreSQL 16 · React 19 + Vite + `@d3cloud/ui` (console served as statics by the server) · `@simplewebauthn/server` 14 · `otpauth` 9 · `argon2` · Vitest · Playwright · pnpm workspaces.

## Layout
```
apps/server            provider + interaction UI routes + console/account API + CLI (recover, backup, export, import, seed, rotate-keys)
apps/console           React app: /login/* (phone-first), /account/*, /admin/*
packages/auth-client   @d3cloud/auth-client (TS SDK + React button)
packages/auth-client-python   d3auth-client (Authlib Starlette wrapper for FastAPI)
workers/mail-relay     Cloudflare Worker: POST /send via send_email; cron readiness probe
examples/              express (dual-login), fastapi, ios
conformance/           OpenID conformance suite harness (runs in CI)
docs/runbooks          deploy, key-rotation, backup-restore, break-glass, upgrade-rollback
```

## Commands (once scaffolded per Phase 0)
```bash
pnpm install
pnpm dev:up                          # writes .env if missing, builds, migrates, seeds dev user + client; loopback 5432/3000
pnpm example:flow                    # code + PKCE flow against the dev stack, prints the ID token
pnpm dev:down
# docker-compose.yml has no host ports; Zima adds docker-compose.tunnel.yml, never the dev overlay
pnpm lint && pnpm typecheck && pnpm test   # lint → unit (what CI runs)
DATABASE_URL=postgresql://d3auth:d3auth@127.0.0.1:5432/d3auth_test pnpm --filter d3auth-server test:integration   # *_test DBs only
./conformance/run.sh                  # Basic + Config OP plans; KEEP_STACK=1 to inspect https://localhost.emobix.co.uk:8443
pnpm e2e
```

## Non-negotiables
- **Never bypass the provider's validation.** No custom redirect matching, no PKCE exceptions for any real client (the only exemption is ADR-002's conformance-suite clients, refused by config on anything but a `.test` issuer), no `alg` other than ES256/RS256, no `alg=none`.
- **Login is a state machine.** Only the `complete` state calls `interactionFinished`. No boolean "MFA pending" flags.
- **Deny by default.** No grant → `access_denied` before any interstitial, audited. This is the never-regress invariant.
- **Link identities by `(iss, sub)`** in every SDK and example. Never by email.
- **Roles claim is per-app.** A token never reveals another app's roles. Groups never appear in tokens.
- **Secrets at rest**: Argon2id + pepper for passwords; AES-256-GCM under `KEK` for TOTP secrets and signing keys; hashed client secrets shown once. Boot refuses without `KEK`, `PEPPER`, `COOKIE_KEYS`.
- **Every mutation and auth event writes an audit row.** Logs never contain tokens, secrets, passwords or codes.
- **Anti-features**: no dynamic client registration, no WebFinger, no wildcard redirect URIs, no telemetry, no social login, no public signup.
- **Throttle before hashing**: per-account 4 free → doubling to 10 min (soft, never lockout); per-IP (`CF-Connecting-IP`) 20 free → doubling.
- **Cookies**: `__Host-` prefix, `Secure; HttpOnly; SameSite=Lax; Path=/` — set the provider cookie path to `/`, not the mount path. One exception: the provider pins the interaction *resume* cookie's path to the resume URL, so it is `__Secure-d3auth_resume`.
- **No host ports.** Cloudflare Tunnel only; `provider.proxy = true`.
- **Deploy is manual** pull-and-restart on Zima from GHCR; migrations run on boot after a pre-migration dump.
- **No time estimates** anywhere. T-shirt sizes only.
- **No Co-Authored-By** or AI attribution in commits.

## Security gate (Phase 5) — exit evidence
Conformance suite (Basic, Config, RP-Initiated + Back-Channel Logout) green in CI · adversarial suite green · ASVS 5.0 L2 self-assessment (V6/V7/V9/V10) in the vault · Semgrep zero · ZAP no High. The repo does not go public before this passes and Bindery Phase 20 is in production.

## Conventions
- Update the vault SOW as tasks land; write an ADR for any deviation from the plan.
- `d3-check-usage` runs on the console: no raw hex, no shadows, tokens only.
- Copy sounds like a person; the operator display name is configurable.
