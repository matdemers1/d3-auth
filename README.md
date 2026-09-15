# D3 Auth

A small, self-hosted OpenID Connect provider with one console for the people who can sign in, the apps they can open, and the roles they hold in each.

**Status: planned, not built.** The full plan lives in the D3 Cloud vault (`D3 Cloud Vault/D3 Auth/`). Nothing here runs yet.

## What it will be
- OpenID Connect provider (authorization code + PKCE only) built on [`oidc-provider`](https://github.com/panva/node-oidc-provider), verified in CI by the OpenID conformance suite.
- Invite-only accounts with password, TOTP and passkeys; trusted devices; admin reset; a host-only break-glass CLI.
- Apps registered from a JSON manifest that declares their roles. Grant a person access to an app and pick their roles; the app receives a `roles` claim containing only its own roles.
- One console on `@d3cloud/ui` for users, apps, groups, sessions, audit, signing keys, settings, export/import.
- Two consumer SDKs: `@d3cloud/auth-client` (TypeScript) and `d3auth-client` (Python/FastAPI), plus runnable examples.
- Designed to be optional: every app keeps its own login and adds *Sign in with D3 Auth* as a configured option.

## Layout
See `CLAUDE.md`.

## Licence
Private until the security gate passes and the reference integration is in production. Intended licence at public release: MIT or Apache-2.0.
