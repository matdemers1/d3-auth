# Changelog

Dates are when the work landed on `main` and was deployed. Before v0.1.0 this repository was
private; the entries below summarise how it got here rather than listing every commit.

## v0.1.0 — 2026-09-17

The first public release, under [Apache-2.0](LICENSE). Running in production with Immich and a
reference Express app signing in through it.

### The provider

- Authorization code with PKCE only, on `oidc-provider` 9, Node 22, PostgreSQL 16. ES256 and RS256
  signing keys sealed under a KEK; `alg=none` refused; no dynamic registration, WebFinger or
  wildcard redirect URIs.
- Four OpenID conformance plans in CI — Basic, Config, RP-Initiated Logout, Back-Channel Logout.
  The only PKCE exemption is the suite's own clients on a `.test` issuer (ADR-002).
- Sign-in is a state machine whose only terminal state issues tokens: password, then a second factor
  when the account holds one, with per-account and per-IP throttling that slows attempts and never
  locks anybody out.
- Deny by default: no grant, no sign-in, refused before any interstitial and audited. Per-app
  `roles` claim carrying only that app's roles. Back-channel logout to every app a session was used
  with; revoking access revokes the tokens with it.

### People

- Invite-only accounts; password (Argon2id + pepper, breached-corpus and context-word checks), TOTP,
  passkeys, trusted devices, admin reset, account self-service, suspend.
- Step-up: anything that changes what the system trusts asks the person to prove it is them again.
- A host-only break-glass CLI that mints a one-time window rather than a standing key (ADR-003), and
  a sealed second admin whose credentials are printed once and whose use raises an alert.

### The console

- People, groups, apps, access, sessions, audit, signing keys, settings, export/import, and a home
  page whose tiles say what to do rather than only what is wrong.
- Rebuilt on `@d3cloud/ui` 1.1's app shell and page patterns: sidebar, account menu, System/Light/Dark
  theme, and a strict CSP with no `'unsafe-inline'` — the theme script allowed by hash, runtime
  styles by a per-response nonce.
- The console signs in through a built-in first-party client, so the address bar alone is enough to
  reach it (ADR-005).
- App presets: pick a known app, give its address, and D3 Auth registers everything on its side and
  shows exactly what to paste into that app's settings, in its own field names. Immich is the first.
  Every app has a connection sheet derived from the provider's own configuration.
- Registering an app grants the owner its highest role by default, so the first sign-in is not
  refused (ADR-007).

### Operations

- Migrations run on boot after an automatic pre-migration dump; readiness stays false until they
  succeed.
- Nightly backup bundle — database dump, state file, public keys, manifest with checksums and a KEK
  fingerprint — to S3 with SSE-KMS, and a nightly **restore drill** that restores it into a throwaway
  database, decrypts the signing keys, and boots a second service against it. The bundle never
  contains the KEK (ADR-004).
- Alert rules that read the audit trail — refresh-token reuse, someone made admin or owner,
  failed-login spikes, mail failures, backup and drill failures, no backup in 36 hours, the sealed
  admin signing in — and a Cloudflare Worker that watches `/readyz` from outside and emails when the
  host itself is down.
- Runbooks for deploy, upgrade and rollback, backup and restore, key rotation, break-glass and the
  sealed admin.

### Security gate

Nineteen defects found and fixed by attacking the project's own work, four of them High: an import
path that could make a factorless account an admin; revoked grants leaving tokens alive; an SDK that
did not verify ID token signatures; back-channel logout that could be pointed at a private address.
Each fixed with a test that fails without the fix. Plus an adversarial suite (74 attacks), an ASVS
5.0 L2 self-assessment with no open failure, Semgrep at zero with custom rules, and a nightly
authenticated ZAP scan with no High.

### Known limits

- Not certified by the OpenID Foundation; the conformance plans are run, not submitted.
- One operator, one instance: no multi-tenancy, no organisations.
- `@d3cloudio/auth-client` and `d3auth-client` are installed from this repository; neither is published
  to npm or PyPI yet.
