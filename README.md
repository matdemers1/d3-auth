# D3 Auth

A small, self-hosted OpenID Connect provider with one console for the people who can sign in, the
apps they can open, and the roles they hold in each. It is meant for a handful of self-hosted apps
and the people you actually know: a household, a workshop, a small team.

Every app keeps its own login. D3 Auth is the *optional* second button — *Sign in with D3 Auth* —
so adopting it is never all-or-nothing, and losing it never locks anybody out of everything.

Running in production since September 2026 behind a Cloudflare Tunnel on a home server, with
[Immich](https://immich.app) and a reference Express app signing in through it.

## What it does

- **OpenID Connect provider**, authorization code with PKCE only, built on
  [`oidc-provider`](https://github.com/panva/node-oidc-provider). Four
  [OpenID conformance](https://openid.net/certification/) plans run in CI on every push: Basic,
  Config, RP-Initiated Logout, Back-Channel Logout. (Run, not certified — no certification is claimed.)
- **Invite-only accounts.** Password (Argon2id, peppered, checked against a breached-password
  corpus), TOTP, passkeys, trusted devices, admin reset, and a host-only break-glass CLI for the day
  the only admin loses their phone.
- **Apps from a manifest** that declares their roles. Give a person access to an app, pick their
  roles, and that app's tokens carry a `roles` claim containing **only its own roles**. No app ever
  learns what else somebody can open.
- **Deny by default.** No grant, no sign-in — refused before any consent screen, and audited.
- **Presets for known apps.** Pick Immich, give its address, and D3 Auth registers everything on its
  side and shows exactly what to paste into Immich's own settings, field by field, in Immich's words.
  Every app also gets a *connection sheet*: issuer, discovery URL, signing algorithm, scopes, the
  roles claim, redirect URIs — each value copyable, derived from how this instance is actually set up.
- **A console** for people, groups, apps, sessions, the audit trail, signing keys, settings, and
  export/import — desktop and phone, light and dark, built on
  [`@d3cloud/ui`](https://github.com/matdemers1/d3-design-system).
- **Operations that are not an afterthought.** Signing keys rotate through
  `next → current → retiring`; nightly backup bundles go offsite encrypted, and a **restore drill**
  restores last night's bundle into a throwaway database, decrypts the keys with the host's KEK, and
  boots a second copy of the service against it. Alert rules read the audit trail and email you;
  a Cloudflare Worker watches `/readyz` from outside, so the alert still arrives when the host is off.
- **Two SDKs and runnable examples**: `@d3cloudio/auth-client` (TypeScript, with a React button) and
  `d3auth-client` (Python/FastAPI), plus Express, FastAPI and iOS examples.

## What it refuses to do

These are decisions, not gaps:

- **No dynamic client registration, no WebFinger, no wildcard redirect URIs.** Clients exist only
  through the console or a seed file.
- **No self-service signup.** Invite-only is the posture, not a toggle.
- **No social login.** D3 Auth holds identities; it does not broker other people's.
- **No telemetry, no phone-home, no update check** that would tell anybody this instance exists.
- **No `alg=none`, no unsigned ID tokens, no PKCE exemptions** outside the conformance suite's own
  clients on a `.test` issuer.
- **No multi-tenancy.** One instance, one operator, one set of people.

## Quick start

Needs Docker and a domain that reaches the machine over HTTPS (a tunnel, or a reverse proxy).
`ISSUER` must be the public address; only a loopback issuer may be plain HTTP.

```bash
git clone https://github.com/matdemers1/d3-auth.git && cd d3-auth
cp .env.example .env

# three secrets, and a database password
for key in KEK PEPPER COOKIE_KEYS POSTGRES_PASSWORD; do
  printf '%s=%s\n' "$key" "$(openssl rand -base64 32)"
done   # paste into .env, and set ISSUER

docker compose up -d
docker compose logs server | grep setupCode    # the one-time first-run code
```

Open `https://your-issuer/login/setup`, enter that code, and claim the owner account. Then register
your first app — **Apps → Add an app** — and give somebody access.

> **Keep the KEK.** It wraps every TOTP secret and signing key at rest, and **no backup contains
> it**. Lose it and those are unrecoverable. Put it in a password manager before the first boot.

Full install, deploy, rollback, backup, break-glass and key-rotation procedures are in
[`docs/runbooks/`](docs/runbooks/). What an app needs from D3 Auth, and what D3 Auth expects of an
app, is in [`docs/consumer-contract.md`](docs/consumer-contract.md).

## Connecting an app

Every app is configured with: the issuer, its client id and secret, `client_secret_basic`, ID tokens
signed **ES256**, PKCE required (`S256`), the scopes it needs (`openid profile email`, plus
`d3:roles` for roles), and its redirect URIs. The console's connection sheet lists all of it with
copy buttons, so none of it has to be remembered — including the settings whose defaults elsewhere
(RS256, `client_secret_post`) fail against D3 Auth without saying why.

## Security

The repo did not go public until a security gate passed: the four conformance plans, an adversarial
test suite (74 attacks in five classes, plus SDK and login-CSRF cases), an
[ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/) Level 2
self-assessment of V6, V7, V9 and V10 with no open failure, Semgrep at zero findings with custom
rules, and a nightly authenticated ZAP scan with no High. The gate found and fixed nineteen defects,
four of them High — the kind that only appear when you attack your own work.

Please report anything you find privately: see [SECURITY.md](SECURITY.md).

## Development

```bash
pnpm install
pnpm dev:up            # postgres + server on loopback, migrated and seeded
pnpm example:flow      # a full code+PKCE flow, printing the ID token
pnpm lint && pnpm typecheck && pnpm test
DATABASE_URL=postgresql://d3auth:d3auth@127.0.0.1:5432/d3auth_test pnpm --filter d3auth-server test:integration
pnpm e2e               # Playwright, phone and desktop, with an axe sweep
./conformance/run.sh   # the four OpenID conformance plans
```

Node 22, TypeScript strict, PostgreSQL 16, pnpm workspaces. Repository layout and the conventions
this code is held to are in [`CLAUDE.md`](CLAUDE.md).

This is a personal project shared in the hope it is useful. Issues and questions are welcome;
please open one before a large pull request, so nobody wastes an afternoon.

## Licence

[Apache-2.0](LICENSE).
