# Deploying D3 Auth to the ZimaOS host

**Host:** ZimaOS at `<zima-lan-ip>` (the same box as Bindery)
**Hostname:** `auth.d3cloud.io`, reached only through the Cloudflare Tunnel — no ports are published on the Zima (REQ-125)
**Deploy:** deliberate `docker compose pull && docker compose up -d`. Nothing auto-updates the service every other app signs in through (REQ-136).

> [!danger] This hostname answers the open internet with a sign-in page
> There is no Cloudflare Access in front of it, exactly as with Bindery. The throttling, password
> policy, CSRF and security headers are load-bearing, not defence in depth.

---

## 0. Two ZimaOS quirks that cost an hour if you meet them cold

Both are copied from Bindery's runbook because they bite every service on this host.

- **`/` is a read-only squashfs.** `/root` cannot be written to even as root. `/etc` and `/DATA` are writable.
- **`HOME=/DATA` for your shell, `HOME=/root` for services.** So `docker login` writes `/DATA/.docker/config.json` while the daemon reads `/root/.docker/`. The symptom is a pull that fails with "tried 5 mirror methods", which reads like a network fault and is a credentials path fault. Fix: `export DOCKER_CONFIG=/DATA/.docker` before any pull.

---

## 1. Secrets, once

Generate on your machine, not on the host, and put all three in the password manager **before** the first boot. Losing `KEK` makes every TOTP secret and signing key unrecoverable (R-03), and no backup contains it.

```bash
openssl rand -base64 32   # KEK
openssl rand -base64 32   # PEPPER
openssl rand -base64 32   # COOKIE_KEYS
```

`/DATA/d3auth/.env` on the host, `chmod 600`:

```ini
ISSUER=https://auth.d3cloud.io
POSTGRES_PASSWORD=<a fourth random value>
KEK=<from the password manager>
PEPPER=<from the password manager>
COOKIE_KEYS=<from the password manager>
OPERATOR_DISPLAY_NAME=Matthew
D3AUTH_TAG=sha-<the commit you are deploying>
```

`COOKIE_KEYS` is comma-separated and rotates by prepending a new value and keeping the old one for a while, so sessions signed with the previous key still verify.

---

## 2. Files on the host

```bash
ssh root@<zima-lan-ip>
mkdir -p /DATA/d3auth && cd /DATA/d3auth
# copy docker-compose.yml and docker-compose.tunnel.yml from the repo
```

Nothing else is needed: migrations run inside the container at boot, after an automatic pre-migration dump (REQ-121).

---

## 3. The image

```bash
export DOCKER_CONFIG=/DATA/.docker           # the quirk from section 0
echo <GHCR PAT with read:packages> | docker login ghcr.io -u matdemers1 --password-stdin
docker compose -f docker-compose.yml -f docker-compose.tunnel.yml pull
```

Images are published by CI from `main` only, after lint, unit, integration, conformance and e2e have passed. Deploy a specific commit by setting `D3AUTH_TAG=sha-<full commit sha>`; `latest` exists but pinning is what makes a rollback trivial.

---

## 4. The tunnel

D3 Auth runs **its own** `cloudflared`, exactly as Bindery does, so neither service can take the
other down. `docker-compose.tunnel.yml` starts it and needs one value in `.env`:

```ini
TUNNEL_TOKEN=<the d3auth tunnel's token>
```

The tunnel is *remotely managed*: its ingress lives in Cloudflare, not in a file on the host.

| Field | Value |
|---|---|
| Tunnel name | `d3auth` |
| Public hostname | `auth.d3cloud.io` |
| Service | `http://server:3000` |
| HTTP Host Header | `auth.d3cloud.io` |

The DNS record is a **proxied** CNAME to `<tunnel-id>.cfargotunnel.com`: the origin is only
reachable through the tunnel. Read the token back at any time with
`GET /accounts/{account}/cfd_tunnel/{tunnel}/token`.

`provider.proxy = true`, so the service trusts `X-Forwarded-Proto` and `CF-Connecting-IP`. That is safe only because nothing but the tunnel can reach it — never publish a host port here.

---

## 5. WAF rate limit (REQ-019, R-07)

`d3cloud.io` is on Cloudflare's **Free** plan: one rate limiting rule, a 10-second window, IP only,
path only. So there is one rule, not the three first planned (ADR-006 in the vault):

| Rule | Match | Limit | Action |
|---|---|---|---|
| `d3auth sign-in, authorize and token` | `starts_with(http.request.uri.path, "/api/interaction/") or http.request.uri.path eq "/oidc/auth" or http.request.uri.path eq "/oidc/token"` | 30 requests / 10 s / IP | Block for 10 s |

No other site on the zone uses those paths, so path-only matching is effectively `auth.d3cloud.io`.
It lives in the zone's `http_ratelimit` entrypoint ruleset (Security → WAF → Rate limiting rules).
The deploy token has no firewall scope; change it in the dashboard or with the account's global key.

It absorbs floods. The in-app throttle (4 free per account, 20 per IP, then doubling) is what protects
an individual account, and it works whether or not Cloudflare is in front.

**Check it** from any machine — the first ~30 answer 400 from the provider, then Cloudflare's 429 for
ten seconds:

```bash
for i in $(seq 1 40); do curl -s -o /dev/null -w "%{http_code} " https://auth.d3cloud.io/oidc/auth; done
```

> [!warning] Block, not challenge, on the sign-in POST
> A challenge page instead of a JSON response breaks sign-in on a phone. If the zone is upgraded and
> the rules are split again, keep sign-in on a limit well above a real person's behaviour, and test it
> from mobile data after any change.

---|---|---|---|
| `d3auth login` | `http.host eq "auth.d3cloud.io" and http.request.uri.path contains "/api/interaction/" and http.request.method eq "POST"` | 20 requests / 10 min / IP | Managed challenge |
| `d3auth token` | `http.host eq "auth.d3cloud.io" and http.request.uri.path eq "/oidc/token"` | 120 requests / 1 min / IP | Block |
| `d3auth authorize` | `http.host eq "auth.d3cloud.io" and http.request.uri.path eq "/oidc/auth"` | 60 requests / 1 min / IP | Managed challenge |

These absorb volume. The in-app throttle (4 free per account, 20 per IP, then doubling) is what protects an individual account, and it works whether or not Cloudflare is in front.

> [!warning] Do not let a bot challenge land on the sign-in POST
> A challenge page instead of a JSON response breaks sign-in on a phone. Keep the first rule on
> *Managed challenge* with a limit well above a real person's behaviour, and test it from mobile
> data after any change.

---

## 6. Start it

```bash
cd /DATA/d3auth
docker compose -f docker-compose.yml -f docker-compose.tunnel.yml up -d
docker compose logs -f server      # expect: migrations applied → provider ready → listening
```

Then, from anywhere:

```bash
curl -sI https://auth.d3cloud.io/.well-known/openid-configuration | grep -i strict-transport
curl -s https://auth.d3cloud.io/.well-known/openid-configuration | jq -r .issuer   # https://auth.d3cloud.io
curl -s -o /dev/null -w '%{http_code}\n' https://auth.d3cloud.io/readyz            # 200
```

The issuer in the discovery document must read `https://auth.d3cloud.io`. If it shows `http://`
or an internal host, the tunnel is not sending `X-Forwarded-Proto`/`Host` — fix that before
anyone signs in, because tokens carry the issuer.

---

## 7. The first account (REQ-141)

There is no public signup (an anti-feature), so a fresh instance is claimed once, from the browser:

```bash
docker compose logs server | grep setupCode
# {"level":"warn",...,"setupCode":"AAYD-60J3-E9DG-12S5-77G8","msg":"This instance has no accounts yet..."}
```

Open `https://auth.d3cloud.io/login/setup`, enter that code with your email, username, display
name and a password, and the owner account is created. The screen then refuses for good: the check
is "does this instance have zero accounts", asked inside the transaction that creates the owner,
so a second claim cannot race it.

The code is minted at boot only while there are no accounts, and only its hash is stored. If you
lose it, restart the service and read the new one. **Claim the instance promptly** — between the
tunnel hostname going live and the claim, anyone who knows the code could claim it, and the code
is in a log only you can read.

Phase 2 adds invites for everyone after the owner; Phase 4 adds export/import and the seed file.

---

## 8. Deploying again

```bash
cd /DATA/d3auth
# edit D3AUTH_TAG in .env to the commit you want
export DOCKER_CONFIG=/DATA/.docker
docker compose -f docker-compose.yml -f docker-compose.tunnel.yml pull
docker compose -f docker-compose.yml -f docker-compose.tunnel.yml up -d
docker compose logs --tail 50 server
```

Migrations run at boot. The pre-migration dump lands in the `backups` volume as
`pre-migration-<timestamp>.dump`.

## 9. Rolling back

```bash
# 1. point D3AUTH_TAG at the previous sha, then
docker compose -f docker-compose.yml -f docker-compose.tunnel.yml up -d
# 2. only if that release migrated the schema, restore the dump it took first:
docker compose exec server sh -c 'ls -t /backups/pre-migration-*.dump | head -1'
docker compose exec server pg_restore --clean --if-exists --no-owner \
  --dbname "$DATABASE_URL" /backups/pre-migration-<timestamp>.dump
```

A rollback that skips step 2 after a schema change will fail readiness rather than serve half a
schema — which is the intended behaviour, not a bug.

## 10. Moving an instance's shape (REQ-072, REQ-057)

The state file describes what this instance *is* — apps, roles, groups, members and who may reach
what. It is not a backup: no client secrets, no password hashes, no passkeys, no signing keys are
in it. That is what makes it safe to keep in version control, and it is also why an instance built
from one is not yet usable until two things are fixed.

```bash
# take one
docker compose exec server node dist/cli/state.js --export > d3auth-state.json

# see what it would do somewhere else — writes nothing
docker compose exec -T server node dist/cli/state.js --import - --dry-run < d3auth-state.json

# do it
docker compose exec -T server node dist/cli/state.js --import - < d3auth-state.json
```

The console does the same three steps under **Export & import**, and the apply is behind a
step-up prompt.

After an import:

1. **Every confidential app is secret pending** (R-11). It has no client secret, so nothing can
   sign in to it. Rotate one on the app's page and give it to the app.
2. **Nobody can sign in yet.** Imported people have no credentials. Invite or reset them — or, if
   the owner is among them, use break-glass (`docs/runbooks/break-glass.md`).

An import only creates and updates. It never deletes, so importing a file that omits an app leaves
that app alone; removing things is done deliberately in the console.

### The seed file

Set `SEED_FILE` to a mounted state file and it is applied on every boot, idempotently. Useful when
the apps an instance should have are part of its configuration rather than something somebody
clicks:

```yaml
# docker-compose.tunnel.yml
    environment:
      SEED_FILE: /config/d3auth.seed.json
    volumes:
      - /DATA/d3auth/d3auth.seed.json:/config/d3auth.seed.json:ro
```

A missing or malformed seed file is logged and the service starts anyway — a seed is a
convenience, not a precondition for serving.

## 10a. Mail and alerts (REQ-106, REQ-114, REQ-115)

Invites, account resets and alerts go out through the **mail relay Worker**, `d3auth-mail-relay`
(`workers/mail-relay`), which sends with Cloudflare Email Sending as `no-reply@no-reply.d3cloud.io`.
`no-reply.d3cloud.io` is onboarded for Email Sending (its `cf-bounce` MX/SPF/DKIM and DMARC records
exist), so it can send to anyone. The binding refuses any other sender, so the relay secret alone
cannot send as another address.

**The Worker** (from `workers/mail-relay`; the scoped d3-qr token has no KV or Email scope, so these
use the account's global key):

```bash
wrangler deploy
printf '%s' "$SECRET" | wrangler secret put RELAY_SECRET     # the server's MAIL_RELAY_SECRET
printf '%s' "you@example.com" | wrangler secret put ALERT_TO # who hears that /readyz is down
```

Every minute it probes `https://auth.d3cloud.io/readyz`: one email after five minutes down, one on
recovery. That is the alert that still arrives when the Zima itself is off.

**The server** — in `/DATA/d3auth/.env`, then `up -d`:

```ini
MAIL_DRIVER=worker
MAIL_RELAY_URL=https://d3auth-mail-relay.<your-subdomain>.workers.dev/send
MAIL_FROM=no-reply@no-reply.d3cloud.io
MAIL_RELAY_SECRET=<the same value as the Worker's RELAY_SECRET>
```

Settings → Mail in the console overrides these when saved; leave it unsaved to keep the container's.

**Alert recipients** live in Settings → Alerts. The rules (refresh-token reuse, someone made admin or
owner, failed-login spikes, mail failures, backup and drill failures, no backup for 36 hours, the
sealed admin signing in) are checked every five minutes and email each recipient at most once an hour
per rule.

**Rotating the relay secret:** generate a new one, `wrangler secret put RELAY_SECRET`, update
`MAIL_RELAY_SECRET` on the host, `up -d`. Mail fails with 401 between the two steps, so do them together.

**Checks:** Settings → Mail → *Send a test message to me* (the Mail tile on Home turns OK); a wrong
secret gets `401` from `/send`.

## 11. If sign-in is down

1. `curl https://auth.d3cloud.io/readyz` — the JSON names which check failed (database, signingKeys, migrations).
2. Red database: `docker compose ps`, then `docker compose logs postgres`.
3. Red signingKeys with a healthy database: the `KEK` is wrong or missing. The service refuses to decrypt rather than mint new keys. Put the right value back; do not "fix" it by deleting the key rows.
4. Apps already signed in keep working — their sessions are their own (consumer contract §2.7). Only new sign-ins are affected.

## See also

- The vault: `D3 Cloud Vault/D3 Auth/Scope of Work.md`, Phase 1; `Architecture.md` L9 for the deploy posture
- `docs/runbooks/` — key rotation, backup and restore, break-glass and upgrade/rollback arrive in Phases 4 and 6
