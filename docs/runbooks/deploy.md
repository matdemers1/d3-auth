# Deploying D3 Auth to the ZimaOS host

**Host:** ZimaOS at `192.168.1.231` (the same box as Bindery)
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
ssh root@192.168.1.231
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

## 4. The tunnel route

`cloudflared` already runs on this host for Bindery and joins the external `tunnel` network. Add a public hostname in the Cloudflare Zero Trust dashboard (Networks → Tunnels → the Zima tunnel → Public Hostnames):

| Field | Value |
|---|---|
| Subdomain | `auth` |
| Domain | `d3cloud.io` |
| Service | `http://server:3000` |
| HTTP Host Header | `auth.d3cloud.io` |

The DNS record is created by Cloudflare and must stay **proxied** (orange cloud): the origin is only reachable through the tunnel.

`provider.proxy = true`, so the service trusts `X-Forwarded-Proto` and `CF-Connecting-IP`. That is safe only because nothing but the tunnel can reach it — never publish a host port here.

---

## 5. WAF rate rules (REQ-019, R-07)

In the dashboard, Security → WAF → Rate limiting rules, on the `d3cloud.io` zone:

| Rule | Match | Limit | Action |
|---|---|---|---|
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

## 7. The first account

There is no public signup (an anti-feature). Until invites land in Phase 2, create the owner with the seed CLI:

```bash
docker compose exec server node dist/cli/dev-seed.js /conformance/seed.json   # Phase 0 shape
```

Phase 2 replaces this with `d3auth.seed.json` and the invite flow, and Phase 4 with export/import.

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

## 10. If sign-in is down

1. `curl https://auth.d3cloud.io/readyz` — the JSON names which check failed (database, signingKeys, migrations).
2. Red database: `docker compose ps`, then `docker compose logs postgres`.
3. Red signingKeys with a healthy database: the `KEK` is wrong or missing. The service refuses to decrypt rather than mint new keys. Put the right value back; do not "fix" it by deleting the key rows.
4. Apps already signed in keep working — their sessions are their own (consumer contract §2.7). Only new sign-ins are affected.

## See also

- The vault: `D3 Cloud Vault/D3 Auth/Scope of Work.md`, Phase 1; `Architecture.md` L9 for the deploy posture
- `docs/runbooks/` — key rotation, backup and restore, break-glass and upgrade/rollback arrive in Phases 4 and 6
