# Backups and restoring D3 Auth

**What runs by itself:** a backup bundle every night at `BACKUP_AT` (02:30 UTC), and a restore drill of it at `DRILL_AT` (03:30 UTC). Both write audit rows (`backup.created`, `backup.failed`, `backup.drill_passed`, `backup.drill_failed`). A failure, or no backup in 36 hours, emails the alert recipients.
**Why it is shaped this way:** ADR-004 — *Backups Leave, the KEK Stays*.

> [!danger] No bundle contains the KEK
> The dump holds every signing key and TOTP secret **sealed under the KEK**. A bundle without the
> KEK restores people, apps and groups, but nobody can sign in with an authenticator and every
> app's tokens stop verifying. The KEK lives in the password manager and in `/DATA/d3auth/.env`,
> and nowhere else (R-03). Before you rely on any of this, open the password manager and look at it.

---

## 1. What is in a bundle

`bundles/YYYY/MM/DD/d3auth-<timestamp>.tar.gz`, in S3 with SSE-KMS, plus the last seven copies in the `backups` volume under `/backups/bundles/`.

| File | What it is |
|------|-----------|
| `database.dump` | `pg_dump -Fc` of the whole database. Secrets inside are sealed or hashed. |
| `state.json` | The export state file (apps, roles, groups, who may reach what). Readable without anything else. |
| `keys.json` | The published **public** keys, so you can tell which kids a bundle should serve. |
| `manifest.json` | Created at, schema revision, KEK fingerprint, key kids, counts, a SHA-256 for every other file. |

The KEK fingerprint is an HMAC under the KEK of a fixed label. It names which KEK opens the bundle without revealing it.

---

## 2. Setting it up, once

### AWS (on your machine, with an admin session: `aws login`)

1. A bucket of its own, e.g. `d3auth-backups-<suffix>`: Block Public Access on, versioning on, default encryption **SSE-KMS** with the key below, bucket key enabled.
2. A customer-managed KMS key, e.g. alias `alias/d3auth-backups`. Key policy: your admin role administers it; the backup user may only `kms:GenerateDataKey` and `kms:Decrypt`.
3. A lifecycle rule: expire objects under `bundles/` after 90 days; expire noncurrent versions after 30.
4. An IAM user `d3auth-backup` with an access key and exactly this policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"], "Resource": "arn:aws:s3:::<bucket>/bundles/*" },
    { "Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::<bucket>", "Condition": { "StringLike": { "s3:prefix": "bundles/*" } } },
    { "Effect": "Allow", "Action": ["kms:GenerateDataKey", "kms:Decrypt"], "Resource": "<key arn>" }
  ]
}
```

No `s3:DeleteObject`: a stolen host credential can add bundles and read them, not erase them. Expiry is the lifecycle rule's job.

### The host

Add to `/DATA/d3auth/.env`, then `up -d`:

```ini
BACKUP_S3_BUCKET=d3auth-backups-<suffix>
BACKUP_S3_REGION=us-east-1
BACKUP_KMS_KEY_ID=<key arn>
AWS_ACCESS_KEY_ID=<d3auth-backup access key>
AWS_SECRET_ACCESS_KEY=<d3auth-backup secret>
# BACKUP_AT=02:30   DRILL_AT=03:30   (UTC, the defaults)
```

Without `BACKUP_S3_BUCKET` the server boots and logs a warning that nothing is being backed up offsite. With a bucket but no key id, it refuses to boot.

Then prove it end to end, straight away rather than tonight:

```bash
cd /DATA/d3auth
docker compose exec server node dist/cli/backup.js --now
docker compose exec server node dist/cli/backup.js --list
docker compose exec server node dist/cli/backup.js --drill
```

The drill prints each step with a tick. The console's home page shows the last backup and the last drill.

---

## 3. When the nightly job fails

The alert email carries the error. The usual causes, in order of likelihood:

| Symptom | Check |
|---------|-------|
| `AccessDenied` / `InvalidAccessKeyId` | The access key was rotated or the policy changed. `aws iam list-access-keys --user-name d3auth-backup`. |
| `KMS.NotFoundException` / `KMS.DisabledException` | The key id in `.env` is wrong, or the key is pending deletion. **Cancel the deletion** — bundles sealed under it are unreadable without it. |
| `pg_dump: server version mismatch` | The Postgres image moved a major version ahead of the server image's client. Pin `postgres:16`. |
| `ENOSPC` | `/tmp` is a tmpfs; the bundle is built there. Check `docker compose exec server df -h /tmp`. |
| No alert, no backup | The container was down at 02:30. `backup_overdue` fires after 36 hours. Take one with `--now`. |

Fix the cause, then `--now` and `--drill`. Both must pass before you call it fixed.

## 4. When the drill fails

A failed drill means **last night's bundle would not have saved you**. The failure names the step:

- **`the KEK on this host is not the one that sealed this bundle`** — somebody changed `KEK` in `.env`. If the service still boots and signs, the running KEK is right and the bundle is from before a change you need to understand. If the service does not boot, restore the old `KEK` from the password manager.
- **`<file> does not match the manifest`** — the object was altered or truncated in transit. Take a new backup; if it recurs, check the bucket for unexpected writers (CloudTrail).
- **`the bundle has no published signing keys`** / **`restored keys ... are not the bundle's ...`** — the database the bundle was taken from had lost or replaced its keys. Treat as an incident: check the audit trail for `key.*` events.
- **`the restored service publishes ...`** — the restore worked but the service built on it disagrees. Usually a migration that changes key handling; run the drill locally against that image.

The drill always drops its `d3auth_drill_<timestamp>` database. If you ever see one left behind (`\l` in psql), the process was killed mid-drill; drop it by hand.

---

## 5. Restoring for real

### 5a. The host is fine, the data is not (bad import, a mistake)

Prefer the **pre-migration dump** if the damage was a release (`upgrade-rollback.md`). Otherwise, restore last night's bundle beside the live database, look at it, then switch:

```bash
cd /DATA/d3auth
docker compose exec server node dist/cli/backup.js --list
docker compose exec postgres createdb -U d3auth d3auth_restored
docker compose exec server sh -c 'node dist/cli/backup.js --restore <key> --into "${DATABASE_URL%/*}/d3auth_restored"'
```

To switch, stop the server, rename the databases, start it:

```bash
docker compose stop server
docker compose exec postgres psql -U d3auth -d postgres -c 'ALTER DATABASE d3auth RENAME TO d3auth_broken' -c 'ALTER DATABASE d3auth_restored RENAME TO d3auth'
docker compose up -d server
```

Keep `d3auth_broken` until you are sure; the audit trail between the bundle and the incident is only in there.

### 5b. The host is gone

1. A new host with Docker, following `deploy.md` §0–§2.
2. `.env` from the password manager — **the same `KEK`, `PEPPER` and `COOKIE_KEYS`**. A new `PEPPER` makes every password fail; a new `COOKIE_KEYS` only signs everybody out.
3. Add the `BACKUP_*` and AWS values above.
4. Start Postgres alone, then restore into the empty database it created:

```bash
docker compose up -d postgres
docker compose run --rm --no-deps server node dist/cli/backup.js --list
docker compose run --rm --no-deps server sh -c 'node dist/cli/backup.js --restore <key> --into "$DATABASE_URL"'
```

`--restore` checks every checksum and the KEK fingerprint **before** it touches the database, and refuses with a sentence if either is wrong.

5. `docker compose -f docker-compose.yml -f docker-compose.tunnel.yml up -d`. Migrations bring the schema up to this image.
6. Check, in this order: `/readyz` is 200; the JWKS kids match `keys.json` in the bundle; you can sign in with your authenticator; Bindery's sign-in works.
7. Anything that happened after the bundle was taken is gone: people invited, grants changed, secrets rotated. Search your notes and the apps' own config for any client secret rotated after the bundle's `createdAt`: the restored instance holds the *old* hash, so that app cannot sign anybody in until you rotate its secret again and update the app.

### 5c. No AWS

The last seven bundles are in the `backups` volume. Copy one out and restore from a directory:

```bash
docker compose cp server:/backups/bundles ./bundles
mkdir -p offline/bundles/local && cp bundles/d3auth-<ts>.tar.gz offline/bundles/local/
docker compose run --rm --no-deps -v "$PWD/offline:/offline:ro" server \
  sh -c 'node dist/cli/backup.js --dir /offline --restore bundles/local/d3auth-<ts>.tar.gz --into "$DATABASE_URL"'
```

A copy of `/backups/bundles` on a disk you keep elsewhere is the cheapest insurance this service has.

---

## See also

- `upgrade-rollback.md` — the pre-migration dump, for a release that went wrong
- `key-rotation.md` — signing keys, and what a restore does to a rotation in progress
- `break-glass.md` — no admin can sign in
- `sealed-admin.md` — the envelope
