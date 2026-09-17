# Upgrading and rolling back D3 Auth

**Deploy is manual** (REQ-136): pick a commit, pull its image, restart. Nothing auto-updates the service every other app signs in through.
**Migrations run on boot**, after an automatic `pg_dump` to `/backups/pre-migration-<timestamp>.dump` (REQ-121). A boot that cannot take the dump does not migrate.

> [!warning] Migrations only go forward
> There are no down migrations. Rolling back a release that changed the schema means restoring the
> dump it took before migrating, and losing whatever was written since. That is why step 1 exists.

---

## 1. Before

```bash
cd /DATA/d3auth
export DOCKER_CONFIG=/DATA/.docker
grep D3AUTH_TAG .env                                   # write down the tag you are leaving
docker compose exec postgres psql -U d3auth -d d3auth -Atc \
  'select migration_name from _prisma_migrations order by migration_name desc limit 1'   # the schema revision — write that down too
docker compose exec server node dist/cli/backup.js --now   # an offsite copy, independent of the pre-migration dump
```

Read the release's commits for `prisma/migrations/` changes. A release with none can be rolled back by changing the tag alone.

Pick a quiet moment: sign-ins in progress when the server restarts fail once and succeed on retry, but a person halfway through enrolling a passkey has to start that over.

## 2. Upgrade

```bash
sed -i 's/^D3AUTH_TAG=.*/D3AUTH_TAG=sha-<new commit>/' .env
docker compose -f docker-compose.yml -f docker-compose.tunnel.yml pull server
docker compose -f docker-compose.yml -f docker-compose.tunnel.yml up -d server
docker compose logs -f --tail 50 server    # expect: pre-migration dump → migrations applied → provider ready → listening
```

## 3. Check

In order, and stop at the first failure:

1. `curl -fsS https://auth.d3cloud.io/readyz` is 200, with `database`, `signingKeys` and `migrations` all true, and the query from §1 names the revision you expect.
2. `curl -fsS https://auth.d3cloud.io/oidc/jwks | jq '[.keys[].kid]'` — the same kids as before. A release never changes keys by itself.
3. Sign in to the console with your authenticator.
4. Sign in to Bindery (or `demo.d3cloud.io`) through D3 Auth, end to end.
5. Console home: no new failures in recent activity.

Record the commit and schema revision wherever you keep deploy notes.

## 4. Roll back

### No schema change in the release

```bash
sed -i 's/^D3AUTH_TAG=.*/D3AUTH_TAG=sha-<previous commit>/' .env
docker compose -f docker-compose.yml -f docker-compose.tunnel.yml up -d server
```

### The release migrated the schema

The old image **will boot** on the newer schema: its readiness check only asks that the migrations *it* ships are applied, and they are. Whether it then works depends on the migration:

- **Purely additive** (a new table, a nullable column): changing the tag back is enough. The extra table or column sits unused until you upgrade again.
- **Anything else** (a renamed or dropped column, a new `NOT NULL`, changed constraints): the old code will fail on those queries at runtime, not at boot. Restore the dump the new release took before migrating:

```bash
docker compose stop server
docker compose run --rm --no-deps server sh -c 'ls -t /backups/pre-migration-*.dump | head -3'
docker compose run --rm --no-deps server sh -c \
  'pg_restore --clean --if-exists --no-owner --dbname "$DATABASE_URL" /backups/pre-migration-<timestamp>.dump'
sed -i 's/^D3AUTH_TAG=.*/D3AUTH_TAG=sha-<previous commit>/' .env
docker compose -f docker-compose.yml -f docker-compose.tunnel.yml up -d server
```

Then run §3 again.

> [!danger] What a schema rollback loses
> Everything written between the dump and the restore: sign-ins, sessions (people sign in again),
> audit rows, invites, grants, secret rotations. Audit rows are the ones you cannot recreate. If the
> release ran for long, `pg_dump` the broken database first (`docker compose exec server sh -c 'pg_dump -Fc "$DATABASE_URL" > /backups/broken-<date>.dump'`) so the trail survives somewhere.

## 5. If the new image will not boot at all

- **A configuration error naming `KEK`, `PEPPER` or `COOKIE_KEYS`** — `.env` lost a value. Restore it from the password manager; never generate a new KEK (R-03).
- **`prisma migrate deploy` failed** — the dump is on disk. Prisma marks the failed migration in `_prisma_migrations`; do not retry blindly. Check what was applied (`select migration_name, finished_at, rolled_back_at from _prisma_migrations order by started_at desc limit 3`), restore the dump, roll back the tag, then read the error.
- **`pg_dump` failed before migrating** — the `backups` volume is full or unwritable, or `pg_dump` cannot reach Postgres. Nothing was migrated. Free space; the service will not migrate without that dump, by design.

## See also

- `deploy.md` — first install, and the ZimaOS quirks
- `backup-restore.md` — nightly bundles, the drill, and restoring onto a new host
- `key-rotation.md`
