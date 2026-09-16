# Rotating the signing keys

**What this changes:** which key signs the tokens every app verifies. Done wrong, every app
rejects every token at once, and the symptom is "nobody can sign in anywhere".

**How long it takes:** two hours of waiting, twice, and about a minute of typing. Do not
compress the waits. They are the whole procedure.

> [!warning] The failure this avoids
> Apps cache the key set. If a key starts signing before they have fetched it, they reject real
> tokens until their cache expires — and you cannot fix that from here, only wait it out.

---

## The shape of it

```
next ──(2h)──▶ current ──(2h)──▶ retiring ──▶ retired
 │                │                  │
 published,       signs, once        still verifies what
 signs nothing    you restart        it already signed
```

Both waits are `MINIMUM_OVERLAP_MS` in `apps/server/src/oidc/keys.ts` — **two hours**: one hour
of assumed consumer JWKS cache, plus the one-hour ID token lifetime. If you shorten either, the
constant is the only place to change.

The CLI refuses to skip a wait. `--force` exists for one situation, in §5.

---

## 1. Generate the next key

```bash
docker compose exec server node dist/cli/rotate-keys.js --generate
```

It is published in `/oidc/jwks` immediately and signs nothing. That is the point: the clock on
the wait starts when apps can *see* it.

Check it is out there:

```bash
curl -s https://auth.d3cloud.io/oidc/jwks | jq '.keys | map(.kid)'
```

## 2. Wait two hours

Genuinely. The CLI prints the earliest time it will accept a promotion, and refuses before it.

## 3. Promote, then restart

```bash
docker compose exec server node dist/cli/rotate-keys.js --promote
docker compose restart server
```

**The restart is part of the step, not an afterthought.** The service loads its signing keys at
startup: until it restarts, the database says the new key is current and the process is still
signing with the old one. Nothing breaks in between — the old key is still published, so its
tokens still verify — but the rotation is not finished.

The console's Keys screen shows a *restart to finish the rotation* banner for exactly this
window.

Confirm which key is signing:

```bash
docker compose logs server | grep 'provider ready' | tail -1
```

## 4. Wait two hours, then retire

```bash
docker compose exec server node dist/cli/rotate-keys.js --retire
docker compose restart server
```

The old key leaves the key set. Anything it signed has expired by now, which is what the second
wait was for.

## 5. When the key is compromised

Someone else has the private key. Now the calculus inverts: tokens nobody can verify for an hour
beat tokens an attacker can mint.

```bash
docker compose exec server node dist/cli/rotate-keys.js --generate
docker compose exec server node dist/cli/rotate-keys.js --promote --force
docker compose restart server
docker compose exec server node dist/cli/rotate-keys.js --retire --force
docker compose restart server
```

Expect sign-ins to fail at consuming apps until their JWKS caches expire — up to an hour. Tell
people before you do it, not after. Both forced steps are audited as `forced: true`, because the
next person to read the log will want to know this was a decision.

## If something is already wrong

| What you see | What it means | What to do |
|---|---|---|
| Apps reject every token after a promote | They cached the key set before the new key existed | Wait out their cache. Do not rotate again. |
| `provider ready` lists a kid the table calls retiring | The service has not been restarted since the promote | `docker compose restart server` |
| `That key has not been published long enough` | The wait has not passed | Wait. This message is the guard doing its job. |
| `Tokens signed with that key may still be in use` | The second wait has not passed | Wait, or `--force` only if the key is compromised |
| Boot fails with a KEK error | The private keys cannot be decrypted | Not a rotation problem — see R-03 and the deploy runbook. **Rotating will not fix it and may make it worse.** |

## What is audited

`key.generated`, `key.promoted`, `key.retired` — each with the algorithm, and `forced: true`
when a wait was skipped. Read them back with:

```bash
docker compose exec postgres psql -U d3auth -d d3auth \
  -c "select event, target_id, detail, at from audit_event where event like 'key.%' order by id desc limit 10;"
```

## See also

- `docs/runbooks/deploy.md` — the restart itself, and the ZimaOS quirks
- `docs/consumer-contract.md` rule 1 — why apps must use discovery rather than pinning a key
- The vault: `D3 Auth/Risk Register` R-04
