# The sealed second admin

**What it is:** an admin account used for nothing, whose password and authenticator seed are printed once and sealed in an envelope (REQ-123, R-06).
**What it is for:** the only admin cannot sign in — every factor lost at once — and the instance still needs running: somebody's access to approve, a compromised person to suspend, an app to disable, another admin to reset. The sealed admin can do all of that without a shell on the host.
**What it is not for:** recovering the **owner**. No admin can suspend or reset the owner from the console (`owner_protected`), sealed or not — otherwise any admin could take over the instance. The owner's own way back is `break-glass.md`, from the host.
**What makes it safe to keep:** opening it is loud. Every sign-in with this account emails every alert recipient within five minutes (`sealed_admin_used`), and the only correct thing to do after using it is rotate it, which makes the old envelope worthless.

> [!warning] Alerts need mail and a recipient
> The alert is only as good as its delivery. Before sealing, set **Settings → Alerts** recipients
> and send a test from **Settings → Mail**. An alert recipient that is only the owner's own
> address — the person who just lost their phone — still leaves a record, but tells nobody new.

---

## 1. Sealing (at go-live, and after every use)

On the host, with a printer or pen nearby and nobody reading the screen:

```bash
cd /DATA/d3auth
docker compose exec -T server node dist/cli/seal-admin.js --email sealed@<your domain> --name "Sealed admin"
```

- The address must have **no existing account**. It need not receive mail; it is never sent any.
- The command refuses if a sealed admin already exists — use `--rotate` (§3).
- It prints the email, a password, the authenticator seed (and an `otpauth://` URI), and the date. **It is shown once.** Nothing printed is logged or stored readable; the audit trail records only `admin.sealed`.

Then:

1. Write or print the block. If you print, use a printer that keeps no job history, directly attached.
2. Put it in an envelope, sign across the seal, write the date on the outside.
3. Store it where the owner can reach it and a houseguest cannot: a safe, a deposit box, a trusted person's safe.
4. `clear && printf '\033[3J'` — clear the terminal **and** its scrollback. Close the SSH session.
5. Record in your deploy notes: date sealed, where it is, who can reach it.

Do **not** add the seed to an authenticator app "just to check". A seed on a phone is not sealed.

## 2. Using it

1. Open the envelope. Add the seed to an authenticator app on any device you trust (type the seed, or make a QR code of the URI line on a machine you control).
2. Sign in at `https://auth.d3cloud.io/admin` with the email, password and a code.
3. Do only what you came to do. The usual ones:
   - **An admin (not the owner) lost their factors:** People → them → **Reset**. They get a link to set the account up again.
   - **Somebody's account is misbehaving:** People → them → **Suspend**.
   - **An app is compromised:** Apps → it → **Disable**, or rotate its secret.
   - **The owner lost their factors:** nothing here. Keep things running and get the owner back with `break-glass.md` when you can reach the host.
4. Sign out of the sealed account.
5. **Rotate it now** (§3). An envelope that has been opened is not sealed.

Within five minutes, alert recipients get *"The sealed admin account was used"* with the time and address. That email is expected here. Anywhere else, it is an incident.

## 3. Rotating

```bash
docker compose exec -T server node dist/cli/seal-admin.js --email sealed@<your domain> --rotate
```

Rotation, in one go: deletes the password and every factor (TOTP, passkeys), revokes trusted devices, ends every session the account has (the provider's own too), revokes every token it holds, and prints a fresh password and seed. Reseal as §1, destroy the old sheet (shred or burn), and update your notes.

Rotate also when: the envelope's location may have been seen by somebody; the person holding it changes; every year, as a matter of course.

## 4. When the alert arrives and nobody opened the envelope

Somebody has the sealed credentials. Act in this order:

1. Console → **People → Sealed admin → Suspend.** Suspension ends its sessions and revokes its tokens at once.
2. **Audit** → filter by that person: every action it took. An admin can change grants and app settings; undo anything you did not do.
3. Rotate it (§3) — rotation reactivates the account with new credentials, so do it once you have finished reviewing.
4. Ask where the envelope has been. Consider rotating the owner's credentials too.

If you cannot sign in to suspend it, `break-glass.md` gets you in from the host.

## 5. Go-live checklist (REQ-123)

- [ ] Alert recipients set; a test mail arrived
- [ ] `seal-admin` run; envelope sealed, dated and stored
- [ ] Sealed admin signed in **once**, on purpose; the `sealed_admin_used` email arrived
- [ ] Rotated after that sign-in; the rotated envelope is the one stored
- [ ] Location recorded in deploy notes

## See also

- `break-glass.md` — recovery from a shell on the host
- `backup-restore.md` — a restore brings back the sealed admin as it was when the bundle was taken; if you rotated since, rotate again after restoring
- `upgrade-rollback.md`
