import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { AdapterFactory, AdapterPayload } from 'oidc-provider';
import { AUDIT_EVENTS } from '../audit/events.js';
import type { AuditWriter } from '../audit/writer.js';
import type { Db } from '../db.js';
import type { SessionControl } from '../security/sessions.js';
import type { TrustedDevices } from '../security/trusted-device.js';

// Break-glass (REQ-122). The last admin has lost the phone that holds their only factor: they
// still know their password, but nothing can answer the second step.
//
// Someone with a shell on the host runs `recover --user <email> --minutes N`. That prints a link.
// Opening the link clears that account's factors and trusted devices and *arms* the account: for
// the next N minutes it signs in with the password alone, and the sign-in carries `amr:
// ["pwd","recovery"]` so the audit trail says plainly that a door was opened.
//
// The link is deliberately not a way in by itself. It is printed on a terminal, and terminals
// end up in scrollback, screenshots and shell history — a link that signed somebody in on its
// own would turn all of those into the owner's account. Requiring the password as well means
// break-glass needs the host *and* something only the owner knows. ADR-003 records the
// deviation from REQ-122's original wording.

const RECOVERY_KIND = 'D3Recovery';
const ARMED_KIND = 'D3RecoveryArmed';

export const DEFAULT_MINUTES = 15;
export const MAX_MINUTES = 60;

const hashOf = (token: string): string => createHash('sha256').update(token).digest('hex');

const sameHash = (a: string, b: string): boolean => {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  return left.length === right.length && timingSafeEqual(left, right);
};

export interface ArmedRecovery {
  url: string;
  expiresAt: Date;
  minutes: number;
}

export interface ClaimResult {
  ok: boolean;
  email?: string;
  expiresAt?: Date;
  factorsCleared?: number;
}

export interface Recovery {
  /** Mints the one-time link. Run from the host, never from the console. */
  mint(input: { email: string; minutes?: number }): Promise<ArmedRecovery>;
  /** Opening the link: clears the factors and arms the account. Works once. */
  claim(token: string): Promise<ClaimResult>;
  /** Is this account allowed to sign in with the password alone right now? */
  armed(userId: string): Promise<boolean>;
  /** Called once the recovered sign-in completes, so the window does not outlive its use. */
  spend(userId: string): Promise<void>;
}

export interface RecoveryDeps {
  db: Db;
  adapterFactory: AdapterFactory;
  audit: AuditWriter;
  sessions: SessionControl;
  trustedDevices: TrustedDevices;
  issuer: string;
}

export function createRecovery({ db, adapterFactory, audit, sessions, trustedDevices, issuer }: RecoveryDeps): Recovery {
  const links = adapterFactory(RECOVERY_KIND);
  const armed = adapterFactory(ARMED_KIND);

  return {
    async mint({ email, minutes = DEFAULT_MINUTES }) {
      const window = Math.min(Math.max(Math.trunc(minutes), 1), MAX_MINUTES);
      const user = await db.user.findUnique({ where: { email: email.trim().toLowerCase() }, select: { id: true, email: true } });
      if (!user) throw Object.assign(new Error(`No account for ${email}`), { code: 'no_such_user' });

      const token = randomBytes(32).toString('base64url');
      const expiresAt = new Date(Date.now() + window * 60 * 1000);
      const payload = { userId: user.id, tokenHash: hashOf(token), minutes: window } as unknown as AdapterPayload;
      await links.upsert(hashOf(token), payload, window * 60);

      await audit.write({
        event: AUDIT_EVENTS.recoveryMinted,
        targetType: 'user',
        targetId: user.id,
        detail: { email: user.email, minutes: window, by: 'host' },
      });
      return { url: `${issuer}/login/recover/${token}`, expiresAt, minutes: window };
    },

    async claim(token) {
      const key = hashOf(token.trim());
      const found = (await links.find(key)) as { userId?: string; tokenHash?: string; minutes?: number } | undefined;
      if (!found?.userId || !found.tokenHash || !sameHash(found.tokenHash, key)) return { ok: false };
      await links.destroy(key);

      const user = await db.user.findUnique({ where: { id: found.userId }, select: { id: true, email: true, status: true } });
      if (!user || user.status === 'suspended') return { ok: false };

      // Forced re-enrolment: the factors that could not be used are gone, and so is anything
      // that would let a browser skip the step they are about to set up again.
      const [passkeys, codes] = await db.$transaction([
        db.webauthnCredential.deleteMany({ where: { userId: user.id } }),
        db.totpCredential.deleteMany({ where: { userId: user.id } }),
      ]);
      await trustedDevices.revokeAll(user.id);
      await sessions.revokeAll(user.id);

      // The window the link was minted with, counted from the moment it was opened.
      const minutes = found.minutes ?? DEFAULT_MINUTES;
      const expiresAt = new Date(Date.now() + minutes * 60 * 1000);
      await armed.upsert(user.id, { userId: user.id }, minutes * 60);

      await audit.write({
        event: AUDIT_EVENTS.recoveryClaimed,
        actorUserId: user.id,
        targetType: 'user',
        targetId: user.id,
        detail: { email: user.email, passkeysCleared: passkeys.count, totpCleared: codes.count },
      });
      return { ok: true, email: user.email, expiresAt, factorsCleared: passkeys.count + codes.count };
    },

    async armed(userId) {
      const found = (await armed.find(userId)) as { userId?: string } | undefined;
      return found?.userId === userId;
    },

    async spend(userId) {
      await armed.destroy(userId);
    },
  };
}
