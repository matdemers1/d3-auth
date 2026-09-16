import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { AdapterFactory, AdapterPayload } from 'oidc-provider';
import { AUDIT_EVENTS } from '../audit/events.js';
import type { AuditWriter } from '../audit/writer.js';
import type { Db } from '../db.js';
import type { Logger } from '../log.js';
import type { SecretHasher } from '../security/hash.js';
import { checkPassword } from '../security/policy.js';

// First-run setup (REQ-141). A freshly deployed instance has no accounts and no way to make one:
// there is no public signup, and invites need an admin to send them. So the browser can claim the
// instance once — and exactly once.
//
// What stops a stranger claiming it first: a setup code, minted at boot only while the user table
// is empty and printed to the server log, which is on the host the operator controls. The screen
// is not merely hidden once an account exists; the endpoint refuses, because the check is "are
// there zero users", asked inside the same transaction that creates the owner.

const KIND = 'D3FirstRunSetup';
const RECORD_ID = 'setup';
/**
 * Crockford base32 without I, L, O and U: no character can be confused for another when read off
 * a terminal and typed on a phone, and nothing in the alphabet collides with the dashes that
 * group it. 20 characters is ~100 bits.
 */
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const CODE_LENGTH = 20;

const hash = (code: string): string => createHash('sha256').update(code).digest('hex');

/** Anything a person might type: spaces, dashes, lower case, and the usual look-alikes. */
export function normaliseCode(input: string): string {
  return input
    .toUpperCase()
    .replace(/[^0-9A-Z]/g, '')
    .replaceAll('I', '1')
    .replaceAll('L', '1')
    .replaceAll('O', '0')
    .replaceAll('U', 'V');
}

function mintCode(): string {
  // Rejection sampling keeps every character equally likely.
  let code = '';
  while (code.length < CODE_LENGTH) {
    for (const byte of randomBytes(CODE_LENGTH)) {
      if (byte >= 248) continue;
      code += ALPHABET.charAt(byte % 32);
      if (code.length === CODE_LENGTH) break;
    }
  }
  return code;
}

const groups = (value: string): string => value.replace(/(.{4})(?=.)/g, '$1-');

export interface FirstRunSetup {
  /** True while the instance has no accounts at all. */
  available(): Promise<boolean>;
  /** Mints and logs the code if the instance is unclaimed. Called once at boot. */
  prepare(): Promise<void>;
  claim(input: ClaimInput): Promise<ClaimResult>;
}

export interface ClaimInput {
  code: string;
  email: string;
  username: string;
  displayName: string;
  password: string;
  ip?: string | undefined;
  userAgent?: string | undefined;
}

export type ClaimResult =
  | { ok: true; userId: string }
  | { ok: false; error: 'already_claimed' | 'bad_code' | 'invalid'; problems?: string[] };

export function createFirstRunSetup(
  db: Db,
  adapterFactory: AdapterFactory,
  hasher: SecretHasher,
  audit: AuditWriter,
  logger: Logger,
): FirstRunSetup {
  const store = adapterFactory(KIND);

  const unclaimed = async (): Promise<boolean> => (await db.user.count()) === 0;

  const storedHash = async (): Promise<string | undefined> => {
    const payload: unknown = await store.find(RECORD_ID);
    return (payload as { codeHash?: string } | undefined)?.codeHash;
  };

  return {
    available: unclaimed,

    async prepare() {
      if (!(await unclaimed())) return;
      const code = mintCode();
      const payload = { codeHash: hash(code) } as unknown as AdapterPayload;
      await store.upsert(RECORD_ID, payload, 0);
      // Deliberately printed in full: this is how the operator gets it, the log lives on their
      // host, and the code is worthless the moment the instance has an account.
      logger.warn(
        { setupCode: groups(code) },
        'This instance has no accounts yet. Open /login/setup and enter the setup code above to create the owner.',
      );
    },

    async claim(input) {
      if (!(await unclaimed())) return { ok: false, error: 'already_claimed' };

      const expected = await storedHash();
      const received = hash(normaliseCode(input.code));
      if (!expected || !timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(received, 'hex'))) {
        logger.warn({ ip: input.ip }, 'first-run setup attempted with the wrong code');
        return { ok: false, error: 'bad_code' };
      }

      const email = input.email.trim().toLowerCase();
      const username = input.username.trim();
      const displayName = input.displayName.trim();
      const problems: string[] = [];
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) problems.push('Enter a valid email address.');
      if (!/^[a-z0-9][a-z0-9._-]{1,30}$/i.test(username)) problems.push('Usernames are 2–31 characters: letters, numbers, dot, dash or underscore.');
      if (displayName.length < 1) problems.push('Enter the name people will see.');
      problems.push(...checkPassword(input.password, { email, username, displayName }).problems);
      if (problems.length > 0) return { ok: false, error: 'invalid', problems };

      const argon2idHash = await hasher.hash(input.password);

      try {
        const user = await db.$transaction(async (tx) => {
          // Asked again inside the transaction: two browsers racing cannot both win.
          await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext('d3auth.first_run'))`;
          if ((await tx.user.count()) > 0) throw new Error('already_claimed');
          const created = await tx.user.create({
            data: { email, username, displayName, kind: 'owner', status: 'active', emailVerified: true },
          });
          await tx.passwordCredential.create({ data: { userId: created.id, argon2idHash } });
          return created;
        });

        await store.destroy(RECORD_ID);
        await audit.write({
          event: AUDIT_EVENTS.ownerClaimed,
          actorUserId: user.id,
          targetType: 'user',
          targetId: user.id,
          ip: input.ip,
          userAgent: input.userAgent,
          detail: { email, username },
        });
        logger.warn({ email, username }, 'owner account created through first-run setup');
        return { ok: true, userId: user.id };
      } catch (err) {
        if (err instanceof Error && err.message === 'already_claimed') return { ok: false, error: 'already_claimed' };
        const message = err instanceof Error ? err.message : '';
        if (message.includes('Unique constraint')) {
          return { ok: false, error: 'invalid', problems: ['That email or username is already taken.'] };
        }
        throw err;
      }
    },
  };
}
