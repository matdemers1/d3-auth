import { randomBytes } from 'node:crypto';
import type { SecretHasher } from './hash.js';

// Password verification for sign-in (REQ-024, REQ-026, REQ-086).
//
// An unknown email costs exactly as much as a known one: there is always an Argon2id verify,
// against a decoy hash computed at boot from a random secret nobody holds. Callers get a plain
// boolean, so no code path can accidentally answer "no such user".

export interface PasswordVerifier {
  /** True only when `hash` exists and matches. Always performs one Argon2id verification. */
  verify(hash: string | null | undefined, password: string): Promise<boolean>;
}

export async function createPasswordVerifier(hasher: SecretHasher): Promise<PasswordVerifier> {
  const decoyHash = await hasher.hash(randomBytes(32).toString('base64'));

  return {
    async verify(hash, password) {
      const matched = await hasher.verify(hash ?? decoyHash, password);
      return hash ? matched : false;
    },
  };
}
