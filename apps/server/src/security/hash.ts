import argon2 from 'argon2';

// Argon2id at the OWASP minimum (19 MiB, t=2, p=1) with a pepper held outside the database
// (REQ-024). Used for passwords and client secrets. T-1.2 adds the decoy verify for unknown accounts.

export const ARGON2_PARAMS = { type: argon2.argon2id, memoryCost: 19_456, timeCost: 2, parallelism: 1 } as const;

export interface SecretHasher {
  hash(value: string): Promise<string>;
  verify(hash: string, value: string): Promise<boolean>;
}

export function createSecretHasher(pepper: Buffer): SecretHasher {
  const secret = Buffer.from(pepper);
  return {
    hash: (value) => argon2.hash(value, { ...ARGON2_PARAMS, secret }),
    async verify(hash, value) {
      try {
        return await argon2.verify(hash, value, { secret });
      } catch {
        // A malformed stored hash is a failed verification, never a thrown 500.
        return false;
      }
    },
  };
}
