import { createHash, generateKeyPairSync, type JsonWebKey } from 'node:crypto';
import type { Db } from '../db.js';
import type { Prisma } from '../generated/prisma/client.js';
import type { KekCrypto } from '../security/kek.js';

// Signing keys live in the database, private halves sealed under the KEK (REQ-006, REQ-117).
// First boot generates one `current` key per algorithm:
//   ES256 — the default for every client.
//   RS256 — OpenID Connect Core requires it in discovery, so it exists and is available.
// Rotation (`next → current → retiring → retired`) arrives in T-4.3.

export const SIGNING_ALGS = ['ES256', 'RS256'] as const;
export type SigningAlg = (typeof SIGNING_ALGS)[number];

export interface PrivateJwk extends JsonWebKey {
  kid: string;
  alg: SigningAlg;
  use: 'sig';
}

const PUBLISHED_STATUSES = ['current', 'next', 'retiring'] as const;
const STATUS_ORDER: Record<(typeof PUBLISHED_STATUSES)[number], number> = { current: 0, next: 1, retiring: 2 };

/** RFC 7638 thumbprint over the required public members. */
export function jwkThumbprint(jwk: JsonWebKey): string {
  const members =
    jwk.kty === 'EC'
      ? { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }
      : { e: jwk.e, kty: jwk.kty, n: jwk.n };
  return createHash('sha256').update(JSON.stringify(members)).digest('base64url');
}

function generate(alg: SigningAlg): { privateJwk: PrivateJwk; publicJwk: JsonWebKey } {
  const { privateKey, publicKey } =
    alg === 'ES256'
      ? generateKeyPairSync('ec', { namedCurve: 'P-256' })
      : generateKeyPairSync('rsa', { modulusLength: 3072 });
  const pub = publicKey.export({ format: 'jwk' });
  const kid = jwkThumbprint(pub);
  return {
    privateJwk: { ...privateKey.export({ format: 'jwk' }), kid, alg, use: 'sig' },
    publicJwk: { ...pub, kid, alg, use: 'sig' },
  };
}

const sealContext = (kid: string): string => `signing_key:${kid}`;

/**
 * Loads the published signing keys, generating any missing `current` key first.
 * Returned private JWKs are ordered current-first, which is the order oidc-provider signs with.
 */
export async function loadSigningKeys(db: Db, kek: KekCrypto): Promise<PrivateJwk[]> {
  await db.$transaction(async (tx) => {
    // Serialise first-boot generation if two processes start together.
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext('d3auth.signing_key.bootstrap'))`;
    for (const alg of SIGNING_ALGS) {
      const existing = await tx.signingKey.findFirst({ where: { alg, status: 'current' } });
      if (existing) continue;
      const { privateJwk, publicJwk } = generate(alg);
      await tx.signingKey.create({
        data: {
          kid: privateJwk.kid,
          alg,
          status: 'current',
          publicJwk: JSON.parse(JSON.stringify(publicJwk)) as Prisma.InputJsonObject,
          privateJwkEncrypted: kek.encrypt(Buffer.from(JSON.stringify(privateJwk)), sealContext(privateJwk.kid)),
        },
      });
      await tx.auditEvent.create({
        data: { event: 'key.generated', targetType: 'signing_key', targetId: privateJwk.kid, detail: { alg, status: 'current' } },
      });
    }
  });

  const rows = await db.signingKey.findMany({ where: { status: { in: [...PUBLISHED_STATUSES] } } });
  rows.sort((a, b) => STATUS_ORDER[a.status as keyof typeof STATUS_ORDER] - STATUS_ORDER[b.status as keyof typeof STATUS_ORDER]);

  return rows.map((row) => {
    const jwk = JSON.parse(kek.decrypt(row.privateJwkEncrypted, sealContext(row.kid)).toString('utf8')) as PrivateJwk;
    if (jwk.kid !== row.kid) throw new Error(`Signing key ${row.kid} decrypted to a different kid`);
    return jwk;
  });
}
