import { createHash, generateKeyPairSync, type JsonWebKey } from 'node:crypto';
import type { Db } from '../db.js';
import type { Prisma } from '../generated/prisma/client.js';
import type { KekCrypto } from '../security/kek.js';

// Signing keys live in the database, private halves sealed under the KEK (REQ-006, REQ-117).
// First boot generates one `current` key per algorithm:
//   ES256 — the default for every client.
//   RS256 — OpenID Connect Core requires it in discovery, so it exists and is available.
//
// Rotation is four states and two waits (REQ-118):
//
//   next → current → retiring → retired
//
// A `next` key is published in JWKS but signs nothing, so consumers can fetch it *before* they
// ever see a token from it. Promoting makes it `current` and pushes the old one to `retiring`,
// which keeps verifying tokens that are already out there. Retiring removes it from JWKS.
//
// Both waits exist for the same reason (R-04): a consumer caches JWKS, and a token lives a
// while. Promote too soon and a consumer that cached the old key set rejects real tokens; retire
// too soon and tokens signed minutes ago stop verifying. The minimum below is the sum of the
// worst cases we know: an hour of consumer cache, plus our longest signed-token lifetime.

export const SIGNING_ALGS = ['ES256', 'RS256'] as const;
export type SigningAlg = (typeof SIGNING_ALGS)[number];

export interface PrivateJwk extends JsonWebKey {
  kid: string;
  alg: SigningAlg;
  use: 'sig';
}

const PUBLISHED_STATUSES = ['current', 'next', 'retiring'] as const;

/** An hour of consumer JWKS cache, plus the ID token's hour. Documented in the runbook. */
export const MINIMUM_OVERLAP_MS = 2 * 60 * 60 * 1000;
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

export interface KeySummary {
  kid: string;
  alg: string;
  status: 'next' | 'current' | 'retiring' | 'retired';
  createdAt: Date;
  retireAfter: Date | null;
  /** True once the wait has passed and the next step is allowed. */
  ready: boolean;
  /** When it will be, for a screen that has to explain why a button is disabled. */
  readyAt: Date | null;
}

export class KeyError extends Error {
  constructor(
    readonly code: 'no_next_key' | 'too_soon' | 'already_pending' | 'nothing_to_retire',
    message: string,
  ) {
    super(message);
    this.name = 'KeyError';
  }
}

const summarise = (row: { kid: string; alg: string; status: string; createdAt: Date; retireAfter: Date | null }, now: Date): KeySummary => {
  const readyAt =
    row.status === 'next'
      ? new Date(row.createdAt.getTime() + MINIMUM_OVERLAP_MS)
      : row.status === 'retiring'
        ? row.retireAfter
        : null;
  return {
    kid: row.kid,
    alg: row.alg,
    status: row.status as KeySummary['status'],
    createdAt: row.createdAt,
    retireAfter: row.retireAfter,
    ready: readyAt !== null && readyAt <= now,
    readyAt,
  };
};

/** Every key and where it is in its life, newest first. */
export async function listKeys(db: Db, now = new Date()): Promise<KeySummary[]> {
  const rows = await db.signingKey.findMany({ orderBy: { createdAt: 'desc' } });
  return rows.map((row) => summarise(row, now));
}

/**
 * Mints the key that will sign next. It appears in JWKS immediately and signs nothing, which is
 * what gives consumers time to see it before they have to trust it.
 */
export async function generateNext(db: Db, kek: KekCrypto, alg: SigningAlg): Promise<KeySummary> {
  const pending = await db.signingKey.findFirst({ where: { alg, status: 'next' } });
  if (pending) throw new KeyError('already_pending', `There is already a next ${alg} key waiting to be promoted.`);

  const { privateJwk, publicJwk } = generate(alg);
  const created = await db.signingKey.create({
    data: {
      kid: privateJwk.kid,
      alg,
      status: 'next',
      publicJwk: JSON.parse(JSON.stringify(publicJwk)) as Prisma.InputJsonObject,
      privateJwkEncrypted: kek.encrypt(Buffer.from(JSON.stringify(privateJwk)), sealContext(privateJwk.kid)),
    },
  });
  await db.auditEvent.create({
    data: { event: 'key.generated', targetType: 'signing_key', targetId: created.kid, detail: { alg, status: 'next' } },
  });
  return summarise(created, new Date());
}

/**
 * Makes the waiting key the signing key.
 *
 * `force` is for one situation only: the current key is compromised, and serving tokens nobody
 * can verify for an hour beats serving tokens signed by a key somebody else holds.
 */
export async function promoteNext(
  db: Db,
  alg: SigningAlg,
  options: { force?: boolean; now?: Date } = {},
): Promise<{ promoted: KeySummary; retiring: string | null }> {
  const now = options.now ?? new Date();
  const next = await db.signingKey.findFirst({ where: { alg, status: 'next' } });
  if (!next) throw new KeyError('no_next_key', `There is no next ${alg} key. Generate one first.`);

  const readyAt = new Date(next.createdAt.getTime() + MINIMUM_OVERLAP_MS);
  if (!options.force && readyAt > now) {
    throw new KeyError(
      'too_soon',
      `That key has not been published long enough. Consumers cache the key set; promoting now would make real tokens fail to verify. Ready at ${readyAt.toISOString()}.`,
    );
  }

  const current = await db.signingKey.findFirst({ where: { alg, status: 'current' } });
  await db.$transaction(async (tx) => {
    if (current) {
      // It keeps verifying what it already signed until the wait passes.
      await tx.signingKey.update({
        where: { kid: current.kid },
        data: { status: 'retiring', retireAfter: new Date(now.getTime() + MINIMUM_OVERLAP_MS) },
      });
    }
    await tx.signingKey.update({ where: { kid: next.kid }, data: { status: 'current' } });
    await tx.auditEvent.create({
      data: {
        event: 'key.promoted',
        targetType: 'signing_key',
        targetId: next.kid,
        detail: { alg, retiring: current?.kid ?? null, forced: options.force === true },
      },
    });
  });

  const promoted = await db.signingKey.findUniqueOrThrow({ where: { kid: next.kid } });
  return { promoted: summarise(promoted, now), retiring: current?.kid ?? null };
}

/** Removes a retiring key from JWKS, once nothing it signed can still be in use. */
export async function retire(db: Db, options: { kid?: string; force?: boolean; now?: Date } = {}): Promise<KeySummary[]> {
  const now = options.now ?? new Date();
  const candidates = await db.signingKey.findMany({
    where: { status: 'retiring', ...(options.kid ? { kid: options.kid } : {}) },
  });
  if (candidates.length === 0) throw new KeyError('nothing_to_retire', 'No key is retiring.');

  const due = options.force ? candidates : candidates.filter((key) => key.retireAfter !== null && key.retireAfter <= now);
  if (due.length === 0) {
    const soonest = candidates
      .map((key) => key.retireAfter)
      .filter((at): at is Date => at !== null)
      .sort((a, b) => a.getTime() - b.getTime())[0];
    throw new KeyError(
      'too_soon',
      `Tokens signed with that key may still be in use. It can be retired after ${soonest?.toISOString() ?? 'its overlap window'}.`,
    );
  }

  for (const key of due) {
    await db.signingKey.update({ where: { kid: key.kid }, data: { status: 'retired' } });
    await db.auditEvent.create({
      data: { event: 'key.retired', targetType: 'signing_key', targetId: key.kid, detail: { alg: key.alg, forced: options.force === true } },
    });
  }
  return due.map((key) => summarise({ ...key, status: 'retired' }, now));
}

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
