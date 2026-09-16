import express, { Router, type Request, type RequestHandler, type Response } from 'express';
import type { Db } from '../db.js';
import type { KekCrypto } from '../security/kek.js';
import { generateNext, KeyError, listKeys, promoteNext, retire, SIGNING_ALGS, type SigningAlg } from './keys.js';

// The key set, served from the database, and the four buttons that move a key through its life
// (REQ-118, REQ-070).
//
// Why our own JWKS route rather than the provider's: `oidc-provider` reads its key set once, at
// startup. A key generated afterwards would not be published until a restart — which defeats the
// point of generating it early, since the overlap window only starts when consumers can see it.
// This route answers from the table, so a new key is published the moment it exists.
//
// Signing is the other half, and it is still whatever the process loaded at boot. So promoting
// takes effect on the next restart, and everything here says so rather than letting an operator
// believe a rotation finished when it has not.

export interface KeysDeps {
  db: Db;
  kek: KekCrypto;
  requireOwner: import('express').RequestHandler;
  /** The kids this process is actually signing with, from boot. */
  loadedKids: string[];
}

const isAlg = (value: unknown): value is SigningAlg => typeof value === 'string' && (SIGNING_ALGS as readonly string[]).includes(value);

export function keysRouter({ db, kek, requireOwner, loadedKids }: KeysDeps): Router {
  const router = Router();
  const asJson = express.json({ limit: '4kb' });
  const body: RequestHandler = (req, res, next) => {
    asJson(req, res, (err: unknown) => {
      if (err) next(err);
      else next();
    });
  };

  const onKeyError = (err: unknown, res: Response): boolean => {
    if (!(err instanceof KeyError)) return false;
    res.status(err.code === 'too_soon' || err.code === 'already_pending' ? 409 : 404).json({ error: err.code, message: err.message });
    return true;
  };

  /** Public keys, from the table. Everything published: next, current and retiring. */
  router.get('/oidc/jwks', (_req: Request, res: Response, next) => {
    void (async () => {
      try {
        const rows = await db.signingKey.findMany({
          where: { status: { in: ['current', 'next', 'retiring'] } },
          orderBy: { createdAt: 'desc' },
        });
        res
          .type('application/jwk-set+json')
          .set('Cache-Control', 'public, max-age=3600')
          .json({ keys: rows.map((row) => row.publicJwk) });
      } catch (err) {
        next(err);
      }
    })();
  });

  router.get('/api/admin/keys', requireOwner, (_req, res, next) => {
    void (async () => {
      try {
        const keys = await listKeys(db);
        res.set('Cache-Control', 'no-store').json({
          keys: keys.map((key) => ({ ...key, signingNow: loadedKids.includes(key.kid) })),
          // The console needs this to say "restart to finish", and to say it only when true.
          restartRequired: keys.some((key) => key.status === 'current' && !loadedKids.includes(key.kid)),
        });
      } catch (err) {
        next(err);
      }
    })();
  });

  router.post('/api/admin/keys/generate', requireOwner, body, (req, res, next) => {
    void (async () => {
      try {
        const alg = (req.body as { alg?: unknown } | undefined)?.alg;
        res.status(201).json(await generateNext(db, kek, isAlg(alg) ? alg : 'ES256'));
      } catch (err) {
        if (!onKeyError(err, res)) next(err);
      }
    })();
  });

  router.post('/api/admin/keys/promote', requireOwner, body, (req, res, next) => {
    void (async () => {
      try {
        const input = (req.body ?? {}) as { alg?: unknown; force?: unknown };
        const result = await promoteNext(db, isAlg(input.alg) ? input.alg : 'ES256', { force: input.force === true });
        res.json({ ...result, restartRequired: true });
      } catch (err) {
        if (!onKeyError(err, res)) next(err);
      }
    })();
  });

  router.post('/api/admin/keys/retire', requireOwner, body, (req, res, next) => {
    void (async () => {
      try {
        const input = (req.body ?? {}) as { kid?: unknown; force?: unknown };
        const retired = await retire(db, {
          ...(typeof input.kid === 'string' ? { kid: input.kid } : {}),
          force: input.force === true,
        });
        res.json({ retired });
      } catch (err) {
        if (!onKeyError(err, res)) next(err);
      }
    })();
  });

  return router;
}
