import express, { Router, type Request, type Response } from 'express';
import type Provider from 'oidc-provider';
import type { Db } from '../db.js';
import type { SecretHasher } from '../security/hash.js';

// THROWAWAY (T-0.8). A bare server-rendered login so the protocol can be exercised end to end and
// by the conformance suite. Phase 1 deletes this file and replaces it with the login state machine,
// throttling, CSRF and the console's /login screens. Config refuses to enable it on a real issuer.

export const INTERACTION_PREFIX = '/interaction';

const escapeHtml = (value: string): string => value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

function page(uid: string, error?: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in — D3 Auth (development)</title></head>
<body>
<h1>Sign in</h1>
<p>Development login. Not for real accounts.</p>
${error ? `<p role="alert">${escapeHtml(error)}</p>` : ''}
<form method="post" action="${INTERACTION_PREFIX}/${escapeHtml(uid)}/login">
  <label>Email <input type="email" name="email" autocomplete="username" required autofocus></label>
  <label>Password <input type="password" name="password" autocomplete="current-password" required></label>
  <button type="submit">Sign in</button>
</form>
</body></html>`;
}

async function grantMissing(provider: Provider, accountId: string, details: Awaited<ReturnType<Provider['interactionDetails']>>): Promise<string> {
  const { prompt, params } = details;
  const clientId = String(params.client_id);
  const grant = details.grantId
    ? ((await provider.Grant.find(details.grantId)) ?? new provider.Grant({ accountId, clientId }))
    : new provider.Grant({ accountId, clientId });

  // No consent screen in D3 Auth (REQ-059/060): access is decided by grants in Phase 3.
  const missing = prompt.details as { missingOIDCScope?: string[]; missingOIDCClaims?: string[] };
  if (missing.missingOIDCScope) grant.addOIDCScope(missing.missingOIDCScope.join(' '));
  if (missing.missingOIDCClaims) grant.addOIDCClaims(missing.missingOIDCClaims);
  return grant.save();
}

export function devLoginRouter(provider: Provider, db: Db, hasher: SecretHasher): Router {
  const router = Router();
  const form = express.urlencoded({ extended: false, limit: '4kb' });

  const noStore = (res: Response): void => {
    res.set('Cache-Control', 'no-store');
  };

  router.get(`${INTERACTION_PREFIX}/:uid`, async (req: Request<{ uid: string }>, res, next) => {
    try {
      noStore(res);
      const details = await provider.interactionDetails(req, res);
      if (details.prompt.name === 'login') {
        res.type('html').send(page(details.uid));
        return;
      }
      const accountId = details.session?.accountId;
      if (!accountId) throw new Error('consent prompt without a session');
      const grantId = await grantMissing(provider, accountId, details);
      await provider.interactionFinished(req, res, { consent: { grantId } }, { mergeWithLastSubmission: true });
    } catch (err) {
      next(err);
    }
  });

  router.post(`${INTERACTION_PREFIX}/:uid/login`, form, async (req: Request<{ uid: string }>, res, next) => {
    try {
      noStore(res);
      const details = await provider.interactionDetails(req, res);
      if (details.prompt.name !== 'login') {
        res.status(400).type('html').send(page(details.uid, 'This sign-in has already moved on.'));
        return;
      }
      const body = req.body as { email?: unknown; password?: unknown };
      const email = typeof body.email === 'string' ? body.email : '';
      const password = typeof body.password === 'string' ? body.password : '';

      const user = await db.user.findUnique({
        where: { email },
        include: { passwordCredentials: { orderBy: { setAt: 'desc' }, take: 1 } },
      });
      const hash = user?.passwordCredentials[0]?.argon2idHash;
      const ok = user?.status === 'active' && hash !== undefined && (await hasher.verify(hash, password));
      if (!ok) {
        res.status(401).type('html').send(page(details.uid, 'That email and password did not match.'));
        return;
      }

      await db.user.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } });
      const grantId = await grantMissing(provider, user.id, details);
      await provider.interactionFinished(
        req,
        res,
        { login: { accountId: user.id, amr: ['pwd'] }, consent: { grantId } },
        { mergeWithLastSubmission: false },
      );
    } catch (err) {
      next(err);
    }
  });

  return router;
}
