import express, { Router, type Request, type RequestHandler } from 'express';
import { clientIp } from '../audit/writer.js';
import { renderSetupPage } from './page.js';
import type { FirstRunSetup } from './first-run.js';

// The first-run setup screen and the one endpoint behind it (REQ-141).

export const SETUP_PATH = '/login/setup';

export interface SetupDeps {
  setup: FirstRunSetup;
  consoleDist: string;
  operatorDisplayName: string;
}

export function setupRouter(deps: SetupDeps): Router {
  const router = Router();
  const asJson = express.json({ limit: '4kb' });
  const asForm = express.urlencoded({ extended: false, limit: '4kb' });
  const body: RequestHandler = (req, res, next) => {
    asJson(req, res, (err: unknown) => {
      if (err) next(err);
      else asForm(req, res, next);
    });
  };

  const wantsJson = (req: Request): boolean =>
    req.is('application/json') !== false || (req.get('accept') ?? '').includes('application/json');

  router.get(SETUP_PATH, (req, res, next) => {
    void (async () => {
      try {
        res.set('Cache-Control', 'no-store');
        const available = await deps.setup.available();
        res.status(available ? 200 : 404).type('html').send(renderSetupPage(deps.consoleDist, { available }));
      } catch {
        next();
      }
    })();
  });

  router.get('/api/setup', (_req, res, next) => {
    void (async () => {
      try {
        res.set('Cache-Control', 'no-store').json({ available: await deps.setup.available() });
      } catch (err) {
        next(err);
      }
    })();
  });

  router.post('/api/setup', body, (req, res, next) => {
    void (async () => {
      try {
        res.set('Cache-Control', 'no-store');
        const input = req.body as Record<string, unknown>;
        const text = (key: string): string => (typeof input[key] === 'string' ? input[key] : '');
        const result = await deps.setup.claim({
          code: text('code'),
          email: text('email'),
          username: text('username'),
          displayName: text('displayName'),
          password: text('password'),
          ip: clientIp(req),
          userAgent: req.get('user-agent'),
        });

        if (result.ok) {
          // Either way the person lands back on the setup URL, which now says setup is finished.
          if (wantsJson(req)) res.json({ ok: true, next: SETUP_PATH });
          else res.redirect(303, SETUP_PATH);
          return;
        }

        const status = result.error === 'already_claimed' ? 409 : result.error === 'bad_code' ? 403 : 400;
        const message =
          result.error === 'already_claimed'
            ? 'This instance already has an account. Setup is finished.'
            : result.error === 'bad_code'
              ? 'That setup code is not right. It is printed in the server log.'
              : (result.problems ?? []).join(' ');
        if (wantsJson(req)) res.status(status).json({ ok: false, error: result.error, message, problems: result.problems ?? [] });
        else res.redirect(303, `${SETUP_PATH}?error=${encodeURIComponent(result.error)}`);
      } catch (err) {
        next(err);
      }
    })();
  });

  return router;
}
