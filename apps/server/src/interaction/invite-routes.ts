import express, { Router, type Request, type RequestHandler, type Response } from 'express';
import { clientIp } from '../audit/writer.js';
import type { Invites } from '../admin/invites.js';
import { renderInvitePage } from './invite-page.js';

// The guest's side of an invite (I-6). Public by design — the token is the credential — and the
// page is server-rendered into the console shell so it works before the JavaScript does.

export const INVITE_PATH = '/login/invite';

export interface InviteRouteDeps {
  invites: Invites;
  consoleDist: string;
  operatorDisplayName: string;
}

export function inviteRouter({ invites, consoleDist, operatorDisplayName }: InviteRouteDeps): Router {
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

  const text = (value: unknown): string => (typeof value === 'string' ? value : '');

  router.get<{ token: string }>(`${INVITE_PATH}/:token`, (req, res, next) => {
    void (async () => {
      try {
        const { token } = req.params;
        const described = await invites.describe(token);
        res
          .status(described.valid ? 200 : 410)
          .set('Cache-Control', 'no-store')
          .type('html')
          .send(renderInvitePage(consoleDist, { ...described, operatorDisplayName, token }));
      } catch (err) {
        next(err);
      }
    })();
  });

  router.get<{ token: string }>(`/api/invite/:token`, (req, res, next) => {
    void (async () => {
      try {
        const described = await invites.describe(req.params.token);
        res.set('Cache-Control', 'no-store').status(described.valid ? 200 : 410).json(described);
      } catch (err) {
        next(err);
      }
    })();
  });

  router.post<{ token: string }>(`/api/invite/:token/accept`, body, (req, res, next) => {
    void (async () => {
      try {
        res.set('Cache-Control', 'no-store');
        const input = req.body as Record<string, unknown>;
        const { token } = req.params;
        const result = await invites.accept({
          token,
          username: text(input.username),
          displayName: text(input.displayName),
          password: text(input.password),
          ip: clientIp(req),
          userAgent: req.get('user-agent'),
        });

        if (result.ok) {
          respond(req, res, 200, { ok: true, next: '/login/welcome' }, '/login/welcome');
          return;
        }
        const status = result.error === 'invalid_or_expired' ? 410 : result.error === 'taken' ? 409 : 400;
        const message =
          result.error === 'invalid_or_expired'
            ? `This invite has expired or has already been used. Ask ${operatorDisplayName} for a new one.`
            : result.error === 'taken'
              ? 'That username is taken. Pick another.'
              : (result.problems ?? []).join(' ');
        respond(req, res, status, { ok: false, error: result.error, message, problems: result.problems ?? [] }, `${INVITE_PATH}/${token}`);
      } catch (err) {
        next(err);
      }
    })();
  });

  function respond(req: Request, res: Response, status: number, payload: Record<string, unknown>, redirectTo: string): void {
    if (wantsJson(req)) {
      res.status(status).json(payload);
      return;
    }
    res.redirect(303, status === 200 ? redirectTo : `${redirectTo}?error=1`);
  }

  return router;
}
