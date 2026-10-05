import express, { Router } from 'express';
import { z } from 'zod';
import { AUDIT_EVENTS } from '../audit/events.js';
import { clientIp, type AuditWriter } from '../audit/writer.js';
import { consoleUserOf, type ConsoleAuth } from '../console/auth.js';
import { isDevicePublicKey } from './envelope.js';
import type { Relay } from './relay.js';

// Push registration (AUTH-T-10.4, the D3 App contract's push): D3 Constellation registers this
// connection at the relay, then tells D3 Auth where to send and the key to seal to — with the token
// its grant mints for D3 Auth's own audience, never the console's cookie. Answered 204, then one
// d3auth.registered notification so the person knows push works.

const Register = z.object({
  devicePublicKey: z.string().min(1).max(200),
  relay: z.object({ url: z.string().min(1).max(500), registration: z.string().min(1).max(200), sendKey: z.string().min(16).max(200) }),
  categories: z.array(z.string().regex(/^[a-z][a-z0-9]*\.[a-z_-]+$/)).max(20),
});

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]']);

export function pushRouter(deps: { auth: ConsoleAuth; relay: Relay; audit: AuditWriter; allowLoopbackHttp: boolean }): Router {
  const router = Router();

  /** https, or a loopback http relay where the test configuration allows one — never in production. */
  const relayUrlOk = (raw: string): boolean => {
    try {
      const url = new URL(raw);
      if (url.username !== '' || url.password !== '' || url.search !== '' || url.hash !== '') return false;
      if (url.protocol === 'https:') return true;
      return url.protocol === 'http:' && deps.allowLoopbackHttp && LOOPBACK.has(url.hostname);
    } catch {
      return false;
    }
  };

  router.post('/api/push/native/register', deps.auth.requireUser, express.json({ limit: '16kb' }), (req, res, next) => {
    void (async () => {
      try {
        const { user, via, grantId } = consoleUserOf(res);
        if (via !== 'bearer' || grantId === undefined) {
          res.status(401).json({ error: 'sign_in_required', message: 'Register from the app.' });
          return;
        }
        const parsed = Register.safeParse(req.body);
        const devicePublicKey = parsed.success ? Buffer.from(parsed.data.devicePublicKey, 'base64') : null;
        if (!parsed.success || devicePublicKey === null || !isDevicePublicKey(devicePublicKey) || !relayUrlOk(parsed.data.relay.url)) {
          res.status(400).json({ error: 'invalid', message: 'That is not a relay registration.' });
          return;
        }
        const relayUrl = parsed.data.relay.url.replace(/\/$/, '');
        const { id } = await deps.relay.register({
          userId: user.id,
          grantId,
          devicePublicKey,
          relayUrl,
          registration: parsed.data.relay.registration,
          sendKey: parsed.data.relay.sendKey,
          categories: parsed.data.categories,
        });
        await deps.audit.write({
          event: AUDIT_EVENTS.pushRegistered,
          actorUserId: user.id,
          targetType: 'user',
          targetId: user.id,
          ip: clientIp(req),
          userAgent: req.get('user-agent'),
          detail: { relay: relayUrl, categories: parsed.data.categories },
        });
        res.status(204).end();
        // After the answer, never instead of it: a relay that is down must not fail the registration.
        void deps.relay.push(id, {
          v: 1,
          category: 'd3auth.registered',
          title: 'Notifications are on',
          body: 'D3 Auth will tell this device about new sign-ins.',
          sentAt: new Date().toISOString(),
        });
      } catch (err) {
        next(err);
      }
    })();
  });

  return router;
}
