import { randomUUID } from 'node:crypto';
import express, { type ErrorRequestHandler, type Express, type RequestHandler, type Router } from 'express';
import type Provider from 'oidc-provider';
import { healthRouter, type ReadinessProbe } from './health.js';
import type { Logger } from './log.js';

export interface AppOptions {
  provider?: Provider;
  /** Routes mounted before the provider (interaction UI, console statics). */
  routers?: Router[];
  readiness?: ReadinessProbe;
  logger?: Logger;
}

const QUIET_PATHS = new Set(['/healthz', '/readyz']);

function requestLog(logger: Logger): RequestHandler {
  return (req, res, next) => {
    const started = process.hrtime.bigint();
    const requestId = randomUUID();
    res.locals.requestId = requestId;
    res.on('finish', () => {
      if (QUIET_PATHS.has(req.path) && res.statusCode < 500) return;
      const clientId = typeof req.query.client_id === 'string' ? req.query.client_id : undefined;
      logger.info(
        {
          requestId,
          method: req.method,
          // Path only: query strings carry codes and state.
          path: req.path,
          status: res.statusCode,
          durationMs: Number((process.hrtime.bigint() - started) / 1_000_000n),
          ...(clientId ? { client_id: clientId } : {}),
          ip: req.get('cf-connecting-ip') ?? req.ip,
        },
        'request',
      );
    });
    next();
  };
}

export function createApp(options: AppOptions = {}): Express {
  const app = express();
  app.disable('x-powered-by');
  // Only the Cloudflare Tunnel reaches the service (REQ-125), so forwarded headers are trusted.
  app.set('trust proxy', true);

  if (options.logger) app.use(requestLog(options.logger));
  app.use(healthRouter(options.readiness));
  for (const router of options.routers ?? []) app.use(router);

  // The provider owns everything else: discovery at the root and /oidc/*. It parses its own
  // bodies, so no body parser runs globally before it.
  if (options.provider) app.use(options.provider.callback());

  const onError: ErrorRequestHandler = (err, _req, res, _next) => {
    options.logger?.error({ err, requestId: res.locals.requestId as string | undefined }, 'unhandled error');
    if (res.headersSent) return;
    res.status(500).type('text').send('Something went wrong.');
  };
  app.use(onError);

  return app;
}
