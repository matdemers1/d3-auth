import express, { type Express, type Router } from 'express';
import type Provider from 'oidc-provider';
import { healthRouter } from './health.js';

export interface AppOptions {
  provider?: Provider;
  /** Routes mounted before the provider (interaction UI, console statics). */
  routers?: Router[];
}

export function createApp(options: AppOptions = {}): Express {
  const app = express();
  app.disable('x-powered-by');
  // Only the Cloudflare Tunnel reaches the service (REQ-125), so forwarded headers are trusted.
  app.set('trust proxy', true);

  app.use(healthRouter());
  for (const router of options.routers ?? []) app.use(router);

  // The provider owns everything else: discovery at the root and /oidc/*. It parses its own
  // bodies, so no body parser runs globally before it.
  if (options.provider) app.use(options.provider.callback());

  return app;
}
