import express, { type Express } from 'express';
import { healthRouter } from './health.js';

export function createApp(): Express {
  const app = express();
  app.disable('x-powered-by');
  app.use(healthRouter());
  return app;
}
