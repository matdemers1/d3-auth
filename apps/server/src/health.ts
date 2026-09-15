import { Router } from 'express';

export function healthRouter(): Router {
  const router = Router();

  router.use(['/healthz', '/readyz'], (_req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });

  // Liveness: the process is up and serving requests.
  router.get('/healthz', (_req, res) => {
    res.json({ status: 'ok' });
  });

  // Readiness stub. T-0.10 gates this on the database and boot state.
  router.get('/readyz', (_req, res) => {
    res.json({ status: 'ready' });
  });

  return router;
}
