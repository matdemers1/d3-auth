import { createApp } from './app.js';

// Structured logging and zod-validated config replace these in T-0.10 and T-0.4.
const port = Number(process.env.PORT ?? 3000);
const log = (msg: string, fields: Record<string, unknown> = {}): void => {
  console.log(JSON.stringify({ level: 'info', msg, ...fields }));
};

const server = createApp().listen(port, (err?: Error) => {
  if (err) throw err;
  log('listening', { port });
});

function shutdown(signal: NodeJS.Signals): void {
  log('shutting down', { signal });
  server.close((err) => {
    process.exit(err ? 1 : 0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.once('SIGTERM', shutdown);
process.once('SIGINT', shutdown);
