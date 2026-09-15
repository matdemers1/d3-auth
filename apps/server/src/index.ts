import { ConfigError, loadConfig, type Config } from './config.js';
import { createService } from './service.js';

// Structured logging replaces these console calls in T-0.10.
const log = (msg: string, fields: Record<string, unknown> = {}): void => {
  console.log(JSON.stringify({ level: 'info', msg, ...fields }));
};

function readConfig(): Config {
  try {
    return loadConfig();
  } catch (err) {
    if (err instanceof ConfigError) {
      console.error(err.message);
      process.exit(1);
    }
    throw err;
  }
}

const config = readConfig();
const service = await createService(config);
for (const skipped of service.skippedClients) {
  console.log(JSON.stringify({ level: 'warn', msg: 'app not loaded', ...skipped }));
}

const server = service.app.listen(config.PORT, (err?: Error) => {
  if (err) throw err;
  log('listening', { port: config.PORT, issuer: config.ISSUER, devLogin: config.DEV_LOGIN_ENABLED });
});

function shutdown(signal: NodeJS.Signals): void {
  log('shutting down', { signal });
  server.close((err) => {
    void service.close().finally(() => process.exit(err ? 1 : 0));
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.once('SIGTERM', shutdown);
process.once('SIGINT', shutdown);
