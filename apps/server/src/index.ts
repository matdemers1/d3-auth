import { ConfigError, loadConfig, type Config } from './config.js';
import { createLogger } from './log.js';
import { createService } from './service.js';

function readConfig(): Config {
  try {
    return loadConfig();
  } catch (err) {
    if (err instanceof ConfigError) {
      // Before a logger exists; the message names variables, never values.
      console.error(err.message);
      process.exit(1);
    }
    throw err;
  }
}

const config = readConfig();
const logger = createLogger({ level: config.LOG_LEVEL });

if (config.INSECURE_HTTP_ISSUER) logger.warn({ issuer: config.ISSUER }, 'running with an http issuer — local testing only');
if (config.DEV_LOGIN_ENABLED) logger.warn('development login is enabled — local testing only');

const service = await createService(config, logger).catch((err: unknown) => {
  logger.fatal({ err }, 'failed to start');
  process.exit(1);
});

const server = service.app.listen(config.PORT, (err?: Error) => {
  if (err) {
    logger.fatal({ err }, 'failed to listen');
    process.exit(1);
  }
  logger.info({ port: config.PORT, issuer: config.ISSUER }, 'listening');
});

function shutdown(signal: NodeJS.Signals): void {
  logger.info({ signal }, 'shutting down');
  server.close((err) => {
    void service.close().finally(() => process.exit(err ? 1 : 0));
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.once('SIGTERM', shutdown);
process.once('SIGINT', shutdown);
