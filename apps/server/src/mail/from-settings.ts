import type { Logger } from '../log.js';
import type { Settings } from '../admin/settings.js';
import { createMailAdapter, type MailAdapter, type MailDriver, type MailResult } from './adapter.js';
import { logDriver } from './log-driver.js';
import { smtpDriver } from './smtp.js';
import { workerRelayDriver } from './worker-relay.js';

// Mail configured from the console rather than the container (REQ-071).
//
// The driver is resolved per send, not at boot, because the whole point of putting it in the
// console is that changing it takes effect without a deploy. Resolution is one indexed row; the
// send that follows is a network round trip, so the cost is noise.

export function mailFromSettings(settings: Settings, logger: Logger): MailAdapter {
  const resolve = async (): Promise<MailDriver> => {
    const configured = await settings.mail();
    const from = configured?.from ?? 'no-reply@localhost';

    if (configured?.driver === 'worker' && configured.relayUrl && configured.secret) {
      return workerRelayDriver({ url: configured.relayUrl, secret: configured.secret, from });
    }
    if (configured?.driver === 'smtp' && (configured.secret ?? configured.smtpHost)) {
      return smtpDriver({ url: configured.secret ?? configured.smtpHost ?? '', from });
    }
    if (configured && configured.driver !== 'log') {
      logger.warn({ driver: configured.driver }, 'mail is configured but incomplete; falling back to the log driver');
    }
    // The log driver *rejects*, so the console shows its copy-link fallback rather than
    // pretending an invite was delivered (REQ-108).
    return logDriver(logger);
  };

  return {
    // What it would use right now; the send below resolves again, in case it just changed.
    driver: 'configured',
    async send(message): Promise<MailResult> {
      const driver = await resolve();
      return createMailAdapter(driver, logger).send(message);
    },
  };
}
