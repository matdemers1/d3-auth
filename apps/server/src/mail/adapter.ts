import type { Logger } from '../log.js';

// Mail (REQ-105, REQ-108). One interface, three drivers, and one rule above all: a failure to
// send must never lose the thing the mail was about. The adapter therefore reports failure
// instead of throwing, so an invite is still created and its link still copyable when the
// mail service is having a bad day (R-13).

export interface MailMessage {
  to: string;
  subject: string;
  /** Plain text is the message; HTML is the alternative, never the only version (REQ-107). */
  text: string;
  html?: string;
}

export interface MailDriver {
  readonly name: string;
  send(message: MailMessage): Promise<void>;
}

export interface MailResult {
  delivered: boolean;
  driver: string;
  /** Present when delivery failed; safe to show an operator, never a guest. */
  error?: string;
}

export interface MailAdapter {
  readonly driver: string;
  send(message: MailMessage): Promise<MailResult>;
}

export function createMailAdapter(driver: MailDriver, logger: Logger): MailAdapter {
  return {
    driver: driver.name,
    async send(message) {
      try {
        await driver.send(message);
        logger.info({ to: message.to, subject: message.subject, driver: driver.name }, 'mail sent');
        return { delivered: true, driver: driver.name };
      } catch (err) {
        const error = err instanceof Error ? err.message : String(err);
        logger.error({ err, to: message.to, subject: message.subject, driver: driver.name }, 'mail failed');
        return { delivered: false, driver: driver.name, error };
      }
    },
  };
}
