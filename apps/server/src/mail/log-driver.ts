import type { Logger } from '../log.js';
import type { MailDriver, MailMessage } from './adapter.js';

// No mail configured: write the message to the log instead of pretending to send it. Development
// uses this, and so does a deployment whose operator has not set mail up yet — the invite screen's
// copy-link fallback is what makes that survivable (REQ-108).

export function logDriver(logger: Logger): MailDriver {
  return {
    name: 'log',
    send(message: MailMessage) {
      logger.warn(
        { to: message.to, subject: message.subject, body: message.text },
        'no mail driver configured — the message was written here instead of sent',
      );
      // Reported as a failure on purpose. Nothing was sent, so the console must show the link to
      // copy rather than tell an operator an email is on its way (REQ-108).
      return Promise.reject(new Error('Mail is not configured, so nothing was sent. Copy the link instead.'));
    },
  };
}
