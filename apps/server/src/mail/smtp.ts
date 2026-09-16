import { createTransport, type Transporter } from 'nodemailer';
import type { MailDriver, MailMessage } from './adapter.js';

// The driver for anyone self-hosting without Cloudflare, and our fallback if the relay's Beta
// quota bites (R-13). Any SMTP URL works: smtps://user:pass@host:465.

export interface SmtpOptions {
  url: string;
  from: string;
  transport?: Transporter;
}

export function smtpDriver(options: SmtpOptions): MailDriver {
  const transport = options.transport ?? createTransport(options.url);
  return {
    name: 'smtp',
    async send(message: MailMessage) {
      await transport.sendMail({
        from: options.from,
        to: message.to,
        subject: message.subject,
        text: message.text,
        ...(message.html ? { html: message.html } : {}),
      });
    },
  };
}
