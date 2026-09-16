// Email templates (REQ-107). Plain text is the message and HTML is the alternative, because these
// arrive on phones, in clients that block images, and in the middle of someone's day. The copy
// says who it is from (the operator's name, REQ-087), what to do, and when it stops working.

export interface TemplateContext {
  /** e.g. "Matthew" — configurable, used wherever a guest is addressed. */
  operatorDisplayName: string;
  /** Where the service lives, e.g. https://auth.d3cloud.io */
  issuer: string;
}

export interface RenderedMail {
  subject: string;
  text: string;
  html: string;
}

const escape = (value: string): string => value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

function page(paragraphs: string[], action?: { label: string; url: string }): string {
  const body = paragraphs.map((p) => `<p>${escape(p)}</p>`).join('\n    ');
  const button = action
    ? `\n    <p><a href="${escape(action.url)}">${escape(action.label)}</a></p>\n    <p>If that link does not work, copy this into your browser:<br>${escape(action.url)}</p>`
    : '';
  return `<!doctype html>
<html lang="en">
  <body style="font-family: system-ui, -apple-system, 'Segoe UI', sans-serif; line-height: 1.5; color: #16171d;">
    ${body}${button}
  </body>
</html>`;
}

const hours = (count: number): string => (count === 1 ? '1 hour' : `${String(count)} hours`);

export function inviteMail(ctx: TemplateContext, input: { url: string; expiresInHours: number }): RenderedMail {
  const lines = [
    `${ctx.operatorDisplayName} has invited you to create an account.`,
    'This account is how you will sign in to their apps. Setting it up takes a minute: pick a username and a password, and optionally add a passkey so you rarely need the password again.',
    `The link works once and expires in ${hours(input.expiresInHours)}.`,
  ];
  return {
    subject: `${ctx.operatorDisplayName} invited you to create an account`,
    text: `${lines.join('\n\n')}\n\n${input.url}\n\nIf you were not expecting this, you can ignore it — nothing happens until you open the link.\n`,
    html: page([...lines, 'If you were not expecting this, you can ignore it — nothing happens until you open the link.'], {
      label: 'Set up your account',
      url: input.url,
    }),
  };
}

export function reEnrolMail(ctx: TemplateContext, input: { url: string; expiresInHours: number }): RenderedMail {
  const lines = [
    `${ctx.operatorDisplayName} has reset your account, so your old password and any passkeys or codes no longer work.`,
    'Use the link below to set a new password and protect your account again.',
    `It works once and expires in ${hours(input.expiresInHours)}.`,
  ];
  return {
    subject: 'Set up your account again',
    text: `${lines.join('\n\n')}\n\n${input.url}\n\nIf you did not ask for this, tell ${ctx.operatorDisplayName} — someone with access to their console did it.\n`,
    html: page([...lines, `If you did not ask for this, tell ${ctx.operatorDisplayName} — someone with access to their console did it.`], {
      label: 'Set up your account again',
      url: input.url,
    }),
  };
}

export function verifyEmailMail(ctx: TemplateContext, input: { url: string; expiresInHours: number }): RenderedMail {
  const lines = [
    'Confirm this email address so it can be used to reach you about your account.',
    `The link expires in ${hours(input.expiresInHours)}.`,
  ];
  return {
    subject: 'Confirm your email address',
    text: `${lines.join('\n\n')}\n\n${input.url}\n`,
    html: page(lines, { label: 'Confirm this address', url: input.url }),
  };
}

export function alertMail(ctx: TemplateContext, input: { event: string; detail: string; at: Date }): RenderedMail {
  const when = input.at.toISOString().replace('T', ' ').slice(0, 19);
  const lines = [`${input.event} at ${when} UTC on ${ctx.issuer}.`, input.detail, 'No action is needed if this was you.'];
  return {
    subject: `D3 Auth: ${input.event}`,
    text: `${lines.join('\n\n')}\n`,
    html: page(lines),
  };
}
