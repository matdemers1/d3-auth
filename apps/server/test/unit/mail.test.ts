import { describe, expect, it, vi } from 'vitest';
import { createLogger } from '../../src/log.js';
import { createMailAdapter, type MailDriver } from '../../src/mail/adapter.js';
import { logDriver } from '../../src/mail/log-driver.js';
import { smtpDriver } from '../../src/mail/smtp.js';
import { alertMail, inviteMail, reEnrolMail, verifyEmailMail } from '../../src/mail/templates.js';
import { workerRelayDriver } from '../../src/mail/worker-relay.js';

const capture = () => {
  const lines: string[] = [];
  return { lines, logger: createLogger({ level: 'debug', destination: { write: (line: string) => { lines.push(line); } } }) };
};

const ctx = { operatorDisplayName: 'Matthew', issuer: 'https://auth.d3cloud.io' };

describe('mail adapter (REQ-105, REQ-108)', () => {
  it('reports delivery instead of throwing, so the action survives a bad mail day', async () => {
    const { logger } = capture();
    const failing: MailDriver = {
      name: 'worker',
      send: () => Promise.reject(new Error('relay answered 503')),
    };
    const result = await createMailAdapter(failing, logger).send({ to: 'a@b.test', subject: 'x', text: 'y' });
    expect(result).toMatchObject({ delivered: false, driver: 'worker' });
    expect(result.error).toMatch(/503/);
  });

  it('reports success with the driver that did it', async () => {
    const { logger } = capture();
    const sent: unknown[] = [];
    const ok: MailDriver = { name: 'smtp', send: (m) => { sent.push(m); return Promise.resolve(); } };
    expect(await createMailAdapter(ok, logger).send({ to: 'a@b.test', subject: 'x', text: 'y' })).toEqual({
      delivered: true,
      driver: 'smtp',
    });
    expect(sent).toHaveLength(1);
  });
});

describe('worker relay driver (REQ-106)', () => {
  it('posts the message with the shared secret', async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const fakeFetch = vi.fn((url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: url instanceof Request ? url.url : url.toString(), init: init ?? {} });
      return Promise.resolve(new Response('{}', { status: 202 }));
    }) as unknown as typeof fetch;

    const driver = workerRelayDriver({ url: 'https://relay.test/send', secret: 'sh4red', from: 'no-reply@d3cloud.io', fetch: fakeFetch });
    await driver.send({ to: 'guest@example.com', subject: 'Hello', text: 'Body', html: '<p>Body</p>' });

    expect(calls[0]?.url).toBe('https://relay.test/send');
    const headers = new Headers(calls[0]?.init.headers);
    expect(headers.get('authorization')).toBe('Bearer sh4red');
    const body = calls[0]?.init.body;
    expect(JSON.parse(typeof body === 'string' ? body : '{}')).toEqual({
      from: 'no-reply@d3cloud.io',
      to: 'guest@example.com',
      subject: 'Hello',
      text: 'Body',
      html: '<p>Body</p>',
    });
  });

  it('turns a refusal into an error the adapter can report', async () => {
    const fakeFetch = (() => Promise.resolve(new Response('quota exceeded', { status: 429 }))) as unknown as typeof fetch;
    const driver = workerRelayDriver({ url: 'https://relay.test/send', secret: 's', from: 'f@d3cloud.io', fetch: fakeFetch });
    await expect(driver.send({ to: 'a@b.test', subject: 's', text: 't' })).rejects.toThrow(/429.*quota exceeded/);
  });
});

describe('smtp driver', () => {
  it('hands the message to the transport', async () => {
    const sent: Record<string, unknown>[] = [];
    const transport = { sendMail: (m: Record<string, unknown>) => { sent.push(m); return Promise.resolve({}); } };
    const driver = smtpDriver({ url: 'smtp://localhost:25', from: 'no-reply@d3cloud.io', transport: transport as never });
    await driver.send({ to: 'a@b.test', subject: 'Subject', text: 'Text' });
    expect(sent[0]).toMatchObject({ from: 'no-reply@d3cloud.io', to: 'a@b.test', subject: 'Subject', text: 'Text' });
    expect(sent[0]).not.toHaveProperty('html');
  });
});

describe('log driver', () => {
  it('writes the message where an operator can find it, and says it did not send', async () => {
    const { lines, logger } = capture();
    const send = logDriver(logger).send({
      to: 'guest@example.com',
      subject: 'Invite',
      text: 'https://auth.d3cloud.io/login/invite/abc',
    });

    await expect(send).rejects.toThrow(/not configured/);
    const written = lines.join('');
    expect(written).toMatch(/written here instead of sent/);
    expect(written).toContain('guest@example.com');
  });

  it('makes the adapter report a failure, so the console offers the link to copy', async () => {
    const { logger } = capture();
    const result = await createMailAdapter(logDriver(logger), logger).send({ to: 'a@b.test', subject: 's', text: 't' });
    expect(result).toMatchObject({ delivered: false, driver: 'log' });
  });
});

describe('templates (REQ-107, REQ-087)', () => {
  it('invites in plain English, with the operator named and an expiry stated', () => {
    const mail = inviteMail(ctx, { url: 'https://auth.d3cloud.io/login/invite/tok', expiresInHours: 72 });
    expect(mail.subject).toBe('Matthew invited you to create an account');
    expect(mail.text).toContain('https://auth.d3cloud.io/login/invite/tok');
    expect(mail.text).toContain('72 hours');
    expect(mail.text).toMatch(/ignore it/);
    expect(mail.html).toContain('Set up your account');
  });

  it('says what happened in a re-enrol email, and who to tell if it was not you', () => {
    const mail = reEnrolMail(ctx, { url: 'https://auth.d3cloud.io/login/reenrol/tok', expiresInHours: 1 });
    expect(mail.text).toContain('1 hour');
    expect(mail.text).toContain('tell Matthew');
    expect(mail.subject).toBe('Set up your account again');
  });

  it('always has a text body, and HTML only as an alternative', () => {
    const mails = [
      inviteMail(ctx, { url: 'https://x.test/a', expiresInHours: 2 }),
      reEnrolMail(ctx, { url: 'https://x.test/b', expiresInHours: 2 }),
      verifyEmailMail(ctx, { url: 'https://x.test/c', expiresInHours: 2 }),
      alertMail(ctx, { event: 'refresh token reuse', detail: 'A refresh token was used twice.', at: new Date('2026-09-16T12:00:00Z') }),
    ];
    for (const mail of mails) {
      expect(mail.text.trim().length).toBeGreaterThan(40);
      expect(mail.text).not.toContain('<');
      expect(mail.html).toMatch(/^<!doctype html>/);
    }
  });

  it('escapes anything that came from outside', () => {
    const mail = inviteMail({ ...ctx, operatorDisplayName: '<script>alert(1)</script>' }, { url: 'https://x.test/a?b=1&c=2', expiresInHours: 1 });
    expect(mail.html).not.toContain('<script>');
    expect(mail.html).toContain('&#60;script&#62;');
    expect(mail.html).toContain('b=1&#38;c=2');
  });

  it('dates an alert to the second, in UTC', () => {
    const mail = alertMail(ctx, { event: 'admin change', detail: 'Someone became an admin.', at: new Date('2026-09-16T12:34:56Z') });
    expect(mail.text).toContain('2026-09-16 12:34:56 UTC');
  });
});
