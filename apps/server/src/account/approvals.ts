import { randomInt } from 'node:crypto';
import type { Db } from '../db.js';
import type { Relay } from '../push/relay.js';

// Sign-in approval (AUTH-T-10.5, d3-app-contract spec/sign-in-approval.md): a browser that has
// reached the second factor can ask the person's phone instead of a code. The browser shows a
// number, the app shows three, and the person picks the browser's — so approving a sign-in they did
// not start takes a guess, not a tap. One answer per approval, a wrong number refuses it exactly as
// a denial does, two minutes and it is gone, and the code is always still there.

export const APPROVAL_TTL_MS = 2 * 60 * 1000;
export const APPROVAL_CATEGORY = 'd3auth.signin-approval';
export const LOGIN_CATEGORY = 'd3auth.login';

export type ApprovalResult = 'approved' | 'denied' | 'wrong_number' | 'expired';
export type ApprovalState = 'pending' | ApprovalResult;

/** Three distinct numbers from 10–99, the right one among them at a random position. */
export function choicesFor(number: number): number[] {
  const choices = new Set([number]);
  while (choices.size < 3) choices.add(randomInt(10, 100));
  const list = [...choices];
  // Fisher–Yates, from the CSPRNG: the right answer's position must not be guessable either.
  for (let i = list.length - 1; i > 0; i--) {
    const j = randomInt(0, i + 1);
    [list[i], list[j]] = [list[j] as number, list[i] as number];
  }
  return list;
}

/** Turns a user agent into what a person recognises: "Safari on Mac". Shallow on purpose. */
export function describeBrowser(userAgent: string | undefined): string {
  if (!userAgent) return 'A browser';
  const browser = [
    [/\bEdg\//, 'Edge'],
    [/\bOPR\//, 'Opera'],
    [/\bChrome\//, 'Chrome'],
    [/\bFirefox\//, 'Firefox'],
    [/\bSafari\//, 'Safari'],
  ].find(([pattern]) => (pattern as RegExp).test(userAgent))?.[1] as string | undefined;
  const platform = [
    [/\biPhone\b/, 'iPhone'],
    [/\biPad\b/, 'iPad'],
    [/\bAndroid\b/, 'Android'],
    [/\bMac OS X\b|\bMacintosh\b/, 'Mac'],
    [/\bWindows\b/, 'Windows'],
    [/\bLinux\b/, 'Linux'],
  ].find(([pattern]) => (pattern as RegExp).test(userAgent))?.[1] as string | undefined;
  if (browser && platform) return `${browser} on ${platform}`;
  return browser ?? platform ?? 'A browser';
}

export interface Approvals {
  /** True when this person can be asked on a phone: a device registered for approvals. */
  available(userId: string): Promise<boolean>;
  /** A fresh approval for this sign-in, pushed to the person's devices. */
  start(input: { userId: string; interactionUid: string; userAgent: string | undefined; ip: string | undefined; now?: Date }): Promise<{ id: string; number: number; expiresAt: Date }>;
  /** Where the browser's approval stands. */
  state(id: string, interactionUid: string, now?: Date): Promise<ApprovalState | null>;
  /** The browser spending an approved approval: true exactly once. */
  consume(id: string, interactionUid: string, now?: Date): Promise<boolean>;
  /** What the app shows: null if it is not this person's, 'gone' once answered or expired. */
  view(id: string, userId: string, now?: Date): Promise<null | 'gone' | { id: string; browser: string; place?: string; requestedAt: string; expiresAt: string; choices: number[] }>;
  /** The app's one answer. */
  answer(id: string, userId: string, input: { number?: number; deny?: boolean }, grantId: string, now?: Date): Promise<null | 'gone' | ApprovalResult>;
}

export function createApprovals({ db, relay, issuer }: { db: Db; relay: Relay; issuer: string }): Approvals {
  const host = new URL(issuer).host;
  return {
    async available(userId) {
      return (await db.relayRegistration.count({ where: { userId, categories: { has: APPROVAL_CATEGORY } } })) > 0;
    },

    async start({ userId, interactionUid, userAgent, ip, now = new Date() }) {
      const number = randomInt(10, 100);
      const browser = describeBrowser(userAgent);
      const row = await db.signinApproval.create({
        data: { userId, interactionUid, number, choices: choicesFor(number), browser, ip: ip ?? null, requestedAt: now, expiresAt: new Date(now.getTime() + APPROVAL_TTL_MS) },
      });
      // After the row, never instead of it: a relay that is down leaves the code as the way in.
      void relay.pushToUser(
        userId,
        {
          v: 1,
          category: APPROVAL_CATEGORY,
          title: 'Is this you signing in?',
          body: `${browser} is asking to sign in. Open to pick the number it shows.`,
          link: `d3constellation://${host}/d3auth/approval/${row.id}`,
          sentAt: now.toISOString(),
        },
        `approval-${row.id}`,
      );
      return { id: row.id, number, expiresAt: row.expiresAt };
    },

    async state(id, interactionUid, now = new Date()) {
      const row = await db.signinApproval.findFirst({ where: { id, interactionUid } });
      if (row === null) return null;
      if (row.result !== null) return row.result as ApprovalResult;
      return row.expiresAt.getTime() <= now.getTime() ? 'expired' : 'pending';
    },

    async consume(id, interactionUid, now = new Date()) {
      const { count } = await db.signinApproval.updateMany({
        where: { id, interactionUid, result: 'approved', consumedAt: null },
        data: { consumedAt: now },
      });
      return count === 1;
    },

    async view(id, userId, now = new Date()) {
      const row = await db.signinApproval.findFirst({ where: { id, userId } });
      if (row === null) return null;
      if (row.answeredAt !== null || row.expiresAt.getTime() <= now.getTime()) return 'gone';
      return {
        id: row.id,
        browser: row.browser,
        requestedAt: row.requestedAt.toISOString(),
        expiresAt: row.expiresAt.toISOString(),
        choices: row.choices,
      };
    },

    async answer(id, userId, input, grantId, now = new Date()) {
      const row = await db.signinApproval.findFirst({ where: { id, userId } });
      if (row === null) return null;
      if (row.answeredAt !== null) return 'gone';
      if (row.expiresAt.getTime() <= now.getTime()) return 'expired';
      const result: Exclude<ApprovalResult, 'expired'> = input.deny === true ? 'denied' : input.number === row.number ? 'approved' : 'wrong_number';
      // One answer: whichever request writes first decides, and every later one finds it answered.
      const { count } = await db.signinApproval.updateMany({
        where: { id, userId, answeredAt: null, expiresAt: { gt: now } },
        data: { answeredAt: now, result, answeredGrantId: grantId },
      });
      return count === 1 ? result : 'gone';
    },
  };
}
