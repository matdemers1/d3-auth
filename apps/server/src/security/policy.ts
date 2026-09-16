import { readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';

// Password policy (REQ-025; ASVS 5.0 6.2): at least 12 characters, no composition rules, no expiry,
// checked only when a password is set. Refused when it is:
//
// - **breached** — in `breached-passwords.txt.gz`: the 200,000 most common passwords of 12 characters
//   or more from the Pwdb breach-frequency list, the NCSC's 100,000 most-used passwords as base
//   words, and the original hand list. 290,041 entries, from SecLists (MIT). Shipped in the image
//   and checked locally, because the service makes no outbound connection but to its database.
// - **about this system** — containing a word from `blocklist.txt` (the documented context-specific
//   list) or one of the instance's own names, registered at boot.
// - **about the person** — containing their email, username or display name.
//
// A minimum length alone lets "passwordpassword" through, which is why the corpus is mostly long.

export const MIN_LENGTH = 12;
/** Argon2 hashes any length; the cap only stops a multi-megabyte body becoming work. */
export const MAX_LENGTH = 256;

export interface PolicyContext {
  email?: string;
  username?: string;
  displayName?: string;
}

export interface PolicyResult {
  ok: boolean;
  /** Shown inline, in order, as written. */
  problems: string[];
}

let cachedBreached: Set<string> | undefined;
let cachedContext: string[] | undefined;
let instanceWords: string[] = [];

const lines = (text: string): string[] =>
  text
    .split('\n')
    .map((line) => line.trim().toLowerCase())
    .filter((line) => line.length > 0 && !line.startsWith('#'));

/** The breached-password corpus. Loaded on first use: about 30 MB of heap, once. */
export function loadBreached(path = new URL('./breached-passwords.txt.gz', import.meta.url)): Set<string> {
  return new Set(lines(gunzipSync(readFileSync(path)).toString('utf8')));
}

/** The documented context-specific words (ASVS 5.0 6.1.2). */
export function loadBlocklist(path = new URL('./blocklist.txt', import.meta.url)): Set<string> {
  return new Set(lines(readFileSync(path, 'utf8')));
}

function breached(): Set<string> {
  cachedBreached ??= loadBreached();
  return cachedBreached;
}

function contextWords(): string[] {
  cachedContext ??= [...loadBlocklist()].map((word) => word.replace(/[^a-z0-9]/g, '')).filter((word) => word.length >= 4);
  return [...cachedContext, ...instanceWords];
}

/**
 * The instance's own names — its operator display name and issuer host, say — which make a
 * password as guessable as the product name does. Called once at boot.
 */
export function registerInstanceWords(words: string[]): void {
  instanceWords = [...new Set(words.map((word) => word.trim().toLowerCase().replace(/[^a-z0-9]/g, '')).filter((word) => word.length >= 4))];
}

/** Strips the padding people add to a common word: "Password123!" is still "password". */
function normalise(password: string): string[] {
  const lower = password.normalize('NFKC').toLowerCase();
  const trimmedDigits = lower.replace(/[0-9!@#$%^&*._-]+$/, '');
  const collapsed = lower.replace(/[^a-z]/g, '');
  return [...new Set([lower, trimmedDigits, collapsed].filter((value) => value.length > 0))];
}

/** Usernames appear in URLs and audit lines, so they stay short, lower-ish and unambiguous. */
export const USERNAME_PATTERN = /^[a-z0-9][a-z0-9._-]{1,30}$/i;
export const USERNAME_RULE = 'Usernames are 2–31 characters: letters, numbers, dot, dash or underscore.';

export function checkPassword(password: string, context: PolicyContext = {}): PolicyResult {
  const problems: string[] = [];

  if (password.length < MIN_LENGTH) problems.push(`Use at least ${MIN_LENGTH} characters.`);
  if (password.length > MAX_LENGTH) problems.push(`Use at most ${MAX_LENGTH} characters.`);

  const candidates = normalise(password);
  const lower = password.toLowerCase();
  const letters = lower.replace(/[^a-z0-9]/g, '');
  if (candidates.some((candidate) => breached().has(candidate))) {
    problems.push('This password is one attackers try first. Pick something else.');
  } else if (contextWords().some((word) => letters.includes(word.replace(/[^a-z0-9]/g, '')))) {
    problems.push('Do not build your password on the name of this service. Pick something else.');
  }

  const personal = [context.email?.split('@')[0], context.email, context.username, context.displayName]
    .filter((value): value is string => Boolean(value && value.length >= 4))
    .map((value) => value.toLowerCase());
  if (personal.some((value) => lower.includes(value))) {
    problems.push('Do not use your name, username or email address in your password.');
  }

  return { ok: problems.length === 0, problems };
}
