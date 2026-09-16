import { readFileSync } from 'node:fs';

// Password policy (REQ-025): at least 12 characters, rejected if it appears in the blocklist —
// which deliberately contains entries of 12 characters and more, because a minimum length alone
// lets "passwordpassword" through. No composition rules, no expiry, checked only when set.

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

let cachedBlocklist: Set<string> | undefined;

export function loadBlocklist(path = new URL('./blocklist.txt', import.meta.url)): Set<string> {
  const entries = readFileSync(path, 'utf8')
    .split('\n')
    .map((line) => line.trim().toLowerCase())
    .filter((line) => line.length > 0 && !line.startsWith('#'));
  return new Set(entries);
}

function blocklist(): Set<string> {
  cachedBlocklist ??= loadBlocklist();
  return cachedBlocklist;
}

/** Strips the padding people add to a common word: "Password123!" is still "password". */
function normalise(password: string): string[] {
  const lower = password.normalize('NFKC').toLowerCase();
  const trimmedDigits = lower.replace(/[0-9!@#$%^&*._-]+$/, '');
  const collapsed = lower.replace(/[^a-z]/g, '');
  return [...new Set([lower, trimmedDigits, collapsed].filter((value) => value.length > 0))];
}

export function checkPassword(password: string, context: PolicyContext = {}): PolicyResult {
  const problems: string[] = [];

  if (password.length < MIN_LENGTH) problems.push(`Use at least ${MIN_LENGTH} characters.`);
  if (password.length > MAX_LENGTH) problems.push(`Use at most ${MAX_LENGTH} characters.`);

  const candidates = normalise(password);
  if (candidates.some((candidate) => blocklist().has(candidate))) {
    problems.push('This password is one attackers try first. Pick something else.');
  }

  const personal = [context.email?.split('@')[0], context.email, context.username, context.displayName]
    .filter((value): value is string => Boolean(value && value.length >= 4))
    .map((value) => value.toLowerCase());
  const lower = password.toLowerCase();
  if (personal.some((value) => lower.includes(value))) {
    problems.push('Do not use your name, username or email address in your password.');
  }

  return { ok: problems.length === 0, problems };
}
