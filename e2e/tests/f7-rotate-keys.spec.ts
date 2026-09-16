import { execFileSync } from 'node:child_process';
import { expect, test, type Page } from '@playwright/test';
import { continueIfAsked } from './interstitial';

// F7 — rotate the signing keys while everybody stays signed in.
//
// The claim being tested is the one an operator actually cares about: a rotation done by the book
// is invisible to the apps. So this drives the real console, promotes with the real CLI in the
// real container, restarts the real service, and then asks the provider which key is signing now.
// If the key changed and signing in still works, the rotation was clean.
//
// The two waits (two hours each) cannot be sat through in a test, so the promote and the retire
// go through the CLI's `--force`, which exists for exactly this — a key nobody else is holding.
// The console's own buttons are checked to be *disabled* until the wait is over, because that
// refusal is the safety, and losing it would be the regression worth catching.

const AUTH = 'http://localhost:3000';
const OWNER = { email: 'dev@example.com', password: 'correct horse battery staple' };
const COMPOSE = ['compose', '-f', 'docker-compose.yml', '-f', 'docker-compose.dev.yml'];

const compose = (...args: string[]): string =>
  execFileSync('docker', [...COMPOSE, ...args], { cwd: '..', encoding: 'utf8' });

const rotate = (...args: string[]): string => compose('exec', '-T', 'server', 'node', 'dist/cli/rotate-keys.js', ...args);

/** Signs in, first signing out if this browser is already signed in from an earlier step. */
async function signIn(page: Page): Promise<void> {
  await page.goto('/');
  if (await page.locator('#signed-in').isVisible()) {
    await page.goto('/logout');
    await page.getByRole('button', { name: 'Yes, sign me out' }).click();
    await page.goto('/');
  }
  await page.getByRole('link', { name: 'Sign in with D3 Auth' }).click();
  await page.getByLabel('Email').fill(OWNER.email);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Password', { exact: true }).fill(OWNER.password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await continueIfAsked(page);
  await expect(page.locator('#signed-in')).toBeVisible();
}

interface KeyRow {
  kid: string;
  alg: string;
  status: 'next' | 'current' | 'retiring' | 'retired';
  /** True for the key this process actually loaded — not merely the one the table calls current. */
  signingNow: boolean;
}

/** What the console itself is told. Reading the token would mean printing one in a page. */
async function keys(page: Page): Promise<KeyRow[]> {
  const answer = await page.request.get(`${AUTH}/api/admin/keys`, { headers: { accept: 'application/json' } });
  expect(answer.status()).toBe(200);
  return ((await answer.json()) as { keys: KeyRow[] }).keys;
}

const signingKid = async (page: Page): Promise<string> =>
  (await keys(page)).find((key) => key.alg === 'ES256' && key.signingNow)?.kid ?? '';

async function publishedKids(page: Page): Promise<string[]> {
  const answer = await page.request.get(`${AUTH}/oidc/jwks`);
  return ((await answer.json()) as { keys: { kid: string }[] }).keys.map((key) => key.kid);
}

/** Waits for the service to answer again after a restart. */
async function waitForReady(page: Page): Promise<void> {
  await expect(async () => {
    const answer = await page.request.get(`${AUTH}/readyz`, { timeout: 2_000 });
    expect(answer.status()).toBe(200);
  }).toPass({ timeout: 60_000 });
}

test.describe.configure({ mode: 'serial', timeout: 180_000 });

test.describe('F7 rotate signing keys', () => {
  test('a rotation done by the book is invisible to the app', async ({ page }, testInfo) => {
    // One project is enough: this restarts the shared stack, and doing it twice buys nothing.
    test.skip(testInfo.project.name !== 'desktop-light', 'restarts the shared stack — once is enough');

    await signIn(page);
    await page.goto(`${AUTH}/admin/keys`);
    const before = await signingKid(page);
    expect(before).not.toBe('');

    // 1. Generate. It is published immediately and signs nothing — that is what gives every
    //    consumer time to fetch it before it has to trust it.
    await page.getByRole('button', { name: 'Generate a next ES256 key' }).click();
    await expect(page.getByText('A next key is published')).toBeVisible();
    await expect(page.getByText('next', { exact: true })).toBeVisible();

    const afterGenerate = await publishedKids(page);
    expect(afterGenerate).toContain(before);
    expect(afterGenerate.length).toBeGreaterThan(1);

    // 2. The console refuses to promote it early, and says when it will stop refusing.
    const promote = page.getByRole('button', { name: /^Promote \(waiting until / });
    await expect(promote).toBeDisabled();

    // Everyone signed in stays signed in while a key is merely published, and the key that was
    // signing before is still the one signing.
    await page.goto('/');
    await expect(page.locator('#signed-in')).toBeVisible();
    expect(await signingKid(page)).toBe(before);

    // 3. Promote, skipping a wait nobody else is holding, then restart so the process picks it up.
    rotate('--promote', '--force');
    compose('restart', 'server');
    await waitForReady(page);

    // 4. Sign in again. A different key is signing, and nothing about signing in changed.
    await signIn(page);
    const after = await signingKid(page);
    expect(after).not.toBe(before);
    expect(after).not.toBe('');

    // The old key is still published while it is retiring, which is why the tokens it signed
    // still verify.
    expect(await publishedKids(page)).toContain(before);
    expect((await keys(page)).find((key) => key.kid === before)?.status).toBe('retiring');

    // 5. Retire it. Now it is gone, and the console says so.
    rotate('--retire', '--force');
    compose('restart', 'server');
    await waitForReady(page);
    await expect(async () => {
      expect(await publishedKids(page)).not.toContain(before);
    }).toPass({ timeout: 30_000 });

    await signIn(page);
    expect(await signingKid(page)).toBe(after);

    // Every step of that is in the trail (REQ-110).
    await page.goto(`${AUTH}/admin/audit`);
    await expect(page.getByText('key.generated').first()).toBeVisible();
    await expect(page.getByText('key.promoted').first()).toBeVisible();
    await expect(page.getByText('key.retired').first()).toBeVisible();
  });
});
