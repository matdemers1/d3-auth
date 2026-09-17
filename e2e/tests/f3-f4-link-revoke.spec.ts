import { continueIfAsked } from './interstitial';
import { expect, test, type Page } from '@playwright/test';

// F3 — connect D3 Auth to an account the app already had (dual-login).
// F4 — revoke access in the console and watch the app find out.
//
// These two are the reason the whole project exists: an admin decides who reaches an app, and
// that decision has to land in the app itself rather than waiting for a token to expire.

const AUTH = 'http://localhost:3000';
const OWNER = { email: 'dev@example.com', password: 'correct horse battery staple' };
const LOCAL = { username: 'owner', password: 'the-local-owner-password' };

async function signInLocally(page: Page): Promise<void> {
  await page.goto('/');
  await page.getByLabel('Username').fill(LOCAL.username);
  await page.getByLabel('Password').fill(LOCAL.password);
  await page.getByRole('button', { name: 'Sign in here instead' }).click();
  await expect(page.locator('#signed-in')).toBeVisible();
}

async function signInWithD3Auth(page: Page): Promise<void> {
  await page.goto('/');
  await page.getByRole('link', { name: 'Sign in with D3 Auth' }).click();
  await page.getByLabel('Email').fill(OWNER.email);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Password', { exact: true }).fill(OWNER.password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await continueIfAsked(page);
  await expect(page.locator('#signed-in')).toBeVisible();
}

test.describe('F3 connecting an account that already exists', () => {
  test('links explicitly, and unlinking asks for the local password', async ({ page }) => {
    await signInLocally(page);
    await expect(page.locator('#via')).toContainText('this app');
    // Nothing is linked by having signed in; linking is a choice (rule 9).
    await expect(page.locator('#linked')).toBeHidden();

    await page.getByRole('link', { name: 'Connect D3 Auth' }).click();
    await page.getByLabel('Email').fill(OWNER.email);
    await page.getByRole('button', { name: 'Continue' }).click();
    await page.getByLabel('Password', { exact: true }).fill(OWNER.password);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await continueIfAsked(page);

    // The identity is stored as (iss, sub) — never the email address.
    const linked = page.locator('#linked');
    await expect(linked).toBeVisible();
    await expect(linked).toContainText('localhost:3000#');
    await expect(linked).not.toContainText(OWNER.email);

    // The local login still works: connecting adds a way in, it does not replace one.
    await page.goto('/logout');
    await signInLocally(page);
    await expect(page.locator('#linked')).toBeVisible();

    // Unlinking needs the password this app knows, so a borrowed session cannot cut the link.
    await page.getByLabel('Your password here').fill('not the password');
    await page.getByRole('button', { name: 'Disconnect D3 Auth' }).click();
    await expect(page.getByText('That password did not match')).toBeVisible();

    await page.goto('/');
    await page.getByLabel('Your password here').fill(LOCAL.password);
    await page.getByRole('button', { name: 'Disconnect D3 Auth' }).click();
    await expect(page.locator('#linked')).toBeHidden();
  });
});

test.describe('F4 revoking access', () => {
  test('signs the person out of the app, not just out of the console', async ({ page }) => {
    // The dev seed registers the example app's back-channel endpoint, which is what makes this
    // flow a revocation rather than a note in a log (REQ-011).
    await signInWithD3Auth(page);
    await expect(page.locator('#roles')).toContainText('admin');

    // The owner revokes their own access to this app from the console.
    await page.goto(`${AUTH}/admin/apps/dev-web`);
    await expect(page.getByRole('heading', { name: 'Local development client' })).toBeVisible();
    const row = page.getByRole('list', { name: 'Who can sign in' }).getByRole('listitem').filter({ hasText: OWNER.email });
    await row.getByRole('button', { name: 'Revoke' }).click();
    await expect(page.getByText('Access revoked')).toBeVisible();

    // The app was told: its own session is gone, so the home page is the signed-out one.
    await page.goto('/');
    await expect(page.locator('#signed-in')).toBeHidden();
    await expect(page.getByRole('link', { name: 'Sign in with D3 Auth' })).toBeVisible();

    // And signing in again is refused before any screen — they are still signed in to the
    // provider, so the grant is the only thing that decides (REQ-051).
    await page.getByRole('link', { name: 'Sign in with D3 Auth' }).click();
    await expect(page.getByText('Sign-in failed')).toBeVisible();
    await expect(page.locator('#signed-in')).toBeHidden();

    // Put the fixture back, so the suite can be run twice.
    await page.goto(`${AUTH}/admin/people`);
    const person = page.getByRole('list', { name: 'People' }).getByRole('listitem').filter({ hasText: OWNER.email });
    await person.getByRole('link', { name: 'Dev Person' }).click();
    await page.getByRole('button', { name: 'Administrator' }).click();
    await expect(page.getByText('Administrator given.')).toBeVisible();
  });
});
