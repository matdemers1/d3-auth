import { continueIfAsked } from './interstitial';
import { expect, test, type Page } from '@playwright/test';

// F5 — lost phone. A guest tells the owner; the owner resets their account; the guest sets it up
// again from the link and signs in. The account is the same one throughout (REQ-039).

const AUTH = 'http://localhost:3000';
const OWNER = { email: 'dev@example.com', password: 'correct horse battery staple' };
const GUEST = { email: 'resetme@example.com', password: 'cardamom trellis window' };
// What they will choose on the way back in. Fixed, so the flow can be run twice.
const NEW_PASSWORD = 'thistle harbour kindling';

async function signIn(page: Page, who: { email: string; password: string }): Promise<void> {
  await page.goto('/');
  await page.getByRole('link', { name: 'Sign in with D3 Auth' }).click();
  await page.getByLabel('Email').fill(who.email);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Password', { exact: true }).fill(who.password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await continueIfAsked(page);
  await expect(page.locator('#signed-in')).toBeVisible();
}

/** The subject the app knows this person by. It must survive the reset (REQ-039). */
async function subjectOf(page: Page): Promise<string> {
  const claims = (await page.locator('#claims').textContent()) ?? '{}';
  return (JSON.parse(claims) as { sub?: string }).sub ?? '';
}

async function signOut(page: Page): Promise<void> {
  await page.goto('/logout');
  await page.getByRole('button', { name: /^Sign out( everywhere)?$/ }).click();
}

test.describe('F5 lost phone', () => {
  test('an owner resets an account and its person sets it up again', async ({ page }) => {
    // Who they are before any of this, so "the same account" can be checked rather than assumed.
    await signIn(page, GUEST);
    const before = await subjectOf(page);
    expect(before).not.toBe('');
    await signOut(page);

    await signIn(page, OWNER);

    // The owner finds them in People and resets the account. It cannot be undone, so it asks first,
    // in a dialog rather than a second button under the pointer.
    await page.goto(`${AUTH}/admin/people`);
    const row = page.getByRole('list', { name: 'People' }).getByRole('listitem').filter({ hasText: GUEST.email });
    await row.getByRole('button', { name: /^More actions for / }).click();
    await page.getByRole('menuitem', { name: 'Reset their account…' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Reset account' }).click();

    // Mail is the log driver in development, so the console shows the link to send by hand —
    // which is the fallback that has to work when mail is down (REQ-108).
    const link = page.locator('code', { hasText: '/login/invite/' });
    await expect(link).toBeVisible();
    const url = (await link.textContent())?.trim() ?? '';
    expect(url).toContain('/login/invite/');
    await signOut(page);

    // The guest opens it and sets the account up again.
    await page.goto(url);
    await page.getByLabel('Your name').fill('Reset Me');
    await page.getByLabel('Username').fill('resetme');
    await page.getByLabel('Password', { exact: true }).fill(NEW_PASSWORD);
    await page.getByRole('button', { name: 'Create my account' }).click();
    await expect(page.getByRole('heading', { name: 'Your account is ready' })).toBeVisible();

    // The old password is gone and the new one works.
    await page.goto('/');
    await page.getByRole('link', { name: 'Sign in with D3 Auth' }).click();
    await page.getByLabel('Email').fill(GUEST.email);
    await page.getByRole('button', { name: 'Continue' }).click();
    await page.getByLabel('Password', { exact: true }).fill(GUEST.password);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.getByText('do not match')).toBeVisible();

    await page.getByLabel('Password', { exact: true }).fill(NEW_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await continueIfAsked(page);
    await expect(page.locator('#signed-in')).toBeVisible();
    // Same account, so the same subject: the reset did not make a new person.
    expect(await subjectOf(page)).toBe(before);

    // Leave the fixture as it was found, so the other viewport project can run this too. The
    // account area is how a person would do it, and it has no factor to step up with.
    await page.goto(`${AUTH}/account/password`);
    await page.getByLabel('Current password').fill(NEW_PASSWORD);
    await page.getByLabel('New password').fill(GUEST.password);
    await page.getByRole('button', { name: 'Change password' }).click();
    await expect(page.getByText('Password changed')).toBeVisible();
  });
});
