import { continueIfAsked } from './interstitial';
import { expect, test } from '@playwright/test';

// F1 — sign in to an app with D3 Auth, then sign out again.
// The provider is the dev stack; the relying party is examples/express.

const USER = { email: process.env.E2E_EMAIL ?? 'dev@example.com', password: process.env.E2E_PASSWORD ?? 'correct horse battery staple' };

test.describe('F1 sign in with D3 Auth', () => {
  test('a person signs in, sees their claims, and signs out', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Example app' })).toBeVisible();
    await page.getByRole('link', { name: 'Sign in with D3 Auth' }).click();

    // Now on the provider's sign-in screen.
    await expect(page.getByRole('heading', { name: /Sign in to/ })).toBeVisible();
    await page.getByLabel('Email').fill(USER.email);
    await page.getByRole('button', { name: 'Continue' }).click();

    await expect(page.getByText(/Signing in as/)).toBeVisible();
    await page.getByLabel('Password', { exact: true }).fill(USER.password);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await continueIfAsked(page);

    // Back at the app, signed in.
    await expect(page.locator('#signed-in')).toBeVisible();
    await expect(page.locator('#username')).toHaveText('dev');
    await expect(page.locator('#claims')).toContainText('"sub"');

    await page.getByRole('link', { name: 'Sign out' }).click();
    await page.getByRole('button', { name: 'Yes, sign me out' }).click();
    await expect(page.getByText('You are signed out.')).toBeVisible();
  });

  test('a wrong password says so without saying which part was wrong', async ({ page }) => {
    await page.goto('/login');
    await page.getByLabel('Email').fill(USER.email);
    await page.getByRole('button', { name: 'Continue' }).click();
    await page.getByLabel('Password', { exact: true }).fill('not the right password');
    await page.getByRole('button', { name: 'Sign in' }).click();

    const alert = page.getByRole('alert');
    await expect(alert).toContainText('That email and password do not match.');
    await expect(alert).not.toContainText(/unknown|no account|not found/i);
    await expect(page.locator('#signed-in')).toHaveCount(0);
  });

  test('an unknown email is answered exactly the same way', async ({ page }) => {
    await page.goto('/login');
    await page.getByLabel('Email').fill(`ghost-${Date.now()}@example.com`);
    await page.getByRole('button', { name: 'Continue' }).click();
    await page.getByLabel('Password', { exact: true }).fill('not the right password');
    await page.getByRole('button', { name: 'Sign in' }).click();

    await expect(page.getByRole('alert')).toContainText('That email and password do not match.');
  });

  test('the sign-in screen is usable with the keyboard alone', async ({ page }) => {
    await page.goto('/login');
    // The email field takes focus on arrival, so a keyboard user types straight away.
    await expect(page.getByLabel('Email')).toBeFocused();
    await page.keyboard.type(USER.email);
    await page.keyboard.press('Enter');
    await expect(page.getByText(/Signing in as/)).toBeVisible();
    await page.getByLabel('Password', { exact: true }).focus();
    await page.keyboard.type(USER.password);
    await page.keyboard.press('Enter');
    await expect(page.locator('#signed-in')).toBeVisible();
  });
});
