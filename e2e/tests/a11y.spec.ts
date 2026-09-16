import AxeBuilder from '@axe-core/playwright';
import { continueIfAsked } from './interstitial';
import { expect, test, type Page } from '@playwright/test';

// REQ-085, REQ-076: every screen a person meets has to be usable by keyboard alone, at AA
// contrast, at phone and desktop sizes, in light and dark. The projects supply the sizes and the
// colour scheme; axe checks the rest.
//
// Contrast is included deliberately: the palette comes from tokens, so a regression here is a
// token regression, and it would be invisible until somebody could not read the screen.

const AUTH = 'http://localhost:3000';
const USER = { email: 'dev@example.com', password: 'correct horse battery staple' };

const scan = (page: Page) => new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']);

async function expectNoViolations(page: Page, where: string): Promise<void> {
  const { violations } = await scan(page).analyze();
  const described = violations.map((violation) => `${violation.id} (${violation.impact ?? 'n/a'}): ${violation.help}`);
  expect(described, `${where} has accessibility violations`).toEqual([]);
}

async function signIn(page: Page): Promise<void> {
  await page.goto('/');
  await page.getByRole('link', { name: 'Sign in with D3 Auth' }).click();
  await page.getByLabel('Email').fill(USER.email);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Password', { exact: true }).fill(USER.password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await continueIfAsked(page);
  await expect(page.locator('#signed-in')).toBeVisible();
}

test.describe('the screens people meet', () => {
  test('sign-in, both steps, has no violations', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('link', { name: 'Sign in with D3 Auth' }).click();
    await expect(page.getByLabel('Email')).toBeVisible();
    await expectNoViolations(page, 'the email step');

    await page.getByLabel('Email').fill(USER.email);
    await page.getByRole('button', { name: 'Continue' }).click();
    await expect(page.getByLabel('Password', { exact: true })).toBeVisible();
    await expectNoViolations(page, 'the password step');
  });

  test('an error on the sign-in screen is announced and readable', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('link', { name: 'Sign in with D3 Auth' }).click();
    await page.getByLabel('Email').fill(USER.email);
    await page.getByRole('button', { name: 'Continue' }).click();
    await page.getByLabel('Password', { exact: true }).fill('not the password');
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.getByText('do not match')).toBeVisible();
    await expectNoViolations(page, 'the sign-in error');
  });

  test('the account screens have no violations', async ({ page }) => {
    await signIn(page);
    for (const [path, heading] of [
      ['/account/profile', 'Your profile'],
      ['/account/password', 'Your password'],
      ['/account/security', 'How you sign in'],
      ['/account/sessions', 'Sessions and devices'],
    ] as const) {
      await page.goto(`${AUTH}${path}`);
      await expect(page.getByRole('heading', { name: heading })).toBeVisible();
      await expectNoViolations(page, path);
    }
  });

  test('the People screen has no violations', async ({ page }) => {
    await signIn(page);
    await page.goto(`${AUTH}/admin/people`);
    await expect(page.getByRole('heading', { name: 'People', exact: true })).toBeVisible();
    await expectNoViolations(page, '/admin/people');
  });

  test('the account area can be reached and used with the keyboard alone', async ({ page }) => {
    await signIn(page);
    await page.goto(`${AUTH}/account/profile`);
    await expect(page.getByRole('heading', { name: 'Your profile' })).toBeVisible();

    // Tab until the display name field has focus, then type into it: no mouse anywhere.
    // Tab until the focused control is the display name field.
    const name = page.getByLabel('Display name');
    for (let presses = 0; presses < 20 && (await page.locator(':focus').getAttribute('name')) !== 'displayName'; presses += 1) {
      await page.keyboard.press('Tab');
    }
    await expect(name).toBeFocused();
    await page.keyboard.press('Control+A');
    await page.keyboard.type('Dev Person');

    // And the nav above it is reachable backwards, so nothing is a keyboard trap.
    await page.keyboard.press('Shift+Tab');
    await expect(page.locator(':focus')).toBeVisible();
  });
});
