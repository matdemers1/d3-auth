import { expect, test } from '@playwright/test';
import { openAccountMenu } from './account-menu';

// Going straight to the console (ADR-005). An operator types the address in, signs in, lands on
// the page they asked for, and signing out puts the sign-in form back in front of them — no app in
// the middle, and no empty screens.

const AUTH = 'http://localhost:3000';
const OWNER = { email: 'dev@example.com', password: 'correct horse battery staple' };

test('the console asks for a sign-in, returns to the page, and asks again after signing out', async ({ page }) => {
  await page.goto(`${AUTH}/admin/people`);

  await expect(page.getByRole('heading', { name: /Sign in to/ })).toBeVisible();
  await page.getByLabel('Email').fill(OWNER.email);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Password', { exact: true }).fill(OWNER.password);
  await page.getByRole('button', { name: 'Sign in' }).click();

  await expect(page).toHaveURL(`${AUTH}/admin/people`);
  await expect(page.getByRole('heading', { name: /^People/ })).toBeVisible();

  // Sign-out is the last item in the account menu, on every console page.
  await openAccountMenu(page);
  await page.getByRole('menuitem', { name: 'Sign out' }).click();
  await page.getByRole('button', { name: 'Yes, sign me out' }).click();
  await expect(page.getByRole('heading', { name: /Sign in to/ })).toBeVisible();

  // And the bare address means the same thing.
  await page.goto(`${AUTH}/`);
  await expect(page.getByRole('heading', { name: /Sign in to/ })).toBeVisible();
});
