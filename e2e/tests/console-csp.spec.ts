import { expect, test } from '@playwright/test';

// The console under its real Content-Security-Policy (REQ-132, D-072). Dialogs lock the page's
// scroll with a <style> element written at runtime; the policy has no 'unsafe-inline', so it is
// allowed only because it carries this response's nonce. A policy that silently blocked it would
// still pass every other test — the dialog opens either way — so this one watches for violations.

const AUTH = 'http://localhost:3000';
const OWNER = { email: 'dev@example.com', password: 'correct horse battery staple' };

test('opening a dialog breaks no CSP rule and locks the page behind it', async ({ page }) => {
  const violations: string[] = [];
  page.on('console', (message) => {
    if (/Content Security Policy/i.test(message.text())) violations.push(message.text());
  });

  await page.goto(`${AUTH}/admin/people`);
  await page.getByLabel('Email').fill(OWNER.email);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Password', { exact: true }).fill(OWNER.password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(`${AUTH}/admin/people`);

  await page.getByRole('button', { name: 'Invite someone' }).click();
  await expect(page.getByRole('dialog')).toBeVisible();

  await expect(page.locator('body')).toHaveCSS('overflow', 'hidden');
  // Browsers hide a nonce's value once the element is in the document, but keep the attribute.
  expect(await page.locator('style[nonce]').count()).toBeGreaterThan(0);
  expect(violations).toEqual([]);
});
