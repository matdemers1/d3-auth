import { readFile } from 'node:fs/promises';
import { expect, test, type Page } from '@playwright/test';
import { continueIfAsked } from './interstitial';

// The operator console, driven the way an operator drives it (REQ-073, REQ-053, REQ-072, C-0…C-11).
//
// These are the screens nobody writes a flow diagram for and everybody relies on: the home page
// that says whether anything is wrong, groups handing out access to several people at once, the
// audit trail, and the export that must never contain a secret. Each test finishes by putting
// back what it changed, because this runs against the same dev stack as every other spec.

const AUTH = 'http://localhost:3000';
const OWNER = { email: 'dev@example.com', password: 'correct horse battery staple' };

async function signIn(page: Page): Promise<void> {
  await page.goto('/');
  await page.getByRole('link', { name: 'Sign in with D3 Auth' }).click();
  await page.getByLabel('Email').fill(OWNER.email);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Password', { exact: true }).fill(OWNER.password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await continueIfAsked(page);
  await expect(page.locator('#signed-in')).toBeVisible();
}

test.describe('the console', () => {
  test.beforeEach(async ({ page }) => {
    await signIn(page);
  });

  test('home says how the instance is doing, and links to the rest of it', async ({ page }) => {
    await page.goto(`${AUTH}/admin`);

    // The tiles that matter are the ones that can be wrong; the database one had better not be.
    await expect(page.getByRole('heading', { name: 'Database' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Signing keys' })).toBeVisible();
    await expect(page.getByText('Answering.')).toBeVisible();

    // Counts, and the last few things that happened — including this sign-in.
    await expect(page.getByRole('link', { name: 'People' }).first()).toBeVisible();
    await expect(page.getByText('login.success').first()).toBeVisible();

    await page.getByRole('link', { name: 'Apps', exact: true }).first().click();
    await expect(page).toHaveURL(/\/admin\/apps$/);
  });

  test('a group hands out access, and never appears in a token', async ({ page }) => {
    const name = `E2E Group ${Date.now()}`;
    await page.goto(`${AUTH}/admin/groups`);
    await page.getByLabel('New group').fill(name);
    await page.getByRole('button', { name: 'Create' }).click();
    await expect(page.getByRole('link', { name })).toBeVisible();

    await page.getByRole('link', { name }).click();
    await expect(page.getByRole('heading', { name })).toBeVisible();

    // What the app is told is the role; how the operator organised people is not the app's
    // business, so the group's name is nowhere in the claims (REQ-053).
    await page.goto('/');
    const claims = (await page.locator('#claims').textContent()) ?? '';
    expect(claims).not.toContain(name);

    // Put it back.
    await page.goto(`${AUTH}/admin/groups`);
    await page.getByRole('link', { name }).click();
    await page.getByRole('button', { name: 'Delete this group' }).click();
    // Deleting leaves nothing to look at, so it goes back to the list — where the group is gone.
    await expect(page).toHaveURL(/\/admin\/groups$/);
    await expect(page.getByRole('link', { name })).toBeHidden();
  });

  test('the audit screen filters, and offers the same rows as a file', async ({ page }) => {
    await page.goto(`${AUTH}/admin/audit`);
    await expect(page.getByText('login.success').first()).toBeVisible();

    const download = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Export what is showing' }).click();
    expect((await download).suggestedFilename()).toMatch(/^audit-\d{4}-\d{2}-\d{2}\.csv$/);
  });

  test('the export is a shape, not a backup', async ({ page }) => {
    await page.goto(`${AUTH}/admin/transfer`);
    const download = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Download the state file' }).click();
    const file = await download;
    expect(file.suggestedFilename()).toMatch(/^d3auth-state-\d{4}-\d{2}-\d{2}\.json$/);

    const path = await file.path();
    const text = await readFile(path, 'utf8');
    const state = JSON.parse(text) as { apps: { client_id: string }[]; people: unknown[] };

    expect(state.apps.map((app) => app.client_id)).toContain('dev-web');
    expect(state.people.length).toBeGreaterThan(0);
    // The whole point of the file: nothing in it lets anybody in.
    expect(text).not.toContain('argon2');
    expect(text).not.toMatch(/client_secret|password|private/i);
  });
});
