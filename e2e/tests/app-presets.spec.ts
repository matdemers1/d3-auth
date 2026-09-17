import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { continueIfAsked } from './interstitial';

// C-6 with a preset (REQ-142, REQ-143, REQ-144): the owner adds Immich from the picker, checks what
// it registers, registers it, and gets the secret once beside Immich's own settings screen. Later
// the app's page shows how to connect it — without the secret.

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

/** Put the stack back: this runs against the same dev stack as every other spec. */
async function removeImmich(page: Page): Promise<void> {
  await page.request.post(`${AUTH}/api/admin/apps/immich/remove`, { headers: { origin: AUTH }, data: {} });
}

async function expectNoViolations(page: Page, where: string): Promise<void> {
  const { violations } = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
  expect(violations.map((v) => `${v.id}: ${v.help}`), `${where} has accessibility violations`).toEqual([]);
}

test.describe('adding an app D3 Auth knows', () => {
  test.beforeEach(async ({ page, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: AUTH });
    await signIn(page);
    await page.goto(`${AUTH}/admin`);
    await removeImmich(page);
  });

  test.afterEach(async ({ page }) => {
    await removeImmich(page);
  });

  test('Immich from the picker: preview, register, the secret once, then Connect this app without it', async ({ page }) => {
    await page.goto(`${AUTH}/admin/apps`);
    await page.getByRole('button', { name: 'Add an app' }).click();
    await expect(page).toHaveURL(/\/admin\/apps\/new$/);
    await expect(page.getByRole('heading', { level: 1, name: 'Add an app' })).toBeVisible();
    await expect(page.getByRole('link', { name: /Register from a manifest/ })).toBeVisible();
    await expectNoViolations(page, 'the picker');

    await page.getByRole('link', { name: /Immich/ }).click();
    await expect(page).toHaveURL(/\/admin\/apps\/new\/immich$/);

    // A path after the address is refused, naming the input.
    await page.getByLabel('Immich address').fill('https://photos.example.com/photos');
    await page.getByRole('button', { name: 'Show the Immich settings' }).click();
    await expect(page.getByText(/^Immich address: /)).toBeVisible();

    await page.getByLabel('Immich address').fill('https://photos.example.com');
    await page.getByRole('button', { name: 'Show the Immich settings' }).click();
    // Before anything is registered: Immich's own settings, top to bottom, and when the secret appears.
    const walkthrough = page.getByRole('region', { name: 'What you will set in Immich' });
    await expect(walkthrough.getByText('issuer_url', { exact: true })).toBeVisible();
    await expect(walkthrough.getByText('Allow insecure requests', { exact: true })).toBeVisible();
    await expect(walkthrough.getByText(/Created when you press Register/)).toBeVisible();
    await expect(walkthrough.locator('code', { hasText: /^ES256$/ })).toBeVisible();
    await expect(page.getByText('Nothing is registered yet')).toBeVisible();
    await expect(page.getByRole('checkbox', { name: 'Give me access to Immich' })).toBeChecked();
    const preview = page.getByRole('region', { name: 'On D3 Auth’s side' });
    await expect(preview.getByText('https://photos.example.com/user-settings', { exact: true })).toBeVisible();
    await expect(preview.getByText('https://photos.example.com/api/oauth/backchannel-logout')).toBeVisible();
    await expectNoViolations(page, 'the Immich form with its preview');

    await page.getByRole('button', { name: 'Register Immich' }).click();
    // Registering needs fresh proof; a sign-in this recent is it, but answer the prompt if it comes.
    const stepUp = page.getByRole('dialog', { name: 'Confirm it is you' });
    const registered = page.getByRole('heading', { level: 1, name: 'Immich is registered' });
    await expect(stepUp.or(registered).first()).toBeVisible();
    if (await stepUp.isVisible()) {
      await stepUp.getByLabel('Your password').fill(OWNER.password);
      await stepUp.getByRole('button', { name: 'Confirm' }).click();
    }
    await expect(registered).toBeVisible();
    await expect(page.getByText('This is the only time the client secret is shown')).toBeVisible();
    await expect(page.getByText('You can sign in to Immich')).toBeVisible();

    // Immich's own fields, with the values that make it work.
    const immich = page.getByRole('region', { name: 'In Immich' });
    await expect(immich.getByText('Administration → Settings → Authentication → OAuth', { exact: false })).toBeVisible();
    const settings = immich.locator('dl');
    for (const value of ['ES256', 'client_secret_basic', 'openid email profile d3:roles', 'roles']) {
      await expect(settings.locator('code', { hasText: new RegExp(`^${value}$`) })).toBeVisible();
    }
    const secretRow = immich.locator('.d3-desc__item', { hasText: 'client_secret' }).filter({ hasNotText: 'token_endpoint' });
    const secret = (await secretRow.locator('code').textContent()) ?? '';
    expect(secret.length).toBeGreaterThan(30);

    // Copy one, and it says so.
    await immich.getByRole('button', { name: 'Copy id_token_signed_response_alg' }).click();
    await expect(immich.getByRole('status').filter({ hasText: 'Copied' })).toBeVisible();
    expect(await page.evaluate<string>('navigator.clipboard.readText()')).toBe('ES256');
    await expectNoViolations(page, 'the registered screen');

    // Later, on the app's page: how to connect it, and no secret anywhere.
    await page.goto(`${AUTH}/admin/apps/immich`);
    const connect = page.getByRole('region', { name: 'Connect this app' });
    await expect(connect).toBeVisible();
    await expect(connect.locator('code', { hasText: /^ES256$/ })).toBeVisible();
    await expect(connect.getByText('Shown once, when the app is registered or its secret is rotated.', { exact: false })).toBeVisible();
    await expect(connect.getByRole('button', { name: 'Copy Client secret' })).toHaveCount(0);
    expect(await page.content()).not.toContain(secret);
    await expectNoViolations(page, 'the app page');

    await connect.getByRole('link', { name: 'Immich paste sheet' }).click();
    await expect(page.getByRole('heading', { level: 1, name: 'Connect Immich' })).toBeVisible();
    expect(await page.content()).not.toContain(secret);
  });

  test('your own app still registers from a manifest, at its new address', async ({ page }) => {
    await page.goto(`${AUTH}/admin/apps/new`);
    await page.getByRole('link', { name: /Register from a manifest/ }).click();
    await expect(page).toHaveURL(/\/admin\/apps\/new\/manifest$/);
    await expect(page.getByRole('heading', { level: 1, name: 'Register an app' })).toBeVisible();
    await expect(page.getByRole('textbox', { name: 'Manifest' })).toBeVisible();
  });
});
