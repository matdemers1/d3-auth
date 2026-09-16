import { expect, test } from '@playwright/test';

// REQ-141. The stack under test has already been claimed (dev:up seeds accounts), so what a
// browser must see here is the closed state — and it must be the server saying so.
test.describe('first-run setup', () => {
  test('is closed once the instance has an account', async ({ page }) => {
    const response = await page.goto('http://localhost:3000/login/setup');
    expect(response?.status()).toBe(404);
    await expect(page.getByRole('heading', { name: 'Setup is finished' })).toBeVisible();
    await expect(page.getByLabel('Setup code')).toHaveCount(0);
  });

  test('refuses a claim outright', async ({ request }) => {
    const res = await request.post('http://localhost:3000/api/setup', {
      data: { code: 'AAAA-BBBB-CCCC-DDDD-EEEE', email: 'a@b.test', username: 'someone', displayName: 'S', password: 'harbour lantern drift 47' },
    });
    expect(res.status()).toBe(409);
  });
});
