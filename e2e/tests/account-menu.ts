import type { Page } from '@playwright/test';

/**
 * Opens the console's account menu — who is signed in, settings, the theme, sign-out.
 *
 * It sits at the foot of the sidebar. On a phone the sidebar is a drawer, so the drawer opens
 * first, the way a person on a phone gets there.
 */
export async function openAccountMenu(page: Page): Promise<void> {
  const drawer = page.getByRole('button', { name: 'Open navigation' });
  if (await drawer.isVisible()) await drawer.click();
  // The trigger is named by the person and their role: "Dev Person Owner · dev@example.com".
  await page.getByRole('button', { name: /·/ }).click();
}
