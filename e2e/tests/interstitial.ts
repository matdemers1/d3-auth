import { expect, type Page } from '@playwright/test';

/**
 * Answers the continue-as interstitial when it appears (REQ-059).
 *
 * The first sign-in to an app stops to say which account is about to be used. A person clicks
 * *Continue*; so does this. Later sign-ins go straight through, so this is a no-op then — which
 * is why it waits on either outcome rather than assuming one.
 */
export async function continueIfAsked(page: Page, signedIn = '#signed-in'): Promise<void> {
  const keepGoing = page.getByRole('button', { name: /^Continue as / });
  await expect(keepGoing.or(page.locator(signedIn)).first()).toBeVisible();
  if (await keepGoing.isVisible()) await keepGoing.click();
}
