import { continueIfAsked } from './interstitial';
import { expect, test, type CDPSession, type Page } from '@playwright/test';

// REQ-034, REQ-032: enrol a passkey and sign in with it.
//
// Chrome's virtual authenticator stands in for a phone or a security key. It is the only way to
// test this without a human thumb, and it exercises the real ceremony: the browser builds and
// signs the assertion, and our server verifies it.

const AUTH = 'http://localhost:3000';
// Its own account: enrolling a factor changes how that person signs in, which would surprise
// every other test using the shared dev user.
const USER = { email: 'passkey@example.com', password: 'willow ember quartz 12' };

async function addVirtualAuthenticator(page: Page): Promise<CDPSession> {
  const client = await page.context().newCDPSession(page);
  await client.send('WebAuthn.enable');
  await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return client;
}

async function signInWithPassword(page: Page): Promise<void> {
  await page.goto('/');
  await page.getByRole('link', { name: 'Sign in with D3 Auth' }).click();
  await page.getByLabel('Email').fill(USER.email);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Password', { exact: true }).fill(USER.password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await continueIfAsked(page);
  await expect(page.locator('#signed-in')).toBeVisible();
}

async function signOut(page: Page): Promise<void> {
  await page.goto('/logout');
  await page.getByRole('button', { name: 'Yes, sign me out' }).click();
}

test.describe('F2 passkeys', () => {
  test.skip(({ browserName }) => browserName !== 'chromium', 'needs Chrome DevTools virtual authenticator');

  test('a person enrols a passkey and then signs in with it', async ({ page }) => {
    await addVirtualAuthenticator(page);
    await signInWithPassword(page);

    // Enrol from the account area.
    await page.goto(`${AUTH}/account/security`);
    await expect(page.getByRole('heading', { name: 'Security', exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Add a passkey' }).click();
    // The ceremony is asynchronous; this is the server's answer, not the heading above the list.
    await expect(page.getByText('Passkey added')).toBeVisible();

    // Asked from inside the page, so it rides the same session the browser is using.
    const listFactors = () =>
      page.evaluate(async () => {
        const res = await fetch('/api/account/factors', { headers: { accept: 'application/json' } });
        return (await res.json()) as { passkeys: { id: string }[] };
      });
    expect((await listFactors()).passkeys).toHaveLength(1);

    // Sign out of the provider, then sign in again using the passkey as the second factor.
    await signOut(page);

    await page.goto('/login');
    await page.getByLabel('Email').fill(USER.email);
    await page.getByRole('button', { name: 'Continue' }).click();
    await page.getByLabel('Password', { exact: true }).fill(USER.password);
    await page.getByRole('button', { name: 'Sign in' }).click();

    // The account now has a factor, so the second step appears — and the passkey answers it.
    await expect(page.getByText('One more step')).toBeVisible();
    await page.getByRole('button', { name: 'Use a passkey' }).click();

    // Having proved it is them, they are offered the trusted device (REQ-036).
    await expect(page.getByText('Skip this step on this browser?')).toBeVisible();
    await page.getByRole('button', { name: 'Yes, remember this browser' }).click();
    await expect(page.locator('#signed-in')).toBeVisible();

    // And the offer means something: the next sign-in asks for the password alone.
    await signOut(page);
    await signInWithPassword(page);

    // Until it is taken back, at which point the factor is asked for again.
    await page.goto(`${AUTH}/account/security`);
    await expect(page.getByRole('heading', { name: 'Browsers that skip the second step' })).toBeVisible();
    await page.getByRole('button', { name: 'Forget' }).click();
    await expect(page.getByRole('heading', { name: 'Browsers that skip the second step' })).toBeHidden();

    await signOut(page);
    await page.goto('/login');
    await page.getByLabel('Email').fill(USER.email);
    await page.getByRole('button', { name: 'Continue' }).click();
    await page.getByLabel('Password', { exact: true }).fill(USER.password);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.getByText('One more step')).toBeVisible();
    await page.getByRole('button', { name: 'Use a passkey' }).click();
    await page.getByRole('button', { name: 'Not this time' }).click();
    await expect(page.locator('#signed-in')).toBeVisible();

    // Leave the account as it was found: the virtual authenticator dies with this browser, so a
    // passkey left behind would lock the next run out of the password-only path.
    await page.goto(`${AUTH}/account/security`);
    await page.getByRole('button', { name: 'Remove' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Remove passkey' }).click();
    await expect(page.getByText('Your account is protected by a password only')).toBeVisible();
  });
});
