import { execFileSync } from 'node:child_process';
import { continueIfAsked } from './interstitial';
import { expect, test, type Page } from '@playwright/test';

// F6 — the owner is locked out. Their only factor is on a phone that is gone; they still know
// their password. Someone with a shell on the host mints a recovery link (REQ-122).
//
// This test runs the real CLI in the real container, because "it works when you run it on the
// host" is the entire claim being made. ADR-003 explains why the link is a window, not a key.

const AUTH = 'http://localhost:3000';
const OWNER = { email: 'dev@example.com', password: 'correct horse battery staple' };

const COMPOSE = ['compose', '-f', 'docker-compose.yml', '-f', 'docker-compose.dev.yml'];

function mintRecoveryLink(minutes = 10): string {
  const output = execFileSync(
    'docker',
    [...COMPOSE, 'exec', '-T', 'server', 'node', 'dist/cli/recover.js', '--user', OWNER.email, '--minutes', String(minutes)],
    { cwd: '..', encoding: 'utf8' },
  );
  const url = /https?:\/\/\S+\/login\/recover\/\S+/.exec(output)?.[0];
  if (!url) throw new Error(`the CLI printed no link:\n${output}`);
  return url;
}

async function startSignIn(page: Page): Promise<void> {
  await page.goto('/');
  await page.getByRole('link', { name: 'Sign in with D3 Auth' }).click();
  await page.getByLabel('Email').fill(OWNER.email);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Password', { exact: true }).fill(OWNER.password);
  await page.getByRole('button', { name: 'Sign in' }).click();
}

/** Signs in and goes all the way through, interstitial included. */
async function signInFully(page: Page): Promise<void> {
  await startSignIn(page);
  await continueIfAsked(page);
}

async function signOut(page: Page): Promise<void> {
  await page.goto('/logout');
  await page.getByRole('button', { name: /^Sign out( everywhere)?$/ }).click();
}

test.describe('F6 break-glass', () => {
  test.skip(({ browserName }) => browserName !== 'chromium', 'needs Chrome DevTools virtual authenticator');

  test('an owner with no usable factor gets back in from the host', async ({ page }) => {
    // Give them a factor, then take away the only thing that could answer it: enrol a passkey
    // on a virtual authenticator and then discard the authenticator, exactly like a lost phone.
    const client = await page.context().newCDPSession(page);
    await client.send('WebAuthn.enable');
    const { authenticatorId } = await client.send('WebAuthn.addVirtualAuthenticator', {
      options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true },
    });

    await signInFully(page);
    await expect(page.locator('#signed-in')).toBeVisible();
    await page.goto(`${AUTH}/account/security`);
    await page.getByRole('button', { name: 'Add a passkey' }).click();
    await expect(page.getByText('Passkey added')).toBeVisible();
    await signOut(page);

    // The phone is gone.
    await client.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });

    // Now they are stuck: the password is right, and the second step cannot be answered.
    await startSignIn(page);
    await expect(page.getByText('One more step')).toBeVisible();
    await expect(page.locator('#signed-in')).toBeHidden();

    // Someone with a shell on the host mints a link.
    const url = mintRecoveryLink();
    await page.goto(url);
    await expect(page.getByRole('heading', { name: 'Recovery is ready' })).toBeVisible();
    // The link does not sign anybody in by itself (ADR-003).
    await expect(page.locator('#signed-in')).toBeHidden();

    // The password alone now works, and the factor that could not be used is gone.
    await signInFully(page);
    await expect(page.locator('#signed-in')).toBeVisible();
    await page.goto(`${AUTH}/account/security`);
    await expect(page.getByText('Your account is protected by a password only')).toBeVisible();

    // The window is spent: the next sign-in is an ordinary one, and the link is dead.
    await signOut(page);
    await signInFully(page);
    await expect(page.locator('#signed-in')).toBeVisible();
    await page.goto(url);
    await expect(page.getByRole('heading', { name: 'This recovery link has expired' })).toBeVisible();
  });
});
