import { expect, test } from '@playwright/test';
import { continueIfAsked } from './interstitial';

// Attack class: finishing somebody else's sign-in (ASVS 5.0 10.1.2; found by the gate, F-12).
//
// The reference app used to remember a sign-in it had started by its `state` alone, so any browser
// that came back with that state was believed. Two ways that goes wrong, both tried here:
//
// - The attacker signs in as themselves and sends the victim the callback link. The victim's browser
//   finishes it and is now signed into the attacker's account, where whatever they do is the
//   attacker's to read.
// - The attacker starts *linking* from their own account and gets a victim who is already signed in
//   to the provider to open the authorization link. The victim's identity — and roles — attach to
//   the attacker's account.
//
// Each sign-in is now bound to the browser that started it. Both attempts end on "Unexpected sign-in
// response", and nobody is signed in to anything they did not start.

const AUTH = 'http://localhost:3000';
const EXAMPLE = process.env.EXAMPLE_URL ?? 'http://localhost:4000';
const VICTIM = { email: 'dev@example.com', password: 'correct horse battery staple' };

test.describe('finishing somebody else sign-in', () => {
  test('a callback link from another browser is refused', async ({ browser }) => {
    const attacker = await browser.newContext();
    const attackerPage = await attacker.newPage();

    // The attacker signs in as themselves once, so the provider will answer the next request silently.
    await attackerPage.goto('/');
    await attackerPage.getByRole('link', { name: 'Sign in with D3 Auth' }).click();
    await attackerPage.getByLabel('Email').fill(VICTIM.email);
    await attackerPage.getByRole('button', { name: 'Continue' }).click();
    await attackerPage.getByLabel('Password', { exact: true }).fill(VICTIM.password);
    await attackerPage.getByRole('button', { name: 'Sign in' }).click();
    await continueIfAsked(attackerPage);
    await expect(attackerPage.locator('#signed-in')).toBeVisible();

    // Then starts another, and follows the redirects by hand so the callback is captured unused.
    let next = `${EXAMPLE}/login`;
    let callback = '';
    for (let hop = 0; hop < 10 && !callback; hop += 1) {
      const answer = await attackerPage.request.get(next, { maxRedirects: 0 });
      const location = answer.headers().location;
      if (!location) break;
      next = new URL(location, next).toString();
      if (new URL(next).pathname === '/callback') callback = next;
    }
    expect(callback).toContain('code=');

    // A different browser — the victim's — opens that link.
    const victim = await browser.newContext();
    const victimPage = await victim.newPage();
    await victimPage.goto(callback);
    await expect(victimPage.getByRole('heading', { name: 'Unexpected sign-in response' })).toBeVisible();
    await victimPage.goto('/');
    await expect(victimPage.locator('#signed-in')).toBeHidden();

    await attacker.close();
    await victim.close();
  });

  test('an authorization link started by another browser does not sign this one in', async ({ browser }) => {
    // The attacker starts a sign-in and hands over the provider URL instead.
    const attacker = await browser.newContext();
    const attackerPage = await attacker.newPage();
    await attackerPage.goto('/');
    const authorizeUrl = await attackerPage.getByRole('link', { name: 'Sign in with D3 Auth' }).getAttribute('href');
    const started = await attackerPage.request.get(new URL(authorizeUrl ?? '/login', attackerPage.url()).toString(), { maxRedirects: 0 });
    const providerUrl = started.headers().location ?? '';
    expect(providerUrl).toContain(`${AUTH}/oidc/auth`);

    // The victim, signed in to the provider in their own browser, opens it and signs in.
    const victim = await browser.newContext();
    const victimPage = await victim.newPage();
    await victimPage.goto(providerUrl);
    await victimPage.getByLabel('Email').fill(VICTIM.email);
    await victimPage.getByRole('button', { name: 'Continue' }).click();
    await victimPage.getByLabel('Password', { exact: true }).fill(VICTIM.password);
    await victimPage.getByRole('button', { name: 'Sign in' }).click();
    await continueIfAsked(victimPage, 'h1');

    // The app never started a sign-in in this browser, so it refuses to finish one.
    await expect(victimPage.getByRole('heading', { name: 'Unexpected sign-in response' })).toBeVisible();
    await victimPage.goto('/');
    await expect(victimPage.locator('#signed-in')).toBeHidden();

    await attacker.close();
    await victim.close();
  });
});
