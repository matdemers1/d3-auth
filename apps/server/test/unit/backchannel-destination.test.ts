import { describe, expect, it } from 'vitest';
import { isPrivateDestination } from '../../src/oidc/backchannel.js';

// Where a logout token may be posted (REQ-011, T-5.2 finding).
//
// The check used to look at the hostname as text, so a name that *resolved* to an internal
// address sailed through. It now asks DNS, and judges the addresses.

describe('a back-channel destination', () => {
  it.each([
    'http://127.0.0.1/cb',
    'http://10.1.2.3/cb',
    'http://172.20.0.4/cb',
    'http://192.168.1.231/cb',
    'http://169.254.169.254/latest/meta-data',
    'http://100.64.0.1/cb',
    'http://[::1]/cb',
    'http://[fd00::1]/cb',
    'http://[::ffff:127.0.0.1]/cb',
    'http://0.0.0.0/cb',
  ])('%s is private', async (url) => {
    expect(await isPrivateDestination(url)).toBe(true);
  });

  it('a name that resolves to loopback is private, whatever it is called', async () => {
    expect(await isPrivateDestination('https://localhost/cb')).toBe(true);
  });

  it('a name that does not resolve at all is refused rather than assumed fine', async () => {
    expect(await isPrivateDestination('https://nothing-here.invalid/cb')).toBe(true);
  });

  it('a public address is allowed', async () => {
    expect(await isPrivateDestination('https://93.184.215.14/cb')).toBe(false);
    expect(await isPrivateDestination('https://[2606:4700::6810:84e5]/cb')).toBe(false);
  });
});
