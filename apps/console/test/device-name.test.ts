import { describe, expect, it } from 'vitest';
import { describeAddress, describeDevice } from '../src/account/device-name';

// A person revoking a session has to recognise it. "Chrome on Mac" is recognisable; 130
// characters of user-agent are not.

describe('describeDevice', () => {
  const cases: [string, string][] = [
    [
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36',
      'Chrome on Mac',
    ],
    ['Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/604.1', 'Safari on iPhone'],
    ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36 Edg/151.0.0.0', 'Edge on Windows'],
    ['Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0', 'Firefox on Linux'],
    ['Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Mobile Safari/537.36', 'Chrome on Android'],
  ];

  for (const [userAgent, expected] of cases) {
    it(`names ${expected}`, () => {
      expect(describeDevice(userAgent)).toBe(expected);
    });
  }

  it('says so rather than inventing a name', () => {
    expect(describeDevice(null)).toBe('Unknown browser');
    expect(describeDevice('curl/8.7.1')).toBe('curl/8.7.1');
  });
});

describe('describeAddress', () => {
  it('unwraps an IPv4 address a proxy handed us as IPv6', () => {
    expect(describeAddress('::ffff:172.19.0.1')).toBe('172.19.0.1');
    expect(describeAddress('2001:db8::1')).toBe('2001:db8::1');
    expect(describeAddress(null)).toBe('no address recorded');
  });
});
