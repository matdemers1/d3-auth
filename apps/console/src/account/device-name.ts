// Turning a user-agent string into something a person can recognise on the Sessions screen.
//
// This is deliberately shallow: it names the browser and the platform and stops. Anything more
// detailed would be guessing, and the full string is kept on the row for anyone who wants it.

const BROWSERS: [RegExp, string][] = [
  [/\bEdg\//, 'Edge'],
  [/\bOPR\//, 'Opera'],
  [/\bChrome\//, 'Chrome'],
  [/\bFirefox\//, 'Firefox'],
  [/\bSafari\//, 'Safari'],
];

const PLATFORMS: [RegExp, string][] = [
  [/\biPhone\b/, 'iPhone'],
  [/\biPad\b/, 'iPad'],
  [/\bAndroid\b/, 'Android'],
  [/\bMac OS X\b|\bMacintosh\b/, 'Mac'],
  [/\bWindows\b/, 'Windows'],
  [/\bLinux\b/, 'Linux'],
];

const match = (value: string, table: [RegExp, string][]): string | undefined =>
  table.find(([pattern]) => pattern.test(value))?.[1];

export function describeDevice(userAgent: string | null): string {
  if (!userAgent) return 'Unknown browser';
  const browser = match(userAgent, BROWSERS);
  const platform = match(userAgent, PLATFORMS);
  if (browser && platform) return `${browser} on ${platform}`;
  return browser ?? platform ?? userAgent.slice(0, 40);
}

/** Docker and some proxies hand us IPv4 addresses wrapped as IPv6. Show the address itself. */
export function describeAddress(ip: string | null): string {
  if (!ip) return 'no address recorded';
  return ip.replace(/^::ffff:/, '');
}
