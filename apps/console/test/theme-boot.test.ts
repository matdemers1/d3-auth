import { readFileSync } from 'node:fs';
import { themeBootScript } from '@d3cloud/ui';
import { describe, expect, it } from 'vitest';

// index.html carries the design system's theme boot script inline, so the first paint already has
// the right theme (D-066). The server's CSP allows that exact script by hash, and its own test
// hashes this file. Together they mean an upgrade that changes the script fails here, not in a
// browser that silently refuses to run it.

const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');

describe('the theme boot script in index.html', () => {
  it('is exactly what @d3cloud/ui ships, for the key ThemeProvider uses by default', () => {
    const inline = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((match) => match[1]);
    expect(inline).toEqual([themeBootScript()]);
  });

  it('runs before the stylesheet and the bundle', () => {
    expect(html.indexOf('<script>')).toBeLessThan(html.indexOf('<script type="module"'));
    expect(html.indexOf('<script>')).toBeLessThan(html.indexOf('</head>'));
  });
});
