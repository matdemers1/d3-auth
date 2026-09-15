#!/usr/bin/env node
// Interaction bundle budget (REQ-077, R-09): everything a phone downloads to render /login —
// the entry chunk, the login chunk, their static imports and all of their CSS — must be
// <= 150 KB gzipped. Reads the Vite manifest so the check follows the real chunk graph.

import { readFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';

const BUDGET_BYTES = 150 * 1024;
const LOGIN_ENTRY = 'src/login/LoginShell.tsx';
const dist = new URL('../dist/', import.meta.url);
const manifest = JSON.parse(readFileSync(new URL('.vite/manifest.json', dist), 'utf8'));

const entryKey = Object.keys(manifest).find((key) => manifest[key].isEntry);
if (!entryKey || !manifest[LOGIN_ENTRY]) {
  console.error(`Bundle check: could not find the entry and ${LOGIN_ENTRY} in the manifest`);
  process.exit(1);
}

const files = new Set();
const visit = (key) => {
  const chunk = manifest[key];
  if (!chunk || files.has(chunk.file)) return;
  files.add(chunk.file);
  for (const css of chunk.css ?? []) files.add(css);
  for (const imported of chunk.imports ?? []) visit(imported);
};
visit(entryKey);
visit(LOGIN_ENTRY);

let total = 0;
const rows = [...files].sort().map((file) => {
  const size = gzipSync(readFileSync(new URL(file, dist)), { level: 9 }).length;
  total += size;
  return `  ${(size / 1024).toFixed(1).padStart(7)} KB  ${file}`;
});

console.log(`Interaction bundle (gzip):\n${rows.join('\n')}\n  ${(total / 1024).toFixed(1).padStart(7)} KB  total, budget ${BUDGET_BYTES / 1024} KB`);
if (total > BUDGET_BYTES) {
  console.error('Interaction bundle is over budget.');
  process.exit(1);
}
