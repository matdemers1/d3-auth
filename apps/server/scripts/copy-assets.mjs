#!/usr/bin/env node
// tsc emits JavaScript only; these data files sit beside the code that reads them.
import { cpSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const assets = [['src/security/blocklist.txt', 'dist/security/blocklist.txt']];

for (const [from, to] of assets) {
  mkdirSync(dirname(to), { recursive: true });
  cpSync(from, to);
}
console.log(`copied ${assets.length} asset(s) into dist`);
