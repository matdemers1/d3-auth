import { randomBytes, randomUUID } from 'node:crypto';
import { createDb, type Db } from '../../src/db.js';
import { createKekCrypto, type KekCrypto } from '../../src/security/kek.js';

export function testDb(): Db {
  return createDb(process.env.DATABASE_URL ?? '');
}

export function testKek(): KekCrypto {
  return createKekCrypto(randomBytes(32));
}

export const unique = (): string => randomUUID().slice(0, 8);
