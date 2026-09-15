import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createKekCrypto, KekError } from '../../src/security/kek.js';

describe('KEK crypto (REQ-117)', () => {
  const kek = createKekCrypto(randomBytes(32));
  const secret = Buffer.from('JBSWY3DPEHPK3PXP', 'utf8');

  it('round-trips', () => {
    const sealed = kek.encrypt(secret, 'totp_credential:abc');
    expect(kek.decrypt(sealed, 'totp_credential:abc').equals(secret)).toBe(true);
  });

  it('never stores the plaintext and uses a fresh IV each time', () => {
    const a = Buffer.from(kek.encrypt(secret, 'ctx'));
    const b = Buffer.from(kek.encrypt(secret, 'ctx'));
    expect(a.includes(secret)).toBe(false);
    expect(a.equals(b)).toBe(false);
  });

  it('refuses a value sealed for another context', () => {
    const sealed = kek.encrypt(secret, 'signing_key:kid-1');
    expect(() => kek.decrypt(sealed, 'signing_key:kid-2')).toThrow(KekError);
  });

  it('refuses a tampered ciphertext', () => {
    const sealed = Buffer.from(kek.encrypt(secret, 'ctx'));
    sealed.writeUInt8(sealed.readUInt8(sealed.length - 1) ^ 0x01, sealed.length - 1);
    expect(() => kek.decrypt(sealed, 'ctx')).toThrow(/failed authentication/);
  });

  it('names a different KEK rather than failing obscurely', () => {
    const other = createKekCrypto(randomBytes(32));
    expect(() => other.decrypt(kek.encrypt(secret, 'ctx'), 'ctx')).toThrow(/different KEK/);
  });

  it('rejects a KEK of the wrong size', () => {
    expect(() => createKekCrypto(randomBytes(16))).toThrow(KekError);
  });
});
