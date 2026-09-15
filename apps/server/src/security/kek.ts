import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto';

// Envelope for secrets at rest (TOTP secrets, signing private keys) — REQ-117.
//
//   [version 1B][kek id 4B][iv 12B][tag 16B][ciphertext]
//
// The key id is an HMAC of a fixed label under the KEK, so it identifies which KEK sealed a
// value without revealing anything about the key. The context string (e.g. "signing_key:<kid>")
// is bound as AAD, so a ciphertext copied into another row or purpose fails to decrypt.

const VERSION = 1;
const KEY_ID_LENGTH = 4;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const HEADER_LENGTH = 1 + KEY_ID_LENGTH + IV_LENGTH + TAG_LENGTH;

export class KekError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KekError';
  }
}

export interface KekCrypto {
  readonly keyId: string;
  /** Returns a fresh ArrayBuffer-backed array, the shape Prisma `Bytes` columns take. */
  encrypt(plaintext: Uint8Array, context: string): Uint8Array<ArrayBuffer>;
  decrypt(sealed: Uint8Array, context: string): Buffer;
}

export function createKekCrypto(kek: Buffer): KekCrypto {
  if (kek.length !== 32) throw new KekError('KEK must be exactly 32 bytes');
  const key = Buffer.from(kek);
  const keyId = createHmac('sha256', key).update('d3auth-kek-id').digest().subarray(0, KEY_ID_LENGTH);

  return {
    keyId: keyId.toString('hex'),

    encrypt(plaintext, context) {
      const iv = randomBytes(IV_LENGTH);
      const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_LENGTH });
      cipher.setAAD(Buffer.from(context, 'utf8'));
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      return Uint8Array.from(Buffer.concat([Buffer.from([VERSION]), keyId, iv, cipher.getAuthTag(), ciphertext]));
    },

    decrypt(sealed, context) {
      const blob = Buffer.from(sealed);
      if (blob.length < HEADER_LENGTH || blob[0] !== VERSION) {
        throw new KekError('Sealed value has an unknown format');
      }
      if (!blob.subarray(1, 1 + KEY_ID_LENGTH).equals(keyId)) {
        throw new KekError('Sealed value was encrypted under a different KEK');
      }
      const ivStart = 1 + KEY_ID_LENGTH;
      const iv = blob.subarray(ivStart, ivStart + IV_LENGTH);
      const tag = blob.subarray(ivStart + IV_LENGTH, HEADER_LENGTH);
      const decipher = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_LENGTH });
      decipher.setAAD(Buffer.from(context, 'utf8'));
      decipher.setAuthTag(tag);
      try {
        return Buffer.concat([decipher.update(blob.subarray(HEADER_LENGTH)), decipher.final()]);
      } catch {
        throw new KekError('Sealed value failed authentication (wrong context or tampered)');
      }
    },
  };
}
