import { randomBytes } from 'node:crypto';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type AuthenticatorTransport,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import type { AdapterFactory, AdapterPayload } from 'oidc-provider';
import type { Db } from '../db.js';
import type { WebauthnDeviceType } from '../generated/prisma/enums.js';

// Passkeys (REQ-034, REQ-032).
//
// Two decisions worth stating. The handle we give the authenticator is an opaque random value per
// user, never the user id and never the email — so a passkey stored on someone's phone does not
// carry our identifiers around. And the RP ID is the bare host: it is what the credential is bound
// to for life, so it can never include a port or a `www`, and changing it later orphans every
// passkey in existence.

const CHALLENGE_KIND = 'D3WebauthnChallenge';
const CHALLENGE_TTL_SECONDS = 5 * 60;

export interface WebAuthnOptions {
  /** Bare host: auth.d3cloud.io, or localhost in development. Never a port. */
  rpId: string;
  rpName: string;
  /** Full origin the browser will report, including the port in development. */
  origin: string;
}

export interface PasskeySummary {
  id: string;
  label: string;
  createdAt: Date;
  lastUsedAt: Date | null;
  backedUp: boolean;
}

export interface WebAuthn {
  beginRegistration(input: { userId: string; accountName: string; displayName: string }): Promise<PublicKeyCredentialCreationOptionsJSON>;
  finishRegistration(input: { userId: string; response: RegistrationResponseJSON; label?: string }): Promise<{ ok: boolean; id?: string }>;
  /** `userId` narrows to that person's credentials; omitting it allows any discoverable passkey. */
  beginAuthentication(input: { userId?: string; sessionKey: string }): Promise<PublicKeyCredentialRequestOptionsJSON>;
  finishAuthentication(input: { sessionKey: string; response: AuthenticationResponseJSON }): Promise<{ ok: boolean; userId?: string }>;
  list(userId: string): Promise<PasskeySummary[]>;
  remove(input: { userId: string; credentialId: string }): Promise<boolean>;
}

const toBase64Url = (value: Uint8Array): string => Buffer.from(value).toString('base64url');
/** Prisma `Bytes` columns want an ArrayBuffer-backed view, which is what this returns. */
const fromBase64Url = (value: string): Uint8Array<ArrayBuffer> => Uint8Array.from(Buffer.from(value, 'base64url'));
const bytes = (value: Uint8Array): Uint8Array<ArrayBuffer> => Uint8Array.from(value);

export function createWebAuthn(db: Db, adapterFactory: AdapterFactory, options: WebAuthnOptions): WebAuthn {
  const challenges = adapterFactory(CHALLENGE_KIND);

  const rememberChallenge = async (key: string, challenge: string, userId?: string): Promise<void> => {
    const payload = { challenge, userId } as unknown as AdapterPayload;
    await challenges.upsert(key, payload, CHALLENGE_TTL_SECONDS);
  };

  const recallChallenge = async <T extends { challenge: string }>(key: string): Promise<T | undefined> => {
    const payload: unknown = await challenges.find(key);
    return payload as T | undefined;
  };

  /** One opaque handle per user, created the first time they enrol anything. */
  const handleFor = async (userId: string): Promise<Uint8Array<ArrayBuffer>> => {
    const existing = await db.webauthnCredential.findFirst({ where: { userId }, select: { webauthnUserId: true } });
    return existing ? bytes(existing.webauthnUserId) : Uint8Array.from(randomBytes(32));
  };

  return {
    async beginRegistration({ userId, accountName, displayName }) {
      const [handle, existing] = await Promise.all([
        handleFor(userId),
        db.webauthnCredential.findMany({ where: { userId }, select: { credentialId: true, transports: true } }),
      ]);

      const created = await generateRegistrationOptions({
        rpName: options.rpName,
        rpID: options.rpId,
        userID: handle,
        userName: accountName,
        userDisplayName: displayName,
        attestationType: 'none',
        excludeCredentials: existing.map((row) => ({ id: toBase64Url(row.credentialId), transports: row.transports as AuthenticatorTransport[] })),
        authenticatorSelection: {
          residentKey: 'preferred',
          // Required so the passkey proves it was the person, not just the device (REQ-035).
          userVerification: 'required',
        },
      });

      const payload = { challenge: created.challenge, userId, handle: toBase64Url(handle) } as unknown as AdapterPayload;
      await challenges.upsert(`register:${userId}`, payload, CHALLENGE_TTL_SECONDS);
      return created;
    },

    async finishRegistration({ userId, response, label }) {
      const payload: { challenge: string; userId?: string; handle?: string } | undefined = await recallChallenge(
        `register:${userId}`,
      );
      if (!payload?.challenge) return { ok: false };

      const verification = await verifyRegistrationResponse({
        response,
        expectedChallenge: payload.challenge,
        expectedOrigin: options.origin,
        expectedRPID: options.rpId,
        requireUserVerification: true,
      }).catch(() => undefined);

      if (!verification?.verified) return { ok: false };
      const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;

      const deviceType: WebauthnDeviceType = credentialDeviceType === 'multiDevice' ? 'multi_device' : 'single_device';
      await db.webauthnCredential.create({
        data: {
          credentialId: fromBase64Url(credential.id),
          userId,
          webauthnUserId: payload.handle ? fromBase64Url(payload.handle) : await handleFor(userId),
          publicKey: bytes(credential.publicKey),
          counter: BigInt(credential.counter),
          transports: credential.transports ?? [],
          deviceType,
          backedUp: credentialBackedUp,
          label: label?.trim() || 'Passkey',
        },
      });
      await challenges.destroy(`register:${userId}`);
      return { ok: true, id: credential.id };
    },

    async beginAuthentication({ userId, sessionKey }) {
      const allowed = userId
        ? await db.webauthnCredential.findMany({ where: { userId }, select: { credentialId: true, transports: true } })
        : [];

      const created = await generateAuthenticationOptions({
        rpID: options.rpId,
        userVerification: 'required',
        // Empty list means "any passkey you have for this site", which is what conditional UI needs.
        allowCredentials: allowed.map((row) => ({ id: toBase64Url(row.credentialId), transports: row.transports as AuthenticatorTransport[] })),
      });

      await rememberChallenge(`auth:${sessionKey}`, created.challenge, userId);
      return created;
    },

    async finishAuthentication({ sessionKey, response }) {
      const remembered = await recallChallenge<{ challenge: string; userId?: string }>(`auth:${sessionKey}`);
      if (!remembered?.challenge) return { ok: false };

      const credential = await db.webauthnCredential.findUnique({ where: { credentialId: fromBase64Url(response.id) } });
      if (!credential) return { ok: false };
      // A passkey belonging to somebody else is not an answer to this challenge.
      if (remembered.userId && remembered.userId !== credential.userId) return { ok: false };

      const verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge: remembered.challenge,
        expectedOrigin: options.origin,
        expectedRPID: options.rpId,
        requireUserVerification: true,
        credential: {
          id: response.id,
          publicKey: bytes(credential.publicKey),
          counter: Number(credential.counter),
          transports: credential.transports,
        },
      }).catch(() => undefined);

      if (!verification?.verified) return { ok: false };

      await db.webauthnCredential.update({
        where: { credentialId: credential.credentialId },
        data: { counter: BigInt(verification.authenticationInfo.newCounter), lastUsedAt: new Date() },
      });
      await challenges.destroy(`auth:${sessionKey}`);
      return { ok: true, userId: credential.userId };
    },

    async list(userId) {
      const rows = await db.webauthnCredential.findMany({ where: { userId }, orderBy: { createdAt: 'asc' } });
      return rows.map((row) => ({
        id: toBase64Url(row.credentialId),
        label: row.label,
        createdAt: row.createdAt,
        lastUsedAt: row.lastUsedAt,
        backedUp: row.backedUp,
      }));
    },

    async remove({ userId, credentialId }) {
      const { count } = await db.webauthnCredential.deleteMany({
        where: { credentialId: fromBase64Url(credentialId), userId },
      });
      return count > 0;
    },
  };
}
