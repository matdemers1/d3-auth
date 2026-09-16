// The login state machine (REQ-029). Pure: no I/O, no clock, no database.
//
//   awaiting_identifier → awaiting_password → awaiting_factor → awaiting_trusted_device → complete
//
// `complete` is the only terminal state and the only one carrying an accountId, so the routes
// physically cannot finish an interaction from a half-authenticated state. There is no
// "MFA pending" boolean anywhere — the state *is* the progress.

export type FactorKind = 'totp' | 'passkey';

/** What the user actually did, in `amr` order (RFC 8176). */
export type AuthMethod = 'pwd' | 'otp' | 'hwk' | 'recovery';

export interface Identity {
  accountId: string;
  /** Second factors enrolled on the account; empty means password-only. */
  factors: readonly FactorKind[];
  /** A valid trusted-device cookie for this account was presented with the request. */
  deviceTrusted: boolean;
  /** Break-glass is armed for this account: the password alone signs in (REQ-122). */
  recovering?: boolean;
}

export type LoginState =
  | { name: 'awaiting_identifier' }
  | { name: 'awaiting_password'; identity: Identity }
  | { name: 'awaiting_factor'; identity: Identity; amr: readonly AuthMethod[] }
  | { name: 'awaiting_trusted_device'; identity: Identity; amr: readonly AuthMethod[] }
  | { name: 'complete'; accountId: string; amr: readonly AuthMethod[]; trustDevice: boolean };

export type LoginEvent =
  | { type: 'identified'; identity: Identity }
  /** Unknown email or an account that cannot sign in. Deliberately indistinguishable (REQ-086). */
  | { type: 'identity_rejected' }
  | { type: 'password_verified' }
  | { type: 'password_rejected' }
  | { type: 'factor_verified'; method: FactorKind }
  | { type: 'factor_rejected' }
  | { type: 'trusted_device_answered'; trust: boolean }
  /** A discoverable passkey authenticated the user outright, before any password (Phase 2). */
  | { type: 'passkey_authenticated'; identity: Identity };

export class InvalidTransitionError extends Error {
  constructor(
    readonly state: LoginState['name'],
    readonly event: LoginEvent['type'],
  ) {
    super(`Login state "${state}" cannot handle "${event}"`);
    this.name = 'InvalidTransitionError';
  }
}

const AMR_FOR_FACTOR: Record<FactorKind, AuthMethod> = { totp: 'otp', passkey: 'hwk' };

/** Where to go once a credential has been accepted: another factor, a device offer, or done. */
function afterCredential(identity: Identity, credentials: readonly AuthMethod[], factorUsed: boolean): LoginState {
  // Recovery is an authentication method in its own right, so it shows up in `amr` and therefore
  // in the id_token and the audit row: a door was opened, and the trail says so.
  const amr: readonly AuthMethod[] = identity.recovering ? [...credentials, 'recovery'] : credentials;
  if (!factorUsed && identity.factors.length > 0 && !identity.deviceTrusted) {
    return { name: 'awaiting_factor', identity, amr };
  }
  if (factorUsed && !identity.deviceTrusted) {
    return { name: 'awaiting_trusted_device', identity, amr };
  }
  return { name: 'complete', accountId: identity.accountId, amr, trustDevice: false };
}

export function advance(state: LoginState, event: LoginEvent): LoginState {
  switch (state.name) {
    case 'awaiting_identifier':
      switch (event.type) {
        case 'identified':
          return { name: 'awaiting_password', identity: event.identity };
        case 'identity_rejected':
          // Stays put: the screen re-renders the same generic error.
          return state;
        case 'passkey_authenticated':
          return { name: 'complete', accountId: event.identity.accountId, amr: ['hwk'], trustDevice: false };
        default:
          throw new InvalidTransitionError(state.name, event.type);
      }

    case 'awaiting_password':
      switch (event.type) {
        case 'password_verified':
          return afterCredential(state.identity, ['pwd'], false);
        case 'password_rejected':
          return state;
        default:
          throw new InvalidTransitionError(state.name, event.type);
      }

    case 'awaiting_factor':
      switch (event.type) {
        case 'factor_verified':
          return afterCredential(state.identity, [...state.amr, AMR_FOR_FACTOR[event.method]], true);
        case 'factor_rejected':
          return state;
        default:
          throw new InvalidTransitionError(state.name, event.type);
      }

    case 'awaiting_trusted_device':
      switch (event.type) {
        case 'trusted_device_answered':
          return { name: 'complete', accountId: state.identity.accountId, amr: state.amr, trustDevice: event.trust };
        default:
          throw new InvalidTransitionError(state.name, event.type);
      }

    case 'complete':
      // Terminal. Nothing re-opens a finished login.
      throw new InvalidTransitionError(state.name, event.type);
  }
}

export const start = (): LoginState => ({ name: 'awaiting_identifier' });

export function isComplete(state: LoginState): state is Extract<LoginState, { name: 'complete' }> {
  return state.name === 'complete';
}
