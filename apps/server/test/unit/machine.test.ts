import { describe, expect, it } from 'vitest';
import {
  advance,
  InvalidTransitionError,
  isComplete,
  start,
  type Identity,
  type LoginEvent,
  type LoginState,
} from '../../src/interaction/machine.js';

const identity = (over: Partial<Identity> = {}): Identity => ({
  accountId: '0192b3e4-0000-7000-8000-000000000001',
  factors: [],
  deviceTrusted: false,
  ...over,
});

const EVENTS: LoginEvent[] = [
  { type: 'identified', identity: identity() },
  { type: 'identity_rejected' },
  { type: 'password_verified' },
  { type: 'password_rejected' },
  { type: 'factor_verified', method: 'totp' },
  { type: 'factor_rejected' },
  { type: 'trusted_device_answered', trust: true },
  { type: 'passkey_authenticated', identity: identity() },
];

const STATES = (): LoginState[] => [
  start(),
  { name: 'awaiting_password', identity: identity() },
  { name: 'awaiting_factor', identity: identity({ factors: ['totp'] }), amr: ['pwd'] },
  { name: 'awaiting_trusted_device', identity: identity({ factors: ['totp'] }), amr: ['pwd', 'otp'] },
  { name: 'complete', accountId: 'x', amr: ['pwd'], trustDevice: false },
];

// The pairs the machine accepts. Everything else must throw — this table is the specification.
const ALLOWED: Record<string, LoginEvent['type'][]> = {
  awaiting_identifier: ['identified', 'identity_rejected', 'passkey_authenticated'],
  awaiting_password: ['password_verified', 'password_rejected'],
  awaiting_factor: ['factor_verified', 'factor_rejected'],
  awaiting_trusted_device: ['trusted_device_answered'],
  complete: [],
};

describe('login state machine (REQ-029)', () => {
  it('rejects every transition outside the table', () => {
    for (const state of STATES()) {
      for (const event of EVENTS) {
        const allowed = ALLOWED[state.name]?.includes(event.type) ?? false;
        if (allowed) expect(() => advance(state, event)).not.toThrow();
        else expect(() => advance(state, event), `${state.name} + ${event.type}`).toThrow(InvalidTransitionError);
      }
    }
  });

  it('password-only account completes after the password', () => {
    const state = advance(advance(start(), { type: 'identified', identity: identity() }), { type: 'password_verified' });
    expect(state).toEqual({ name: 'complete', accountId: identity().accountId, amr: ['pwd'], trustDevice: false });
  });

  it('account with a factor must pass it before completing', () => {
    const id = identity({ factors: ['totp'] });
    const afterPassword = advance(advance(start(), { type: 'identified', identity: id }), { type: 'password_verified' });
    expect(afterPassword.name).toBe('awaiting_factor');
    expect(isComplete(afterPassword)).toBe(false);

    const afterFactor = advance(afterPassword, { type: 'factor_verified', method: 'totp' });
    expect(afterFactor).toMatchObject({ name: 'awaiting_trusted_device', amr: ['pwd', 'otp'] });

    const done = advance(afterFactor, { type: 'trusted_device_answered', trust: true });
    expect(done).toEqual({ name: 'complete', accountId: id.accountId, amr: ['pwd', 'otp'], trustDevice: true });
  });

  it('records hwk for a passkey second factor', () => {
    const id = identity({ factors: ['passkey'] });
    const afterPassword = advance(advance(start(), { type: 'identified', identity: id }), { type: 'password_verified' });
    const afterFactor = advance(afterPassword, { type: 'factor_verified', method: 'passkey' });
    expect(afterFactor).toMatchObject({ amr: ['pwd', 'hwk'] });
  });

  it('a trusted device skips the factor and the offer', () => {
    const id = identity({ factors: ['totp'], deviceTrusted: true });
    const state = advance(advance(start(), { type: 'identified', identity: id }), { type: 'password_verified' });
    expect(state).toEqual({ name: 'complete', accountId: id.accountId, amr: ['pwd'], trustDevice: false });
  });

  it('a rejected credential never advances and never leaks which part was wrong', () => {
    const afterIdentify = advance(start(), { type: 'identified', identity: identity() });
    expect(advance(afterIdentify, { type: 'password_rejected' })).toEqual(afterIdentify);
    expect(advance(start(), { type: 'identity_rejected' })).toEqual(start());

    const afterPassword = advance(
      advance(start(), { type: 'identified', identity: identity({ factors: ['totp'] }) }),
      { type: 'password_verified' },
    );
    expect(advance(afterPassword, { type: 'factor_rejected' })).toEqual(afterPassword);
  });

  it('only complete carries an accountId', () => {
    for (const state of STATES()) {
      expect('accountId' in state).toBe(state.name === 'complete');
    }
  });

  it('a discoverable passkey can authenticate outright', () => {
    const state = advance(start(), { type: 'passkey_authenticated', identity: identity() });
    expect(state).toMatchObject({ name: 'complete', amr: ['hwk'] });
  });

  it('is terminal at complete', () => {
    const done = advance(advance(start(), { type: 'identified', identity: identity() }), { type: 'password_verified' });
    for (const event of EVENTS) expect(() => advance(done, event)).toThrow(InvalidTransitionError);
  });

  it('does not mutate the state it is given', () => {
    const before = advance(start(), { type: 'identified', identity: identity({ factors: ['totp'] }) });
    const snapshot = structuredClone(before);
    advance(before, { type: 'password_verified' });
    expect(before).toEqual(snapshot);
  });
});
