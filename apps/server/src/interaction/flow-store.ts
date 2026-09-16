import type { AdapterFactory, AdapterPayload } from 'oidc-provider';
import type { LoginState } from './machine.js';

// Where a half-finished login lives: one row per interaction in the provider's own payload table,
// keyed by the interaction uid and expiring with it. Server-side, so the browser never holds the
// state and cannot skip a step by editing a cookie.

export const FLOW_KIND = 'D3LoginFlow';

export interface LoginFlow {
  state: LoginState;
  csrf: string;
  /** Lower-cased email as typed, kept for throttling and the audit trail. */
  attemptedEmail?: string;
}

export interface FlowStore {
  load(uid: string): Promise<LoginFlow | undefined>;
  save(uid: string, flow: LoginFlow, ttlSeconds: number): Promise<void>;
  clear(uid: string): Promise<void>;
}

export function createFlowStore(adapterFactory: AdapterFactory): FlowStore {
  const adapter = adapterFactory(FLOW_KIND);
  return {
    async load(uid) {
      const payload: unknown = await adapter.find(uid);
      return (payload as { flow?: LoginFlow } | undefined)?.flow;
    },
    async save(uid, flow, ttlSeconds) {
      // The adapter stores opaque JSON; the provider never reads this kind.
      const payload = { flow } as unknown as AdapterPayload;
      await adapter.upsert(uid, payload, ttlSeconds);
    },
    async clear(uid) {
      await adapter.destroy(uid);
    },
  };
}
