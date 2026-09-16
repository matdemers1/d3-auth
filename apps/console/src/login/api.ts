// The interaction API (server: apps/server/src/interaction/routes.ts). The screens never decide
// anything; they render what the server says the current step is.

export type Step = 'identify' | 'password' | 'factor' | 'trust' | 'done';

export interface InteractionView {
  step: Step;
  csrf: string;
  clientName: string;
  operatorDisplayName: string;
  /** Which second factors this person has, so the screen can lead with the passkey. */
  factors?: ('totp' | 'passkey')[];
  email?: string;
}

export interface StepResult {
  step?: Step;
  csrf?: string;
  factors?: ('totp' | 'passkey')[];
  email?: string;
  redirectTo?: string;
  error?: string;
  message?: string;
  retryAfterSeconds?: number;
}

const base = (uid: string): string => `/api/interaction/${encodeURIComponent(uid)}`;

async function post(uid: string, path: string, body: Record<string, unknown>): Promise<StepResult> {
  const res = await fetch(`${base(uid)}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify(body),
  });
  const payload = (await res.json()) as StepResult;
  return { ...payload, ...(res.status === 429 && !payload.retryAfterSeconds ? { retryAfterSeconds: 60 } : {}) };
}

export async function loadInteraction(uid: string): Promise<InteractionView> {
  const res = await fetch(base(uid), { headers: { accept: 'application/json' } });
  if (!res.ok) throw new Error(`interaction ${String(res.status)}`);
  return (await res.json()) as InteractionView;
}

export const submitEmail = (uid: string, csrf: string, email: string): Promise<StepResult> =>
  post(uid, '/identify', { csrf, email });

export const submitPassword = (uid: string, csrf: string, password: string): Promise<StepResult> =>
  post(uid, '/password', { csrf, password });

/** The trusted-device offer (REQ-036). Either answer finishes the login. */
export const answerTrust = (uid: string, csrf: string, trust: boolean): Promise<StepResult> => post(uid, '/trust', { csrf, trust });

export const submitCode = (uid: string, csrf: string, code: string): Promise<StepResult> => post(uid, '/totp', { csrf, code });

/** Runs the passkey ceremony end to end: options from the server, browser prompt, verification. */
export async function signInWithPasskey(uid: string, csrf: string): Promise<StepResult> {
  const { startAuthentication } = await import('@simplewebauthn/browser');
  const options = (await post(uid, '/passkey/begin', {})) as unknown as Parameters<typeof startAuthentication>[0]['optionsJSON'];
  const response = await startAuthentication({ optionsJSON: options });
  return post(uid, '/passkey/finish', { csrf, response });
}
