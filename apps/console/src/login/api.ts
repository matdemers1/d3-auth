// The interaction API (server: apps/server/src/interaction/routes.ts). The screens never decide
// anything; they render what the server says the current step is.

export type Step = 'identify' | 'password' | 'factor' | 'trust' | 'continue' | 'done';

export interface InteractionView {
  step: Step;
  csrf: string;
  clientName: string;
  operatorDisplayName: string;
  /** Which second factors this person has, so the screen can lead with the passkey. */
  factors?: ('totp' | 'passkey' | 'push')[];
  email?: string;
  /** Who the continue-as interstitial is about (REQ-059). */
  username?: string;
}

export interface StepResult {
  step?: Step;
  csrf?: string;
  factors?: ('totp' | 'passkey' | 'push')[];
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

/** The two answers to the continue-as interstitial (REQ-059). */
export const answerContinue = (uid: string, csrf: string): Promise<StepResult> => post(uid, '/continue', { csrf });
export const switchAccount = (uid: string, csrf: string): Promise<StepResult> => post(uid, '/switch', { csrf });

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

/** Sign-in approval on the phone (AUTH-T-10.5): the number this browser shows. */
export interface ApprovalStarted {
  approvalId?: string;
  number?: number;
  expiresAt?: string;
  error?: string;
  retryAfterSeconds?: number;
}

export async function startApproval(uid: string, csrf: string): Promise<ApprovalStarted> {
  return (await post(uid, '/approval', { csrf }));
}

/** Where the approval stands; an approved one comes back as the next step, or the redirect. */
export const pollApproval = (uid: string, csrf: string, id: string): Promise<StepResult & { status?: 'pending' | 'approved' | 'denied' | 'wrong_number' | 'expired' }> =>
  post(uid, `/approval/${encodeURIComponent(id)}`, { csrf });
