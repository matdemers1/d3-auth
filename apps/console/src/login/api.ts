// The interaction API (server: apps/server/src/interaction/routes.ts). The screens never decide
// anything; they render what the server says the current step is.

export type Step = 'identify' | 'password' | 'done';

export interface InteractionView {
  step: Step;
  csrf: string;
  clientName: string;
  operatorDisplayName: string;
  email?: string;
}

export interface StepResult {
  step?: Step;
  csrf?: string;
  email?: string;
  redirectTo?: string;
  error?: string;
  message?: string;
  retryAfterSeconds?: number;
}

const base = (uid: string): string => `/api/interaction/${encodeURIComponent(uid)}`;

async function post(uid: string, path: string, body: Record<string, string>): Promise<StepResult> {
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
