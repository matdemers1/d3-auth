// One place for talking to our own API. Every call is same-origin and rides the session cookie.

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly body: Record<string, unknown>,
  ) {
    super(typeof body.message === 'string' ? body.message : `Request failed (${String(status)})`);
    this.name = 'ApiError';
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  headers.set('accept', 'application/json');
  if (init?.body !== undefined) headers.set('content-type', 'application/json');
  const res = await fetch(path, { ...init, headers });
  const body: unknown = res.status === 204 ? {} : await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, body as Record<string, unknown>);
  return body as T;
}

export const api = {
  get: <T>(path: string): Promise<T> => request<T>(path),
  post: <T>(path: string, body?: unknown): Promise<T> =>
    request<T>(path, { method: 'POST', ...(body === undefined ? {} : { body: JSON.stringify(body) }) }),
};

export interface Me {
  id: string;
  email: string;
  username: string;
  displayName: string;
  kind: 'owner' | 'admin' | 'guest';
  status: 'invited' | 'active' | 'suspended';
  /** Whoever runs this instance, by name, for copy like "Ask Matthew" (REQ-087). */
  operatorDisplayName: string;
}

export interface Person {
  id: string;
  email: string;
  username: string;
  displayName: string;
  kind: Me['kind'];
  status: Me['status'];
  lastLoginAt: string | null;
  createdAt: string;
}

export interface PendingInvite {
  id: string;
  email: string;
  createdAt: string;
  expiresAt: string;
}

export interface InviteCreated {
  id: string;
  email: string;
  url: string;
  expiresAt: string;
  mail: { delivered: boolean; error?: string };
}
