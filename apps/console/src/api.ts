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

/** Where the console goes to get a session, remembering the page it was on (ADR-005). */
export const signInHref = (): string => `/signin?next=${encodeURIComponent(window.location.pathname + window.location.search)}`;

/**
 * The console and account pages have nothing to show without a session. Rather than render empty
 * screens, a missing one sends the browser to sign in and back. A request for step-up is different
 * — the person is signed in and is asked to prove it again — so only `sign_in_required` does this.
 */
const signedOut = (status: number, body: unknown): boolean =>
  status === 401 &&
  (body as { error?: unknown }).error === 'sign_in_required' &&
  /^\/(admin|account)(\/|$)/.test(window.location.pathname);

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  headers.set('accept', 'application/json');
  if (init?.body !== undefined) headers.set('content-type', 'application/json');
  const res = await fetch(path, { ...init, headers });
  const body: unknown = res.status === 204 ? {} : await res.json().catch(() => ({}));
  if (signedOut(res.status, body)) {
    window.location.assign(signInHref());
    // The page is going away; nothing should render an error in the meantime.
    return new Promise<T>(() => undefined);
  }
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

export interface AppRole {
  key: string;
  displayName: string;
  description: string;
  sortOrder: number;
  isDefault: boolean;
  granted: number;
}

export interface App {
  id: string;
  clientId: string;
  name: string;
  description: string;
  clientType: 'confidential_web' | 'public_native';
  enabled: boolean;
  backchannelLogoutUri: string | null;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  roles: AppRole[];
  people: number;
  /** The preset that built it, if one did. */
  preset: string | null;
  presetInputs: Record<string, string>;
  createdAt: string;
}

export interface AccessRow {
  userId: string;
  displayName: string;
  email: string;
  roles: string[];
  grantedAt: string;
  grantedBy: string | null;
  lastSignIn: string | null;
}

export interface PersonAccess {
  clientId: string;
  name: string;
  roles: string[];
  grantedAt: string;
}

export interface PersonDetail extends Person {
  emailVerified: boolean;
  factors: { passkeys: number; authenticatorApps: number; trustedDevices: number };
  sessions: { id: string; ip: string | null; userAgent: string | null; lastSeenAt: string }[];
  access: PersonAccess[];
}

/** A manifest as the server parsed it. */
export interface Manifest {
  client_id: string;
  name: string;
  description: string;
  client_type: 'confidential_web' | 'public_native';
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  backchannel_logout_uri?: string;
  roles: { key: string; display: string; description: string; default: boolean }[];
}

export interface ManifestDiff {
  isNew: boolean;
  changed: { field: string; from: string; to: string }[];
  redirectUris: { added: string[]; removed: string[] };
  roles: { added: { key: string }[]; removed: { key: string; granted?: number }[]; changed: { key: string }[] };
  blocking: { key: string; granted?: number }[];
}

export interface InviteCreated {
  id: string;
  email: string;
  url: string;
  expiresAt: string;
  mail: { delivered: boolean; error?: string };
}

/** What to do with one field on the other app's settings screen. */
export type SheetAction = 'set' | 'leave' | 'on' | 'off';

export interface SheetRow {
  id: string;
  label: string;
  /** Null for a toggle, an empty field, or a secret that is not being shown. */
  value: string | string[] | null;
  why?: string;
  action?: SheetAction;
  /** The client secret. Its value is there only at registration or rotation. */
  secret?: true;
}

export interface PresetSheet {
  preset: string;
  name: string;
  docsUrl: string;
  where: string;
  checked: string;
  steps: string[];
  cautions: string[];
  rows: SheetRow[];
}

export interface Connection {
  clientId: string;
  rows: SheetRow[];
  preset: PresetSheet | null;
}

export interface PresetInput {
  key: string;
  label: string;
  kind: 'address' | 'client_id';
  help: string;
  placeholder?: string;
  default?: string;
}

export interface PresetSummary {
  key: string;
  name: string;
  summary: string;
  docsUrl: string;
  inputs: PresetInput[];
}

/** What registering answers with: the secret and the sheet, both once. */
export interface Registration {
  app: App;
  secret?: string;
  diff: ManifestDiff;
  connection: Connection;
}

export interface Problem {
  field: string;
  message: string;
}
