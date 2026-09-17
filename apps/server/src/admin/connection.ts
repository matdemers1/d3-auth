import { ROUTES } from '../oidc/provider.js';
import {
  DISCOVERY_PATH,
  ID_TOKEN_SIGNING_ALG,
  IDENTITY_SCOPES,
  OFFLINE_SCOPE,
  PKCE_METHOD,
  ROLES_CLAIM,
  ROLES_SCOPE,
  TOKEN_ENDPOINT_AUTH_METHOD,
} from '../oidc/protocol.js';

// The connection sheet (REQ-142): every value an app needs to sign people in with D3 Auth, each
// with a line saying why it is that value.
//
// Nothing here is typed by hand. The protocol values come from protocol.ts, which the provider
// itself is configured from, and the rest from the app row — so the sheet cannot drift from what
// the provider actually does. It never holds a stored secret: the only secret it can carry is one
// the caller has just generated and is about to show once.

/** What the other app's settings screen wants done with a field. */
export type SheetAction = 'set' | 'leave' | 'on' | 'off';

export interface SheetRow {
  /** Stable, for tests and React keys. */
  id: string;
  /** In D3 Auth's words for the generic sheet, and in the other app's own words for a preset. */
  label: string;
  /** Null for a toggle, an empty field, or a secret that is not being shown. */
  value: string | string[] | null;
  why?: string;
  /** Present on preset rows: what to do with the field. */
  action?: SheetAction;
  /** The client secret row. Its value is present only at registration or rotation. */
  secret?: true;
}

export interface SheetApp {
  clientId: string;
  clientType: string;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  backchannelLogoutUri: string | null;
  roles: readonly unknown[];
}

export const discoveryUrl = (issuer: string): string => `${issuer}${DISCOVERY_PATH}`;
export const endSessionUrl = (issuer: string): string => `${issuer}${ROUTES.end_session}`;

/** `client_secret_basic` for an app that holds a secret, `none` for one that cannot. */
export const authMethodFor = (clientType: string): string =>
  clientType === 'public_native' ? TOKEN_ENDPOINT_AUTH_METHOD.public_native : TOKEN_ENDPOINT_AUTH_METHOD.confidential_web;

/** The scopes an app should ask for: who somebody is, and its roles when it declares any. */
export const scopesFor = (app: Pick<SheetApp, 'roles'>): string[] => [...IDENTITY_SCOPES, ...(app.roles.length > 0 ? [ROLES_SCOPE] : [])];

export const SECRET_ON_REGISTER = 'Created when you press Register below, and shown once on the next screen, in this same list. Paste it in then.';
export const SECRET_NOT_SHOWN = 'Shown once, when the app is registered or its secret is rotated. Rotate it to see a new one.';

/** The sheet for any app. `secret` only when it has just been generated. */
export function genericSheet(issuer: string, app: SheetApp, secret?: string): SheetRow[] {
  const confidential = app.clientType !== 'public_native';
  const rows: SheetRow[] = [
    { id: 'issuer', label: 'Issuer', value: issuer, why: 'The one address the app needs. Everything else is discovered from it.' },
    {
      id: 'discovery',
      label: 'Discovery URL',
      value: discoveryUrl(issuer),
      why: 'For apps that ask for the full address. Endpoints and signing keys are read from here, never pasted.',
    },
    { id: 'client_id', label: 'Client ID', value: app.clientId, why: 'Cannot be changed once registered.' },
  ];

  if (confidential) {
    rows.push({
      id: 'client_secret',
      label: 'Client secret',
      value: secret ?? null,
      secret: true,
      why: secret ? 'Shown this once. Put it in the app now.' : SECRET_NOT_SHOWN,
    });
  }

  rows.push(
    {
      id: 'token_endpoint_auth_method',
      label: 'Token endpoint auth method',
      value: authMethodFor(app.clientType),
      why: confidential
        ? 'The secret goes in the Authorization header. Sending it in the form body (client_secret_post) is refused.'
        : 'A native app holds no secret. It proves itself with PKCE instead.',
    },
    {
      id: 'id_token_signing_alg',
      label: 'ID token signing algorithm',
      value: ID_TOKEN_SIGNING_ALG,
      why: `ID tokens are signed with ${ID_TOKEN_SIGNING_ALG}. An app expecting RS256 fails every sign-in.`,
    },
    {
      id: 'pkce',
      label: 'PKCE',
      value: PKCE_METHOD,
      why: `Required on every sign-in, with the ${PKCE_METHOD} method — confidential apps included.`,
    },
    {
      id: 'scopes',
      label: 'Scopes',
      value: scopesFor(app).join(' '),
      why:
        app.roles.length > 0
          ? `${ROLES_SCOPE} puts the roles claim in the token. Add ${OFFLINE_SCOPE} if the app keeps people signed in with refresh tokens.`
          : `This app declares no roles, so it has no use for ${ROLES_SCOPE}. Add ${OFFLINE_SCOPE} if it keeps people signed in with refresh tokens.`,
    },
    {
      id: 'roles_claim',
      label: 'Roles claim',
      value: ROLES_CLAIM,
      why: 'A list of role keys — only this app’s, never another app’s.',
    },
    {
      id: 'redirect_uris',
      label: 'Redirect URIs',
      value: app.redirectUris,
      why: 'Matched exactly. A different path, port or trailing slash is refused.',
    },
    {
      id: 'post_logout_redirect_uris',
      label: 'Post-logout redirect URIs',
      value: app.postLogoutRedirectUris.length > 0 ? app.postLogoutRedirectUris : null,
      why: app.postLogoutRedirectUris.length > 0 ? 'Where signing out may send people back to.' : 'None registered. People land on D3 Auth’s own signed-out page.',
    },
    {
      id: 'backchannel_logout_uri',
      label: 'Back-channel logout',
      value: app.backchannelLogoutUri,
      why: app.backchannelLogoutUri
        ? 'Where D3 Auth sends a signed logout token when somebody signs out or loses access.'
        : 'Not set — access removal takes effect when tokens expire (slow revoke).',
    },
    {
      id: 'end_session_endpoint',
      label: 'End session endpoint',
      value: endSessionUrl(issuer),
      why: 'Signing out here ends the D3 Auth session, not just the app’s. Also in discovery.',
    },
  );
  return rows;
}
