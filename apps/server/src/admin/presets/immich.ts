import { authMethodFor, SECRET_NOT_SHOWN } from '../connection.js';
import { ID_TOKEN_SIGNING_ALG, ROLES_CLAIM, ROLES_SCOPE } from '../../oidc/protocol.js';
import type { Preset, PresetInputs } from './types.js';

// Immich (REQ-144). Every value below was a default that failed against D3 Auth the first time:
// Immich signs requests with client_secret_post, expects RS256 and reads roles from immich_role.
// None of those errors said so. This sheet does.
//
// Field labels and their order are Immich's own, from its OAuth settings screen
// (Administration → Settings → Authentication → OAuth), checked against Immich's source on
// 17 September 2026. When Immich changes that screen, this is the one file to change.

const address = (inputs: PresetInputs): string => inputs.address ?? '';

export const immich: Preset = {
  key: 'immich',
  name: 'Immich',
  summary: 'Photos and videos',
  docsUrl: 'https://immich.app/docs/administration/oauth',
  where: 'Administration → Settings → Authentication → OAuth',
  checked: '17 September 2026',
  inputs: [
    {
      key: 'address',
      label: 'Immich address',
      kind: 'address',
      help: 'The address you open Immich at. Nothing after it.',
      placeholder: 'https://photos.example.com',
      feeds: ['redirect_uris', 'post_logout_redirect_uris', 'backchannel_logout_uri'],
    },
    {
      key: 'client_id',
      label: 'Client ID',
      kind: 'client_id',
      help: 'What Immich is called in tokens. Change it only if you run more than one Immich.',
      default: 'immich',
      feeds: ['client_id'],
    },
  ],
  steps: [
    'Give yourself access to Immich with the Administrator role before you sign in with D3 Auth. Immich sets who is an admin from the roles claim on every sign-in.',
    'Keep Password Login on in Immich until an admin has signed in with D3 Auth once.',
  ],
  cautions: [
    'The first sign-in links an existing Immich account by email address. Immich does not check that the address was verified.',
    'Signing out of Immich ends the whole D3 Auth session, not just Immich’s.',
  ],

  manifest(inputs) {
    const at = address(inputs);
    return {
      client_id: inputs.client_id,
      name: 'Immich',
      description: 'Photos and videos',
      client_type: 'confidential_web',
      redirect_uris: [`${at}/auth/login`, `${at}/user-settings`, `${at}/api/oauth/mobile-redirect`],
      post_logout_redirect_uris: [`${at}/auth/login`],
      backchannel_logout_uri: `${at}/api/oauth/backchannel-logout`,
      roles: [
        { key: 'admin', display: 'Administrator', description: 'An Immich admin, set on every sign-in' },
        { key: 'user', display: 'User', description: 'Their own library', default: true },
      ],
    };
  },

  sheet({ issuer, app, inputs, secret }) {
    const at = address(inputs);
    return [
      { id: 'enabled', label: 'Login with OAuth', value: null, action: 'on' },
      { id: 'issuer_url', label: 'issuer_url', value: issuer, action: 'set', why: 'Immich finds everything else from here.' },
      { id: 'client_id', label: 'client_id', value: app.clientId, action: 'set' },
      {
        id: 'client_secret',
        label: 'client_secret',
        value: secret ?? null,
        action: 'set',
        secret: true,
        ...(secret ? {} : { why: SECRET_NOT_SHOWN }),
      },
      {
        id: 'token_endpoint_auth_method',
        label: 'token_endpoint_auth_method',
        value: authMethodFor(app.clientType),
        action: 'set',
        why: 'Appears once the secret is entered. Immich’s default, client_secret_post, is refused.',
      },
      {
        id: 'scope',
        label: 'scope',
        // Immich's own default, in its order, with ours on the end.
        value: `openid email profile ${ROLES_SCOPE}`,
        action: 'set',
        why: `${ROLES_SCOPE} adds the roles claim.`,
      },
      {
        id: 'id_token_signed_response_alg',
        label: 'id_token_signed_response_alg',
        value: ID_TOKEN_SIGNING_ALG,
        action: 'set',
        why: `D3 Auth signs ID tokens with ${ID_TOKEN_SIGNING_ALG}. Immich’s default, RS256, fails every sign-in.`,
      },
      { id: 'userinfo_signed_response_alg', label: 'userinfo_signed_response_alg', value: 'none', action: 'leave' },
      { id: 'prompt', label: 'prompt', value: null, action: 'leave', why: 'Leave it empty.' },
      { id: 'end_session_endpoint', label: 'end_session_endpoint', value: null, action: 'leave', why: 'Leave it empty. Immich discovers it from D3 Auth.' },
      {
        id: 'storage_label_claim',
        label: 'Storage label claim',
        value: 'preferred_username',
        action: 'leave',
        why: 'The D3 Auth username, which never changes.',
      },
      {
        id: 'role_claim',
        label: 'Role Claim',
        value: ROLES_CLAIM,
        action: 'set',
        why: 'Immich accepts a list. admin makes somebody an Immich admin, on every sign-in.',
      },
      {
        id: 'storage_quota_claim',
        label: 'Storage quota claim',
        value: 'immich_quota',
        action: 'leave',
        why: 'D3 Auth sends none, so Immich’s default quota applies.',
      },
      { id: 'auto_register', label: 'Auto register', value: null, action: 'leave', why: 'On. Only people given Immich in D3 Auth can reach it.' },
      {
        id: 'mobile_override',
        label: 'Mobile redirect URI override',
        value: null,
        action: 'on',
        why: 'D3 Auth will not mix web and app.immich:// redirects in one app.',
      },
      { id: 'mobile_redirect_uri', label: 'Mobile redirect URI', value: `${at}/api/oauth/mobile-redirect`, action: 'set' },
    ];
  },
};
