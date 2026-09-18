import type { Preset, PresetInputs } from './types.js';
import { SECRET_NOT_SHOWN, SECRET_ON_REGISTER } from '../connection.js';

// Bindery (Bindery Phase 20). The reference relying party, and the shortest sheet here — not
// because it does less, but because its client is the D3 Auth SDK: the scopes, the signing
// algorithm, the endpoints and the roles claim are pinned in Bindery's own code and are not
// settings anybody can get wrong. Immich's sheet is long because Immich's OAuth screen is long,
// and every row of it was a default that failed against D3 Auth the first time.
//
// So this preset earns its place on the other side: the owner answers one question, and the
// redirect URI, the post-logout URI and the back-channel URI are built from it rather than
// typed. The first real registration here was refused with invalid_redirect_uri because the
// http form had been registered against an https address — which is exactly the mistake an
// answer-one-question form does not let you make.
//
// Field labels and their order are Bindery's own, from Settings → Sign in with D3 Auth,
// checked against Bindery d98d69a on 17 September 2026.

const address = (inputs: PresetInputs): string => inputs.address ?? '';

export const bindery: Preset = {
  key: 'bindery',
  name: 'Bindery',
  summary: 'The household document archive',
  docsUrl: 'https://github.com/matdemers1/d3-auth/blob/main/docs/consumer-contract.md',
  where: 'Settings → Sign in with D3 Auth',
  checked: '17 September 2026',
  ownerRole: 'admin',
  inputs: [
    {
      key: 'address',
      label: 'Bindery address',
      kind: 'address',
      help: 'The address you open Bindery at. Nothing after it.',
      placeholder: 'https://bindery.example.com',
      feeds: ['redirect_uris', 'post_logout_redirect_uris', 'backchannel_logout_uri'],
    },
    {
      key: 'client_id',
      label: 'Client ID',
      kind: 'client_id',
      help: 'What Bindery is called in tokens. Change it only if you run more than one Bindery.',
      default: 'bindery',
      feeds: ['client_id'],
    },
  ],
  steps: [
    'Give yourself access to Bindery with the Administrator role before you sign in. Bindery provisions nobody who arrives without a role.',
    'Leave Bindery on Optional until you have signed in through D3 Auth once. Required makes this the way in.',
    'If you already have a Bindery account at the same email address, connect it from Settings while signed in there. An address that already exists is deliberately refused at the callback rather than linked.',
  ],
  cautions: [
    'Identity is the issuer and the subject, never the email address. Changing somebody’s address here does not move their documents, and does not need to.',
    'The admin role does not make a Bindery administrator until that account has enrolled Bindery’s own two-factor. Bindery refuses the grant, not the sign-in.',
    'Taking a role away here takes effect on Bindery’s next token renewal — minutes, not the next sign-in.',
  ],

  manifest(inputs) {
    const at = address(inputs);
    return {
      client_id: inputs.client_id,
      name: 'Bindery',
      description: 'The household document archive: page-level search inside bundled scans.',
      client_type: 'confidential_web',
      redirect_uris: [`${at}/api/auth/oidc/callback`],
      post_logout_redirect_uris: [`${at}/`],
      backchannel_logout_uri: `${at}/api/auth/oidc/backchannel-logout`,
      roles: [
        {
          key: 'admin',
          display: 'Administrator',
          description: 'Invites people, issues reset codes, reads the pipeline. Granted only once Bindery’s own two-factor is enrolled.',
        },
        {
          key: 'member',
          display: 'Member',
          description: 'An ordinary account with its own library and no storage limit.',
          default: true,
        },
        {
          key: 'guest',
          display: 'Guest',
          description: 'An ordinary account with a 5 GB limit, for somebody keeping a few documents here.',
        },
      ],
    };
  },

  sheet({ issuer, app, inputs, secret, preview }) {
    const at = address(inputs);
    return [
      {
        id: 'issuer',
        label: 'Issuer',
        value: issuer,
        action: 'set',
        why: 'Bindery finds everything else from here, and verifies every ID token against it.',
      },
      { id: 'client_id', label: 'Client ID', value: app.clientId, action: 'set' },
      {
        id: 'client_secret',
        label: 'Client secret',
        value: secret ?? null,
        action: 'set',
        secret: true,
        ...(secret ? {} : { why: preview ? SECRET_ON_REGISTER : SECRET_NOT_SHOWN }),
      },
      {
        id: 'sso_mode',
        label: 'How much of the front door it owns',
        value: 'Optional',
        action: 'set',
        why: 'Both ways in. Passwords keep working, and nothing changes for an account that never uses this. Bindery refuses Optional until the three values above are filled in.',
      },
      {
        id: 'redirect_uri',
        label: 'Redirect URI',
        value: `${at}/api/auth/oidc/callback`,
        action: 'leave',
        why: 'Registered here already, and Bindery builds the same one. Shown so you can check the two match — they are compared character for character, and https is not the same as http.',
      },
      {
        id: 'backchannel',
        label: 'Back-channel logout',
        value: `${at}/api/auth/oidc/backchannel-logout`,
        action: 'leave',
        why: 'Nothing to enter. Signing out here ends the Bindery session too.',
      },
    ];
  },
};
