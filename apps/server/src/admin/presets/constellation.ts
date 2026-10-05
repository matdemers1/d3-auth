import type { Preset } from './types.js';

// D3 Constellation (AUTH-T-9.2, CON-ADR-004, AUTH-ADR-008): the native Apple app that is the front
// door to every D3 product. One public native client — authorization code with PKCE, no secret,
// redirecting to the app's own scheme — whose one grant mints a token for each product's audience.
//
// Everything here is fixed by the app, not chosen by the owner: Constellation sends exactly this
// client id and redirect, so a preset with answers would only be a way to get them wrong. This is
// also the one client allowed to name another app's resource (`CONSTELLATION_PRESET` in
// oidc/resources.ts) — registering it is what turns that on.

export const CONSTELLATION_CLIENT_ID = 'd3-constellation';
export const CONSTELLATION_REDIRECT = 'd3constellation://oauth/d3auth';

export const constellation: Preset = {
  key: 'constellation',
  name: 'D3 Constellation',
  summary: 'The app for iPhone, iPad and Mac',
  docsUrl: 'https://github.com/matdemers1/d3-app-contract',
  where: 'Constellation → Add a product → D3 Auth',
  checked: '4 October 2026',
  inputs: [],
  steps: [
    'Give each person access to D3 Constellation, as you would any app. Without it they cannot sign in to the app with D3 Auth.',
    'Give each product its address: Bindery and Immich get one from their presets; any other app needs home_url in its manifest. That address is the audience Constellation asks tokens for.',
    'In Constellation, add D3 Auth by its address. Products added after it sign in through it.',
  ],
  cautions: [
    'This is the only app allowed to ask D3 Auth for a token meant for another app — and only for apps the person has been given. Taking somebody’s access to a product stops that product’s tokens at their next renewal, within minutes.',
    'Signing out of D3 Auth in Constellation signs the app out of every product that used D3 Auth.',
  ],

  manifest() {
    return {
      client_id: CONSTELLATION_CLIENT_ID,
      name: 'D3 Constellation',
      description: 'The native app for iPhone, iPad and Mac: one sign-in for every D3 product.',
      client_type: 'public_native',
      redirect_uris: [CONSTELLATION_REDIRECT],
      roles: [],
    };
  },

  sheet({ issuer }) {
    return [
      { id: 'address', label: 'D3 Auth address', value: issuer, action: 'set', why: 'Add D3 Auth in Constellation with this address. The app finds everything else from it.' },
      { id: 'client_id', label: 'Client ID', value: CONSTELLATION_CLIENT_ID, action: 'leave', why: 'Built into the app.' },
      { id: 'redirect', label: 'Redirect', value: CONSTELLATION_REDIRECT, action: 'leave', why: 'Built into the app. Exact match, like every redirect here.' },
    ];
  },
};
