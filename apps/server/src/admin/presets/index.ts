import { CLIENT_ID, parseManifest, type Manifest, type ManifestProblem } from '../manifest.js';
import { genericSheet, type SheetApp, type SheetRow } from '../connection.js';
import { bindery } from './bindery.js';
import { immich } from './immich.js';
import type { Preset, PresetInput, PresetInputs } from './types.js';

export type { Preset, PresetInput, PresetInputs } from './types.js';

// The preset registry (REQ-143). One list, served to the console, so the picker and the logic
// that registers from it cannot disagree about which apps are known.

export const PRESETS: readonly Preset[] = [bindery, immich];

const BY_KEY = new Map(PRESETS.map((preset) => [preset.key, preset]));

/** A Map rather than an object lookup, so "__proto__" and friends are simply not presets. */
export const findPreset = (key: string): Preset | undefined => BY_KEY.get(key);

/** What the console needs to draw the picker and the form. No functions, nothing derived. */
export const describePreset = (preset: Preset) => ({
  key: preset.key,
  name: preset.name,
  summary: preset.summary,
  docsUrl: preset.docsUrl,
  ...(preset.ownerRole ? { ownerRole: preset.ownerRole } : {}),
  inputs: preset.inputs.map(({ key, label, kind, help, placeholder, default: fallback }) => ({
    key,
    label,
    kind,
    help,
    ...(placeholder ? { placeholder } : {}),
    ...(fallback ? { default: fallback } : {}),
  })),
});

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

/**
 * An app's address: its origin and nothing else, without a trailing slash.
 *
 * The rules are the manifest's (https, or http on localhost) plus the ones an address needs so the
 * URIs built from it are the ones the owner expects: no path — the preset adds the paths — and no
 * query, fragment, credentials or wildcard to be carried into every redirect URI.
 */
export function readAddress(raw: string, label: string, appName: string): { ok: true; value: string } | { ok: false; message: string } {
  const value = raw.trim();
  const fail = (message: string) => ({ ok: false as const, message: `${label}: ${message}` });
  if (value === '') return fail(`enter the address you open ${appName} at, like https://photos.example.com.`);
  if (value.includes('*')) return fail('wildcards are not allowed. Enter one exact address.');

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return fail(`that is not a web address. Start it with https://, like https://photos.example.com.`);
  }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && LOOPBACK.has(url.hostname))) {
    return fail('it must start with https:// (plain http is only allowed for localhost).');
  }
  if (url.username || url.password) return fail('leave out the user name and password.');
  if (value.includes('?') || value.includes('#')) return fail('leave out everything from the "?" or "#" onwards.');
  if (url.pathname !== '/' && url.pathname !== '') {
    return fail(`just the address, with nothing after it — ${url.protocol}//${url.host}, not ${url.protocol}//${url.host}${url.pathname}.`);
  }
  return { ok: true, value: `${url.protocol}//${url.host}` };
}

function readOne(input: PresetInput, raw: unknown, appName: string): { ok: true; value: string } | { ok: false; message: string } {
  if (raw !== undefined && raw !== null && typeof raw !== 'string') return { ok: false, message: `${input.label}: must be text.` };
  const given = typeof raw === 'string' ? raw.trim() : '';
  const value = given === '' ? (input.default ?? '') : given;

  switch (input.kind) {
    case 'address':
      return readAddress(value, input.label, appName);
    case 'client_id':
      if (value === '') return { ok: false, message: `${input.label}: enter a client ID.` };
      return CLIENT_ID.test(value)
        ? { ok: true, value }
        : { ok: false, message: `${input.label}: 2–64 characters — lower-case letters, numbers, dot, dash or underscore.` };
  }
}

export type PresetResult = { ok: true; inputs: PresetInputs; manifest: Manifest } | { ok: false; problems: ManifestProblem[] };

/**
 * Answers → a manifest the rest of the system can trust, or problems named after the inputs.
 *
 * The manifest is parsed exactly as a pasted one is. If that refuses it, the problem is reported
 * against the input the field was built from, because the owner never saw a manifest.
 */
export function buildFromPreset(preset: Preset, raw: unknown): PresetResult {
  const given = raw !== null && typeof raw === 'object' && !Array.isArray(raw) ? (raw as Record<string, unknown>) : {};
  const inputs: Record<string, string> = {};
  const problems: ManifestProblem[] = [];
  for (const input of preset.inputs) {
    const read = readOne(input, Object.hasOwn(given, input.key) ? given[input.key] : undefined, preset.name);
    if (read.ok) inputs[input.key] = read.value;
    else problems.push({ field: input.key, message: read.message });
  }
  if (problems.length > 0) return { ok: false, problems };

  const parsed = parseManifest(preset.manifest(inputs));
  if (parsed.ok) return { ok: true, inputs, manifest: parsed.manifest };

  return {
    ok: false,
    problems: parsed.problems.map((problem) => {
      const top = problem.field.split('.')[0] ?? '';
      const input = preset.inputs.find((candidate) => candidate.feeds.includes(top));
      return input
        ? { field: input.key, message: `${input.label}: ${problem.message}` }
        : { field: 'preset', message: `${preset.name}: ${problem.message}` };
    }),
  };
}

export interface PresetSheet {
  preset: string;
  name: string;
  docsUrl: string;
  where: string;
  checked: string;
  steps: readonly string[];
  cautions: readonly string[];
  rows: SheetRow[];
}

export interface Connection {
  clientId: string;
  /** Every value any app needs. */
  rows: SheetRow[];
  /** The paste sheet, when a preset built this app and still reads its stored answers. */
  preset: PresetSheet | null;
}

/**
 * The whole sheet for one app. Stored answers are read again through the same validators before
 * any URL is built from them: an imported state file can carry answers nobody typed here.
 */
/** The paste sheet before anything is registered: from the manifest the answers build, with no secret yet. */
export function previewSheet(issuer: string, preset: Preset, inputs: PresetInputs, manifest: Manifest): PresetSheet {
  const app: SheetApp = {
    clientId: manifest.client_id,
    clientType: manifest.client_type,
    redirectUris: manifest.redirect_uris,
    postLogoutRedirectUris: manifest.post_logout_redirect_uris,
    backchannelLogoutUri: manifest.backchannel_logout_uri ?? null,
    roles: manifest.roles,
  };
  return describeSheet(preset, preset.sheet({ issuer, app, inputs, preview: true }));
}

const describeSheet = (preset: Preset, rows: SheetRow[]): PresetSheet => ({
  preset: preset.key,
  name: preset.name,
  docsUrl: preset.docsUrl,
  where: preset.where,
  checked: preset.checked,
  steps: preset.steps,
  cautions: preset.cautions,
  rows,
});

export function connectionFor(
  issuer: string,
  app: SheetApp & { preset: string | null; presetInputs: unknown },
  secret?: string,
): Connection {
  const rows = genericSheet(issuer, app, secret);
  const preset = app.preset ? findPreset(app.preset) : undefined;
  const built = preset ? buildFromPreset(preset, app.presetInputs) : undefined;
  return {
    clientId: app.clientId,
    rows,
    preset:
      preset && built?.ok ? describeSheet(preset, preset.sheet({ issuer, app, inputs: built.inputs, secret })) : null,
  };
}
