import type { SheetApp, SheetRow } from '../connection.js';

// What a preset is (REQ-143). A plain module: the questions only the owner can answer, a function
// from those answers to an ordinary manifest, and a paste sheet in the other app's own words.
//
// A preset decides nothing a manifest does not. What it builds goes through the same
// `parseManifest` and the same `apps.register` as a manifest somebody pasted, so a preset cannot
// register a wildcard, a fragment, plain http on a real host, or the console's own client id —
// and adding one is a reviewed change to this directory, never a file somebody uploads.

/** How an answer is read. Each kind has one validator, shared by every preset. */
export type PresetInputKind = 'address' | 'client_id';

export interface PresetInput {
  key: string;
  /** Shown as the field label, and the prefix of every problem with it: "Immich address: …". */
  label: string;
  kind: PresetInputKind;
  help: string;
  /** A format example, never a label. */
  placeholder?: string;
  /** Used when the answer is left out. An input without one is required. */
  default?: string;
  /** Manifest fields built from this answer, so a manifest problem is reported against it. */
  feeds: readonly string[];
}

/** Answers, read and normalised. Only declared keys, only strings. */
export type PresetInputs = Readonly<Record<string, string>>;

export interface SheetContext {
  issuer: string;
  app: SheetApp;
  inputs: PresetInputs;
  /** Only at registration or rotation. */
  secret?: string | undefined;
}

export interface Preset {
  key: string;
  name: string;
  summary: string;
  docsUrl: string;
  inputs: readonly PresetInput[];
  /** Where the settings live in the other app: "Administration → Settings → Authentication → OAuth". */
  where: string;
  /** When the sheet was last checked against the other app's real settings screen. */
  checked: string;
  /** Before and after: what to do around the pasting. */
  steps: readonly string[];
  /** What the owner should know before people start signing in. */
  cautions: readonly string[];
  /** The ordinary manifest. Unvalidated on purpose: the caller parses it like any other. */
  manifest(inputs: PresetInputs): unknown;
  /** The other app's settings screen, in order, in its own labels. */
  sheet(context: SheetContext): SheetRow[];
}
