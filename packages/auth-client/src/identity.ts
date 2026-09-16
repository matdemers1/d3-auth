// Who somebody is, as far as a consuming app is concerned (REQ-093).
//
// An identity is `(iss, sub)` and nothing else. Not the email — an email can change, can be
// reassigned, and can be claimed by somebody who has not proved they own it. An app that keys
// its accounts on the email address is one unverified sign-up away from handing over somebody
// else's data, which is why this SDK offers no lookup helper that takes one.

export interface Identity {
  /** The issuer that vouched for this person. */
  iss: string;
  /** Stable, opaque, and unique only within that issuer. */
  sub: string;
  /** Everything the ID token said. Useful for display; never for identity. */
  claims: Readonly<Record<string, unknown>>;
  /** This person's roles *in this app*, as of the last token or userinfo response. */
  roles: string[];
}

/**
 * The key to store on a local account. Both halves matter: two issuers can use the same `sub`,
 * and one issuer's `sub` means nothing at another.
 */
export function identityKey(identity: Pick<Identity, 'iss' | 'sub'>): string {
  return `${identity.iss}#${identity.sub}`;
}

/** True when this token describes the same person as the stored key. */
export function isSameIdentity(stored: string, identity: Pick<Identity, 'iss' | 'sub'>): boolean {
  return stored === identityKey(identity);
}
