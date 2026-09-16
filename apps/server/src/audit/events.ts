// Typed audit event names (REQ-110). Every mutation and every authentication event appends one
// row; the table refuses updates and deletes, so this list only ever grows.

export const AUDIT_EVENTS = {
  loginSuccess: 'login.success',
  loginFailure: 'login.failure',
  loginThrottled: 'login.throttled',
  loginAborted: 'login.aborted',
  logout: 'session.logout',
  sessionStarted: 'session.started',
  sessionRevoked: 'session.revoked',
  keyGenerated: 'key.generated',
  ownerClaimed: 'owner.claimed',
  personSuspended: 'person.suspended',
  personReactivated: 'person.reactivated',
  personReset: 'person.reset',
  personKindChanged: 'person.kind_changed',
  inviteCreated: 'invite.created',
  inviteAccepted: 'invite.accepted',
  inviteRevoked: 'invite.revoked',
  deviceTrusted: 'device.trusted',
  deviceRevoked: 'device.revoked',
  profileUpdated: 'person.profile_updated',
  passwordChanged: 'password.changed',
  factorAdded: 'factor.added',
  factorRemoved: 'factor.removed',
  devSeedUser: 'dev.seed.user',
  devSeedApp: 'dev.seed.app',
} as const;

export type AuditEventName = (typeof AUDIT_EVENTS)[keyof typeof AUDIT_EVENTS];

export type AuditTargetType = 'user' | 'app' | 'session' | 'signing_key' | 'grant' | 'group';
