import { execFileSync } from 'node:child_process';

// Every run starts from the seeded fixtures (REQ-133).
//
// Flows here change accounts on purpose: F5 resets a password, F2 enrols and removes a passkey.
// Without this, a second run of the suite would start from the state the first one left behind,
// and the failure would look like a bug in the code rather than in the test.

export default function seedTheStack(): void {
  execFileSync('pnpm', ['dev:seed'], { cwd: '..', stdio: 'inherit' });
}
