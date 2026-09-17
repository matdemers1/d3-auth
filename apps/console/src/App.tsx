import { AuthLayout, Link, ThemeProvider } from '@d3cloud/ui';
import type { ComponentType } from 'react';
import type { Surface } from './surface';

// Each surface is its own chunk, so a phone on the sign-in screen never downloads the admin
// console (REQ-077, R-09).

function NotFound() {
  return (
    <AuthLayout
      title="There is nothing at this address"
      description="Check the link you followed."
      footer={
        <Link variant="standalone" href="/signin">
          Sign in to your account
        </Link>
      }
    />
  );
}

export async function loadSurface(surface: Surface): Promise<ComponentType> {
  switch (surface) {
    case 'login':
      return (await import('./login/LoginShell')).default;
    case 'account':
      return (await import('./account/AccountShell')).default;
    case 'admin':
      return (await import('./admin/AdminShell')).default;
    default:
      return NotFound;
  }
}

/**
 * The theme follows the OS, with System / Light / Dark in the account menu, remembered per browser
 * (D-066). `index.html` sets the same attribute from the same key before first paint, so nothing
 * flashes while this loads.
 */
export function App({ Surface }: { Surface: ComponentType }) {
  return (
    <ThemeProvider>
      <Surface />
    </ThemeProvider>
  );
}
