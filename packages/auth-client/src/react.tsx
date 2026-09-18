import { useEffect, useState } from 'react';
import type { SsoMode } from './client.js';

// The *Sign in with D3 Auth* button (REQ-089).
//
// Plain elements and two class names, no design system: an app installing this SDK should not have
// to install somebody else's components to render one button. Style `.d3auth-signin` to taste.
//
// The interesting part is what it does when the provider is unreachable. An app in `required`
// mode has nothing else to offer, so the button says so plainly instead of throwing people at a
// sign-in that cannot work; an app in `optional` mode hides it and leaves its own login alone.

export interface ProviderHealth {
  checking: boolean;
  healthy: boolean;
}

/** Polls the provider's public readiness probe. No credentials, no CORS surprises. */
export function useProviderHealth(issuer: string, intervalMs = 30_000): ProviderHealth {
  const [health, setHealth] = useState<ProviderHealth>({ checking: true, healthy: false });

  useEffect(() => {
    let live = true;
    const check = async () => {
      try {
        const response = await fetch(`${issuer.replace(/\/$/, '')}/readyz`, { mode: 'cors' });
        if (live) setHealth({ checking: false, healthy: response.ok });
      } catch {
        if (live) setHealth({ checking: false, healthy: false });
      }
    };
    void check();
    const timer = setInterval(() => void check(), intervalMs);
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, [issuer, intervalMs]);

  return health;
}

export interface SignInButtonProps {
  /** Where the app starts its own sign-in, e.g. /auth/start. */
  href: string;
  issuer: string;
  ssoMode?: SsoMode;
  operatorDisplayName?: string;
  children?: React.ReactNode;
  /**
   * Styling is yours. The button carries `d3auth-signin` and, while the provider is unreachable,
   * `d3auth-signin--unavailable`; anything passed here is added to both.
   */
  className?: string;
}

export function SignInWithD3Auth({ href, issuer, ssoMode = 'optional', operatorDisplayName = 'D3 Auth', children, className }: SignInButtonProps) {
  const { checking, healthy } = useProviderHealth(issuer);

  if (ssoMode === 'off') return null;
  // Optional mode: the app has its own login, so a dead provider is best said with silence.
  if (!checking && !healthy && ssoMode === 'optional') return null;

  const unavailable = !checking && !healthy;
  return (
    <button
      type="button"
      className={['d3auth-signin', unavailable ? 'd3auth-signin--unavailable' : '', className ?? ''].filter(Boolean).join(' ')}
      disabled={checking || !healthy}
      onClick={() => {
        window.location.assign(href);
      }}
    >
      {unavailable ? `${operatorDisplayName} is unavailable` : (children ?? `Sign in with ${operatorDisplayName}`)}
    </button>
  );
}
