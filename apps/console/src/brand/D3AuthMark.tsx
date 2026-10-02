// AUTH-T-8.1: the D3 Auth mark — the "Keyhole" from d3cloud.io's product marks (DI-REQ-040). Every
// D3 Cloud product keeps the planisphere's ring; inside it, ink lines, round joints, and exactly one
// lit star in the product's own colour.
//
// Ink is currentColor, so the mark takes the text colour in either theme. The lit star's colour is
// set by the `auth-mark__star` class (brand/mark.css), never a style attribute: the server draws
// this same mark into the no-JavaScript sign-in page (apps/server/src/interaction/auth-markup.ts),
// where the CSP allows no inline style. The star's fill="currentColor" is only the fallback for a
// page whose stylesheet did not load. public/favicon.svg is the same drawing with fixed colours.

export const D3_AUTH_MARK_NAME = 'D3 Auth';

export interface D3AuthMarkProps {
  /** Rendered width and height in px. Display weights from 72 up, as on d3cloud.io. */
  size?: number;
  /**
   * Set when "D3 Auth" is written beside the mark, so a screen reader does not read it twice. Left
   * off, the mark stands alone and is announced as an image named "D3 Auth".
   */
  decorative?: boolean;
}

/** d3cloud.io's two weights: heavier at icon sizes, finer at display sizes. */
export function markWeights(size: number): { line: number; joint: number; star: number } {
  return size >= 72 ? { line: 2.2, joint: 2.6, star: 4.4 } : { line: 3.5, joint: 3.4, star: 5.5 };
}

export function D3AuthMark({ size = 20, decorative = false }: D3AuthMarkProps) {
  const weights = markWeights(size);
  const ink = { stroke: 'currentColor', strokeWidth: weights.line, strokeLinecap: 'round', strokeLinejoin: 'round' } as const;
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      viewBox="0 0 64 64"
      fill="none"
      className="auth-mark"
      {...(decorative ? { 'aria-hidden': true } : { role: 'img', 'aria-label': D3_AUTH_MARK_NAME })}
    >
      <circle cx="32" cy="32" r="26" {...ink} />
      <circle cx="32" cy="25" r="7.5" {...ink} />
      <path d="M28.5 31.5 L25 45 L39 45 L35.5 31.5" {...ink} />
      <circle cx="25" cy="45" r={weights.joint} fill="currentColor" />
      <circle cx="39" cy="45" r={weights.joint} fill="currentColor" />
      <circle cx="32" cy="25" r={weights.star} fill="currentColor" className="auth-mark__star" />
    </svg>
  );
}
