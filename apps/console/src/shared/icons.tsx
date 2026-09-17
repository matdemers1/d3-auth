import type { LucideIcon } from 'lucide-react';

// Lucide at the system's three icon sizes, with the stroke D-025 gives each: 16 in navigation and
// buttons, 20 leading a list row, 24 or more for an empty state or the product mark.

export type IconSize = 14 | 16 | 20 | 24 | 32;

export function icon(Glyph: LucideIcon, size: IconSize = 16) {
  const stroke = size >= 24 ? 1.5 : size === 20 ? 1.6 : size === 14 ? 2 : 1.8;
  return <Glyph size={size} strokeWidth={stroke} aria-hidden />;
}
