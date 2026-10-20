// Tenant branding helpers (Admin > Branding): the same WCAG contrast rule the API enforces, so the form can warn
// before saving, and the CSS variables a branded public page sets. Self-contained so it can be tested on its own.

export const MIN_CONTRAST = 4.5;

const HEX = /^#[0-9a-f]{6}$/i;

export const isHex = (s: string) => HEX.test(s.trim());

function lin(c: number): number {
  const v = c / 255;
  return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
}

function luminance(hex: string): number {
  const n = parseInt(hex.trim().slice(1), 16);
  return 0.2126 * lin((n >> 16) & 255) + 0.7152 * lin((n >> 8) & 255) + 0.0722 * lin(n & 255);
}

/** The WCAG contrast ratio of two #rrggbb colours (1 to 21). */
export function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

/** White or black text, whichever reads better on `bg` (what the API picks when no text colour is given). */
export function bestOn(bg: string): "#ffffff" | "#000000" {
  return contrast(bg, "#000000") > contrast(bg, "#ffffff") ? "#000000" : "#ffffff";
}

/** Mix two #rrggbb colours (t of the way from a to b). */
export function mix(a: string, b: string, t: number): string {
  const pa = parseInt(a.slice(1), 16);
  const pb = parseInt(b.slice(1), 16);
  const ch = (shift: number) => Math.round(((pa >> shift) & 255) * (1 - t) + ((pb >> shift) & 255) * t);
  return "#" + [16, 8, 0].map((s) => ch(s).toString(16).padStart(2, "0")).join("");
}

/** Why a colour pair is not allowed, or null when it reaches AA. */
export function pairProblem(primary: string, on: string): string | null {
  if (!isHex(primary)) return "The button colour must be #rrggbb.";
  const text = on.trim() || bestOn(primary);
  if (!isHex(text)) return "The text colour must be #rrggbb.";
  const c = contrast(primary, text);
  if (c >= MIN_CONTRAST) return null;
  const better = bestOn(primary);
  return `${text} on ${primary} has a contrast of ${c.toFixed(2)}:1; WCAG AA needs ${MIN_CONTRAST}:1 (${better} gives ${contrast(primary, better).toFixed(2)}:1).`;
}

/**
 * The CSS variables a branded public page sets on its wrapper. Only the button colours change; text and link
 * colours stay the theme's, so they keep their contrast whatever the tenant picks. The hover colour moves away
 * from the text colour, so the pair never loses contrast on hover.
 */
export function brandStyle(b: { configured: boolean; primary_color: string; on_primary_color: string } | null | undefined): Record<string, string> | undefined {
  if (!b || !b.configured || !isHex(b.primary_color) || !isHex(b.on_primary_color) || pairProblem(b.primary_color, b.on_primary_color)) return undefined;
  const away = b.on_primary_color.toLowerCase() === "#ffffff" || luminance(b.on_primary_color) > luminance(b.primary_color) ? "#000000" : "#ffffff";
  return { "--accent": b.primary_color, "--accent-hover": mix(b.primary_color, away, 0.14), "--on-accent": b.on_primary_color };
}
