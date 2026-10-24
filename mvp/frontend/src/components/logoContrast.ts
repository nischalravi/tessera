// Pure helpers for VendorLogo: WCAG contrast of a brand colour against the tile surface in each theme.
// Kept free of React so `npm test` can run them.

/** Tile surface colours, mirroring --surface in styles.css (light, dark). */
export const LOGO_SURFACE = { light: "#ffffff", dark: "#292929" } as const;
/** Neutral fills, mirroring --text in each theme. */
export const LOGO_NEUTRAL = { light: "#242424", dark: "#ffffff" } as const;
/** AA for normal text; logos are held to the stricter bar so they read as clearly as labels. */
export const LOGO_MIN_CONTRAST = 4.5;

const lin = (c: number) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);

export function luminance(hex: string): number {
  const h = hex.replace("#", "");
  const [r, g, b] = [0, 2, 4].map((i) => lin(parseInt(h.slice(i, i + 2), 16) / 255));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

export function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

/** The fill to use per theme: the brand colour where it meets AA against the surface, else the neutral. */
export function logoFills(brandHex: string): { light: string; dark: string } {
  const hex = brandHex.startsWith("#") ? brandHex : `#${brandHex}`;
  return {
    light: contrast(hex, LOGO_SURFACE.light) >= LOGO_MIN_CONTRAST ? hex : LOGO_NEUTRAL.light,
    dark: contrast(hex, LOGO_SURFACE.dark) >= LOGO_MIN_CONTRAST ? hex : LOGO_NEUTRAL.dark,
  };
}
