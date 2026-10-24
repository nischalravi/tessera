import { ReactNode } from "react";
import { siGoogle, siOkta } from "simple-icons";

/**
 * A recognizable mark per system on a fixed light "logo plate" (white, subtle border, both themes) so brand colours
 * read on dark mode too. Logos are exempt from WCAG 1.4.3/1.4.11, so brand marks keep their brand colour.
 * Brand marks come from simple-icons (CC0, named imports so only these ship); systems without one get an original
 * generic glyph in its own colour, not vendor artwork.
 */
const BRAND: Record<string, { path: string; hex: string }> = {
  okta: { path: siOkta.path, hex: siOkta.hex },
  google: { path: siGoogle.path, hex: siGoogle.hex },
};

const stroke = { fill: "none", strokeWidth: 1.7, strokeLinecap: "round", strokeLinejoin: "round" } as const;

// Generic glyphs on a 24x24 grid, each with its own colour (all legible on the white plate).
const GENERIC: Record<string, { color: string; glyph: ReactNode }> = {
  // directory tree
  ad: { color: "#0f6cbd", glyph: <g {...stroke} stroke="#0f6cbd"><rect x="9" y="2.5" width="6" height="4.5" rx="1" /><rect x="2.5" y="16.5" width="6" height="4.5" rx="1" /><rect x="15.5" y="16.5" width="6" height="4.5" rx="1" /><path d="M12 7v4.5M5.5 16.5v-5h13v5" /></g> },
  // root with a list of entries
  ldap: { color: "#0e7a7a", glyph: <g {...stroke} stroke="#0e7a7a"><circle cx="5" cy="5" r="2" /><path d="M5 7v12M5 12h5M5 19h5" /><rect x="11" y="9.5" width="9" height="5" rx="1" /><rect x="11" y="16.5" width="9" height="5" rx="1" /></g> },
  // identity shield with a person
  entra: { color: "#5b4bc4", glyph: <g {...stroke} stroke="#5b4bc4"><path d="M12 2.5l8 3v6c0 5-3.4 8.5-8 10-4.6-1.5-8-5-8-10v-6z" /><circle cx="12" cy="10" r="2.5" /><path d="M7.5 17c.8-2.4 2.6-3.5 4.5-3.5s3.7 1.1 4.5 3.5" /></g> },
  // org chart: HR source
  workday: { color: "#c75000", glyph: <g {...stroke} stroke="#c75000"><circle cx="12" cy="5" r="2.5" /><circle cx="5" cy="19" r="2.5" /><circle cx="19" cy="19" r="2.5" /><path d="M12 7.5v4M5 16.5v-5h14v5" /></g> },
  // protocol glyph: two-way arrows
  scim_app: { color: "#475569", glyph: <g {...stroke} stroke="#475569"><path d="M4 8h14M14 4l4 4-4 4M20 16H6M10 12l-4 4 4 4" /></g> },
};

/** `label` gives the logo an accessible name; without it the logo is decorative (the caller names the system). */
export function VendorLogo({ vendor, label, size = 56 }: { vendor: string; label?: string; size?: number }) {
  const brand = BRAND[vendor];
  const generic = GENERIC[vendor] ?? GENERIC.scim_app;
  const a11y = label ? { role: "img", "aria-label": label } : { "aria-hidden": true as const };
  return (
    <span className="vendor-plate" style={{ width: size, height: size }} {...a11y}>
      <svg viewBox="0 0 24 24" width={Math.round(size * 0.6)} height={Math.round(size * 0.6)} focusable={false} aria-hidden>
        {brand ? <path d={brand.path} fill={`#${brand.hex}`} /> : generic.glyph}
      </svg>
    </span>
  );
}
