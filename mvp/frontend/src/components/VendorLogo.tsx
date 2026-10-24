import { CSSProperties, ReactNode } from "react";
import { siGoogle, siOkta } from "simple-icons";
import { logoFills } from "./logoContrast";

/**
 * A recognizable mark per system. Brand marks come from simple-icons (CC0, named imports so only these ship);
 * systems without one get a generic glyph drawn here, not vendor artwork. The brand colour is used only where it
 * meets AA against the tile in that theme, else a neutral fill.
 */
type Mark = { path: string; hex: string };

const BRAND: Record<string, Mark> = {
  okta: { path: siOkta.path, hex: siOkta.hex },
  google: { path: siGoogle.path, hex: siGoogle.hex },
};

const stroke = { fill: "none", stroke: "currentColor", strokeWidth: 1.7, strokeLinecap: "round", strokeLinejoin: "round" } as const;

// Generic glyphs on a 24x24 grid.
const GENERIC: Record<string, ReactNode> = {
  // directory tree
  ad: <g {...stroke}><rect x="9" y="2.5" width="6" height="4.5" rx="1" /><rect x="2.5" y="16.5" width="6" height="4.5" rx="1" /><rect x="15.5" y="16.5" width="6" height="4.5" rx="1" /><path d="M12 7v4.5M5.5 16.5v-5h13v5" /></g>,
  // root with a flat list of entries
  ldap: <g {...stroke}><circle cx="5" cy="5" r="2" /><path d="M5 7v12M5 12h5M5 19h5" /><rect x="11" y="9.5" width="9" height="5" rx="1" /><rect x="11" y="16.5" width="9" height="5" rx="1" /></g>,
  // identity shield with a person
  entra: <g {...stroke}><path d="M12 2.5l8 3v6c0 5-3.4 8.5-8 10-4.6-1.5-8-5-8-10v-6z" /><circle cx="12" cy="10" r="2.5" /><path d="M7.5 17c.8-2.4 2.6-3.5 4.5-3.5s3.7 1.1 4.5 3.5" /></g>,
  // org chart: HR source
  workday: <g {...stroke}><circle cx="12" cy="5" r="2.5" /><circle cx="5" cy="19" r="2.5" /><circle cx="19" cy="19" r="2.5" /><path d="M12 7.5v4M5 16.5v-5h14v5" /></g>,
  // protocol glyph: two-way arrows
  scim_app: <g {...stroke}><path d="M4 8h14M14 4l4 4-4 4M20 16H6M10 12l-4 4 4 4" /></g>,
};

/** `label` gives the logo an accessible name; without it the logo is decorative (the caller names the system). */
export function VendorLogo({ vendor, label, size = 40 }: { vendor: string; label?: string; size?: number }) {
  const brand = BRAND[vendor];
  const fills = brand ? logoFills(brand.hex) : null;
  const style = fills ? ({ "--logo-light": fills.light, "--logo-dark": fills.dark } as CSSProperties) : undefined;
  const a11y = label ? { role: "img", "aria-label": label } : { "aria-hidden": true as const, focusable: false };
  return (
    <svg className={`vendor-logo ${brand ? "brand" : "generic"}`} viewBox="0 0 24 24" width={size} height={size} style={style} {...a11y}>
      {brand ? <path d={brand.path} fill="currentColor" /> : GENERIC[vendor] ?? GENERIC.scim_app}
    </svg>
  );
}
