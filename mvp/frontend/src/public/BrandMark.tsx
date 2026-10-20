import { PublicBranding } from "../api";

/** The tenant's logo (decorative: the name beside it is the text) and its product name. */
export function BrandMark({ branding, name }: { branding?: PublicBranding | null; name: string }) {
  return (
    <span className="brand-mark">
      {branding?.logo_url && <img className="brand-logo" src={branding.logo_url} alt="" width={branding.logo_width} height={branding.logo_height} />}
      <span>{name}</span>
    </span>
  );
}
