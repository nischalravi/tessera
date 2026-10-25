import { useEffect, useSyncExternalStore } from "react";
import { PublicBranding, publicBranding } from "../api";
import { DEFAULT_PRODUCT, consoleBrandStyle, productName } from "../branding";
import { createBrandingStore } from "../brandingStore";

export { DEFAULT_PRODUCT, consoleBrandStyle, productName };

// The tenant's branding inside the console: the top bar name and logo, the page title and the button colour.
// One shared copy, fetched once per tenant (the public branding route needs no permission, so every signed-in
// person sees it, not only admins) and refreshed by `refreshConsoleBranding` when an admin saves.

const store = createBrandingStore(publicBranding);

/** Fetch again (after Save branding), so the console changes without a reload. */
export const refreshConsoleBranding = () => store.refresh();

/** The branding for the signed-in tenant; the shell passes the slug to load it, other callers only read. */
export function useConsoleBranding(slug?: string): PublicBranding | null {
  useEffect(() => {
    if (slug) store.use(slug);
  }, [slug]);
  return useSyncExternalStore(store.subscribe, store.get);
}
