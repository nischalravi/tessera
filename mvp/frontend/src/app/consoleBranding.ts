import { useEffect, useSyncExternalStore } from "react";
import { PublicBranding, publicBranding } from "../api";
import { DEFAULT_PRODUCT, consoleBrandStyle, productName } from "../branding";

export { DEFAULT_PRODUCT, consoleBrandStyle, productName };

// The tenant's branding inside the console: the top bar name and logo, the page title and the button colour.
// One shared copy, fetched once per tenant (the public branding route needs no permission, so every signed-in
// person sees it, not only admins) and refreshed by `refreshConsoleBranding` when an admin saves.

let state: { slug: string; branding: PublicBranding | null } = { slug: "", branding: null };
const subs = new Set<() => void>();
const set = (slug: string, branding: PublicBranding | null) => {
  state = { slug, branding };
  subs.forEach((f) => f());
};
const subscribe = (f: () => void) => {
  subs.add(f);
  return () => void subs.delete(f);
};

async function load(slug: string) {
  const b = await publicBranding(slug);
  if (state.slug === slug || state.slug === "") set(slug, b ?? state.branding);
}

/** Fetch again (after Save branding), so the console changes without a reload. */
export const refreshConsoleBranding = () => (state.slug ? load(state.slug) : Promise.resolve());

/** The branding for the signed-in tenant; pass the slug once from the shell to load it. */
export function useConsoleBranding(slug?: string): PublicBranding | null {
  useEffect(() => {
    if (slug && state.slug !== slug) {
      set(slug, null);
      void load(slug);
    }
  }, [slug]);
  return useSyncExternalStore(subscribe, () => state.branding);
}
