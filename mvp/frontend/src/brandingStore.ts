import type { PublicBranding } from "./api";

// The shared copy of the tenant's branding the console reads (top bar, tab title, button colour). Kept free of the
// API client so it can be tested on its own: the fetcher is passed in. `fresh` asks the fetcher to revalidate
// instead of trusting a cached answer (the route is served with max-age=300).

export type BrandingFetcher = (slug: string, fresh: boolean) => Promise<PublicBranding | null>;

export function createBrandingStore(fetcher: BrandingFetcher) {
  let state: { slug: string; branding: PublicBranding | null } = { slug: "", branding: null };
  const subs = new Set<() => void>();
  let latest = 0; // the newest request issued
  let applied = 0; // the newest request whose successful answer is shown; an older answer arriving after it is stale
  const set = (slug: string, branding: PublicBranding | null) => {
    state = { slug, branding };
    subs.forEach((f) => f());
  };
  async function load(slug: string, fresh: boolean) {
    const seq = ++latest;
    const b = await fetcher(slug, fresh);
    if (state.slug !== slug) return; // the tenant changed while this was in flight: its answer is stale
    if (!b) return; // a failed read keeps what is shown, and never supersedes an older read that succeeded
    if (seq < applied) return; // a newer read (for example the refresh after Save branding) already answered: this one is stale
    applied = seq;
    set(slug, b);
  }
  return {
    get: () => state.branding,
    slug: () => state.slug,
    subscribe(f: () => void) {
      subs.add(f);
      return () => void subs.delete(f);
    },
    /** Switch to a tenant and load it (no-op if already on it). */
    use(slug: string) {
      if (!slug || state.slug === slug) return;
      applied = latest; // answers to reads issued for the previous tenant are dropped by the slug check; start clean
      set(slug, null);
      void load(slug, false);
    },
    /** Fetch again, revalidating, after Save branding. */
    refresh: () => (state.slug ? load(state.slug, true) : Promise.resolve()),
  };
}
