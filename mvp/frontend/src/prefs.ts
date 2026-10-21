/**
 * User preferences (issue #298): time zone, date format, locale and the page to land on. The server stores
 * them per user (/api/me/preferences); this module holds the signed-in user's copy and renders dates with it.
 * An empty value is the default: the browser's time zone and locale, the locale's medium date, the home page.
 * It imports nothing from api.ts, which formats its dates through it.
 */
export interface Preferences {
  time_zone: string;
  date_format: "" | "iso" | "dmy" | "mdy" | "long";
  locale: string;
  landing_page: string;
}
export interface PreferencesView extends Preferences {
  time_zones: string[];
  date_formats: string[];
  locales: string[];
  landing_pages: string[];
}

export const NO_PREFERENCES: Preferences = { time_zone: "", date_format: "", locale: "", landing_page: "" };
export const preferencesPath = "/me/preferences";

let current: Preferences = NO_PREFERENCES;
/** The signed-in user's preferences, as the date helpers see them. */
export const getDisplayPrefs = () => current;
export const setDisplayPrefs = (p: Preferences) => {
  current = { ...NO_PREFERENCES, ...p };
};

export const DATE_FORMAT_LABEL: Record<string, string> = {
  "": "Follow the locale",
  iso: "2026-10-21",
  dmy: "21/10/2026",
  mdy: "10/21/2026",
  long: "21 Oct 2026",
};

/** The locale to format with: the user's, else the browser's (undefined). */
const loc = (p: Preferences) => p.locale || undefined;
const zone = (p: Preferences) => p.time_zone || undefined;

/** Intl refuses an unknown zone or locale; fall back to the browser's rather than break a page. */
function safely<T>(f: () => T, fallback: () => T): T {
  try {
    return f();
  } catch {
    return fallback();
  }
}

const DAY_PARTS: Record<string, [string, Intl.DateTimeFormatOptions]> = {
  iso: ["en-CA", { year: "numeric", month: "2-digit", day: "2-digit" }],
  dmy: ["en-GB", { year: "numeric", month: "2-digit", day: "2-digit" }],
  mdy: ["en-US", { year: "numeric", month: "2-digit", day: "2-digit" }],
};

/** A date in the user's time zone and format. */
export function formatDay(d: Date, p: Preferences = current): string {
  const part = DAY_PARTS[p.date_format];
  return safely(
    () =>
      part
        ? d.toLocaleDateString(part[0], { ...part[1], timeZone: zone(p) })
        : p.date_format === "long"
          ? d.toLocaleDateString(loc(p), { day: "numeric", month: "short", year: "numeric", timeZone: zone(p) })
          : d.toLocaleDateString(loc(p), { dateStyle: "medium", timeZone: zone(p) }),
    () => d.toLocaleDateString(undefined, { dateStyle: "medium" }),
  );
}

/** A date and time in the user's time zone and format. */
export function formatDateTime(d: Date, p: Preferences = current): string {
  if (!p.date_format) {
    return safely(
      () => d.toLocaleString(loc(p), { dateStyle: "medium", timeStyle: "short", timeZone: zone(p) }),
      () => d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }),
    );
  }
  const time = safely(
    () => d.toLocaleTimeString(loc(p), { timeStyle: "short", timeZone: zone(p) }),
    () => d.toLocaleTimeString(undefined, { timeStyle: "short" }),
  );
  return `${formatDay(d, p)}, ${time}`;
}

/** The browser's own time zone name, for the "Browser default" choice. */
export const browserZone = () => safely(() => Intl.DateTimeFormat().resolvedOptions().timeZone, () => "UTC");

/**
 * Where to send the user who just arrived at `pathname`: their landing page when they arrived at the root and
 * chose another one, else nowhere. The server only stores paths from its own list; this checks again so a
 * stale or tampered value never navigates anywhere but inside the app.
 */
export function landingTarget(p: Preferences, pathname: string, allowed: readonly string[]): string | null {
  if (pathname !== "/" || !p.landing_page || p.landing_page === "/") return null;
  if (!p.landing_page.startsWith("/") || p.landing_page.startsWith("//") || !allowed.includes(p.landing_page)) return null;
  return p.landing_page;
}
