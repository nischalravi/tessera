import { en } from "./en.ts";
import type { MessageKey } from "./en.ts";

/**
 * A small message catalog for the public pages: `t("key", { name })` looks the key up in the active
 * language and fills {placeholders}. Only English exists today; to add a language, create `xx.ts`
 * exporting `Partial<Record<MessageKey, string>>`, register it in `catalogs` and it is picked from
 * the browser's language list. A key missing from a language falls back to English, then to the key
 * itself, so a gap never renders blank. Message values are plain text, never HTML: React escapes them.
 * No React and no browser APIs here, so `npm test` can run it.
 */
export type { MessageKey } from "./en.ts";
type Params = Record<string, string | number>;

const catalogs: Record<string, Partial<Record<MessageKey, string>>> = { en };
let active = "en";

/** The languages this build has messages for. */
export const locales = () => Object.keys(catalogs);

/** The best supported language for a browser's preference list ("fr-CA", "en-GB" …), or English. */
export function pickLocale(preferred: readonly string[]): string {
  for (const p of preferred) {
    const tag = p.toLowerCase();
    if (catalogs[tag]) return tag;
    const base = tag.split("-")[0];
    if (catalogs[base]) return base;
  }
  return "en";
}

export function setLocale(preferred: readonly string[]): string {
  active = pickLocale(preferred);
  return active;
}

export const locale = () => active;

/** Fills {name} placeholders; an unknown placeholder is left as written so the gap is visible. */
export function format(message: string, params?: Params): string {
  if (!params) return message;
  return message.replace(/\{([a-z_]+)\}/g, (whole, k: string) => (k in params ? String(params[k]) : whole));
}

export function t(key: MessageKey, params?: Params): string {
  return format(catalogs[active]?.[key] ?? en[key] ?? key, params);
}
