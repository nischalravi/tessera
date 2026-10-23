/**
 * The words a tenant renamed (Admin → Branding & labels): `{ entitlement: "permission set" }`. The server sends them with
 * the user's preferences before the app renders; `applyLabels` swaps them, singular and plural and keeping the capital
 * letter, in the navigation and the page titles. Pure, so `npm test` can run it.
 */
export type Labels = Record<string, string>;

let current: Labels = {};
export const setLabels = (l: Labels | undefined | null) => {
  current = l ?? {};
};
export const getLabels = () => current;

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** "permission set" -> "permission sets"; "policy" -> "policies"; "class" -> "classes". */
export function pluralOf(word: string): string {
  if (/[^aeiou]y$/i.test(word)) return word.slice(0, -1) + "ies";
  if (/(s|x|z|ch|sh)$/i.test(word)) return word + "es";
  return word + "s";
}

function matchCase(from: string, to: string): string {
  if (from.length > 1 && from === from.toUpperCase() && from !== from.toLowerCase()) return to.toUpperCase();
  if (from[0] !== from[0].toLowerCase()) return to[0].toUpperCase() + to.slice(1);
  return to;
}

/** Replaces each renamed term in `text`. Whole words only: "grouping" is not "group". */
export function applyLabels(text: string, labels: Labels = current): string {
  const keys = Object.keys(labels).sort((a, b) => b.length - a.length);
  if (!keys.length || !text) return text;
  let out = text;
  for (const k of keys) {
    const to = labels[k];
    const re = new RegExp(`\\b${escapeRe(k)}(s|es)?\\b`, "gi");
    out = out.replace(re, (m: string, tail?: string) => matchCase(m, tail ? pluralOf(to) : to));
  }
  return out;
}
