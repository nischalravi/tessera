/**
 * Device user codes (design §9.3, §10.3): eight letters from an alphabet with no vowels and no
 * look-alikes, shown as XXXX-XXXX. Pure helpers, no DOM, so they are unit-tested (`npm test`).
 */
export const USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ";
export const USER_CODE_LENGTH = 8;

/**
 * Formats what a person has typed or pasted as a user code: upper case, only letters the codes
 * use (a dash, space or any other character is dropped), at most eight, a dash after the fourth.
 */
export function formatUserCode(raw: string): string {
  let out = "";
  for (const c of raw.toUpperCase()) {
    if (USER_CODE_ALPHABET.includes(c)) out += c;
    if (out.length === USER_CODE_LENGTH) break;
  }
  return out.length > 4 ? `${out.slice(0, 4)}-${out.slice(4)}` : out;
}

/** True once all eight characters are there. */
export const isCompleteUserCode = (formatted: string): boolean => formatted.replace("-", "").length === USER_CODE_LENGTH;
