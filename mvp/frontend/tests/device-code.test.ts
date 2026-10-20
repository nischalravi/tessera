// Device user codes in the approval page (design §9.3): typed or pasted input is normalized to
// XXXX-XXXX over the 20-letter alphabet. Run with `npm test`.
import assert from "node:assert/strict";
import { test } from "node:test";
import { USER_CODE_ALPHABET, formatUserCode, isCompleteUserCode } from "../src/deviceCode.ts";

test("input is upper-cased, filtered and dashed after four letters", () => {
  assert.equal(formatUserCode("kdqv-tmwb"), "KDQV-TMWB");
  assert.equal(formatUserCode("bcdf"), "BCDF");
  assert.equal(formatUserCode("bcdfg"), "BCDF-G");
  assert.equal(formatUserCode("bcdf-ghjk"), "BCDF-GHJK");
  assert.equal(formatUserCode("  bcdf ghjk  "), "BCDF-GHJK");
  assert.equal(formatUserCode("B-C-D-F-G-H-J-K"), "BCDF-GHJK");
});

test("letters outside the alphabet are dropped, not mapped", () => {
  // vowels, and the look-alikes 0, 1, 5, 8 and Y, never appear in a code
  assert.equal(formatUserCode("aeiouy015 8"), "");
  assert.equal(formatUserCode("bAcEdIfOgUhY"), "BCDF-GH");
});

test("never longer than eight letters; pasted text is cut", () => {
  assert.equal(formatUserCode("bcdfghjklmnp"), "BCDF-GHJK");
  assert.equal(formatUserCode("x".repeat(500)), "XXXX-XXXX");
});

test("a complete code has eight letters", () => {
  assert.equal(isCompleteUserCode(formatUserCode("bcdfghj")), false);
  assert.equal(isCompleteUserCode(formatUserCode("bcdfghjk")), true);
  assert.equal(isCompleteUserCode(""), false);
});

test("the alphabet is the server's", () => {
  assert.equal(USER_CODE_ALPHABET.length, 20);
  assert.equal(new Set(USER_CODE_ALPHABET).size, 20);
  assert.ok(!/[AEIOU]/.test(USER_CODE_ALPHABET));
});
