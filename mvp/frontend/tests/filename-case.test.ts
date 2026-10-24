// Two source files whose paths differ only by letter case work on Linux but
// collide on case-insensitive file systems (macOS, Windows): an import then
// resolves to the wrong file and the page fails to render.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";

function walk(dir: string, out: string[]): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

test("no two source modules differ only by case", () => {
  const seen = new Map<string, string>();
  const clashes: string[] = [];
  for (const f of walk("src", [])) {
    // module specifiers omit the extension, so compare without it
    const key = f.replace(/\.(tsx?|jsx?|css)$/, "").toLowerCase();
    const prev = seen.get(key);
    if (prev && prev !== f) clashes.push(`${prev} <-> ${f}`);
    else seen.set(key, f);
  }
  assert.deepEqual(clashes, []);
});
