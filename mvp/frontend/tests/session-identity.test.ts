// The signed-in user's directory person (#319) and the 403 guard of useApi data fetching (#320).
// Run with `npm test`.
import assert from "node:assert/strict";
import { test } from "node:test";

(globalThis as any).window = Object.assign(new EventTarget(), { location: { assign: () => {} } });
const { resolveMe } = await import("../src/app/me.ts");
const { ApiError, isDenied } = await import("../src/api.ts");

const people: any[] = [
  { id: 6, name: "Ilya Kowalczyk", email: "ilya@larkspur.example" },
  { id: 11, name: "Anders Zeller", email: "anders@larkspur.example" },
  { id: 12, name: "Olu Other", email: "olu@idp.example" },
];

test("the server's linked identity wins, even when the emails differ", () => {
  const cases: { name: string; user: any; want: number | null }[] = [
    { name: "linked, email differs (Olu)", user: { email: "olu@idp.example", identity_id: 6 }, want: 6 },
    { name: "linked, no email", user: { email: null, identity_id: 11 }, want: 11 },
    { name: "linked beats a matching email", user: { email: "olu@idp.example", identity_id: 11 }, want: 11 },
    { name: "unlinked falls back to the email", user: { email: "OLU@idp.example", identity_id: null }, want: 12 },
    { name: "link to an identity not in the list falls back", user: { email: "anders@larkspur.example", identity_id: 99 }, want: 11 },
    { name: "unlinked and unmatched", user: { email: "nobody@x.example", identity_id: null }, want: null },
    { name: "no email, no link", user: { email: null, identity_id: null }, want: null },
  ];
  for (const c of cases) assert.equal(resolveMe(people, c.user)?.id ?? null, c.want, c.name);
});

test("nothing resolves before the directory or the session is there", () => {
  assert.equal(resolveMe(null, { email: "olu@idp.example", identity_id: 6 }), null);
  assert.equal(resolveMe(people, null), null);
});

test("only a 403 is a denial that must not be refetched", () => {
  assert.equal(isDenied(new ApiError("forbidden", 403, null)), true);
  assert.equal(isDenied(new ApiError("down", 500, null)), false);
  assert.equal(isDenied(new ApiError("signed out", 401, null)), false);
  assert.equal(isDenied(new Error("x")), false);
});
