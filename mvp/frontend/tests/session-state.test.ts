// Session state in the API client (design §11, §17): sign-out and sign-in forget the CSRF token
// and every cached GET, and a GET that started under the previous session never refills the
// cache. Run with `npm test` (Node's test runner; no extra dependencies).
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

(globalThis as any).window = new EventTarget();

type Call = { url: string; method: string; headers: Record<string, string> };
let calls: Call[] = [];
let answer: (url: string) => Promise<any> = async () => ({});

(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", headers: init.headers ?? {} });
  const body = await answer(url);
  const status = url === "/api/auth/session" && body === null ? 401 : 200;
  return { ok: status < 400, status, statusText: "", json: async () => body };
};

const api = await import("../src/api.ts");

const SESSION = { csrf_token: "csrf-alice", tenant: { slug: "larkspur" }, user: {} };

beforeEach(async () => {
  calls = [];
  answer = async (url) => (url === "/api/auth/session" ? SESSION : url.startsWith("/api/auth/dev-login") ? { status: "signed_in" } : { who: "alice" });
  await api.getSession();
  await api.api("/identities");
  assert.deepEqual(api.cached("/identities"), { who: "alice" });
});

const lastCsrf = () => calls.at(-1)!.headers["x-tessera-csrf"];

test("sign-out clears the cache and the CSRF token", async () => {
  await api.logout();
  assert.equal(calls.at(-1)!.headers["x-tessera-csrf"], "csrf-alice"); // the logout itself is protected
  assert.equal(api.cached("/identities"), undefined);
  await api.api("/jit/sweep", {});
  assert.equal(lastCsrf(), undefined);
});

test("sign-in clears the cache and the CSRF token", async () => {
  await api.devLogin("larkspur", "00u-ivan-admin2", "passkey");
  assert.equal(api.cached("/identities"), undefined);
  assert.equal(lastCsrf(), undefined); // dev-login sends no previous session's token
  await api.api("/jit/sweep", {});
  assert.equal(lastCsrf(), undefined);
});

test("a session that ended on the server clears the cache and the CSRF token", async () => {
  answer = async () => null;
  assert.equal(await api.getSession(), null);
  assert.equal(api.cached("/identities"), undefined);
  await api.api("/jit/sweep", {}).catch(() => undefined);
  assert.equal(lastCsrf(), undefined);
});

test("a GET from the previous session does not refill the cache", async () => {
  let release!: () => void;
  answer = (url) => (url === "/api/reviews" ? new Promise((r) => (release = () => r({ who: "alice" }))) : Promise.resolve({}));
  const pending = api.api("/reviews");
  await new Promise((r) => setTimeout(r, 0));
  await api.logout();
  release();
  await pending;
  assert.equal(api.cached("/reviews"), undefined);
});
