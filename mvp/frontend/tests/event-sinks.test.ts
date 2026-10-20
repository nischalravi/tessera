// Group event sink client calls (issue #61, GR-18): each call is the method and path the API registers,
// carries the session's CSRF token, and credentials travel only in the request body. Run with `npm test`.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

(globalThis as any).window = new EventTarget();

type Call = { url: string; method: string; headers: Record<string, string>; body: any };
let calls: Call[] = [];

(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", headers: init.headers ?? {}, body: init.body ? JSON.parse(init.body) : undefined });
  const body = url === "/api/auth/session" ? { csrf_token: "csrf-sinks", tenant: { slug: "larkspur" }, user: {} } : { id: "s1" };
  return { ok: true, status: 200, statusText: "", json: async () => body };
};

const api = await import("../src/api.ts");

beforeEach(async () => {
  await api.getSession();
  calls = [];
});

test("sink calls use the registered methods and paths", async () => {
  await api.groupSinks.create({ name: "siem", kind: "kafka", config: { brokers: ["k:9093"], topic: "t", sasl: "plain" }, credentials: { username: "u", password: "p" },
    event_types: ["membership."], enabled: true, from: "now" });
  await api.groupSinks.patch("s1", { enabled: false });
  await api.groupSinks.redeliver("s1", 7);
  await api.groupSinks.discard("s1", 8);
  await api.groupSinks.remove("s1");
  assert.deepEqual(
    calls.map((c) => [c.method, c.url]),
    [
      ["POST", "/api/groups/event-sinks"],
      ["PATCH", "/api/groups/event-sinks/s1"],
      ["POST", "/api/groups/event-sinks/s1/dead-letters/7/redeliver"],
      ["POST", "/api/groups/event-sinks/s1/dead-letters/8/discard"],
      ["DELETE", "/api/groups/event-sinks/s1"],
    ],
  );
  assert.deepEqual(calls[0].body.credentials, { username: "u", password: "p" });
  assert.deepEqual(calls[1].body, { enabled: false }, "a patch without credentials leaves the stored ones alone");
  for (const c of calls) assert.equal(c.headers["x-tessera-csrf"], "csrf-sinks", `${c.method} ${c.url} carries the CSRF token`);
});

test("the dead letter list asks for every status, bounded", () => {
  assert.equal(api.groupSinks.deadLettersPath("s1"), "/groups/event-sinks/s1/dead-letters?status=all&limit=100");
});
