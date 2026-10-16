// Agent authorization client calls (issue #115): every call goes through api(), with the session's
// CSRF token on state changes, the paths and methods the API registers, and the browser is only
// ever sent to a client redirect that is https or on the user's own machine. Run with `npm test`.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

(globalThis as any).window = new EventTarget();

type Call = { url: string; method: string; headers: Record<string, string>; body: any };
let calls: Call[] = [];

(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", headers: init.headers ?? {}, body: init.body ? JSON.parse(init.body) : undefined });
  const body = url === "/api/auth/session" ? { csrf_token: "csrf-mcp", tenant: { slug: "larkspur" }, user: {} } : {};
  return { ok: true, status: 200, statusText: "", json: async () => body };
};

const api = await import("../src/api.ts");

beforeEach(async () => {
  await api.getSession();
  calls = [];
});

test("changes send method, path, body and CSRF", async () => {
  await api.mcpAuthz.registerClient("https://client.example/agent.json");
  await api.mcpAuthz.updateClient("c 1", { agent_identity_id: 7, status: "active" });
  await api.mcpAuthz.createResource("https://mcp.example/mcp", "mcp");
  await api.mcpAuthz.updateResource("r/1", "disabled");
  await api.mcpAuthz.revokeToken("j 1");
  await api.mcpAuthz.decide("a/1", true);
  assert.deepEqual(
    calls.map((c) => [c.method, c.url, c.body, c.headers["x-tessera-csrf"]]),
    [
      ["POST", "/api/mcp/clients", { client_id: "https://client.example/agent.json" }, "csrf-mcp"],
      ["PUT", "/api/mcp/clients/c%201", { agent_identity_id: 7, status: "active" }, "csrf-mcp"],
      ["POST", "/api/mcp/resources", { resource: "https://mcp.example/mcp", name: "mcp" }, "csrf-mcp"],
      ["PUT", "/api/mcp/resources/r%2F1", { status: "disabled" }, "csrf-mcp"],
      ["POST", "/api/mcp/tokens/j%201/revoke", {}, "csrf-mcp"],
      ["POST", "/api/mcp/authorizations/a%2F1/decision", { approve: true }, "csrf-mcp"],
    ],
  );
});

test("the consent request is a GET with no body", async () => {
  await api.mcpAuthz.consent("abc");
  assert.equal(calls[0].method, "GET");
  assert.equal(calls[0].url, "/api/mcp/authorizations/abc");
  assert.equal(calls[0].body, undefined);
});

test("the browser is sent only to https or local redirects", () => {
  for (const ok of ["https://client.example/cb?code=1", "http://localhost:8123/cb", "http://127.0.0.1:9/cb"]) assert.ok(api.safeRedirect(ok), ok);
  for (const bad of ["javascript:alert(1)", "data:text/html,x", "http://client.example/cb", "//client.example/cb", "/relative", "", "ftp://x/y", "http://localhost.evil.example/cb"]) {
    assert.ok(!api.safeRedirect(bad), bad);
  }
});
