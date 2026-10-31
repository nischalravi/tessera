// The GitHub App settings page (issue #771, AC-10): what is checked before a save, the body a save sends (only what changed, a
// blank private key left out so the stored one stays), the webhook URL, and that the API client never keeps a body that can carry
// the private key or the webhook secret for a step-up resume. Run with `npm test`.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

// Fake PEM blocks are built from parts so secret scanners do not read them as leaked keys.
const fakePEM = (label: string, body: string) => [`-----BEGIN ${label}`, `-----\n${body}\n-----END ${label}-----`].join("");

const mem = new Map<string, string>();
(globalThis as any).sessionStorage = {
  getItem: (k: string) => mem.get(k) ?? null,
  setItem: (k: string, v: string) => void mem.set(k, v),
  removeItem: (k: string) => void mem.delete(k),
};
const win = Object.assign(new EventTarget(), { location: { pathname: "/admin/github-app", search: "", assign() {} } });
(globalThis as any).window = win;
const calls: { url: string; method: string; body: unknown }[] = [];
let reply: { ok: boolean; status: number; body: unknown } = { ok: true, status: 200, body: {} };
(globalThis as any).fetch = async (url: string, init: { method: string; body?: string }) => {
  calls.push({ url, method: init.method, body: init.body ? JSON.parse(init.body) : undefined });
  return { ok: reply.ok, status: reply.status, statusText: "", json: async () => reply.body, text: async () => JSON.stringify(reply.body), headers: new Headers() };
};

const api = await import("../src/api.ts");
const model = await import("../src/features/admin/githubAppModel.ts");

const stored = (over: Partial<import("../src/api.ts").GitHubAppSettings> = {}): import("../src/api.ts").GitHubAppSettings => ({
  enabled: true, app_id: "4242", installation_id: 77, repo: "o/policy", key_set: true, key_fingerprint: "SHA256:abcdefghijklmnopqrstuvwxyz0123456789", key_set_at: "2026-01-01T00:00:00Z",
  updated_by: "ta@example.com", updated_at: "2026-01-01T00:00:00Z", api_base: "https://api.github.com", permissions: { checks: "write", pull_requests: "write" },
  contents_permissions: {}, webhook_path: "/public/t/acme/github/webhook", webhook_secret_set: true, webhook_secret_set_at: "2026-01-02T00:00:00Z", ...over,
});

beforeEach(() => { mem.clear(); calls.length = 0; reply = { ok: true, status: 200, body: {} }; });

test("the form starts from what is stored and never from the key", () => {
  const f = model.formOf(stored());
  assert.deepEqual(f, { enabled: true, appId: "4242", installationId: "77", repo: "o/policy", privateKey: "" });
  assert.equal(model.formOf(stored({ installation_id: 0, app_id: "", repo: "" })).installationId, "");
});

test("fields are checked before a save, and enabling needs all of them and a key", () => {
  const ok = model.formOf(stored());
  assert.deepEqual(model.checkForm(ok, true), {});
  assert.ok(model.checkForm({ ...ok, appId: "12a" }, true).appId);
  assert.ok(model.checkForm({ ...ok, installationId: "0" }, true).installationId);
  assert.ok(model.checkForm({ ...ok, installationId: "-3" }, true).installationId);
  assert.ok(model.checkForm({ ...ok, repo: "just-a-name" }, true).repo);
  assert.ok(model.checkForm({ ...ok, repo: "o/../x" }, true).repo);
  assert.ok(model.checkForm({ ...ok, privateKey: "hello" }, true).privateKey);
  assert.equal(model.checkForm({ ...ok, privateKey: fakePEM("RSA PRIVATE KEY", "AAAA") }, true).privateKey, undefined);
  assert.equal(model.checkForm({ ...ok, privateKey: fakePEM("PRIVATE KEY", "AAAA") }, false).privateKey, undefined);
  // enabling with a gap
  const empty = model.formOf(stored({ app_id: "", installation_id: 0, repo: "", key_set: false }));
  const e = model.checkForm({ ...empty, enabled: true }, false);
  assert.deepEqual(Object.keys(e).sort(), ["appId", "installationId", "privateKey", "repo"]);
  assert.deepEqual(model.checkForm({ ...empty, enabled: false }, false), {}, "a switched-off App may be half filled in");
});

test("a save sends only what changed, and a blank private key stays out", () => {
  const s = stored();
  const f = model.formOf(s);
  assert.deepEqual(model.inputOf(f, s), { enabled: true });
  assert.equal(model.changed(f, s), false);
  assert.deepEqual(model.inputOf({ ...f, repo: " o/other " }, s), { enabled: true, repo: "o/other" });
  assert.deepEqual(model.inputOf({ ...f, installationId: "78", enabled: false }, s), { enabled: false, installation_id: 78 });
  const pem = fakePEM("PRIVATE KEY", "x");
  const withKey = { ...f, privateKey: `  ${pem}\n` };
  assert.equal(model.inputOf(withKey, s).private_key, pem);
  assert.equal(model.changed(withKey, s), true);
  assert.equal(model.changed({ ...f, enabled: false }, s), true);
});

test("the webhook URL is the Tessera address and the tenant's path", () => {
  assert.equal(model.webhookURL("https://tessera.example.com", "/public/t/acme/github/webhook"), "https://tessera.example.com/public/t/acme/github/webhook");
  assert.equal(model.webhookURL("https://tessera.example.com/", "/public/t/acme/github/webhook"), "https://tessera.example.com/public/t/acme/github/webhook");
  assert.equal(model.shortFingerprint("SHA256:abcdefghijklmnopqrstuvwxyz0123456789"), "SHA256:abcdefghijklmnopq…");
  assert.equal(model.shortFingerprint(""), "");
});

test("the client reads and saves through /policy/github/app and never keeps the body for a resume", async () => {
  reply = { ok: true, status: 200, body: stored() };
  const got = await api.githubApp.get();
  assert.equal(got.webhook_secret_set, true);
  assert.equal(calls[0].url, "/api/policy/github/app");
  assert.equal(calls[0].method, "GET");

  reply = { ok: true, status: 200, body: stored({ webhook_secret: "whsec_once" }) };
  const saved = await api.githubApp.save({ enabled: true, rotate_webhook_secret: true });
  assert.equal(saved.webhook_secret, "whsec_once");
  assert.equal(calls[1].method, "PUT");
  assert.deepEqual(calls[1].body, { enabled: true, rotate_webhook_secret: true });

  // a step-up refusal on a body that carries the key or the secret is not kept in browser storage
  reply = { ok: false, status: 401, body: { error: "step_up_required", acr: "urn:tessera:acr:phr", max_age: 900, step_up_url: "/api/auth/step-up" } };
  await assert.rejects(api.githubApp.save({ enabled: true, private_key: fakePEM("PRIVATE KEY", "secret-material") }));
  await assert.rejects(api.githubApp.save({ enabled: true, rotate_webhook_secret: true }));
  assert.equal(mem.size, 0, [...mem.values()].join());
  assert.equal(api.takePendingAction(), null);
});
