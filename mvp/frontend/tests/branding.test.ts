// Admin > Branding and Certificates clients: the contrast rule (the same one the API enforces), the CSS a
// branded public page sets, and the routes, verbs and bodies of the certificate and branding calls.
// Run with `npm test`.
import assert from "node:assert/strict";
import { test } from "node:test";

(globalThis as any).window = new EventTarget();

const calls: { url: string; method: string; body: any }[] = [];
let reply: { ok: boolean; status: number; body: any } = { ok: true, status: 200, body: {} };
(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", body: init.body ? JSON.parse(init.body) : undefined });
  return { ok: reply.ok, status: reply.status, statusText: "", json: async () => reply.body };
};

const api = await import("../src/api.ts");
const b = await import("../src/branding.ts");

test("contrast follows WCAG", () => {
  assert.ok(Math.abs(b.contrast("#000000", "#ffffff") - 21) < 0.01);
  assert.ok(Math.abs(b.contrast("#ffffff", "#ffffff") - 1) < 0.001);
  assert.ok(b.contrast("#0f6cbd", "#ffffff") >= b.MIN_CONTRAST);
});

test("the automatic text colour is the more readable of white and black", () => {
  assert.equal(b.bestOn("#1a1a1a"), "#ffffff");
  assert.equal(b.bestOn("#ffe08a"), "#000000");
  for (const c of ["#ff8800", "#808080", "#00aa55", "#cc3366"]) assert.ok(b.contrast(c, b.bestOn(c)) >= b.MIN_CONTRAST, c);
});

test("a pair below AA is refused with the contrast and a colour that works", () => {
  assert.equal(b.pairProblem("#0f6cbd", "#ffffff"), null);
  assert.equal(b.pairProblem("#ffe08a", ""), null);
  const p = b.pairProblem("#ffe08a", "#ffffff");
  assert.ok(p && p.includes("#000000") && p.includes(":1"));
  assert.ok(b.pairProblem("red", "#ffffff"));
  assert.ok(b.pairProblem("#0f6cbd", "white"));
});

test("a branded page sets only the button colours, and only for a pair that passes", () => {
  const ok = b.brandStyle({ configured: true, primary_color: "#0f6cbd", on_primary_color: "#ffffff" })!;
  assert.deepEqual(Object.keys(ok).sort(), ["--accent", "--accent-hover", "--on-accent"]);
  assert.equal(ok["--accent"], "#0f6cbd");
  assert.ok(b.contrast(ok["--accent-hover"], ok["--on-accent"]) >= b.MIN_CONTRAST, "hover keeps its contrast");
  const light = b.brandStyle({ configured: true, primary_color: "#ffe08a", on_primary_color: "#000000" })!;
  assert.ok(b.contrast(light["--accent-hover"], light["--on-accent"]) >= b.MIN_CONTRAST, "hover keeps its contrast on a light colour");
  assert.equal(b.brandStyle({ configured: false, primary_color: "#0f6cbd", on_primary_color: "#ffffff" }), undefined);
  assert.equal(b.brandStyle({ configured: true, primary_color: "#ffe08a", on_primary_color: "#ffffff" }), undefined);
  assert.equal(b.brandStyle({ configured: true, primary_color: "javascript:", on_primary_color: "#ffffff" }), undefined);
  assert.equal(b.brandStyle(null), undefined);
});

test("certificate calls", async () => {
  await api.certificatesApi.upload({ purpose: "mtls_client", label: "Workday", certificate_pem: "C", private_key_pem: "K" });
  assert.deepEqual(calls.at(-1), { url: "/api/admin/certificates", method: "POST", body: { purpose: "mtls_client", label: "Workday", certificate_pem: "C", private_key_pem: "K" } });
  await api.certificatesApi.generate("conn-1");
  assert.deepEqual(calls.at(-1), { url: "/api/admin/certificates/generate", method: "POST", body: { connection_id: "conn-1" } });
  await api.certificatesApi.promote("cert:abc");
  assert.equal(calls.at(-1)!.url, "/api/admin/certificates/abc/promote");
  await api.certificatesApi.retire("cert:a/b");
  assert.equal(calls.at(-1)!.url, "/api/admin/certificates/a%2Fb/retire");
  assert.equal(api.certificateRowId("cert:xyz"), "xyz");
  for (const p of ["saml_sp", "mtls_client", "signing", "encryption"] as const) assert.ok(api.PURPOSE_LABEL[p]);
});

test("a private key is never kept for resuming after a step-up", async () => {
  const store = new Map<string, string>();
  (globalThis as any).sessionStorage = { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => store.set(k, v), removeItem: (k: string) => store.delete(k) };
  reply = { ok: false, status: 401, body: { error: "step_up_required" } };
  await assert.rejects(api.certificatesApi.upload({ purpose: "signing", label: "x", certificate_pem: "C", private_key_pem: "SECRET-KEY" }));
  assert.ok(![...store.values()].some((v) => v.includes("SECRET-KEY")), "the key reached browser storage");
  reply = { ok: true, status: 200, body: {} };
});

test("branding calls", async () => {
  await api.brandingApi.save({ display_name: "Larkspur", primary_color: "#0f6cbd", remove_logo: true });
  assert.deepEqual(calls.at(-1), { url: "/api/admin/branding", method: "PUT", body: { display_name: "Larkspur", primary_color: "#0f6cbd", remove_logo: true } });
  reply = { ok: true, status: 200, body: { name: "Larkspur", configured: true, primary_color: "#0f6cbd", on_primary_color: "#ffffff", logo_url: null } };
  const pb = await api.publicBranding("larkspur");
  assert.equal(calls.at(-1)!.url, "/api/auth/branding?tenant=larkspur");
  assert.equal(pb?.name, "Larkspur");
  reply = { ok: false, status: 500, body: {} };
  assert.equal(await api.publicBranding("larkspur"), null, "a failure falls back to the default page");
  reply = { ok: true, status: 200, body: {} };
});

test("console branding keeps the default accent when the colour fails contrast in the theme in use", async () => {
  const cb = await import("../src/branding.ts");
  const mk = (primary: string, on: string, configured = true) => ({ name: "Acme", configured, primary_color: primary, on_primary_color: on, logo_url: null });
  // a strong blue passes in both themes
  for (const t of ["light", "dark"] as const) assert.equal(cb.consoleBrandStyle(mk("#0f6cbd", "#ffffff"), t)?.["--accent"], "#0f6cbd");
  // near-white fails against the light surface, passes on dark; near-black the reverse
  assert.equal(cb.consoleBrandStyle(mk("#fff3b0", "#000000"), "light"), undefined);
  assert.ok(cb.consoleBrandStyle(mk("#fff3b0", "#000000"), "dark"));
  assert.ok(cb.consoleBrandStyle(mk("#111111", "#ffffff"), "light"));
  assert.equal(cb.consoleBrandStyle(mk("#111111", "#ffffff"), "dark"), undefined);
  // a failing text pair, an unconfigured tenant and no branding all keep the default
  assert.equal(cb.consoleBrandStyle(mk("#0f6cbd", "#0f6cbe"), "light"), undefined);
  assert.equal(cb.consoleBrandStyle(mk("#0f6cbd", "#ffffff", false), "light"), undefined);
  assert.equal(cb.consoleBrandStyle(null, "light"), undefined);
});

test("the product name is the saved one only when branding is configured", async () => {
  const cb = await import("../src/branding.ts");
  const b = { name: " Acme ", configured: true, primary_color: "#0f6cbd", on_primary_color: "#ffffff", logo_url: null };
  assert.equal(cb.productName(b), "Acme");
  assert.equal(cb.productName({ ...b, configured: false }), "Tessera");
  assert.equal(cb.productName(null), "Tessera");
});
