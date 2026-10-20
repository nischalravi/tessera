// The guest claim page's model and client (issue #69): the claim link's token is read from the
// fragment only, every request is signed with the page's non-extractable key and carries no admin
// CSRF token, and the token never appears in a URL. The page itself is checked by hand (see the
// "Guest claim" section of mvp/README.md); everything it decides is here. Run with `npm test`.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

(globalThis as any).window = new EventTarget();

type Call = { url: string; method: string; headers: Record<string, string>; body: any; credentials?: string };
let calls: Call[] = [];
let reply: { status: number; body: any } = { status: 200, body: {} };

(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", headers: init.headers ?? {}, body: init.body ? JSON.parse(init.body) : undefined, credentials: init.credentials });
  return { ok: reply.status < 400, status: reply.status, statusText: "", json: async () => reply.body };
};

const api = await import("../src/api.ts");
const model = await import("../src/public/claim/model.ts");
const proof = await import("../src/public/claim/proof.ts");
const guestModel = await import("../src/features/access/guestModel.ts");

const TOKEN = "A".repeat(20) + "b-_".repeat(5) + "Zzz9Y8xQ";
beforeEach(() => {
  calls = [];
  reply = { status: 200, body: {} };
});

test("the token is read from the fragment, and only a well-formed one", () => {
  assert.equal(TOKEN.length, 43);
  assert.equal(model.tokenFromHash(`#t=${TOKEN}`), TOKEN);
  assert.equal(model.tokenFromHash(`t=${TOKEN}`), TOKEN);
  assert.equal(model.tokenFromHash(`#x=1&t=${TOKEN}`), TOKEN);
  for (const bad of ["", "#", "#t=", "#t=short", `#t=${TOKEN}A`, `#t=${TOKEN.slice(1)}!`, `#token=${TOKEN}`, `#u=${TOKEN}`]) {
    assert.equal(model.tokenFromHash(bad), null, bad);
  }
});

test("the tenant comes from the build, the host or the demo default", () => {
  assert.equal(model.tenantSlug("localhost"), "larkspur");
  assert.equal(model.tenantSlug("127.0.0.1"), "larkspur");
  assert.equal(model.tenantSlug("acme.tessera.example"), "acme");
  assert.equal(model.tenantSlug("www.tessera.example"), "larkspur");
  assert.equal(model.tenantSlug("tessera.example"), "larkspur");
  assert.equal(model.tenantSlug("acme.tessera.example", "globex"), "globex");
  assert.equal(model.tenantSlug("localhost", "Bad Slug!"), "larkspur");
});

const status = (over: object = {}) => ({
  step: "verify_contact", steps: ["verify_contact", "verify_identity", "existing_account", "credential", "complete"], first_name: "Gwen",
  tenant: "Larkspur Labs", sponsor: "Sam", population: "visitor", ends_at: "2026-10-20T00:00:00Z", pending: "", complete: false, ...over,
});

test("which screen a status calls for", () => {
  assert.deepEqual(model.viewOf(status() as any), { kind: "step", step: "verify_contact" });
  assert.deepEqual(model.viewOf(status({ step: "credential", pending: "organization" }) as any), { kind: "step", step: "credential" });
  assert.deepEqual(model.viewOf(status({ step: "verify_identity", pending: "identity_verification" }) as any), { kind: "waiting", why: "identity_verification" });
  assert.deepEqual(model.viewOf(status({ step: "complete", complete: true }) as any), { kind: "complete" });
  // identity verification is only a step when it is the open one; the list stays extensible
  assert.deepEqual(model.visibleSteps(status() as any), ["verify_contact", "existing_account", "credential", "complete"]);
  assert.equal(model.stepIndex(status({ step: "existing_account" }) as any), 1);
  assert.equal(model.resultFromSearch("?result=failed"), "failed");
  assert.equal(model.resultFromSearch("?result=complete"), "complete");
  assert.equal(model.resultFromSearch("?result=<script>"), null);
});

test("a confirmation code is six digits, however it was typed", () => {
  assert.equal(model.normalizeCode("123 456"), "123456");
  assert.equal(model.normalizeCode("12-34-56-78"), "123456");
  assert.equal(model.codeReady("12345"), false);
  assert.equal(model.codeReady(" 123456 "), true);
  assert.equal(model.emailOk("a@b.example"), true);
  assert.equal(model.emailOk("a b@c"), false);
});

test("a proof is a signature by the page's key over the request, in the server's format", async () => {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])) as CryptoKeyPair;
  assert.equal(pair.privateKey.extractable, false);
  const jwk = await proof.publicJwk(pair);
  assert.deepEqual(Object.keys(jwk).sort(), ["crv", "kty", "x", "y"]);
  assert.equal(jwk.kty, "EC");
  assert.equal(jwk.crv, "P-256");
  const now = Date.UTC(2026, 9, 8, 9, 30, 0);
  const body = JSON.stringify({ code: "123456" });
  const p = await proof.makeProof(pair.privateKey, "POST", "/public/t/larkspur/claim/verify/check", "nonce-123", body, now);
  const [secs, sig] = p.split(".");
  assert.equal(secs, String(Math.floor(now / 1000)));
  const raw = Uint8Array.from(atob(sig.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (sig.length % 4)) % 4)), (c) => c.charCodeAt(0));
  assert.equal(raw.length, 64, "r||s");
  // the body's digest: base64url(SHA-256(body)), as the server's claim.BodyHash
  const digest = await proof.bodyHash(body);
  assert.equal(digest, proof.b64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body))));
  assert.equal(await proof.bodyHash(""), "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU", "the empty body has a digest too");
  const message = "tessera-claim-proof-v2\nPOST\n/public/t/larkspur/claim/verify/check\n" + secs + "\nnonce-123\n" + digest;
  assert.equal(proof.proofMessage("POST", "/public/t/larkspur/claim/verify/check", Number(secs), "nonce-123", digest), message);
  const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pair.publicKey, raw, new TextEncoder().encode(message));
  assert.ok(ok, "the signature verifies");
  const other = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pair.publicKey, raw, new TextEncoder().encode(message.replace("POST", "GET")));
  assert.equal(other, false);
  const otherBody = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pair.publicKey, raw,
    new TextEncoder().encode(message.replace(digest, await proof.bodyHash(JSON.stringify({ code: "654321" })))));
  assert.equal(otherBody, false, "the proof is bound to the body");
  // randomized: the same request signed twice is two different proofs (the server refuses a repeat)
  assert.notEqual(p, await proof.makeProof(pair.privateKey, "POST", "/public/t/larkspur/claim/verify/check", "nonce-123", body, now));
});

const signer = { sign: async (m: string, p: string, n: string, b: string) => `proof(${m} ${p} ${n} ${b})` };

test("start sends the token in the body, signed, with no admin session assumptions", async () => {
  reply = { status: 200, body: { next: "verify_contact", nonce: "n1", status: status() } };
  const jwk = { kty: "EC", crv: "P-256", x: "x", y: "y" };
  const r = await api.claimApi.start("larkspur", TOKEN, jwk, signer);
  assert.equal(r.next, "verify_contact");
  assert.equal(calls.length, 1);
  const c = calls[0];
  assert.equal(c.method, "POST");
  assert.equal(c.url, "/public/t/larkspur/claim/start");
  assert.deepEqual(c.body, { token: TOKEN, key: jwk });
  assert.equal(c.headers["x-claim-proof"], `proof(POST /public/t/larkspur/claim/start  ${JSON.stringify({ token: TOKEN, key: jwk })})`, "the proof covers the exact body sent");
  assert.equal(c.headers["x-tessera-csrf"], undefined);
  assert.equal(c.credentials, "same-origin");
  assert.ok(!c.url.includes(TOKEN), "the token is never in the URL");
});

test("every session call is signed with its own method, path and the session's nonce", async () => {
  reply = { status: 200, body: {} };
  await api.claimApi.status("larkspur", signer, "n1");
  await api.claimApi.sendCode("larkspur", signer, "n1");
  await api.claimApi.checkCode("larkspur", signer, "n1", "123456");
  await api.claimApi.existingAccount("larkspur", signer, "n1", "no");
  await api.claimApi.credential("larkspur", signer, "n1");
  assert.deepEqual(calls.map((c) => [c.method, c.url, c.body, c.headers["x-claim-proof"]]), [
    ["GET", "/public/t/larkspur/claim/status", undefined, "proof(GET /public/t/larkspur/claim/status n1 )"],
    ["POST", "/public/t/larkspur/claim/verify/send", undefined, "proof(POST /public/t/larkspur/claim/verify/send n1 )"],
    ["POST", "/public/t/larkspur/claim/verify/check", { code: "123456" }, `proof(POST /public/t/larkspur/claim/verify/check n1 ${JSON.stringify({ code: "123456" })})`],
    ["POST", "/public/t/larkspur/claim/existing-account", { answer: "no" }, `proof(POST /public/t/larkspur/claim/existing-account n1 ${JSON.stringify({ answer: "no" })})`],
    ["POST", "/public/t/larkspur/claim/credential", undefined, "proof(POST /public/t/larkspur/claim/credential n1 )"],
  ]);
  assert.ok(calls.every((c) => c.headers["x-tessera-csrf"] === undefined));
  assert.equal(api.claimPath("a b/c", "status"), "/public/t/a%20b%2Fc/claim/status");
});

test("errors are plain language and carry the API's code", async () => {
  reply = { status: 401, body: { error: "session_required" } };
  await assert.rejects(api.claimApi.status("larkspur", signer, "n1"), (e: any) => e instanceof api.ClaimError && e.status === 401 && e.code === "session_required" && /new one/.test(e.message));
  reply = { status: 422, body: { error: "code_invalid", message: "That code did not work. Check it, or ask for a new one." } };
  await assert.rejects(api.claimApi.checkCode("larkspur", signer, "n1", "000000"), (e: any) => e.code === "code_invalid" && /did not work/.test(e.message));
  reply = { status: 429, body: { error: "rate_limited" } };
  await assert.rejects(api.claimApi.sendCode("larkspur", signer, "n1"), (e: any) => /Too many/.test(e.message));
});

test("asking for a new link needs no session and says nothing about whether one exists", async () => {
  reply = { status: 200, body: { message: "If an invitation exists for this address, we have sent a new link." } };
  assert.match(await api.claimResend("larkspur", "g@x.example"), /If an invitation exists/);
  assert.equal(calls[0].url, "/public/t/larkspur/claim/resend");
  assert.deepEqual(calls[0].body, { email: "g@x.example" });
  assert.equal(calls[0].headers["x-claim-proof"], undefined);
});

test("the sponsor's invitation calls and wording", async () => {
  await api.guests.resendInvitation(7);
  await api.guests.revokeInvitation(7);
  assert.deepEqual(calls.map((c) => [c.method, c.url, c.body]), [
    ["POST", "/api/guests/7/resend-invitation", {}],
    ["POST", "/api/guests/7/revoke-invitation", {}],
  ]);
  const fmt = (s: string) => `<${s}>`;
  assert.match(guestModel.invitationNote({ invitation: "sent", invitation_expires_at: "2026-10-15T00:00:00Z" }, fmt), /works until <2026-10-15T00:00:00Z>/);
  assert.match(guestModel.invitationNote({ invitation: "expired", invitation_expires_at: null }, fmt), /Send a new one/);
  for (const k of Object.keys(guestModel.INVITATION_LABEL)) assert.ok(guestModel.INVITATION_TONE[k as keyof typeof guestModel.INVITATION_TONE], k);
});
