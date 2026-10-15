// Break-glass in the UI (design §9.6, §15.4): the base64url conversions between go-webauthn's JSON and
// the browser's WebAuthn API, which address is the break-glass sign-in, and what the banner and the
// session notice say. The API enforces the rules; this checks the glue and the wording. Run with `npm test`.
import assert from "node:assert/strict";
import { test } from "node:test";
import type { BreakGlassUse } from "../src/api.ts";
import { breakGlassSlug, inBreakGlassSession, minutesLeft, sessionNotice, unexplainedItems } from "../src/features/admin/breakGlassState.ts";
import { b64uToBytes, bytesToB64u, ceremonyMessage, creationOptions, requestOptions } from "../src/features/admin/webauthn.ts";

test("base64url round-trips every byte value, without padding", () => {
  const all = new Uint8Array(256).map((_, i) => i);
  const s = bytesToB64u(all);
  assert.match(s, /^[A-Za-z0-9_-]+$/);
  assert.deepEqual([...b64uToBytes(s)], [...all]);
  assert.equal(bytesToB64u(new Uint8Array([0xfb, 0xff])), "-_8");
  assert.deepEqual([...b64uToBytes("-_8")], [0xfb, 0xff]);
  assert.deepEqual([...b64uToBytes("-_8=")].length, 2); // padding is tolerated
  assert.equal(bytesToB64u(new Uint8Array()), "");
  assert.deepEqual([...b64uToBytes("")], []);
  assert.throws(() => b64uToBytes("a+b/"), /base64url/);
  assert.throws(() => b64uToBytes("not base64!"), /base64url/);
});

test("an ArrayBuffer encodes like the bytes it holds", () => {
  const bytes = new Uint8Array([1, 2, 3, 250]);
  assert.equal(bytesToB64u(bytes.buffer), bytesToB64u(bytes));
});

const challenge = bytesToB64u(new Uint8Array(32).fill(7));
const credId = bytesToB64u(new Uint8Array(16).fill(9));

test("creation options decode the challenge, the user handle and the excluded keys", () => {
  const o = creationOptions({ publicKey: { challenge, rp: { id: "tessera.example.com", name: "Tessera" },
    user: { id: bytesToB64u(new Uint8Array(16).fill(3)), name: "Break-glass: Safe A", displayName: "Break-glass: Safe A" },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }], timeout: 300000, attestation: "direct",
    authenticatorSelection: { authenticatorAttachment: "cross-platform", residentKey: "discouraged", userVerification: "required" },
    excludeCredentials: [{ id: credId, type: "public-key", transports: ["usb"] }] } });
  assert.deepEqual([...(o.challenge as Uint8Array)], new Array(32).fill(7));
  assert.deepEqual([...(o.user.id as Uint8Array)], new Array(16).fill(3));
  assert.equal(o.user.name, "Break-glass: Safe A");
  assert.equal(o.attestation, "direct");
  assert.equal(o.authenticatorSelection?.userVerification, "required");
  assert.equal(o.authenticatorSelection?.authenticatorAttachment, "cross-platform");
  assert.equal(o.excludeCredentials?.length, 1);
  assert.deepEqual([...(o.excludeCredentials![0].id as Uint8Array)], new Array(16).fill(9));
  assert.deepEqual(o.excludeCredentials![0].transports, ["usb"]);
});

test("request options decode the challenge and the allowed keys, and need none to be listed", () => {
  const o = requestOptions({ publicKey: { challenge, rpId: "tessera.example.com", userVerification: "required",
    allowCredentials: [{ id: credId, type: "public-key" }, { id: credId, type: "public-key", transports: ["usb", "nfc"] }] } });
  assert.deepEqual([...(o.challenge as Uint8Array)], new Array(32).fill(7));
  assert.equal(o.rpId, "tessera.example.com");
  assert.equal(o.userVerification, "required");
  assert.equal(o.allowCredentials?.length, 2);
  assert.deepEqual([...(o.allowCredentials![1].id as Uint8Array)], new Array(16).fill(9));
  assert.equal(requestOptions({ publicKey: { challenge } }).allowCredentials?.length, 0);
});

test("a challenge that is not base64url is refused rather than guessed", () => {
  assert.throws(() => requestOptions({ publicKey: { challenge: "not base64url!" } }), /base64url/);
});

test("the break-glass sign-in page is /t/<slug>/break-glass and nothing else", () => {
  assert.equal(breakGlassSlug("/t/larkspur/break-glass"), "larkspur");
  assert.equal(breakGlassSlug("/t/larkspur/break-glass/"), "larkspur");
  assert.equal(breakGlassSlug("/t/acme-2/break-glass"), "acme-2");
  for (const p of ["/", "/login", "/admin/break-glass", "/t/larkspur", "/t/larkspur/bootstrap", "/t/Larkspur/break-glass", "/t//break-glass",
    "/t/a b/break-glass", "/t/larkspur/break-glass/x", "/x/t/larkspur/break-glass", "/t/" + "a".repeat(64) + "/break-glass"]) {
    assert.equal(breakGlassSlug(p), null, p);
  }
});

test("a session is a break-glass session when break_glass is its active role", () => {
  assert.equal(inBreakGlassSession({ active_roles: ["break_glass"] }), true);
  assert.equal(inBreakGlassSession({ active_roles: ["tenant_admin"] }), false);
  assert.equal(inBreakGlassSession({ active_roles: [] }), false);
});

const NOW = Date.parse("2026-10-08T09:30:00Z");
const session = (absolute: string) => ({ session: { id: "s", idle_expires_at: absolute, absolute_expires_at: absolute } });

test("the session notice counts the minutes left and says what the session can do", () => {
  assert.equal(minutesLeft("2026-10-08T10:30:00Z", NOW), 60);
  assert.equal(minutesLeft("2026-10-08T09:30:01Z", NOW), 1);
  assert.equal(minutesLeft("2026-10-08T09:00:00Z", NOW), 0);
  const n = sessionNotice(session("2026-10-08T10:10:00Z"), NOW);
  assert.match(n, /ends in 40 minutes/);
  assert.match(n, /15 idle minutes/);
  assert.match(n, /disable an IdP connection/);
  assert.match(n, /revoke other sessions/);
  assert.match(n, /one hour/);
  assert.match(sessionNotice(session("2026-10-08T09:30:30Z"), NOW), /ends in 1 minute /);
});

const use = (o: Partial<BreakGlassUse>): BreakGlassUse => ({ id: "u1", session_id: "s1", credential_id: "k1", key: "Safe A, key 1",
  used_at: "2026-10-07T21:05:00Z", ip: "203.0.113.9", answered: false, answered_at: null, answered_by: null, reason: null, ...o });

test("the banner lists the sign-ins nobody explained, newest first, and drops the explained ones", () => {
  const items = unexplainedItems([
    use({ id: "old", used_at: "2026-10-01T08:00:00Z" }),
    use({ id: "done", answered: true, reason: "Okta outage INC-1", used_at: "2026-10-05T08:00:00Z" }),
    use({ id: "new", used_at: "2026-10-07T21:05:00Z" }),
  ]);
  assert.deepEqual(items.map((i) => i.id), ["break-glass:new", "break-glass:old"]);
  assert.equal(items[0].tone, "bad");
  assert.equal(items[0].to, "/admin/break-glass");
  assert.match(items[0].text, /Safe A, key 1/);
  assert.match(items[0].text, /2026-10-07 at 21:05 UTC from 203\.0\.113\.9/);
  assert.match(items[0].text, /Say why it was used/);
  assert.deepEqual(unexplainedItems([]), []);
  assert.doesNotMatch(unexplainedItems([use({ ip: null })])[0].text, /from /);
});

test("the browser's refusals are explained in plain words", () => {
  assert.match(ceremonyMessage({ name: "NotAllowedError" }), /cancelled or timed out/);
  assert.match(ceremonyMessage({ name: "InvalidStateError" }), /already registered/);
  assert.match(ceremonyMessage({ name: "NotSupportedError" }), /PIN or fingerprint/);
  assert.match(ceremonyMessage({ name: "SecurityError" }), /own Tessera address/);
  assert.equal(ceremonyMessage(new Error("boom")), "boom");
});
