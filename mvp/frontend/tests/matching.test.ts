// Identity matching client calls (issue #68): each decision is a state-changing request with the
// session's CSRF token, the path the API registers (an action is a path segment, never a colon),
// and the reason in the body. A merge that needs a second reviewer answers 202 with a request,
// which the client tells apart from a merge. Run with `npm test`.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

(globalThis as any).window = new EventTarget();

type Call = { url: string; method: string; headers: Record<string, string>; body: any };
let calls: Call[] = [];
let reply: any = {};

(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", headers: init.headers ?? {}, body: init.body ? JSON.parse(init.body) : undefined });
  const body = url === "/api/auth/session" ? { csrf_token: "csrf-pat", tenant: { slug: "larkspur" }, user: {} } : reply;
  return { ok: true, status: 200, statusText: "", json: async () => body };
};

const api = await import("../src/api.ts");
const claim = await import("../src/public/claim/model.ts");

beforeEach(async () => {
  await api.getSession();
  calls = [];
  reply = {};
});

test("decisions and approvals send method, path, body and CSRF", async () => {
  await api.decideIdentityMatch("m 1/x", "link", "same person");
  await api.decideIdentityMatch("m2", "new_person", "a different Bob");
  await api.decideIdentityMatch("m3", "reject", "fraud");
  await api.approveMergeRequest("r/1");
  await api.rejectMergeRequest("r/1", "not the same");
  await api.putMatchingSettings({ auto_link_tier_b: true, require_review_tier_a: false, unmerge_window_days: 30 });
  assert.deepEqual(
    calls.map((c) => [c.method, c.url, c.body]),
    [
      ["POST", "/api/identity-matches/m%201%2Fx/decide", { decision: "link", reason: "same person" }],
      ["POST", "/api/identity-matches/m2/decide", { decision: "new_person", reason: "a different Bob" }],
      ["POST", "/api/identity-matches/m3/decide", { decision: "reject", reason: "fraud" }],
      ["POST", "/api/identity-merge-requests/r%2F1/approve", {}],
      ["POST", "/api/identity-merge-requests/r%2F1/reject", { reason: "not the same" }],
      ["PUT", "/api/admin/matching", { auto_link_tier_b: true, require_review_tier_a: false, unmerge_window_days: 30 }],
    ],
  );
  for (const c of calls) assert.equal(c.headers["x-tessera-csrf"], "csrf-pat", `${c.method} ${c.url} carries the CSRF token`);
  for (const c of calls) assert.ok(!c.url.includes(":"), `${c.url} uses a path segment for the action`);
});

test("a merge that waits for a second reviewer is told apart from one that happened", async () => {
  reply = { status: "pending_approval", request: { id: "r1", status: "pending", risk: ["employee"] } };
  const pending = await api.mergeIdentity(5, 2, "duplicate");
  assert.equal(api.isPendingMerge(pending), true);
  reply = { id: "m1", survivor_id: 2, merged_id: 5, moves: [] };
  const done = await api.mergeIdentity(5, 2, "duplicate");
  assert.equal(api.isPendingMerge(done), false);
});

test("the claim page reads the result of a sign-in as an existing account", () => {
  assert.equal(claim.resultFromSearch("?result=continue"), "continue");
  assert.equal(claim.resultFromSearch("?result=complete"), "complete");
  assert.equal(claim.resultFromSearch("?result=linked"), null);
  assert.equal(claim.signInRedirect({ status: "redirect", redirect: "https://idp.example/authorize?x=1" }), "https://idp.example/authorize?x=1");
  assert.equal(claim.signInRedirect({ status: "redirect" }), null);
  assert.equal(claim.signInRedirect({}), null);
  assert.equal(claim.signInRedirect({ redirect: "https://idp.example/" }), null);
});
