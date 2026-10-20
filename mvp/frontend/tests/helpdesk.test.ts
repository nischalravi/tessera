// The help-desk client (issue #108): paths, bodies and the step-up labels. Run with `npm test`.
import assert from "node:assert/strict";
import { test } from "node:test";

const calls: { url: string; method: string; body: any }[] = [];
(globalThis as any).sessionStorage = { getItem: () => null, setItem() {}, removeItem() {} };
(globalThis as any).window = Object.assign(new EventTarget(), { location: { pathname: "/helpdesk", search: "" } });
(globalThis as any).fetch = async (url: string, init: any) => {
  calls.push({ url, method: init.method, body: init.body ? JSON.parse(init.body) : undefined });
  return { ok: true, status: 200, json: async () => ({}) };
};

const api = await import("../src/api.ts");

test("verifications and approvals go to the case's own routes", async () => {
  const id = "0c9f7a4e-0000-4000-8000-000000000001";
  await api.startHelpdeskCase({ identity_id: 7, kind: "mfa", system: "okta", reason: "lost phone, called in" });
  await api.verifyHelpdeskCase(id, { method: "callback", number_source: "hr", evidence: "called the HR number" });
  await api.managerApproveHelpdeskCase(id);
  await api.secondApproveHelpdeskCase(id);
  await api.executeHelpdeskCase(id);
  assert.deepEqual(
    calls.map((c) => `${c.method} ${c.url}`),
    [
      "POST /api/helpdesk/cases",
      `POST /api/helpdesk/cases/${id}/verifications`,
      `POST /api/helpdesk/cases/${id}/manager-approval`,
      `POST /api/helpdesk/cases/${id}/second-approval`,
      `POST /api/helpdesk/cases/${id}/execute`,
    ],
  );
  assert.equal(calls[1].body.number_source, "hr");
});

test("a refused step-up on the reset is labelled in plain language", () => {
  assert.equal(api.actionLabel("POST", "/helpdesk/cases/abc/execute"), "Run the verified reset");
  assert.match(api.actionLabel("POST", "/helpdesk/cases/abc/second-approval"), /second approval/);
  assert.match(api.actionLabel("POST", "/helpdesk/cases/abc/manager-approval"), /manager approval/);
});
