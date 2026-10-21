// Workflow designer (issue #298): the client calls and the editor's logic. The server validates every
// definition (ids, references, cycles, reachability, four eyes); these check what the form sends and
// the checks that spare a round trip. Run with `npm test`.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

(globalThis as any).window = new EventTarget();

type Call = { url: string; method: string; body: any };
let calls: Call[] = [];

(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", body: init.body ? JSON.parse(init.body) : undefined });
  const body = url === "/api/auth/session" ? { csrf_token: "csrf-pat", tenant: { slug: "larkspur" }, user: {} } : {};
  return { ok: true, status: 200, statusText: "", json: async () => body };
};

const api = await import("../src/api.ts");
const m = await import("../src/features/governance/workflowModel.ts");
const sa = await import("../src/features/access/serviceAccountModel.ts");

beforeEach(async () => {
  await api.getSession();
  calls = [];
});

const approvers = ["manager", "owner", "group", "decider"];
const attributes = ["risk", "item", "privileged", "system", "requester_org", "beneficiary_org"];
const blank = (type: any, steps: any[] = []) => m.blankStep(type, steps, approvers, attributes);

test("client calls: create, validate, edit with the version read, retire and assign", async () => {
  const spec = { name: "Fast", description: "", steps: [{ id: "d", type: "approval" as const, approver: "decider" }] };
  await api.workflows.create("access", spec);
  await api.workflows.validate("service_account", spec.steps);
  await api.workflows.edit("a b", 3, spec);
  await api.workflows.retire("a b");
  await api.workflows.assign("a b", [{ kind: "request_type", target_id: "access" }]);
  assert.deepEqual(calls.map((c) => [c.method, c.url]), [
    ["POST", "/api/workflows"], ["POST", "/api/workflows/validate"], ["PUT", "/api/workflows/a%20b"], ["POST", "/api/workflows/a%20b/retire"],
    ["PUT", "/api/workflows/a%20b/assignments"],
  ]);
  assert.equal(calls[0].body.scope, "access");
  assert.equal(calls[0].body.name, "Fast");
  assert.deepEqual(calls[1].body, { scope: "service_account", steps: spec.steps });
  assert.equal(calls[2].body.version, 3);
  assert.deepEqual(calls[4].body, { targets: [{ kind: "request_type", target_id: "access" }] });
});

test("service-account client calls and the needed query", async () => {
  await api.serviceAccountRequests.file({ kind: "create", name: "svc", justification: "x" });
  await api.serviceAccountRequests.approve("r 1");
  await api.serviceAccountRequests.approve("r 1", "ok");
  await api.serviceAccountRequests.deny("r 1", "no");
  await api.serviceAccountRequests.cancel("r 1");
  assert.deepEqual(calls.map((c) => [c.method, c.url]), [
    ["POST", "/api/service-account-requests"], ["POST", "/api/service-account-requests/r%201/approve"], ["POST", "/api/service-account-requests/r%201/approve"],
    ["POST", "/api/service-account-requests/r%201/deny"], ["POST", "/api/service-account-requests/r%201/cancel"],
  ]);
  assert.deepEqual(calls[1].body, {});
  assert.deepEqual(calls[2].body, { reason: "ok" });
  assert.equal(api.neededPath({ serviceAccount: { kind: "transfer", primaryOwnerId: 7, system: "okta", identityId: 3 } }),
    "/questionnaires/needed?service_account_kind=transfer&primary_owner_id=7&system=okta&identity_id=3");
});

test("blank steps have defaults for their type and a fresh id", () => {
  const a = blank("approval");
  assert.equal(a.id, "s1");
  assert.equal(a.approver, "decider");
  const n = blank("notify", [a]);
  assert.deepEqual([n.id, n.notify], ["s2", "requester"]);
  assert.equal(blank("wait", [a, n]).hours, 4);
  const c = blank("condition", [a]);
  assert.deepEqual(c.when, { attribute: "risk", op: "eq", values: [""] });
  assert.equal(m.nextId([{ id: "s2", type: "provisioning" }]), "s3");
  assert.equal(m.blankStep("approval", [], ["manager"], attributes).approver, "manager"); // no decider offered: the first approver
});

test("retyping keeps the id, label and next step and drops what no longer applies", () => {
  const s = { ...blank("approval"), name: "Boss", next: "end", escalate_after_hours: 12 };
  const n = m.retypeStep(s, "wait", [s], approvers, attributes);
  assert.deepEqual([n.id, n.type, n.name, n.next, n.hours, n.approver, n.escalate_after_hours], ["s1", "wait", "Boss", "end", 4, undefined, undefined]);
  const c = m.retypeStep(s, "condition", [s], approvers, attributes);
  assert.equal(c.next, undefined); // a condition names its branches instead
  assert.ok(c.when);
});

test("removing a step clears what pointed at it; moving swaps places", () => {
  const steps: any[] = [
    { id: "a", type: "condition", when: { attribute: "risk", op: "eq", values: ["high"] }, then: "b", else: "c" },
    { id: "b", type: "approval", approver: "owner", next: "c" },
    { id: "c", type: "approval", approver: "decider" },
  ];
  const out = m.removeStep(steps, "b");
  assert.deepEqual(out.map((s) => s.id), ["a", "c"]);
  assert.equal(out[0].then, "");
  assert.equal(out[0].else, "c");
  const gone = m.removeStep(steps, "c");
  assert.equal(gone[1].next, undefined);
  assert.equal(gone[0].else, "");
  assert.deepEqual(m.moveStep(steps, 0, 1).map((s) => s.id), ["b", "a", "c"]);
  assert.equal(m.moveStep(steps, 0, -1), steps);
  assert.equal(m.moveStep(steps, 2, 1), steps);
});

test("cleanSteps sends only what the step's type takes, trimmed, nothing empty", () => {
  const dirty: any[] = [
    { id: " a ", type: "approval", approver: "owner", group_id: "g", escalate_after_hours: 0, name: "  ", hours: 3, message: "x" },
    { id: "g", type: "approval", approver: "group", group_id: "grp", escalate_after_hours: 12, next: "end" },
    { id: "n", type: "notify", notify: "requester", message: " hi ", group_id: "g" },
    { id: "c", type: "condition", when: { attribute: "item", op: "in", values: [" x ", "", "y"] }, then: "g", else: "end", next: "n" },
    { id: "q", type: "questionnaire", questionnaire_id: "qq", approver: "owner" },
    { id: "p", type: "provisioning", approver: "owner", hours: 2 },
  ];
  assert.deepEqual(m.cleanSteps(dirty), [
    { id: "a", type: "approval", approver: "owner" },
    { id: "g", type: "approval", approver: "group", group_id: "grp", escalate_after_hours: 12, next: "end" },
    { id: "n", type: "notify", notify: "requester", message: "hi" },
    { id: "c", type: "condition", when: { attribute: "item", op: "in", values: ["x", "y"] }, then: "g", else: "end" },
    { id: "q", type: "questionnaire", questionnaire_id: "qq" },
    { id: "p", type: "provisioning" },
  ]);
  assert.ok(m.sameSteps(dirty, m.cleanSteps(dirty)));
});

test("local problems: the required fields a form can check", () => {
  assert.deepEqual(m.localProblems([]).map((p) => p.message), ["Add at least one step"]);
  const ok: any[] = [{ id: "a", type: "approval", approver: "decider" }];
  assert.deepEqual(m.localProblems(ok), []);
  const bad: any[] = [
    { id: "a", type: "approval", approver: "group" },
    { id: "a", type: "questionnaire", questionnaire_id: "" },
    { id: "n", type: "notify", notify: "group" },
    { id: "w", type: "wait", hours: 0 },
    { id: "c", type: "condition", when: { attribute: "risk", op: "eq", values: [""] }, then: "", else: "" },
    { id: "d", type: "condition", when: { attribute: "risk", op: "eq", values: ["high"] }, then: "a", else: "a" },
    { id: "e", type: "approval", approver: "decider", next: "zz" },
  ];
  const msgs = m.localProblems(bad).map((p) => `${p.step}: ${p.message}`);
  for (const want of ["a: Choose the group", "a: The id is used twice", "a: Choose the questionnaire", "n: Choose the group", "w: Wait between 1 and 720 hours",
    "c: Enter the value to test", "c: Choose where to go when it holds and when it does not", "d: Both branches go to the same step", "e: The next step does not exist"]) {
    assert.ok(msgs.includes(want), `${want} not in ${JSON.stringify(msgs)}`);
  }
  assert.ok(m.localProblems(Array.from({ length: 21 }, (_, i) => ({ id: `s${i}`, type: "provisioning" as const }))).some((p) => p.message.startsWith("At most")));
  assert.deepEqual(m.localProblems([{ id: "a", type: "approval", approver: "decider", next: "end" }]), []);
});

test("descriptions and flow in words", () => {
  const steps: any[] = [
    { id: "c", type: "condition", when: { attribute: "risk", op: "in", values: ["medium", "high"] }, then: "a", else: "end" },
    { id: "a", type: "approval", approver: "group", group_id: "g1", escalate_after_hours: 24 },
    { id: "p", type: "provisioning" },
  ];
  assert.equal(m.describeStep(steps[0]), "If Risk of the item is one of medium, high");
  assert.equal(m.describeStep(steps[1], { group: () => "Approvers" }), "Group Approvers approves, escalates after 24 h");
  assert.equal(m.describeStep({ id: "x", type: "wait", hours: 2 }), "Wait 2 h before the next approval");
  assert.equal(m.flowLabel(steps, 0), "yes: a, no: end");
  assert.equal(m.flowLabel(steps, 1), "p");
  assert.equal(m.flowLabel(steps, 2), "end");
  assert.equal(m.flowLabel([{ id: "x", type: "approval", approver: "decider", next: "end" }, { id: "y", type: "provisioning" }], 0), "end");
  assert.equal(m.appliesTo([]), "Nothing yet");
  assert.equal(m.appliesTo([{ kind: "request_type", target_id: "service_account_transfer" }, { kind: "catalog_item", target_id: "i1" }], () => "okta:eng"),
    "Transfer a service account; okta:eng");
  assert.equal(m.appliesTo([{ kind: "catalog_item", target_id: "a" }, { kind: "catalog_item", target_id: "b" }]), "2 catalog items");
});

const form = (o: Partial<ReturnType<typeof sa.blankForm>> = {}) => ({ ...sa.blankForm(), ...o });
const account = (o: any = {}) => ({ id: 5, name: "svc", status: "active", purpose: "sync", primary_owner: { id: 1, name: "Bob", type: "human", status: "active" },
  backup_owner: { id: 2, name: "Carol", type: "human", status: "active" }, systems: ["okta"], open_request: null, ...o });

test("service-account form: owners are mandatory", () => {
  const ok = form({ name: "svc-x", system: "okta", username: "svc-x", primary: 1, backup: 2, justification: "why" });
  assert.equal(sa.formProblem(ok), null);
  assert.match(sa.formProblem({ ...ok, primary: null })!, /primary owner/);
  assert.match(sa.formProblem({ ...ok, backup: null })!, /backup owner/);
  assert.match(sa.formProblem({ ...ok, username: "a b" })!, /account name/);
  assert.match(sa.formProblem({ ...ok, system: "" })!, /application/);
  assert.match(sa.formProblem({ ...ok, name: " " })!, /name/);
  assert.match(sa.formProblem({ ...ok, justification: " " })!, /why/);
});

test("service-account form: transfer and change", () => {
  const t = form({ kind: "transfer", identityId: 5, primary: 3, justification: "x" });
  assert.equal(sa.formProblem(t, account()), null);
  assert.match(sa.formProblem({ ...t, identityId: null })!, /Choose the service account/);
  assert.match(sa.formProblem({ ...t, primary: 1 }, account())!, /already owns/);
  assert.match(sa.formProblem({ ...t, primary: 2 }, account())!, /backup owner must be someone else/);
  assert.match(sa.formProblem(t, account({ backup_owner: null }))!, /backup owner/);
  assert.match(sa.formProblem(t, account({ open_request: "r" }))!, /already an open request/);
  const c = form({ kind: "change", identityId: 5, purpose: "weekly", justification: "x" });
  assert.equal(sa.formProblem(c, account()), null);
  assert.match(sa.formProblem({ ...c, purpose: "sync" }, account())!, /Change the purpose/);
  assert.equal(sa.formProblem({ ...c, purpose: "sync", backup: 3 }, account()), null);
  assert.match(sa.formProblem({ ...c, backup: 1 }, account())!, /backup owner must be someone else/);
  assert.match(sa.formProblem(c, account({ primary_owner: null }))!, /transfer/);
});

test("service-account form body", () => {
  assert.deepEqual(sa.toInput(form({ name: " svc ", system: "okta", username: " svc ", description: " d ", primary: 1, backup: 2, purpose: " p ", justification: " j " })),
    { kind: "create", justification: "j", name: "svc", system: "okta", username: "svc", description: "d", purpose: "p", primary_owner_id: 1, backup_owner_id: 2 });
  assert.deepEqual(sa.toInput(form({ kind: "transfer", identityId: 5, primary: 3, justification: "j" })), { kind: "transfer", justification: "j", identity_id: 5, primary_owner_id: 3 });
  // a change never names the primary owner
  assert.deepEqual(sa.toInput(form({ kind: "change", identityId: 5, primary: 3, backup: 4, justification: "j" })), { kind: "change", justification: "j", identity_id: 5, backup_owner_id: 4 });
});

test("service-account request words", () => {
  const person = (id: number, name: string) => ({ id, name, type: "human", status: "active" });
  const r: any = { kind: "transfer", status: "pending", primary_owner: person(3, "Alice"), backup_owner: person(2, "Carol"), previous_primary_owner: person(1, "Bob"),
    stages: [{ index: 0, kind: "owner", label: "Current owner approval", status: "waiting", assignee: person(1, "Bob") }, { index: 1, kind: "decider", status: "queued", assignee: null }] };
  assert.equal(sa.ownerSummary(r), "Bob to Alice (backup Carol)");
  assert.equal(sa.waitingFor(r), "Current owner approval: waiting for Bob");
  r.stages[0].status = "approved";
  r.stages[1].status = "waiting";
  assert.equal(sa.waitingFor(r), "decider: waiting for an access approver");
  assert.equal(sa.waitingFor({ ...r, status: "fulfilled" }), null);
  assert.equal(sa.ownerSummary({ ...r, kind: "create", previous_primary_owner: null }), "Alice (backup Carol)");
  assert.equal(sa.statusTone("fulfilled"), "ok");
  assert.equal(sa.statusTone("denied"), "critical");
  assert.equal(sa.statusTone("pending"), "warning");
});
