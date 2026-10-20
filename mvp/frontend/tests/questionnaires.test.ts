// Questionnaires (issue #298): the client calls and the form logic. The server validates every answer
// against the version in force; these check what the form shows and sends. Run with `npm test`.
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
const m = await import("../src/features/governance/questionnaireModel.ts");

beforeEach(async () => {
  await api.getSession();
  calls = [];
});

const need = {
  id: "qn", title: "Risk", description: "", version: 2,
  questions: [
    { id: "why", type: "long_text", text: "Why?", required: true, max_length: 10 },
    { id: "env", type: "single_choice", text: "Env", required: false, options: ["prod", "test"] },
    { id: "tools", type: "multi_choice", text: "Tools", required: false, options: ["cli", "ui"] },
    { id: "ack", type: "yes_no", text: "Ack", required: true },
    { id: "until", type: "date", text: "Until", required: false },
  ],
} as const;
const N = need as any;

test("client calls: create, edit with the version read, retire, attach, and the needed query", async () => {
  const spec = { title: "Why", description: "", questions: [{ id: "q1", type: "yes_no" as const, text: "x", required: false }] };
  await api.questionnaires.create(spec);
  await api.questionnaires.edit("a b", 3, spec);
  await api.questionnaires.retire("a b");
  await api.questionnaires.attach("a b", [{ kind: "privileged", target_id: "*" }]);
  assert.deepEqual(calls.map((c) => [c.method, c.url]), [
    ["POST", "/api/questionnaires"], ["PUT", "/api/questionnaires/a%20b"], ["POST", "/api/questionnaires/a%20b/retire"], ["PUT", "/api/questionnaires/a%20b/attachments"],
  ]);
  assert.equal(calls[1].body.version, 3);
  assert.deepEqual(calls[3].body.targets, [{ kind: "privileged", target_id: "*" }]);
  assert.equal(api.neededPath({ catalogItemIds: ["a", "b"] }), "/questionnaires/needed?catalog_item_ids=a%2Cb");
  assert.equal(api.neededPath({ reviewCampaignId: 4 }), "/questionnaires/needed?review_campaign_id=4");
  assert.equal(api.neededPath({ roleId: "r1" }), "/questionnaires/needed?role_id=r1");
});

test("answers travel with a request, a role request and a review decision, and only when there are some", async () => {
  await api.submitRequest({ beneficiary_ids: [1], catalog_item_ids: ["i"], justification: "j", answers: { qn: { why: "x" } } });
  await api.roles.request("r", 1, "j", { qn: { why: "x" } });
  await api.roles.request("r", 1, "j");
  await api.reviewDecide(5, "keep", undefined, undefined, { why: "x" });
  await api.reviewDecide(5, "keep");
  assert.deepEqual(calls[0].body.answers, { qn: { why: "x" } });
  assert.deepEqual(calls[1].body.answers, { qn: { why: "x" } });
  assert.equal("answers" in calls[2].body, false);
  assert.deepEqual(calls[3].body.answers, { why: "x" });
  assert.equal("answers" in calls[4].body, false);
});

test("an answer is checked as the server checks it", () => {
  const q = (id: string) => N.questions.find((x: any) => x.id === id);
  assert.equal(m.answerError(q("why"), undefined), "An answer is required");
  assert.equal(m.answerError(q("why"), "   "), "An answer is required");
  assert.match(m.answerError(q("why"), "x".repeat(11)) ?? "", /At most 10 characters/);
  assert.equal(m.answerError(q("why"), "fine"), null);
  assert.equal(m.answerError(q("env"), undefined), null, "optional");
  assert.equal(m.answerError(q("env"), "dev"), "Choose one of the options");
  assert.equal(m.answerError(q("tools"), ["cli", "fax"]), "Choose from the options");
  assert.equal(m.answerError(q("tools"), []), null, "an empty optional choice is no answer");
  assert.equal(m.answerError(q("ack"), undefined), "An answer is required");
  assert.equal(m.answerError(q("ack"), false), null, "no is an answer");
  assert.equal(m.answerError(q("until"), "2026-02-30"), "Enter a date as YYYY-MM-DD");
  assert.equal(m.answerError(q("until"), "2026-02-28"), null);
  assert.equal(m.isDate("31/12/2026"), false);
});

test("a form is ready only when every required question is answered and nothing is invalid", () => {
  assert.match(m.needsError([N], {}) ?? "", /Risk: Why\?/);
  assert.match(m.needsError([N], { qn: { why: "ok" } }) ?? "", /Ack/);
  assert.equal(m.needsError([N], { qn: { why: "ok", ack: false } }), null);
  assert.match(m.needsError([N], { qn: { why: "ok", ack: true, env: "dev" } }) ?? "", /Env/);
  assert.equal(m.needsError([], {}), null, "no questionnaire asks nothing");
});

test("the payload keeps answered questions only, trimmed", () => {
  assert.equal(m.answersPayload([N], {}), undefined);
  assert.deepEqual(m.answersPayload([N], { qn: { why: "  because ", ack: false, env: "", tools: [], until: "" } }), { qn: { why: "because", ack: false } });
  assert.deepEqual(m.answersPayload([N], { qn: { why: "x", ack: true, tools: ["ui"] } }), { qn: { why: "x", ack: true, tools: ["ui"] } });
});

test("answers read to an approver", () => {
  assert.equal(m.answerText(true), "Yes");
  assert.equal(m.answerText(false), "No");
  assert.equal(m.answerText(["cli", "ui"]), "cli, ui");
  assert.equal(m.answerText("text"), "text");
});

test("the editor checks a draft as the server does", () => {
  const q = (o: any = {}) => ({ id: "q1", type: "short_text", text: "Why?", required: true, ...o });
  const spec = (qs: any[], o: any = {}) => ({ title: "T", description: "", questions: qs, ...o });
  assert.equal(m.specError(spec([q()])), null);
  assert.match(m.specError(spec([q()], { title: " " })) ?? "", /title/);
  assert.match(m.specError(spec([])) ?? "", /at least one question/);
  assert.match(m.specError(spec([q(), q()])) ?? "", /used twice/);
  assert.match(m.specError(spec([q({ text: " " })])) ?? "", /Question 1: the text/);
  assert.match(m.specError(spec([q({ type: "single_choice", options: ["a"] })])) ?? "", /2 to 20 options/);
  assert.match(m.specError(spec([q({ type: "single_choice", options: ["a", "a"] })])) ?? "", /different from each other/);
  assert.match(m.specError(spec([q({ type: "single_choice", options: ["a", ""] })])) ?? "", /different from each other/);
  assert.equal(m.specError(spec([q({ type: "multi_choice", options: ["a", "b"] })])), null);
  assert.match(m.specError(spec([q({ max_length: 501 })])) ?? "", /maximum length/);
  assert.equal(m.specError(spec([q({ type: "long_text", max_length: 5000 })])), null);
  assert.match(m.specError(spec(Array.from({ length: 31 }, (_, i) => q({ id: `q${i + 1}` })))) ?? "", /At most 30/);
});

test("a new question gets a free id; changing the type keeps what still applies", () => {
  const a = m.blankQuestion("yes_no", []);
  const b = m.blankQuestion("single_choice", [a, { ...a, id: "q3" }]);
  assert.equal(a.id, "q1");
  assert.equal(b.id, "q4");
  assert.deepEqual(b.options, ["", ""]);
  const long = { id: "q1", type: "long_text" as const, text: "t", required: true, max_length: 900, help: "h" };
  assert.deepEqual(m.retype(long, "short_text"), long && { id: "q1", type: "short_text", text: "t", required: true, help: "h", max_length: 900 });
  assert.equal(m.retype(long, "yes_no").max_length, undefined);
  assert.deepEqual(m.retype(long, "multi_choice").options, ["", ""]);
  assert.deepEqual(m.parseOptions(" a \n\n b\n"), ["a", "b"]);
});

test("cleanSpec trims and drops what does not apply; sameSpec ignores that noise", () => {
  const dirty = { title: " T ", description: " d ", questions: [{ id: "q1", type: "yes_no" as const, text: " x ", required: false, help: "  ", options: ["a"], max_length: 5 }] };
  assert.deepEqual(m.cleanSpec(dirty), { title: "T", description: "d", questions: [{ id: "q1", type: "yes_no", text: "x", required: false }] });
  assert.equal(m.sameSpec(dirty, { title: "T", description: "d", questions: [{ id: "q1", type: "yes_no", text: "x", required: false }] }), true);
  assert.equal(m.sameSpec(dirty, { ...dirty, title: "U" }), false);
});

test("one questionnaire asked twice is asked once; targets read in words", () => {
  const a = { ...N, id: "a" }, b = { ...N, id: "b" };
  assert.deepEqual(m.mergeNeeds([[a], [a, b], []]).map((n) => n.id), ["a", "b"]);
  assert.equal(m.askedOf([]), "Not attached");
  assert.equal(m.askedOf([{ kind: "privileged", target_id: "*" }, { kind: "catalog_item", target_id: "1" }, { kind: "review_campaign", target_id: "2" }, { kind: "review_campaign", target_id: "3" }]),
    "privileged requests, 1 item, 2 reviews");
  assert.equal(m.targetLabel({ kind: "business_role", target_id: "r" }, { "business_role:r": "Payments" }), "Role: Payments");
  assert.equal(m.targetLabel({ kind: "catalog_item", target_id: "x" }, {}), "Item: x");
});
