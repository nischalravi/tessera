// Admin > Notifications and Email delivery: the wording checks (the same ones the server makes), and the routes, verbs and
// bodies of the relay, chat, timings, wording and suppression calls. Run with `npm test`.
import assert from "node:assert/strict";
import { test } from "node:test";

(globalThis as any).window = new EventTarget();

const calls: { url: string; method: string; body: any }[] = [];
(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", body: init.body ? JSON.parse(init.body) : undefined });
  return { ok: true, status: 200, statusText: "", json: async () => ({}) };
};

const api = await import("../src/api.ts");
const t = await import("../src/features/notifications/templates.ts");
const NAMES = ["subject", "body", "link", "product", "recipient"];

test("a template renders only its placeholders", () => {
  assert.equal(t.renderTemplate("Decide: {{subject}} ({{ product }})"), "Decide: Approval needed: Production database, read access (Tessera)");
  assert.equal(t.renderTemplate("{{secret}}x", { subject: "S" }), "x");
  assert.equal(t.renderTemplate("{{body}}", { body: "{{subject}}" }), "{{subject}}", "a value is not rendered again");
});

test("template problems", () => {
  const p = (s: string, b: string) => t.templateProblem(s, b, NAMES, 300, 4000);
  assert.equal(p("{{subject}}", ""), null);
  assert.equal(p("", "{{body}}\n{{link}}"), null);
  assert.match(p("", "  ")!, /subject or a body/);
  assert.match(p("a\nb", "x")!, /one line/);
  assert.match(p("{{password}}", "x")!, /not a placeholder/);
  assert.match(p("x", "{{body")!, /\{\{name\}\}/);
  assert.match(p("x".repeat(301), "x")!, /at most 300/);
  assert.match(p("x", "y".repeat(4001))!, /at most 300/);
});

test("mail relay calls", async () => {
  await api.mailRelayApi.save({ version: 1, enabled: true, host: "smtp.example.com", port: 587, tls: "starttls", username: "u", password: "pw", from: "a@example.com" });
  assert.deepEqual(calls.at(-1), { url: "/api/admin/mail-relay", method: "PUT", body: { version: 1, enabled: true, host: "smtp.example.com", port: 587, tls: "starttls", username: "u", password: "pw", from: "a@example.com" } });
  await api.mailRelayApi.test();
  assert.deepEqual(calls.at(-1), { url: "/api/admin/mail-relay/test", method: "POST", body: {} });
  await api.mailRelayApi.remove(3);
  assert.deepEqual(calls.at(-1), { url: "/api/admin/mail-relay", method: "DELETE", body: { version: 3 } });
});

test("the relay password and the webhook URL are never kept for resuming after a step-up", async () => {
  const store: Record<string, string> = {};
  (globalThis as any).sessionStorage = { getItem: (k: string) => store[k] ?? null, setItem: (k: string, v: string) => { store[k] = v; }, removeItem: (k: string) => { delete store[k]; } };
  (globalThis as any).fetch = async () => ({ ok: false, status: 401, statusText: "", json: async () => ({ error: "step_up_required" }) });
  await assert.rejects(api.mailRelayApi.save({ version: 0, enabled: true, host: "h.example.com", port: 25, tls: "tls", username: "u", password: "SECRET-PASSWORD", from: "a@example.com" }));
  await assert.rejects(api.chatApi.save({ version: 0, provider: "slack", enabled: true, webhook_url: "https://hooks.slack.com/services/SECRET-HOOK", kinds: ["security.alert"] }));
  assert.ok(!JSON.stringify(store).includes("SECRET-PASSWORD") && !JSON.stringify(store).includes("SECRET-HOOK"), JSON.stringify(store));
});

test("chat, timing, wording and suppression calls", async () => {
  (globalThis as any).fetch = async (url: string, init: any = {}) => {
    calls.push({ url, method: init.method ?? "GET", body: init.body ? JSON.parse(init.body) : undefined });
    return { ok: true, status: 200, statusText: "", json: async () => ({}) };
  };
  await api.chatApi.save({ version: 0, provider: "teams", enabled: true, webhook_url: "https://x.webhook.office.com/y", kinds: ["security.alert"] });
  assert.deepEqual(calls.at(-1), { url: "/api/admin/chat", method: "PUT", body: { version: 0, provider: "teams", enabled: true, webhook_url: "https://x.webhook.office.com/y", kinds: ["security.alert"] } });
  await api.chatApi.test();
  assert.equal(calls.at(-1)!.url, "/api/admin/chat/test");
  await api.notificationPolicyApi.save({ version: 2, review_remind_after_days: 3, review_remind_every_days: 2, request_warn_hours: 48, jit_warn_minutes: 15, escalate_after_hours: 12 });
  assert.deepEqual(calls.at(-1), { url: "/api/admin/notification-policy", method: "PUT", body: { version: 2, review_remind_after_days: 3, review_remind_every_days: 2, request_warn_hours: 48, jit_warn_minutes: 15, escalate_after_hours: 12 } });
  await api.notificationTemplatesApi.save("request.approval_needed", "S {{subject}}", "{{body}}");
  assert.deepEqual(calls.at(-1), { url: "/api/admin/notification-templates/request.approval_needed", method: "PUT", body: { subject_tpl: "S {{subject}}", body_tpl: "{{body}}" } });
  await api.notificationTemplatesApi.reset("review.reminder");
  assert.deepEqual(calls.at(-1), { url: "/api/admin/notification-templates/review.reminder", method: "DELETE", body: undefined });
  await api.emailSuppressionsApi.add("a@example.com", "left");
  assert.deepEqual(calls.at(-1), { url: "/api/email/suppressions", method: "POST", body: { address: "a@example.com", note: "left" } });
  await api.emailSuppressionsApi.lift("a+b@example.com");
  assert.deepEqual(calls.at(-1), { url: "/api/email/suppressions/a%2Bb%40example.com", method: "DELETE", body: undefined });
});
