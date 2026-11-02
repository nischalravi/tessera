// Issue #830: the wizard warns before an edit that moves a connection's endpoint, which clears its credential.
import assert from "node:assert/strict";
import { test } from "node:test";

(globalThis as any).window = new EventTarget();

const { endpointFieldsMoved, ENDPOINT_CLEARS_CREDENTIAL } = await import("../src/api.ts");

test("endpoint edits are named, other edits are not", () => {
  assert.deepEqual(endpointFieldsMoved({ org_url: "https://a.okta.com" }, { org_url: "https://b.okta.com" }), ["org_url"]);
  assert.deepEqual(endpointFieldsMoved({ org_url: "https://a.okta.com" }, { org_url: "https://a.okta.com" }), []);
  assert.deepEqual(endpointFieldsMoved({}, { stale_days: 30, technical_owner: "x" }), []);
  assert.deepEqual(endpointFieldsMoved({ settings: { host: "a", username: "u" } }, { settings: { host: "b", username: "u" } }), ["settings.host"]);
  assert.deepEqual(endpointFieldsMoved({ settings: { host: "a", username: "u" } }, { settings: { host: "a", username: "v" } }), []);
  assert.match(ENDPOINT_CLEARS_CREDENTIAL, /clears the stored credential/);
});
