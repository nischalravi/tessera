import { test } from "node:test";
import assert from "node:assert/strict";
import { REGISTER_PATH, canRegister, purgeStaleMock, registerRedirect } from "../src/features/directory/registerModel.ts";

// No component-render harness exists in this repo (node:test, no DOM), so the logic is tested as pure functions.
const yes = (p: string) => p === "requests.create";
const no = () => false;

test("?new=1 redirects to the service-account request form only with requests.create", () => {
  assert.equal(registerRedirect("new=1", yes), REGISTER_PATH);
  assert.equal(registerRedirect("tab=mcp&new=1", yes), REGISTER_PATH);
  assert.equal(registerRedirect("new=1", no), null);
  assert.equal(registerRedirect("", yes), null);
  assert.equal(registerRedirect("new=0", yes), null);
});

test("Register is hidden without requests.create", () => {
  assert.equal(canRegister(yes), true);
  assert.equal(canRegister(no), false);
});

test("the stale preview store is removed once, and a failing storage does not throw", () => {
  const gone: string[] = [];
  purgeStaleMock({ removeItem: (k) => void gone.push(k) });
  assert.deepEqual(gone, ["tessera.mock.v1"]);
  assert.doesNotThrow(() => purgeStaleMock({ removeItem: () => { throw new Error("denied"); } }));
});
