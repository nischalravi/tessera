// The wizard marks the fields a config save was refused for (issue #622). Run with `npm test`.
import assert from "node:assert/strict";
import { test } from "node:test";

import { fieldErrorsByKey, fieldErrorsSummary, formKeyOf } from "../src/features/admin/connections/fieldErrors.ts";

// the answer of PATCH /api/connections/{id}/config for a Kubernetes URL with a bad port and a path (UAT, Test pass 2)
const K8S = [
  { field: "base_url", msg: "the port must be one of 443, 6443, 8443" },
  { field: "base_url", msg: "must be an https URL with no credentials or port" },
  { field: "base_url", msg: "must be a host without a path (the paths are settings)" },
];

test("each rejected field gets its messages, joined, under the form's key", () => {
  assert.deepEqual(fieldErrorsByKey(K8S), {
    base_url: "the port must be one of 443, 6443, 8443; must be an https URL with no credentials or port; must be a host without a path (the paths are settings)",
  });
  assert.deepEqual(fieldErrorsByKey([
    { field: "settings.port", msg: "must be between 1 and 65535" },
    { field: "host", msg: "a host name like ldap.example.com, without a scheme such as ldaps://" },
    { field: "host", msg: "a host name like ldap.example.com, without a scheme such as ldaps://" },
  ]), { "settings.port": "must be between 1 and 65535", host: "a host name like ldap.example.com, without a scheme such as ldaps://" });
});

test("sql fields map to the sql_ inputs; nothing to mark is an empty map", () => {
  assert.equal(formKeyOf("sql.host"), "sql_host");
  assert.equal(formKeyOf("settings.region"), "settings.region");
  assert.deepEqual(fieldErrorsByKey(undefined), {});
  assert.deepEqual(fieldErrorsByKey([]), {});
  assert.deepEqual(fieldErrorsByKey([{ field: "", msg: "x" }, { field: "port", msg: "" }]), {});
});

test("the toast names the fields once each, and is empty for a clean save", () => {
  assert.equal(fieldErrorsSummary(K8S), "Saved as a draft, but 1 field is not valid yet: base_url. Fix the marked field and save again.");
  assert.equal(fieldErrorsSummary([{ field: "settings.region", msg: "a" }, { field: "base_url", msg: "b" }]),
    "Saved as a draft, but 2 fields are not valid yet: settings.region, base_url. Fix the marked fields and save again.");
  assert.equal(fieldErrorsSummary([]), "");
  assert.equal(fieldErrorsSummary(undefined), "");
});
