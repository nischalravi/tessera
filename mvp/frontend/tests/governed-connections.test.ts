// New connection, connect step: the fields of the governed connector types. Run with `npm test`.
import assert from "node:assert/strict";
import { test } from "node:test";

import { GOVERNED, SETTING_KEYS, isGoverned, missingRequired, settingValues, settingsPatch } from "../src/features/admin/connections/governed.ts";

test("every governed type lists the keys of its settings, in the same order", () => {
  assert.deepEqual(Object.keys(GOVERNED).sort(), Object.keys(SETTING_KEYS).sort());
  for (const [type, t] of Object.entries(GOVERNED)) assert.deepEqual(t.settings.map((f) => f.key), SETTING_KEYS[type], type);
});

test("which types take a base URL and a credential", () => {
  for (const type of ["sap", "oracle", "cyberark", "beyondtrust", "delinea", "fieldglass", "beeline", "csvfeed", "successfactors"]) assert.equal(GOVERNED[type].baseUrl?.required, true, type);
  assert.equal(GOVERNED.githubscan.baseUrl?.required, false); // GitHub.com when empty
  assert.equal(GOVERNED.awsorg.baseUrl, undefined);
  assert.equal(GOVERNED.agentcore.baseUrl, undefined);
  assert.equal(GOVERNED.azurerbac.baseUrl, undefined); // fixed Microsoft endpoints
  assert.equal(GOVERNED.gcpiam.baseUrl, undefined); // fixed Google endpoints
  assert.equal(GOVERNED.gcpiam.credential?.area, true); // the key JSON
  assert.equal(GOVERNED.unixssh.baseUrl, undefined); // the host is a setting, not a URL
  assert.equal(GOVERNED.unixssh.credential?.area, true); // the private key
  for (const type of ["kubernetes", "vault"]) {
    assert.equal(GOVERNED[type].baseUrl?.required, true, type); // the server's own address
    assert.equal(GOVERNED[type].credential?.area, true, type);
  }
  assert.equal(GOVERNED.agentcore.credential, null); // a recorded snapshot holds no secret
  assert.equal(GOVERNED.awsorg.credential?.area, true); // JSON keys
  for (const [type, t] of Object.entries(GOVERNED)) if (type !== "agentcore") assert.ok(t.credential, type);
  assert.ok(isGoverned("cyberark"));
  assert.ok(!isGoverned("ldap") && !isGoverned("demo-ad") && !isGoverned("scim_app"));
});

test("form values come from the saved settings, blank when unset", () => {
  assert.deepEqual(settingValues("cyberark", { username: "svc", api_root: "/x" }), { "settings.username": "svc", "settings.api_root": "/x" });
  assert.deepEqual(settingValues("cyberark"), { "settings.username": "", "settings.api_root": "" });
  assert.deepEqual(settingValues("ldap", { a: "b" }), {}); // not a governed type
});

test("the patch carries only the type's own keys, trimmed, blanks left out, and is null when nothing changed", () => {
  const saved = { username: "svc" };
  assert.equal(settingsPatch("cyberark", { "settings.username": "svc", "settings.api_root": "" }, saved), null);
  assert.equal(settingsPatch("cyberark", { "settings.username": " svc ", "settings.api_root": "" }, saved), null);
  assert.deepEqual(settingsPatch("cyberark", { "settings.username": "svc2", "settings.api_root": "/PasswordVault" }, saved), { username: "svc2", api_root: "/PasswordVault" });
  assert.deepEqual(settingsPatch("cyberark", { "settings.username": "svc", "settings.api_root": "" }, { username: "svc", api_root: "/old" }), { username: "svc" }); // cleared
  assert.deepEqual(settingsPatch("cyberark", { "settings.username": "svc", "settings.password": "x" }, undefined), { username: "svc" }); // never a key the type does not take
  assert.equal(settingsPatch("cyberark", {}, undefined), null);
});

test("required fields are named until they are filled", () => {
  assert.deepEqual(missingRequired("cyberark", "", {}), ["Vault URL", "Service user"]);
  assert.deepEqual(missingRequired("cyberark", "https://pvwa.example.com", { "settings.username": "svc" }), []);
  assert.deepEqual(missingRequired("githubscan", "", {}), ["Organization"]); // the API URL is optional
  assert.deepEqual(missingRequired("awsorg", "", { "settings.regions": "us-east-1" }), ["External id"]);
  assert.deepEqual(missingRequired("agentcore", "", {}), ["Snapshot file"]);
  assert.deepEqual(missingRequired("azurerbac", "", {}), ["Directory (tenant) id", "Application (client) id"]); // no base URL: the public cloud
  assert.deepEqual(missingRequired("gcpiam", "", {}), []); // one of organization, folders or projects: the server checks
  assert.deepEqual(missingRequired("kubernetes", "", {}), ["API server URL"]);
  assert.deepEqual(missingRequired("vault", "", {}), ["Vault URL"]);
  assert.deepEqual(missingRequired("unixssh", "", {}), ["Host", "SSH user", "Host key"]);
  assert.deepEqual(missingRequired("ldap", "", {}), []);
});

test("SuccessFactors: API server, company and API user are required; the credential holds a password or a key bundle", () => {
  assert.deepEqual(missingRequired("successfactors", "", {}), ["API server", "Company id", "API user"]);
  assert.deepEqual(missingRequired("successfactors", "https://api4.successfactors.com", { "settings.company_id": "acme", "settings.username": "svc" }), []);
  assert.equal(GOVERNED.successfactors.credential?.area, true); // a PEM bundle is multi-line
  assert.deepEqual(settingsPatch("successfactors", { "settings.company_id": "acme", "settings.username": "svc", "settings.password": "x" }, undefined), { company_id: "acme", username: "svc" });
});
