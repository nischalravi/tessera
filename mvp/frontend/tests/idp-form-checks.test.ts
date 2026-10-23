// New IdP connection form: SAML field checks and server-error mapping. Run with `npm test`.
import assert from "node:assert/strict";
import { test } from "node:test";
import { checkSAMLFields, serverFieldError } from "../src/features/admin/idpFormChecks.ts";

const pem = "-----BEGIN CERTIFICATE-----\nMIIC" + "A".repeat(300) + "\n-----END CERTIFICATE-----";

test("a typed word is not a certificate", () => {
  const e = checkSAMLFields("https://idp.example.com/sso", "cdacsa");
  assert.match(e.cert ?? "", /isn't a certificate/);
  assert.equal(e.sso, undefined);
});

test("a PEM block and an https URL pass", () => {
  assert.deepEqual(checkSAMLFields("https://idp.example.com/sso", pem), {});
});

test("bare base64 DER passes the shape check", () => {
  assert.deepEqual(checkSAMLFields("https://idp.example.com/sso", "MIIC" + "B".repeat(400)), {});
});

test("the sign-in URL must be a URL", () => {
  assert.ok(checkSAMLFields("idp.example.com", pem).sso);
  assert.ok(checkSAMLFields("ftp://idp.example.com", pem).sso);
});

test("server errors land on their field", () => {
  assert.equal(serverFieldError("idp_signing_certs: samlsp: pinned certificate: x509: malformed certificate")?.key, "cert");
  assert.match(serverFieldError("idp_sso_url must be https with TESSERA_ENV=prod")?.text ?? "", /https/);
  assert.equal(serverFieldError("idp_entity_id is required")?.key, "entity");
  assert.equal(serverFieldError("something else"), null);
});
