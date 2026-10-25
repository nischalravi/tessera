// Every server readiness template whose config takes a base_url has a Connect-step input for it (issue #555 left
// Salesforce without one). Run with `npm test`.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";

import { BASE_URL_FIELDS } from "../src/features/admin/connections/baseUrl.ts";
import { GOVERNED } from "../src/features/admin/connections/governed.ts";

const dir = new URL("../../server/internal/readiness/templates/", import.meta.url);
// the governed connector types of each template (mirrors CONNECTOR_TYPES in shared.tsx)
const GOVERNED_TYPES: Record<string, string[]> = {
  erp: ["sap", "oracle"], pam: ["cyberark", "beyondtrust", "delinea"], vms: ["fieldglass", "beeline", "csvfeed"],
  githubscan: ["githubscan"], successfactors: ["successfactors"], servicenow: ["servicenow"], atlassian: ["atlassian"], mcp: ["mcp"],
};

test("every template with a base_url config field has an input", () => {
  const needs = readdirSync(dir).filter((f) => f.endsWith(".yaml") && f !== "base.yaml")
    .filter((f) => /config_fields:\s*\[[^\]]*\bbase_url\b/.test(readFileSync(new URL(f, dir), "utf8")))
    .map((f) => f.replace(/\.yaml$/, ""));
  assert.ok(needs.includes("salesforce") && needs.includes("scim_app"), needs.join(","));
  for (const tpl of needs) {
    const gov = GOVERNED_TYPES[tpl];
    if (gov) for (const t of gov) assert.ok(GOVERNED[t]?.baseUrl, `${tpl}: governed type ${t} has no baseUrl field`);
    else assert.ok(BASE_URL_FIELDS[tpl], `${tpl}: no base URL input on the Connect step`);
  }
});
