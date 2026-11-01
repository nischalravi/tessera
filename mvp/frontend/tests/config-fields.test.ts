// Every config field a server readiness template item declares has a wizard input (issue #595; Workday api_version,
// Entra hybrid and AD use_dirsync once had none, and Google base_dns still has none until #594). Run with `npm test`.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";

import { NOT_AN_INPUT, WIZARD_INPUTS } from "../src/features/admin/connections/configFields.ts";

const dir = new URL("../../server/internal/readiness/templates/", import.meta.url);
const wizard = readFileSync(new URL("../src/features/admin/connections/Wizard.tsx", import.meta.url), "utf8");

function fieldsOf(file: string): string[] {
  const out = new Set<string>();
  for (const m of readFileSync(new URL(file, dir), "utf8").matchAll(/config_fields:\s*\[([^\]]*)\]/g)) {
    for (const f of m[1].split(",").map((s) => s.trim()).filter(Boolean)) out.add(f);
  }
  return [...out];
}
const files = readdirSync(dir).filter((f) => f.endsWith(".yaml"));
const templates = files.filter((f) => f !== "base.yaml").map((f) => f.replace(/\.yaml$/, ""));

test("every template config_fields entry has a wizard input", () => {
  assert.ok(templates.includes("google") && templates.includes("workday") && templates.length > 20, templates.join(","));
  const missing: string[] = [];
  for (const tpl of templates) {
    for (const f of fieldsOf(`${tpl}.yaml`)) {
      if (NOT_AN_INPUT[f]) continue;
      const ok = (WIZARD_INPUTS[f] ?? []).some((i) => i.templates.includes(tpl) || i.templates.includes("*"));
      if (!ok) missing.push(`${tpl}.${f}`);
    }
  }
  assert.deepEqual(missing, [], `config fields with no wizard input (add one in Wizard.tsx and configFields.ts, or justify in NOT_AN_INPUT): ${missing.join(", ")}`);
});

test("the shared base items' fields have an input", () => {
  for (const f of fieldsOf("base.yaml")) assert.ok(WIZARD_INPUTS[f] || NOT_AN_INPUT[f], `base.${f}: no wizard input`);
});

test("each declared input is still rendered by Wizard.tsx", () => {
  for (const [f, inputs] of Object.entries(WIZARD_INPUTS)) {
    for (const i of inputs) assert.ok(new RegExp(i.evidence).test(wizard), `${f} (${i.templates.join(",")}): Wizard.tsx no longer matches ${i.evidence}`);
  }
});

test("the table names real templates and no stale allow-list entry", () => {
  for (const [f, inputs] of Object.entries(WIZARD_INPUTS)) {
    for (const t of inputs.flatMap((i) => i.templates)) assert.ok(t === "*" || templates.includes(t), `${f}: unknown template ${t}`);
  }
  const used = new Set(files.flatMap(fieldsOf));
  for (const f of Object.keys(NOT_AN_INPUT)) assert.ok(used.has(f), `NOT_AN_INPUT.${f} is not declared by any template`);
});
