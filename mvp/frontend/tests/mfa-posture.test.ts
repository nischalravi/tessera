// The MFA posture page asks the API for its filters in the query string, and is reachable:
// a lazy route, a tab of the Insights group and an entry in the palette's page list.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

(globalThis as any).window = Object.assign(new EventTarget(), { location: { assign: () => undefined } });

const api = await import("../src/api.ts");
const src = (p: string) => readFileSync(new URL(`../src/${p}`, import.meta.url), "utf8");

test("the posture path carries only the filters that are set, encoded", () => {
  assert.equal(api.mfaPosturePath("", ""), "/mfa/posture");
  assert.equal(api.mfaPosturePath("Customer Success & Ops", ""), "/mfa/posture?department=Customer+Success+%26+Ops");
  assert.equal(api.mfaPosturePath("", "true"), "/mfa/posture?privileged=true");
  assert.equal(api.mfaPosturePath("Finance", "false"), "/mfa/posture?department=Finance&privileged=false");
});

test("MFA posture is a lazy route, an Insights tab and a searchable page", () => {
  assert.match(src("app/App.tsx"), /const MfaPosture = named\(\(\) => import\("..\/features\/insights\/MfaPosture"\), "MfaPosture"\)/);
  assert.match(src("app/App.tsx"), /path="\/insights\/mfa" element=\{<MfaPosture \/>\}/);
  assert.match(src("components/SectionTabs.tsx"), /to: "\/insights\/mfa", label: "MFA posture"/);
  assert.match(src("app/nav.ts"), /path: "\/insights\/mfa", label: "MFA posture", keywords: "[^"]*passkey/);
});

test("the page goes through the API client only", () => {
  assert.doesNotMatch(src("features/insights/MfaPosture.tsx"), /\bfetch\(/);
});
