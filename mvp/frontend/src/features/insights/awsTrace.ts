// Pure helpers behind the AWS fidelity badges and the "Why?" trace viewer. No DOM and no imports of
// React, so `npm test` covers them. The shapes are the Go ones (internal/authz/core.go); a Go nil
// slice or map arrives as null, so every list is read through `?? []`.
import type { AwsAtom, AwsResidual, AwsSpan, AwsStep, AwsStmtRef } from "../../api";

export type Tone = "ok" | "warning" | "bad" | "neutral" | "info";

/** The three fidelity values the API returns (authz.Fidelity). Always shown in words, never colour alone. */
export function fidelityTone(f: string): Tone {
  return f === "exact" ? "ok" : f === "approximate" ? "warning" : "bad";
}

export function fidelityMeaning(f: string): string {
  switch (f) {
    case "exact": return "Every input the engine models was known; no downgrade reason applies.";
    case "approximate": return "An assumption the engine had to make could change this answer. Shown for information; least privilege never acts on it.";
    case "unsupported": return "The engine cannot answer this reliably, for example because a policy could not be read. Do not rely on it.";
    default: return "Unknown fidelity; treat it as unsupported.";
  }
}

/** The decision outcome (authz.Outcome): allow, deny or conditional. */
export function outcomeTone(o: string): Tone {
  return o === "allow" ? "ok" : o === "deny" ? "bad" : o === "conditional" ? "warning" : "neutral";
}

export function outcomeMeaning(o: string, denyKind: string): string {
  if (o === "allow") return "Allowed.";
  if (o === "conditional") return "Allowed only if the condition below holds; the request context needed to decide was not known.";
  if (o === "deny") {
    if (denyKind === "explicit") return "Denied by a Deny statement.";
    if (denyKind === "guardrail") return "Denied by a guardrail that is not a policy, such as S3 Block Public Access.";
    return "Denied because nothing allowed it, or a required layer had no Allow.";
  }
  return "Unknown outcome.";
}

const STAGES: Record<string, string> = {
  parse: "Policy parsing", context: "Request context", explicit_deny: "Explicit deny", rcp: "Resource control policy (RCP)",
  scp: "Service control policy (SCP)", resource_policy: "Resource policy", identity: "Identity policy", boundary: "Permissions boundary",
  session: "Session policy", kms_grant: "KMS grant", s3_acl: "S3 ACL", s3_bpa: "S3 Block Public Access", vpce: "VPC endpoint policy",
  cross_account: "Cross-account check", special_rule: "Service-specific rule", final: "Final decision",
};
export const stageLabel = (s: string) => STAGES[s] ?? s;

const RESULTS: Record<string, [string, Tone]> = {
  allow: ["Allowed", "ok"], deny: ["Denied", "bad"], no_match: ["No match", "neutral"], not_applicable: ["Not applicable", "neutral"],
  pass: ["Passed", "ok"], fail: ["Failed", "bad"], conditional: ["Conditional", "warning"],
};
export const resultLabel = (r: string) => RESULTS[r]?.[0] ?? r;
export const resultTone = (r: string): Tone => RESULTS[r]?.[1] ?? "neutral";

const MAX_DEPTH = 8;
const MAX_TEXT = 600;

export function atomText(a: AwsAtom): string {
  const vals = (a.values ?? []).join(", ");
  const op = `${a.qualifier ? `${a.qualifier}:` : ""}${a.op}${a.if_exists ? "IfExists" : ""}`;
  return `${a.negated ? "not " : ""}${a.raw_key || a.key} ${op} [${vals}]`;
}

function isAtom(r: object): r is AwsAtom {
  return "op" in r && "key" in r;
}

/** A residual as one line of text: the formula that must hold for a conditional answer to be an allow. */
export function residualText(r: AwsResidual | undefined, depth = 0): string {
  if (r === null || r === undefined) return "";
  if (typeof r === "boolean") return r ? "always true" : "never true";
  if (depth > MAX_DEPTH) return "…";
  let out: string;
  if ("and" in r) out = `(${(r.and ?? []).map((t) => residualText(t, depth + 1)).join(" AND ") || "always true"})`;
  else if ("or" in r) out = `(${(r.or ?? []).map((t) => residualText(t, depth + 1)).join(" OR ") || "never true"})`;
  else if ("not" in r) out = `NOT ${residualText(r.not, depth + 1)}`;
  else if (isAtom(r)) out = atomText(r);
  else out = "";
  return out.length > MAX_TEXT ? `${out.slice(0, MAX_TEXT)}…` : out;
}

const lastPart = (arn: string) => arn.split(/[/:]/).filter(Boolean).pop() ?? arn;

export function spanText(s: AwsSpan | null): string {
  if (!s) return "";
  return s.start_line === s.end_line ? `line ${s.start_line}` : `lines ${s.start_line} to ${s.end_line}`;
}

/** "SCP p-1234, statement 2 (Sid), at ou-abcd": which policy and statement a step is about. */
export function stmtText(s: AwsStmtRef): string {
  const name = s.policy_id || lastPart(s.source_arn);
  const parts = [`${s.policy_kind} ${name}`.trim(), `statement ${s.statement_index + 1}${s.sid ? ` (${s.sid})` : ""}`];
  if (s.org_level) parts.push(`at ${s.org_level}`);
  const at = spanText(s.span);
  if (at) parts.push(at);
  return parts.join(", ");
}

/** The sentence a screen reader gets for a step: stage, result, statement, and whether it decided the answer. */
export function stepSummary(st: AwsStep): string {
  const parts = [stageLabel(st.stage), resultLabel(st.result)];
  if (st.statement) parts.push(stmtText(st.statement));
  if (st.decisive) parts.push("decisive");
  return parts.join(": ");
}

export function matchedOn(st: AwsStep): [string, string][] {
  return Object.entries(st.matched_on ?? {}).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
}

/** True when the id is a 64-hex explanation id (the server checks too). */
export const isExplanationId = (id: string | null): id is string => !!id && /^[0-9a-f]{64}$/.test(id);

export function shortId(id: string): string {
  return id.length > 12 ? `${id.slice(0, 8)}…` : id;
}
