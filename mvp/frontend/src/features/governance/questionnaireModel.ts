/**
 * View logic for questionnaires (issue #298): the editor's checks and the answer form's checks. The
 * server validates every answer against the questionnaire version in force (internal/questionnaires);
 * these functions mirror it so people see a problem before they submit. Pure functions; `npm test`
 * covers them.
 */
import type { AnswerValue, AnswersByQuestionnaire, Question, QuestionType, QuestionnaireAnswers, QuestionnaireNeed, QuestionnaireSpec, QuestionnaireTarget, QuestionnaireTargetKind } from "../../api";

export const QUESTION_TYPES: { id: QuestionType; label: string; hint: string }[] = [
  { id: "short_text", label: "Short text", hint: "One line, up to 200 characters unless you set a limit (at most 500)" },
  { id: "long_text", label: "Long text", hint: "Several lines, up to 2000 characters unless you set a limit (at most 5000)" },
  { id: "single_choice", label: "Single choice", hint: "Pick one of the options" },
  { id: "multi_choice", label: "Multiple choice", hint: "Pick any of the options" },
  { id: "yes_no", label: "Yes or no", hint: "A yes or no answer" },
  { id: "date", label: "Date", hint: "A calendar date" },
];

export const typeLabel = (t: QuestionType): string => QUESTION_TYPES.find((x) => x.id === t)?.label ?? t;

export const LIMITS = { questions: 30, title: 120, description: 500, questionText: 300, help: 300, options: 20, optionText: 100, shortText: 500, longText: 5000 };
export const DEFAULT_MAX = { short_text: 200, long_text: 2000 } as const;

const isText = (t: QuestionType) => t === "short_text" || t === "long_text";
const isChoice = (t: QuestionType) => t === "single_choice" || t === "multi_choice";

/** The longest answer a text question takes. */
export const maxLength = (q: Question): number => (q.max_length && q.max_length > 0 ? q.max_length : q.type === "long_text" ? DEFAULT_MAX.long_text : DEFAULT_MAX.short_text);

/** A new question of a type, with an id no other question uses. */
export function blankQuestion(type: QuestionType, existing: Question[]): Question {
  let n = existing.length + 1;
  while (existing.some((q) => q.id === `q${n}`)) n++;
  return { id: `q${n}`, type, text: "", required: false, ...(isChoice(type) ? { options: ["", ""] } : {}) };
}

/** Changing a question's type keeps what still applies and drops what no longer does. */
export function retype(q: Question, type: QuestionType): Question {
  const out: Question = { id: q.id, type, text: q.text, required: q.required };
  if (q.help) out.help = q.help;
  if (isChoice(type)) out.options = q.options && q.options.length >= 2 ? q.options : ["", ""];
  if (isText(type) && q.max_length) out.max_length = q.max_length;
  return out;
}

/** Options are typed one per line. */
export const optionsText = (o: string[] | undefined): string => (o ?? []).join("\n");
export const parseOptions = (text: string): string[] => text.split("\n").map((l) => l.trim()).filter(Boolean);

/** The first problem with an editor draft, or null. Mirrors Spec.Check on the server. */
export function specError(s: QuestionnaireSpec): string | null {
  if (!s.title.trim() || s.title.trim().length > LIMITS.title) return `A title of 1 to ${LIMITS.title} characters is required`;
  if (s.description.trim().length > LIMITS.description) return `The description is at most ${LIMITS.description} characters`;
  if (s.questions.length === 0) return "Add at least one question";
  if (s.questions.length > LIMITS.questions) return `At most ${LIMITS.questions} questions`;
  const seen = new Set<string>();
  for (const [i, q] of s.questions.entries()) {
    const n = i + 1;
    if (seen.has(q.id)) return `Question ${n}: the id ${q.id} is used twice`;
    seen.add(q.id);
    const text = q.text.trim();
    if (!text || text.length > LIMITS.questionText) return `Question ${n}: the text is 1 to ${LIMITS.questionText} characters`;
    if ((q.help ?? "").trim().length > LIMITS.help) return `Question ${n}: the help text is at most ${LIMITS.help} characters`;
    if (isChoice(q.type)) {
      const opts = (q.options ?? []).map((o) => o.trim());
      if (opts.length < 2 || opts.length > LIMITS.options) return `Question ${n}: a choice question has 2 to ${LIMITS.options} options`;
      if (opts.some((o) => !o || o.length > LIMITS.optionText) || new Set(opts).size !== opts.length) return `Question ${n}: options are different from each other, 1 to ${LIMITS.optionText} characters each`;
    }
    if (isText(q.type) && q.max_length) {
      const cap = q.type === "long_text" ? LIMITS.longText : LIMITS.shortText;
      if (!Number.isInteger(q.max_length) || q.max_length < 1 || q.max_length > cap) return `Question ${n}: the maximum length is 1 to ${cap}`;
    }
  }
  return null;
}

/** The spec the server receives: text trimmed, options without blanks, no stray fields. */
export function cleanSpec(s: QuestionnaireSpec): QuestionnaireSpec {
  return {
    title: s.title.trim(),
    description: s.description.trim(),
    questions: s.questions.map((q) => {
      const out: Question = { id: q.id, type: q.type, text: q.text.trim(), required: q.required };
      if (q.help?.trim()) out.help = q.help.trim();
      if (isChoice(q.type)) out.options = (q.options ?? []).map((o) => o.trim());
      if (isText(q.type) && q.max_length) out.max_length = q.max_length;
      return out;
    }),
  };
}

/** Whether two drafts are the same questionnaire (to enable Save only after a change). */
export const sameSpec = (a: QuestionnaireSpec, b: QuestionnaireSpec): boolean => JSON.stringify(cleanSpec(a)) === JSON.stringify(cleanSpec(b));

// ---------------------------------------------------------------- answers

/** Whether an answer counts as given: text trimmed, a choice made, a yes or no chosen. */
export function isAnswered(v: AnswerValue | undefined): boolean {
  if (v === undefined || v === null) return false;
  if (typeof v === "boolean") return true;
  if (Array.isArray(v)) return v.length > 0;
  return v.trim() !== "";
}

/** Why one answer cannot be submitted, or null (a missing optional answer is fine). */
export function answerError(q: Question, v: AnswerValue | undefined): string | null {
  if (!isAnswered(v)) return q.required ? "An answer is required" : null;
  switch (q.type) {
    case "short_text":
    case "long_text": {
      const n = (v as string).trim().length;
      return n > maxLength(q) ? `At most ${maxLength(q)} characters (${n} so far)` : null;
    }
    case "single_choice":
      return typeof v === "string" && (q.options ?? []).includes(v) ? null : "Choose one of the options";
    case "multi_choice":
      return Array.isArray(v) && v.every((x) => (q.options ?? []).includes(x)) ? null : "Choose from the options";
    case "yes_no":
      return typeof v === "boolean" ? null : "Choose yes or no";
    case "date":
      return typeof v === "string" && isDate(v.trim()) ? null : "Enter a date as YYYY-MM-DD";
  }
}

/** A calendar date as YYYY-MM-DD (2026-02-30 is not one). */
export function isDate(s: string): boolean {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
  if (!m) return false;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const t = new Date(Date.UTC(y, mo - 1, d));
  return t.getUTCFullYear() === y && t.getUTCMonth() === mo - 1 && t.getUTCDate() === d;
}

/** The first problem with the answers to a questionnaire, naming the question, or null. */
export function needError(n: QuestionnaireNeed, a: QuestionnaireAnswers | undefined): string | null {
  for (const q of n.questions) {
    const e = answerError(q, a?.[q.id]);
    if (e) return `${n.title}: ${q.text}. ${e}`;
  }
  return null;
}

/** The first problem across every questionnaire a form asks, or null. */
export function needsError(needs: QuestionnaireNeed[], all: AnswersByQuestionnaire): string | null {
  for (const n of needs) {
    const e = needError(n, all[n.id]);
    if (e) return e;
  }
  return null;
}

/** What is sent: answered questions only, text trimmed, a questionnaire left out when nothing in it was answered. */
export function answersPayload(needs: QuestionnaireNeed[], all: AnswersByQuestionnaire): AnswersByQuestionnaire | undefined {
  const out: AnswersByQuestionnaire = {};
  for (const n of needs) {
    const given: QuestionnaireAnswers = {};
    for (const q of n.questions) {
      const v = all[n.id]?.[q.id];
      if (!isAnswered(v)) continue;
      given[q.id] = typeof v === "string" ? v.trim() : (v as AnswerValue);
    }
    if (Object.keys(given).length > 0) out[n.id] = given;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

/** How an answer reads to an approver. */
export function answerText(v: AnswerValue): string {
  if (typeof v === "boolean") return v ? "Yes" : "No";
  return Array.isArray(v) ? v.join(", ") : v;
}

/** The needs of several carts or items merged: one questionnaire is asked once. */
export function mergeNeeds(lists: QuestionnaireNeed[][]): QuestionnaireNeed[] {
  const out: QuestionnaireNeed[] = [];
  for (const l of lists) for (const n of l) if (!out.some((o) => o.id === n.id)) out.push(n);
  return out;
}

export const TARGET_KINDS: { id: QuestionnaireTargetKind; label: string }[] = [
  { id: "privileged", label: "Privileged items and high-risk roles" },
  { id: "catalog_item", label: "Catalog item" },
  { id: "business_role", label: "Business role" },
  { id: "review_campaign", label: "Access review campaign" },
];

/** A target as it reads in a chip; names are looked up by the caller (kind and id -> name). */
export function targetLabel(t: QuestionnaireTarget, names: Record<string, string>): string {
  if (t.kind === "privileged") return "Privileged items and high-risk roles";
  const kind = t.kind === "catalog_item" ? "Item" : t.kind === "business_role" ? "Role" : "Review";
  return `${kind}: ${names[`${t.kind}:${t.target_id}`] ?? t.target_id}`;
}

/** Who is asked, in words: requesters answer at submit, reviewers with each decision. */
export function askedOf(targets: QuestionnaireTarget[]): string {
  if (targets.length === 0) return "Not attached";
  const n = (k: QuestionnaireTargetKind) => targets.filter((t) => t.kind === k).length;
  const parts: string[] = [];
  if (n("privileged")) parts.push("privileged requests");
  if (n("catalog_item")) parts.push(`${n("catalog_item")} item${n("catalog_item") === 1 ? "" : "s"}`);
  if (n("business_role")) parts.push(`${n("business_role")} role${n("business_role") === 1 ? "" : "s"}`);
  if (n("review_campaign")) parts.push(`${n("review_campaign")} review${n("review_campaign") === 1 ? "" : "s"}`);
  return parts.join(", ");
}
