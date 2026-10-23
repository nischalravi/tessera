/** Notification wording (Admin → Notifications): the same placeholder substitution the server does, for the preview and the checks. */
export const SAMPLE: Record<string, string> = {
  subject: "Approval needed: Production database, read access",
  body: "Dana Ito asked for read access to the production database until 14 November.",
  link: "https://tessera.example.com/inbox",
  product: "Tessera",
  recipient: "you@example.com",
};
const PLACEHOLDER = /\{\{\s*([a-z_]+)\s*\}\}/g;
/** The same substitution the server does: only the five placeholders, nothing else. */
export const renderTemplate = (tpl: string, vars: Record<string, string> = SAMPLE) => tpl.replace(PLACEHOLDER, (_m, n: string) => vars[n] ?? "");
/** The first problem with a template, in words, or null (the server checks again). */
export function templateProblem(subject: string, body: string, names: string[], maxSubject: number, maxBody: number): string | null {
  if (!subject.trim() && !body.trim()) return "Give a subject or a body, or reset the kind to its default.";
  if (/[\r\n]/.test(subject)) return "A subject is one line.";
  if (subject.length > maxSubject || body.length > maxBody) return `A subject is at most ${maxSubject} characters and a body ${maxBody}.`;
  for (const t of [subject, body]) {
    for (const m of t.matchAll(PLACEHOLDER)) if (!names.includes(m[1])) return `{{${m[1]}}} is not a placeholder. Use ${names.map((n) => `{{${n}}}`).join(", ")}.`;
    const rest = t.replace(PLACEHOLDER, "");
    if (rest.includes("{{") || rest.includes("}}")) return "A placeholder is written {{name}}.";
  }
  return null;
}

