// Review types (issue #298): the page's wording and the checks the form makes before the server does.
import type { OnIncomplete, ReviewTypeRow, ReviewTypeSettings, ReviewerSource } from "../../api";

export const SOURCE_LABEL: Record<ReviewerSource, string> = {
  owner: "The owner",
  owner_or_backup: "The owner, else the backup owner",
  fixed: "One named person",
};

export const INCOMPLETE_LABEL: Record<OnIncomplete, string> = {
  revoke: "Revoke the undecided items",
  escalate: "Escalate to the fallback reviewer, then revoke",
  keep: "Keep the access and close the review incomplete",
};

export const INCOMPLETE_HINT: Record<OnIncomplete, string> = {
  revoke: "What every review did before: items nobody decided are revoked at the due date.",
  escalate: "The fallback reviewer gets the undecided items for the days below; what is still undecided then is revoked.",
  keep: "Nothing is removed. The review closes as incomplete and the audit log records how many items stayed undecided.",
};

export function reviewTypeProblem(s: ReviewTypeSettings): string | null {
  if (s.reviewer_source === "fixed" && s.reviewer_id === null) return "Choose the person who reviews.";
  if (s.on_incomplete === "escalate" && s.fallback_reviewer_id === null) return "Escalation goes to the fallback reviewer: choose one.";
  if (s.on_incomplete === "escalate" && !(Number.isInteger(s.escalation_days) && s.escalation_days >= 1 && s.escalation_days <= 30)) {
    return "Escalation lasts 1 to 30 days.";
  }
  return null;
}

/** Who reviews, in words, for the table. */
export function summary(t: ReviewTypeRow): string {
  if (t.reviewer_source === "fixed") return t.reviewer_person?.name ?? "A named person";
  return `${SOURCE_LABEL[t.reviewer_source]} (${t.reviewer})`;
}
