import type { Affiliation, AffiliationType, PersonIdentifier, PersonState } from "../../api";

/** Labels and rules for affiliations and identifiers (issue #64). No React, so `npm test` can import it. */

export const AFFILIATION_LABEL: Record<AffiliationType, string> = {
  employee: "Employee",
  student: "Student",
  applicant: "Applicant",
  admit: "Admitted student",
  prehire: "Pre-hire",
  contractor: "Contractor",
  guest_visitor: "Guest visitor",
  volunteer: "Volunteer",
  partner: "Partner",
  alum: "Alum",
  retiree: "Retiree",
};

/**
 * Types an administrator may add by hand. Employee, student, applicant, admit and pre-hire come from
 * the HR or student system; the API refuses them (type_not_manual), this list only keeps them out of the form.
 */
export const MANUAL_TYPES: AffiliationType[] = ["guest_visitor", "contractor", "volunteer", "partner", "alum", "retiree"];

/** Types that must have an end date (every guest relationship has one). */
export const NEEDS_END: AffiliationType[] = ["guest_visitor", "contractor", "volunteer", "partner"];

export const SOURCE_LABEL: Record<Affiliation["source"], string> = {
  hris: "HR system",
  sis: "Student system",
  sponsorship: "Sponsorship",
  partner_org: "Partner organization",
  manual: "Added by an administrator",
};

export const STATE_LABEL: Record<PersonState, string> = {
  unaffiliated: "No affiliation",
  prospective: "Prospective",
  active: "Active",
  expiring: "Expiring",
  expired: "Expired",
  revoked: "Revoked",
  merged: "Merged",
};

export const STATE_TONE: Record<PersonState, "ok" | "warning" | "critical" | "neutral" | "info"> = {
  unaffiliated: "neutral",
  prospective: "info",
  active: "ok",
  expiring: "warning",
  expired: "neutral",
  revoked: "critical",
  merged: "neutral",
};

export const VERIFIED_LABEL: Record<NonNullable<PersonIdentifier["verified_by"]>, string> = {
  confirmation_code: "Confirmation code",
  federation: "Federation",
  authoritative_source: "Authoritative source",
  proofing_agent: "Proofing agent",
};

export const IDENTIFIER_LABEL: Record<string, string> = {
  email: "Email",
  phone: "Phone",
  employee_id: "Employee ID",
  student_id: "Student ID",
  applicant_id: "Applicant ID",
  netid: "NetID",
  eppn: "eduPersonPrincipalName",
  saml_subject_id: "SAML subject ID",
  saml_pairwise_id: "SAML pairwise ID",
  oidc_sub: "OIDC subject",
  national_id_hmac: "National ID (hash only)",
};

/** A pending or running affiliation can be ended; ended and revoked ones are history. */
/** An administrator may end only the relationships they may add; HR and student ones end at the source. */
export const canEnd = (a: Pick<Affiliation, "status" | "type">) =>
  (a.status === "pending" || a.status === "active") && MANUAL_TYPES.includes(a.type);

/** A date input value (YYYY-MM-DD) as the end of that day in UTC, or undefined when empty or invalid. */
export function endOfDayUtc(day: string): string | undefined {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) return undefined;
  const d = new Date(`${day}T23:59:59Z`);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

/** What the form can say about its own input before the API does. */
export function addProblem(type: AffiliationType, endDay: string, reason: string, now = new Date()): string | null {
  if (!reason.trim()) return "Say why: the reason goes in the audit record.";
  if (NEEDS_END.includes(type) && !endDay) return `${AFFILIATION_LABEL[type]} needs an end date.`;
  if (endDay) {
    const end = endOfDayUtc(endDay);
    if (!end) return "The end date is not a date.";
    if (new Date(end) <= now) return "The end date must be in the future.";
  }
  return null;
}
