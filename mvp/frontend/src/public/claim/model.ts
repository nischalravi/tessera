import type { ClaimStatus, ClaimStep } from "../../api";

/**
 * The claim page's rules, with no React and no browser APIs, so `npm test` can run them.
 * The claim link is `<base>/claim#t=<43 characters>`: the token is in the fragment, which the
 * browser never sends in a request line or a Referer.
 */

/** The 43 base64url characters of a 256-bit token. */
const TOKEN = /^[A-Za-z0-9_-]{43}$/;

/** The token in a location hash ("#t=..."), or null. Anything else in the hash is ignored. */
export function tokenFromHash(hash: string): string | null {
  const h = hash.startsWith("#") ? hash.slice(1) : hash;
  for (const part of h.split("&")) {
    const [k, ...v] = part.split("=");
    if (k === "t") {
      const t = v.join("=");
      return TOKEN.test(t) ? t : null;
    }
  }
  return null;
}

/** The URL to leave in the address bar once the token has been read: no fragment, no query. */
export const cleanPath = (pathname: string) => pathname;

const SLUG = /^[a-z0-9][a-z0-9_-]{2,39}$/;

/**
 * Which tenant the page belongs to. A build or deployment may fix it (`configured`); otherwise it is
 * the first label of a tenant host (larkspur.tessera.example), and in development (localhost, an IP
 * address, a bare host) the demo tenant larkspur.
 */
export function tenantSlug(hostname: string, configured?: string): string {
  if (configured && SLUG.test(configured)) return configured;
  const labels = hostname.toLowerCase().split(".");
  if (labels.length >= 3 && SLUG.test(labels[0]) && labels[0] !== "www" && !/^\d+$/.test(labels[0])) return labels[0];
  return "larkspur";
}

export const STEP_LABEL: Record<ClaimStep, string> = {
  verify_contact: "Confirm your email",
  verify_identity: "Verify your identity",
  existing_account: "Existing account",
  credential: "Choose how you sign in",
  complete: "Done",
};

/** The steps a person goes through, from what the API listed (identity verification only when it is the step). */
export function visibleSteps(s: Pick<ClaimStatus, "steps" | "step">): ClaimStep[] {
  return s.steps.filter((x) => x !== "verify_identity" || s.step === "verify_identity");
}

/** 0-based position of the current step among the visible ones. */
export const stepIndex = (s: Pick<ClaimStatus, "steps" | "step">) => Math.max(0, visibleSteps(s).indexOf(s.step));

/** What a six-digit code field holds: digits only, at most six (people paste "123 456"). */
export const normalizeCode = (v: string) => v.replace(/\D/g, "").slice(0, 6);
export const codeReady = (v: string) => normalizeCode(v).length === 6;

const EMAIL = /^[^\s@]+@[^\s@]+$/;
export const emailOk = (v: string) => EMAIL.test(v.trim());

export type ClaimView =
  | { kind: "loading" }
  | { kind: "check_link" }
  | { kind: "step"; step: ClaimStep }
  | { kind: "waiting"; why: "organization" | "identity_verification" }
  | { kind: "complete" };

/** Which screen a status calls for. */
export function viewOf(s: ClaimStatus): ClaimView {
  if (s.complete || s.step === "complete") return { kind: "complete" };
  if (s.pending === "organization" && s.step === "credential") return { kind: "step", step: "credential" };
  if (s.pending === "identity_verification") return { kind: "waiting", why: "identity_verification" };
  return { kind: "step", step: s.step };
}

export type ClaimResult = "complete" | "failed" | "continue";

/**
 * ?result=complete|failed|continue, which the sign-in callbacks send the browser back with.
 * "continue" is a sign-in as an existing account that did not link anything: it looks the same whatever the
 * reason, and the claim goes on at the credential step.
 */
export function resultFromSearch(search: string): ClaimResult | null {
  const v = new URLSearchParams(search).get("result");
  return v === "complete" || v === "failed" || v === "continue" ? v : null;
}

/** Where a "yes, I have an account" answer sends the browser: the sign-in the API started, or nowhere. */
export const signInRedirect = (r: { status?: string; redirect?: string }): string | null =>
  r.status === "redirect" && typeof r.redirect === "string" && r.redirect !== "" ? r.redirect : null;

/** Population in a sentence. */
export const POPULATION_PHRASE: Record<string, string> = {
  visitor: "a visitor",
  contractor: "a contractor",
  volunteer: "a volunteer",
  partner: "a partner",
};
