// Break-glass in the UI (design §9.6, §15.4): which page the address is, what the session may do, and
// what the admin banner says about sign-ins nobody has explained yet. The API enforces all of it; this
// is the wording and the offers. Pure, so `npm test` covers it.
import type { BreakGlassUse, SessionInfo } from "../../api";
import type { BannerItem } from "./changeState";

/** The tenant slug of /t/<slug>/break-glass, or null for any other path. */
export function breakGlassSlug(pathname: string): string | null {
  const m = pathname.match(/^\/t\/([a-z0-9-]{1,63})\/break-glass\/?$/);
  return m ? m[1] : null;
}

/**
 * The same-origin path of a tenant's break-glass sign-in, or null unless the typed organization is a
 * plain slug (allow-list: lower-case letters, digits and hyphens). Typed text never reaches an href
 * except through this check, and the slug is encoded, so it cannot add a scheme, host or markup.
 */
export function breakGlassPath(typed: string): string | null {
  const slug = typed.trim().toLowerCase();
  return /^[a-z0-9-]{1,63}$/.test(slug) ? `/t/${encodeURIComponent(slug)}/break-glass` : null;
}

/** True for a session that signed in with a break-glass key (its only active role is break_glass). */
export const inBreakGlassSession = (s: Pick<SessionInfo, "active_roles">): boolean => s.active_roles.includes("break_glass");

/** Minutes left until a timestamp from the API (ends in Z), never negative. */
export function minutesLeft(until: string, now: number): number {
  return Math.max(0, Math.ceil((Date.parse(until) - now) / 60_000));
}

/** What the session notice says: how long it has left and what it can do. */
export function sessionNotice(session: Pick<SessionInfo, "session">, now: number): string {
  const left = minutesLeft(session.session.absolute_expires_at, now);
  return `You are in a break-glass session. It ends in ${left} minute${left === 1 ? "" : "s"} (and after 15 idle minutes). ` +
    "It can view admin settings, disable an IdP connection, change its trust, grant tenant_admin to a named user and revoke other sessions. " +
    "Each of those takes effect after one hour unless an admin cancels it, and everyone has been told.";
}

/** The banner lines for sign-ins no admin has explained yet, newest first. */
export function unexplainedItems(uses: BreakGlassUse[]): BannerItem[] {
  return uses
    .filter((u) => !u.answered)
    .sort((a, b) => b.used_at.localeCompare(a.used_at))
    .map((u) => ({
      id: `break-glass:${u.id}`, tone: "bad" as const, to: "/admin/break-glass",
      text: `A break-glass key (${u.key}) was used on ${u.used_at.slice(0, 10)} at ${u.used_at.slice(11, 16)} UTC${u.ip ? ` from ${u.ip}` : ""}. Say why it was used.`,
    }));
}
