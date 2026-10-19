import type { IdentityRow, SessionInfo } from "../api";

/**
 * The directory person a signed-in user is: the identity the server linked the sign-in to
 * (`session.user.identity_id`) first, the email match only as a fallback for sessions the server
 * has not linked. null when there is neither, or the directory has not loaded.
 */
export function resolveMe(
  identities: IdentityRow[] | null | undefined,
  user: Pick<SessionInfo["user"], "email" | "identity_id"> | null | undefined,
): IdentityRow | null {
  if (!identities || !user) return null;
  if (user.identity_id != null) {
    const linked = identities.find((i) => i.id === user.identity_id);
    if (linked) return linked;
  }
  const email = user.email?.toLowerCase();
  return email ? identities.find((i) => i.email?.toLowerCase() === email) ?? null : null;
}
