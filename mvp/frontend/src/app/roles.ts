/** What a user must do to activate a role the session's sign-in is too weak for (reasons from the server's role activation). */
export function inactiveRoleHint(role: string, reason: string): string {
  switch (reason) {
    case "multi_factor_authentication_required":
      return `${role} is inactive: a password alone is not enough, sign in again with a one-time code or a passkey`;
    case "break_glass_key_required":
      return `${role} is inactive: it needs a registered security key`;
    case "phishing_resistant_authentication_required":
      return `${role} is inactive: sign in with a passkey or security key to use it. If your account has none, ask an administrator`;
    default:
      return `${role} is inactive: sign in again with a stronger method to use it`;
  }
}
