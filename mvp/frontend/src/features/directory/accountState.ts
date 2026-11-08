// Account disable and enable in the target systems (issue #915): the wording of the status and of the answers.
// Pure, so `npm test` covers it.
import type { AccountRow, AccountStateResult } from "../../api";

/** What the Status column says: a change waiting for the target's re-read comes first. */
export function accountStatusLabel(a: Pick<AccountRow, "status" | "pending">): string {
  if (a.pending === "disable") return "disable pending";
  if (a.pending === "enable") return "enable pending";
  return a.status;
}

const REASONS: Record<string, string> = {
  target_read_only: "this system is read-only for Tessera",
  not_found: "no longer exists",
  invalid_state: "is not in a state this applies to",
  operation_in_flight: "has the opposite change waiting",
};

/** One sentence for a toast: how many were sent, and why the others were not. */
export function accountStateSummary(verb: "disable" | "enable", rs: AccountStateResult[], name: (id: number) => string = String): { text: string; ok: boolean } {
  const sent = rs.filter((r) => r.status !== "error");
  const held = rs.filter((r) => r.status === "held").length;
  const failed = rs.filter((r) => r.status === "error");
  const head = sent.length
    ? `${sent.length} account${sent.length === 1 ? "" : "s"} sent to ${verb} (${verb} pending until the target confirms)`
    : `Nothing was sent to ${verb}`;
  const heldNote = held ? `, ${held} held for a second admin by the deletion guard` : "";
  if (!failed.length) return { text: head + heldNote + ".", ok: true };
  const f = failed[0];
  const why = REASONS[f.error ?? ""] ?? f.detail ?? "was refused";
  return { text: `${head}${heldNote}. ${failed.length} not sent: ${name(f.id)} ${why}${failed.length > 1 ? ` (and ${failed.length - 1} more)` : ""}.`, ok: sent.length > 0 };
}
