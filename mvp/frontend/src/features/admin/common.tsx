import { ReactNode } from "react";
import { AdminChange, ApiError, fmtDate } from "../../api";
import { Badge } from "../../components";
import { STATUS_LABEL } from "./changeState";

const TONE: Record<AdminChange["status"], "ok" | "warning" | "critical" | "neutral" | "info"> = {
  pending_approval: "warning", cooling_off: "info", applied: "ok", rejected: "neutral", cancelled: "neutral", expired: "neutral", failed: "critical",
};

export const StatusBadge = ({ status }: { status: AdminChange["status"] }) => <Badge tone={TONE[status]} dot>{STATUS_LABEL[status]}</Badge>;

/** A timestamp from the API (ends in Z) as a readable local date. */
export const when = (s?: string | null) => (s ? fmtDate(s.replace("Z", "")) : "—");

/** One labelled fact of a detail panel. */
export function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <div className="xs faint">{label}</div>
      <div className="small">{children}</div>
    </div>
  );
}

/** What a submitted request did, in a sentence for the toast. */
export function outcome(c: AdminChange): string {
  switch (c.status) {
    case "applied": return "Done: the change is applied.";
    case "cooling_off": return `Approved. It takes effect ${when(c.effective_at)}; any admin can cancel it until then.`;
    case "pending_approval": return "Submitted. A different admin must approve it within 72 hours.";
    default: return STATUS_LABEL[c.status];
  }
}

/** The message of an API error (the 409 and 422 bodies carry a plain-language detail). */
export const errText = (e: unknown) => (e instanceof ApiError ? e.message : String((e as Error)?.message ?? e));
