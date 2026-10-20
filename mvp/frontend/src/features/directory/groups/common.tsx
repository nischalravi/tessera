import { ReactNode, useId } from "react";
import { Link } from "react-router-dom";
import { Folder, Users } from "lucide-react";
import { GrpGroup, IdentityRow, useApi } from "../../../api";
import { Badge, Callout, Chip } from "../../../components";
import { parseIdentityRef } from "./model";

export const DEFINITION_LABEL: Record<string, string> = { basic: "Basic", composite: "Composite", policy: "Policy" };
export const OP_LABEL: Record<string, string> = { union: "Union (any of)", intersection: "Intersection (all of)", complement: "Complement (first minus the rest)" };

/** The type, definition and status of a group as badges. */
export function GroupBadges({ g }: { g: GrpGroup }) {
  return (
    <>
      <Badge tone="outline">{g.type === "role" ? "Role" : "Group"}</Badge>
      {g.definition !== "basic" && <Badge tone="accent">{DEFINITION_LABEL[g.definition] ?? g.definition}{g.composite_op ? ` · ${g.composite_op}` : ""}</Badge>}
      {g.status !== "active" && <Badge tone="warning">{g.status === "deleted" ? "Deleted" : "Disabled"}</Badge>}
      {g.managed_by !== "ui" && <Badge tone="info">{g.managed_by.replace(/_/g, " ")}</Badge>}
    </>
  );
}

/** Shown while a queued recompute has not finished: the members listed may lag. */
export function RecomputeBanner({ state }: { state: string }) {
  if (state === "clean") return null;
  return (
    <Callout tone={state === "failed" ? "bad" : "warn"}>
      {state === "failed"
        ? "The last recalculation of this group's members failed. The member lists may be out of date; an administrator can verify the engine."
        : "Recalculating members… a large change is still being applied, so the effective members below may lag behind."}
    </Callout>
  );
}

export const FolderLink = ({ id, children }: { id: string; children: ReactNode }) => (
  <Link to={`/directory/groups/folders/${id}`} className="row tight"><Folder size={14} aria-hidden />{children}</Link>
);
export const GroupLink = ({ id, children }: { id: string; children: ReactNode }) => (
  <Link to={`/directory/groups/${id}`} className="row tight"><Users size={14} aria-hidden />{children}</Link>
);

/**
 * Pick a person by typing a name or an id. `value` is the id (null while nothing valid is chosen);
 * the list of suggestions is every identity the caller may see (the identities API is its own gate).
 */
export function IdentityPicker({ label, text, onText, onPick, autoFocus }: { label: string; text: string; onText: (t: string) => void; onPick: (id: number | null) => void; autoFocus?: boolean }) {
  const list = useId();
  const { data } = useApi<IdentityRow[]>("/identities");
  const options = (data ?? []).slice(0, 2000);
  const set = (t: string) => {
    onText(t);
    onPick(parseIdentityRef(t));
  };
  return (
    <label className="field">
      <span>{label}</span>
      <input className="input" list={list} value={text} onChange={(e) => set(e.target.value)} placeholder="Name, or an identity id" autoComplete="off" data-autofocus={autoFocus || undefined} />
      <datalist id={list}>
        {options.map((i) => <option key={i.id} value={`${i.name} (#${i.id})`} />)}
      </datalist>
    </label>
  );
}

export const Mono = ({ children }: { children: ReactNode }) => <Chip mono>{children}</Chip>;

/** A date as shown in a table, "Never" for none (the start of a membership shows "Always" for none). */
export const fmtWhen = (s: string | null | undefined, none = "Never") => (s ? new Date(s).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : none);
