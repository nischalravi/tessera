import { useState } from "react";
import { Plus } from "lucide-react";
import { GrpGroup, groupLoaders } from "../../../api";
import { useSession } from "../../../app/auth";
import { Button, Callout, EmptyState, Loading } from "../../../components";
import { useLoad } from "./hooks";
import { LoaderPanel } from "./LoaderPanel";
import { LoaderWizard } from "./LoaderWizard";

/**
 * The Source tab of a group: whether a loader fills it, and everything about that loader. A group edited by hand
 * has no source; a loader makes and owns its own groups, so "Add a source" starts one in this group's folder.
 */
export function LoaderTab({ g }: { g: GrpGroup }) {
  const { can } = useSession();
  const [adding, setAdding] = useState(false);
  const fed = g.managed_by === "loader" && !!g.loader_id;
  const loader = useLoad(fed ? () => groupLoaders.get(g.loader_id!) : null, `loader:${g.loader_id ?? ""}`);
  const canAdmin = can("groups.loader.admin");

  if (fed) {
    return loader.data
      ? <LoaderPanel loader={loader.data} onChanged={loader.reload} />
      : <Loading kind="block" error={loader.error} />;
  }
  return (
    <div className="stack">
      {g.managed_by !== "ui" && <Callout tone="info">This group is managed by {g.managed_by.replace(/_/g, " ")}, not by a membership source.</Callout>}
      <EmptyState title="No source feeds this group"
        action={canAdmin && g.managed_by === "ui" ? <Button variant="primary" icon={<Plus size={16} />} onClick={() => setAdding(true)}>Add a source</Button> : undefined}>
        Its members are added by hand, from a CSV import, or through nesting. A membership source reads a database, a CSV file, a connected system or an identity attribute on a schedule and keeps its groups in sync.
        A source makes its own groups in a folder, so it cannot take over a group that people edit by hand.
      </EmptyState>
      {adding && <LoaderWizard folder={g.folder_id} onClose={() => setAdding(false)} />}
    </div>
  );
}
