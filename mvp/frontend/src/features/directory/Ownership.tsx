import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { UserCheck } from "lucide-react";
import { OwnedKind, OwnedObject, OwnershipList, ownershipPath, relTime, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Column, DataTable, Page, Tabs } from "../../components";
import { BulkOwnerDrawer, KIND_LABEL, OwnerCell, OwnerForm } from "./owners";

const KINDS: OwnedKind[] = ["app", "group", "resource", "identity"];

/** Ownership coverage (issue #167): every application, entitlement, resource and machine identity with its owners. */
export function Ownership() {
  const [params, setParams] = useSearchParams();
  const kind = (KINDS.includes(params.get("kind") as OwnedKind) ? params.get("kind") : "group") as OwnedKind;
  const { data, error, reload } = useApi<OwnershipList>(ownershipPath(kind));
  const { can } = useSession();
  const manage = can("ownership.manage");
  const [edit, setEdit] = useState<OwnedObject | null>(null);
  const [bulk, setBulk] = useState<OwnedObject[] | null>(null);
  const setKind = (k: OwnedKind) => {
    const next = new URLSearchParams(params);
    next.set("kind", k);
    setParams(next, { replace: true });
  };
  const counts = data?.counts;
  const unowned = counts ? KINDS.reduce((n, k) => n + counts[k].unowned, 0) : null;
  const cols: Column<OwnedObject>[] = [
    { id: "label", header: KIND_LABEL[kind].replace(/s$/, ""), sort: (r) => r.label.toLowerCase(), csv: (r) => r.label, cell: (r) => <span className="name-link">{r.label}</span> },
    { id: "owner", header: "Owner", sort: (r) => r.primary_owner?.name ?? "", csv: (r) => r.primary_owner?.name ?? "", cell: (r) => <OwnerCell o={r} /> },
    { id: "group", header: "Owner group", sort: (r) => r.owner_group?.name ?? "", csv: (r) => r.owner_group?.name ?? "", cell: (r) => <span className="small">{r.owner_group?.name ?? <span className="faint">-</span>}</span>, hideNarrow: true },
    { id: "purpose", header: "Purpose", csv: (r) => r.purpose, cell: (r) => <span className="small truncate">{r.purpose || <span className="faint">-</span>}</span>, hideNarrow: true },
    { id: "source", header: "Set by", sort: (r) => r.source ?? "", csv: (r) => r.source ?? "", cell: (r) => (r.source === "tessera" ? <span className="small nowrap">Tessera{r.updated_at && <span className="faint"> · {relTime(r.updated_at)}</span>}</span> : r.source === "connector" ? <Badge tone="outline">Connector</Badge> : <span className="faint">-</span>), hideNarrow: true },
  ];
  return (
    <Page
      title="Ownership"
      count={unowned == null ? null : `${unowned.toLocaleString()} without an owner`}
      crumbs={[["Identity"], ["Ownership"]]}
      sub="Owners approve access requests and review access. When an owner leaves, the leaver plan promotes the backup owner, or hands it to the owner's manager."
      tabs={<Tabs label="Object kind" value={kind} onChange={setKind} tabs={KINDS.map((k) => ({ id: k, label: <>{KIND_LABEL[k]}{counts && counts[k].unowned > 0 && <> <Badge tone="critical">{counts[k].unowned}</Badge></>}</> }))} />}
    >
      <DataTable
        key={kind}
        id={`ownership-${kind}`}
        rows={data?.kind === kind ? data.items : null}
        error={error}
        rowKey={(r) => r.key}
        columns={cols}
        initialSort={["owner", 1]}
        searchText={(r) => `${r.label} ${r.primary_owner?.name ?? ""} ${r.backup_owner?.name ?? ""} ${r.purpose}`}
        searchPlaceholder={`Search ${KIND_LABEL[kind].toLowerCase()} or owners…`}
        filters={[
          { id: "owned", label: "Owner", options: [{ value: "no", label: "No owner" }, { value: "yes", label: "Has owner" }, { value: "nobackup", label: "No backup" }], get: (r) => (r.primary_owner ? (r.backup_owner ? ["yes"] : ["yes", "nobackup"]) : ["no"]) },
          { id: "source", label: "Set by", options: [{ value: "tessera", label: "Tessera" }, { value: "connector", label: "Connector" }], get: (r) => r.source },
        ]}
        onRefresh={reload}
        bulkActions={manage ? [{ label: "Assign owner", icon: <UserCheck size={16} />, run: (rs) => setBulk(rs) }] : []}
        rowLabel={(r) => r.label}
        onRowClick={manage ? (r) => setEdit(r) : undefined}
      />
      {edit && <OwnerForm obj={edit} onClose={() => setEdit(null)} onSaved={() => reload()} />}
      {bulk && <BulkOwnerDrawer objects={bulk} onClose={() => setBulk(null)} onDone={() => reload()} />}
    </Page>
  );
}
