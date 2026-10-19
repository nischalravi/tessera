import { FormEvent, ReactNode, useState } from "react";
import { UserCheck } from "lucide-react";
import {
  Group, IdentityRow, OwnedKind, OwnedObject, OwnershipList, bulkSetOwnership, fmtDay, ownedObject, ownershipPath, setOwnership, useApi,
} from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, Drawer, IdLink, useToast } from "../../components";

/**
 * Ownership of applications, entitlements, resources and machine identities (issue #167): who is
 * accountable (primary), who covers (backup), which group co-owns it, and why it exists. Owners
 * approve requests and review access; when an owner leaves, the leaver plan promotes the backup.
 */
export const KIND_LABEL: Record<OwnedKind, string> = { app: "Applications", group: "Entitlements", resource: "Resources", identity: "Machine identities" };
const KIND_ONE: Record<OwnedKind, string> = { app: "application", group: "entitlement", resource: "resource", identity: "machine identity" };

function usePeople() {
  return useApi<IdentityRow[]>("/identities?type=human&status=active").data ?? [];
}

function PersonSelect({ label, value, onChange, people, exclude, required }: {
  label: string; value: string; onChange: (v: string) => void; people: IdentityRow[]; exclude?: string; required?: boolean;
}) {
  return (
    <label className="field">{label}
      <select className="input" value={value} onChange={(e) => onChange(e.target.value)} required={required}>
        <option value="">{required ? "Choose a person…" : "Nobody"}</option>
        {people.filter((p) => String(p.id) !== exclude).map((p) => <option key={p.id} value={p.id}>{p.name}{p.department ? ` · ${p.department}` : ""}</option>)}
      </select>
    </label>
  );
}

const num = (v: string) => (v ? Number(v) : null);

/** Edit one object's owners and purpose. */
export function OwnerForm({ obj, onClose, onSaved }: { obj: OwnedObject; onClose: () => void; onSaved?: (o: OwnedObject) => void }) {
  const people = usePeople();
  const { data: groups } = useApi<Group[]>("/groups");
  const toast = useToast();
  const [f, setF] = useState({
    primary: obj.primary_owner ? String(obj.primary_owner.id) : "", backup: obj.backup_owner ? String(obj.backup_owner.id) : "",
    group: obj.owner_group ? String(obj.owner_group.id) : "", purpose: obj.purpose,
  });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const o = await setOwnership(obj.kind, obj.key, { primary_owner_id: num(f.primary), backup_owner_id: f.primary ? num(f.backup) : null, owner_group_id: num(f.group), purpose: f.purpose });
      toast(`Owners of ${obj.label} saved`);
      onSaved?.(o);
      onClose();
    } catch (err: any) {
      setError(String(err.message ?? err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Drawer title={`Owners of ${obj.label}`} sub={KIND_ONE[obj.kind]} onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        {obj.source === "connector" && <Callout tone="info">The connector names {obj.primary_owner?.name} as owner. Saving here takes over: later syncs keep the owner you set.</Callout>}
        <PersonSelect label="Owner" value={f.primary} onChange={(v) => setF({ ...f, primary: v, backup: v === f.backup ? "" : f.backup })} people={people} />
        <PersonSelect label="Backup owner" value={f.backup} onChange={(v) => setF({ ...f, backup: v })} people={f.primary ? people : []} exclude={f.primary} />
        <label className="field">Owner group
          <select className="input" value={f.group} onChange={(e) => setF({ ...f, group: e.target.value })}>
            <option value="">None</option>
            {(groups ?? []).map((g) => <option key={g.id} value={g.id}>{g.system}:{g.name}</option>)}
          </select>
        </label>
        <label className="field">Purpose<textarea className="input" rows={3} maxLength={500} value={f.purpose} onChange={(e) => setF({ ...f, purpose: e.target.value })} placeholder={`Why this ${KIND_ONE[obj.kind]} exists and who uses it`} /></label>
        <p className="small muted">Owners approve access requests and review access. When the owner leaves, the leaver plan hands it to the backup, or to the owner's manager.</p>
        {error && <Callout tone="bad">{error}</Callout>}
        <div className="row"><Button type="submit" variant="primary" disabled={busy}>{busy ? "Saving…" : "Save"}</Button><Button onClick={onClose}>Cancel</Button></div>
      </form>
    </Drawer>
  );
}

/** Give several objects the same owner and backup; each keeps its purpose. */
export function BulkOwnerDrawer({ objects, onClose, onDone }: { objects: { kind: OwnedKind; key: string; label: string }[]; onClose: () => void; onDone?: () => void }) {
  const people = usePeople();
  const toast = useToast();
  const [primary, setPrimary] = useState("");
  const [backup, setBackup] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await bulkSetOwnership(objects.map(({ kind, key }) => ({ kind, key })), { primary_owner_id: num(primary), backup_owner_id: num(backup), owner_group_id: null });
      toast(`Owner set on ${r.updated} ${r.updated === 1 ? "object" : "objects"}`);
      onDone?.();
      onClose();
    } catch (err: any) {
      setError(String(err.message ?? err));
    } finally {
      setBusy(false);
    }
  };
  const shown = objects.slice(0, 8).map((o) => o.label).join(", ");
  return (
    <Drawer title={`Assign an owner to ${objects.length} ${objects.length === 1 ? "object" : "objects"}`} onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        <p className="small">{shown}{objects.length > 8 ? ` and ${objects.length - 8} more` : ""}</p>
        <PersonSelect label="Owner" value={primary} onChange={(v) => { setPrimary(v); if (v === backup) setBackup(""); }} people={people} required />
        <PersonSelect label="Backup owner" value={backup} onChange={setBackup} people={people} exclude={primary} />
        <p className="small muted">This replaces the owner, backup and owner group of every selected object. Purposes are kept.</p>
        {error && <Callout tone="bad">{error}</Callout>}
        <div className="row"><Button type="submit" variant="primary" disabled={busy}>{busy ? "Saving…" : "Assign"}</Button><Button onClick={onClose}>Cancel</Button></div>
      </form>
    </Drawer>
  );
}

export function OwnerCell({ o }: { o: OwnedObject }) {
  if (!o.primary_owner) return <Badge tone="critical">No owner</Badge>;
  return <span className="small nowrap"><IdLink i={{ ...o.primary_owner, type: "human", status: "active" }} />{o.backup_owner && <span className="faint"> · backup {o.backup_owner.name}</span>}</span>;
}

/** Owner rows for a detail panel's <dl>, with an Edit button for ownership managers. */
export function OwnershipRows({ kind, objectKey, label, extra }: { kind: OwnedKind; objectKey: string | number; label: string; extra?: ReactNode }) {
  const { data, reload } = useApi<OwnershipList>(ownershipPath(kind));
  const { can } = useSession();
  const [edit, setEdit] = useState(false);
  const o = ownedObject(data, objectKey) ?? { kind, key: String(objectKey), label, primary_owner: null, backup_owner: null, owner_group: null, purpose: "", source: null, updated_at: null };
  return (
    <>
      <dt>Owner</dt>
      <dd>
        <span className="row tight">
          <OwnerCell o={o} />
          {can("ownership.manage") && <Button size="sm" variant="ghost" icon={<UserCheck size={14} />} onClick={() => setEdit(true)}>{o.primary_owner ? "Change" : "Assign"}</Button>}
        </span>
      </dd>
      {o.owner_group && <><dt>Owner group</dt><dd className="small">{o.owner_group.name}</dd></>}
      {o.purpose && <><dt>Purpose</dt><dd className="small">{o.purpose}</dd></>}
      {o.updated_at && <><dt>Owner set</dt><dd className="small">{fmtDay(o.updated_at)}</dd></>}
      {extra}
      {edit && <OwnerForm obj={o} onClose={() => setEdit(false)} onSaved={() => reload()} />}
    </>
  );
}
