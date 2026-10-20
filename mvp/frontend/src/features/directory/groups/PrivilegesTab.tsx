import { FormEvent, useState } from "react";
import { Plus, Search, ShieldCheck, Trash2 } from "lucide-react";
import { GrpGroup, GrpList, PrivRow, groups } from "../../../api";
import { Badge, Button, Callout, Drawer, EmptyState, Loading, useConfirm, useToast } from "../../../components";
import { IdentityPicker } from "./common";
import { errText, useLoad } from "./hooks";
import { grantBody, parseIdentityRef, privilegesFor } from "./model";

type Kind = "group" | "folder";
const APPLIES: Record<string, string> = { self: "This folder", groups: "Groups inside", folders: "Folders inside", attr_defs: "Attribute definitions inside" };

const holderText = (r: PrivRow) => (r.holder_type === "everyone" ? "Everyone" : r.holder_name || r.holder_id || "");
const scopeText = (r: PrivRow) => (r.applies_to === "self" ? "This object" : `${APPLIES[r.applies_to] ?? r.applies_to}, ${r.scope === "one" ? "one level" : "all levels"}`);

/**
 * Privileges of a group or folder: who holds what directly or by inheritance, and why (the explanation lists every
 * path). Granting and revoking need the object's admin privilege; the server checks it on every request.
 */
export function PrivilegesTab({ kind, id, name, canWrite }: { kind: Kind; id: string; name: string; canWrite: boolean }) {
  const toast = useToast();
  const confirm = useConfirm();
  const rows = useLoad(() => groups.privileges(kind, id), `privs:${kind}:${id}`);
  const [grant, setGrant] = useState(false);
  const [asked, setAsked] = useState<number | undefined>(undefined);
  const [whoText, setWhoText] = useState("");
  const explain = useLoad(() => groups.effectivePrivileges(kind, id, asked), `effective:${kind}:${id}:${asked ?? "me"}`);

  const revoke = async (r: PrivRow) => {
    const ok = await confirm({
      title: `Revoke ${r.privilege}?`, danger: true, confirmLabel: "Revoke",
      body: `${holderText(r)} will no longer hold ${r.privilege} on ${r.object_name || name}${r.applies_to === "self" ? "" : ` (${scopeText(r)})`}. Access they have another way is not affected.`,
    });
    if (ok === null) return;
    try {
      await groups.revoke(kind, id, r.id);
      toast("Privilege revoked");
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  };

  return (
    <div className="stack">
      <section className="stack-sm">
        <div className="spread">
          <h3 style={{ fontSize: "var(--fs-lg)" }}>Granted here</h3>
          {canWrite && <Button icon={<Plus size={14} />} onClick={() => setGrant(true)}>Grant a privilege</Button>}
        </div>
        {!rows.data && <Loading error={rows.error} kind="block" />}
        {rows.data && rows.data.items.length === 0 && <EmptyState title="No privileges granted here" icon={<ShieldCheck size={18} />}>Anyone with a platform role that covers groups still has access. Inherited privileges from folders above are listed under &ldquo;Who can do what&rdquo;.</EmptyState>}
        {rows.data && rows.data.items.length > 0 && (
          <div className="table-scroll">
            <table>
              <caption className="sr-only">Privileges granted on {name}</caption>
              <thead><tr><th scope="col">Holder</th><th scope="col">Privilege</th><th scope="col">Applies to</th><th scope="col">Source</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>
                {rows.data.items.map((r) => (
                  <tr key={r.id}>
                    <td>{holderText(r)} <span className="faint small">({r.holder_type})</span></td>
                    <td><span className="sys">{r.privilege}</span></td>
                    <td>{scopeText(r)}</td>
                    <td>{r.source}{r.granted_by ? <span className="faint small"> by {r.granted_by}</span> : null}</td>
                    <td>{canWrite && <Button size="sm" variant="ghost" icon={<Trash2 size={14} />} label={`Revoke ${r.privilege} from ${holderText(r)}`} onClick={() => revoke(r)} />}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="stack-sm">
        <h3 style={{ fontSize: "var(--fs-lg)" }}>Who can do what</h3>
        <form className="row" onSubmit={(e: FormEvent) => { e.preventDefault(); setAsked(parseIdentityRef(whoText) ?? undefined); }}>
          <div className="grow"><IdentityPicker label="Explain for another person (administrators only)" text={whoText} onText={setWhoText} onPick={() => undefined} /></div>
          <Button type="submit" icon={<Search size={14} />}>Explain</Button>
          {asked !== undefined && <Button onClick={() => { setAsked(undefined); setWhoText(""); }}>Show mine</Button>}
        </form>
        {!explain.data && <Loading error={explain.error} kind="block" />}
        {explain.data && (
          <ul className="stack-sm" style={{ listStyle: "none", padding: 0 }} aria-label="Effective privileges">
            {explain.data.privileges.map((p) => (
              <li key={p.privilege} className="card" style={{ padding: "8px 12px" }}>
                <div className="row tight"><span className="sys">{p.privilege}</span><Badge tone={p.allowed ? "ok" : "neutral"}>{p.allowed ? "Allowed" : "Not held"}</Badge></div>
                {p.paths.length > 0 && <ul className="small" style={{ margin: "4px 0 0", paddingLeft: 18 }}>{p.paths.map((x, i) => <li key={i}>{x.text}</li>)}</ul>}
              </li>
            ))}
          </ul>
        )}
      </section>

      {grant && <GrantDrawer kind={kind} id={id} name={name} onClose={() => setGrant(false)} />}
    </div>
  );
}

function GrantDrawer({ kind, id, name, onClose }: { kind: Kind; id: string; name: string; onClose: () => void }) {
  const toast = useToast();
  const [f, setF] = useState({ privilege: "", holder: "identity" as "identity" | "group" | "everyone", identity: "", group: "", appliesTo: "self", scope: "sub" });
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const all = useLoad<GrpList<GrpGroup>>(f.holder === "group" ? () => groups.listGroups({ limit: 500 }) : null, "grantpick");
  const { body, problem } = grantBody(kind, f);
  const set = (p: Partial<typeof f>) => setF({ ...f, ...p });
  const options = privilegesFor(kind, f.appliesTo);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!body) return;
    setBusy(true);
    setErr(null);
    try {
      await groups.grant(kind, id, body);
      toast("Privilege granted");
      onClose();
    } catch (x) {
      setErr(errText(x));
      setBusy(false);
    }
  };
  return (
    <Drawer title="Grant a privilege" sub={name} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button type="submit" form="grant" variant="primary" disabled={!body || busy}>{busy ? "Granting…" : "Grant"}</Button></>}>
      <form id="grant" className="stack" onSubmit={submit}>
        <label className="field">
          <span>Holder</span>
          <select className="input" value={f.holder} onChange={(e) => set({ holder: e.target.value as typeof f.holder })} data-autofocus>
            <option value="identity">A person</option>
            <option value="group">Members of a group</option>
            <option value="everyone">Everyone (tenant administrators only)</option>
          </select>
        </label>
        {f.holder === "identity" && <IdentityPicker label="Person" text={text} onText={setText} onPick={(n) => set({ identity: n ? String(n) : "" })} />}
        {f.holder === "group" && (
          <label className="field">
            <span>Group</span>
            <select className="input" value={f.group} onChange={(e) => set({ group: e.target.value })}>
              <option value="">Select…</option>
              {(all.data?.items ?? []).map((x) => <option key={x.id} value={x.id}>{x.name}</option>)}
            </select>
          </label>
        )}
        {kind === "folder" && (
          <>
            <label className="field">
              <span>Applies to</span>
              <select className="input" value={f.appliesTo} onChange={(e) => set({ appliesTo: e.target.value, privilege: "" })}>
                {Object.entries(APPLIES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
            </label>
            {f.appliesTo !== "self" && (
              <label className="field">
                <span>How far</span>
                <select className="input" value={f.scope} onChange={(e) => set({ scope: e.target.value })}>
                  <option value="one">One level below this folder</option>
                  <option value="sub">Every level below (inherited as things are added)</option>
                </select>
              </label>
            )}
          </>
        )}
        <label className="field">
          <span>Privilege</span>
          <select className="input" value={f.privilege} onChange={(e) => set({ privilege: e.target.value })}>
            <option value="">Select…</option>
            {options.map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
        </label>
        {f.privilege && <Callout tone="neutral">{f.holder === "everyone" ? "Everyone" : f.holder === "group" ? "Every member of the group" : "This person"} will hold <strong>{f.privilege}</strong>{f.appliesTo === "self" ? ` on ${name}` : ` on ${APPLIES[f.appliesTo].toLowerCase()} ${name}`}. Higher privileges imply the ones below them.</Callout>}
        {problem && f.privilege && <Callout tone="bad">{problem}</Callout>}
        {err && <Callout tone="bad">{err}</Callout>}
      </form>
    </Drawer>
  );
}
