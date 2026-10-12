/** Rotation policies (max age, grace period, adapter per secret kind) and the adapters that reach your vaults and clouds. */
import { FormEvent, ReactNode, useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import {
  ApiError, RotationAdapter, RotationAdapterList, RotationAdapterType, RotationPolicy, RotationSecretStatus, fmtDate, rotation, useApi,
} from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, Chip, Column, DataTable, Drawer, Page, useConfirm, useToast } from "../../components";
import { ADAPTER_FIELDS, ADAPTER_TYPE_LABEL, DEST_PLACEHOLDERS, MODE_LABEL, graceText } from "./model";
import { RotationTabs } from "./shared";

const DESTINATION_TYPES: RotationAdapterType[] = ["vault", "aws_secretsmanager", "fake"];

export function RotationPolicies() {
  const { data: policies, error, reload } = useApi<RotationPolicy[]>(rotation.paths.policies);
  const { data: adapterList, error: adapterError, reload: reloadAdapters } = useApi<RotationAdapterList>(rotation.paths.adapters);
  const { data: secrets } = useApi<RotationSecretStatus[]>(rotation.paths.overview);
  const { can } = useSession();
  const allowed = can("secrets.rotate");
  const [policy, setPolicy] = useState<RotationPolicy | "new" | null>(null);
  const [adapter, setAdapter] = useState<RotationAdapter | "new" | null>(null);
  const adapters = adapterList?.adapters ?? [];
  const policyCols: Column<RotationPolicy>[] = [
    { id: "kind", header: "Secret kind", sort: (r) => r.kind, csv: (r) => r.kind, cell: (r) => <b className="name-link">{r.kind.replace(/_/g, " ")}</b> },
    { id: "system", header: "System", sort: (r) => r.system, cell: (r) => (r.system ? <Chip mono>{r.system}</Chip> : <span className="faint small">any</span>) },
    { id: "age", header: "Max age", num: true, sort: (r) => r.max_age_days, cell: (r) => `${r.max_age_days} d` },
    { id: "grace", header: "Grace period", num: true, sort: (r) => r.grace_hours, cell: (r) => graceText(r.grace_hours), hideNarrow: true },
    { id: "mode", header: "Rotation", sort: (r) => r.mode, cell: (r) => <Badge tone={r.mode === "automatic" ? "ok" : r.mode === "scheduled" ? "info" : "outline"}>{MODE_LABEL[r.mode]}</Badge> },
    { id: "adapter", header: "Adapter → vault", csv: (r) => `${r.adapter ?? ""} ${r.destination ?? ""}`, cell: (r) => (r.adapter ? <span className="small">{r.adapter}{r.destination && <span className="faint"> → {r.destination}</span>}</span> : <span className="faint small">owner rotates by hand</span>), hideNarrow: true },
    { id: "path", header: "Vault path", cell: (r) => <span className="sys small">{r.dest_path || "–"}</span>, hideNarrow: true },
  ];
  const adapterCols: Column<RotationAdapter>[] = [
    { id: "name", header: "Adapter", sort: (r) => r.name.toLowerCase(), csv: (r) => r.name, cell: (r) => <b className="name-link">{r.name}</b> },
    { id: "type", header: "Type", sort: (r) => r.type, csv: (r) => r.type, cell: (r) => <span className="small">{ADAPTER_TYPE_LABEL[r.type] ?? r.type}</span> },
    { id: "config", header: "Settings", csv: (r) => JSON.stringify(r.config), cell: (r) => <span className="small sys">{Object.entries(r.config).map(([k, v]) => `${k}=${v}`).join(" ") || "–"}</span>, hideNarrow: true },
    { id: "cred", header: "Credential", cell: (r) => (r.type === "fake" ? <span className="faint small">none</span> : r.credential_set ? <Badge tone="ok">Sealed</Badge> : <Badge tone="critical">Missing</Badge>) },
    { id: "updated", header: "Updated", sort: (r) => r.updated_at, cell: (r) => <span className="small nowrap">{fmtDate(r.updated_at)}</span>, hideNarrow: true },
  ];
  return (
    <Page
      title="Rotation policies & adapters"
      crumbs={[["Identity"], ["Secret rotation", "/rotation/secrets"], ["Policies & adapters"]]}
      sub="A policy says how old a kind of secret may get, how long the old credential lives after the new one is handed over, and which adapter rotates it. Adapters hold the credentials Tessera uses to reach your providers; they are sealed with the platform key and never shown again."
      tabs={<RotationTabs />}
    >
      <h2>Policies</h2>
      <DataTable<RotationPolicy>
        id="rotation-policies"
        rows={policies}
        error={error}
        rowKey={(r) => r.id}
        columns={policyCols}
        searchText={(r) => `${r.kind} ${r.system} ${r.adapter ?? ""} ${r.destination ?? ""}`}
        searchPlaceholder="Search policies…"
        commands={allowed ? [{ label: "New policy", icon: <Plus size={16} />, onClick: () => setPolicy("new") }] : []}
        onRefresh={reload}
        onRowClick={(r) => setPolicy(r)}
        initialSort={["kind", 1]}
        rowLabel={(r) => `${r.kind} policy`}
      />
      <h2 className="mt">Adapters</h2>
      <DataTable<RotationAdapter>
        id="rotation-adapters"
        rows={adapterList?.adapters ?? null}
        error={adapterError}
        rowKey={(r) => r.id}
        columns={adapterCols}
        searchText={(r) => `${r.name} ${r.type}`}
        searchPlaceholder="Search adapters…"
        commands={allowed ? [{ label: "New adapter", icon: <Plus size={16} />, onClick: () => setAdapter("new") }] : []}
        onRefresh={reloadAdapters}
        onRowClick={(r) => setAdapter(r)}
        initialSort={["name", 1]}
        rowLabel={(r) => `${r.name} adapter`}
      />
      <Callout tone="neutral">
        Tessera is not a password vault. New credentials are written into your vault (HashiCorp Vault KV v2 or AWS Secrets Manager); Tessera keeps only the adapters' own credentials, sealed. GitHub personal access tokens and App keys have no rotation API and stay manual: the owner is told.
      </Callout>
      {policy && (
        <PolicyDrawer
          policy={policy === "new" ? null : policy}
          adapters={adapters}
          systems={[...new Set((secrets ?? []).map((s) => s.system))].sort()}
          kinds={[...new Set((secrets ?? []).map((s) => s.kind))].sort()}
          allowed={allowed}
          onClose={() => { setPolicy(null); reload(); }}
        />
      )}
      {adapter && (
        <AdapterDrawer
          adapter={adapter === "new" ? null : adapter}
          types={adapterList?.types ?? []}
          allowed={allowed}
          onClose={() => { setAdapter(null); reloadAdapters(); reload(); }}
        />
      )}
    </Page>
  );
}

function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return <label className="field">{label}{children}{hint && <span className="hint">{hint}</span>}</label>;
}

function PolicyDrawer({ policy, adapters, systems, kinds, allowed, onClose }: { policy: RotationPolicy | null; adapters: RotationAdapter[]; systems: string[]; kinds: string[]; allowed: boolean; onClose: () => void }) {
  const [kind, setKind] = useState(policy?.kind ?? "");
  const [system, setSystem] = useState(policy?.system ?? "");
  const [maxAge, setMaxAge] = useState(String(policy?.max_age_days ?? 90));
  const [grace, setGrace] = useState(String(policy?.grace_hours ?? 24));
  const [adapter, setAdapter] = useState(policy?.adapter ?? "");
  const [dest, setDest] = useState(policy?.destination ?? "");
  const [path, setPath] = useState(policy?.dest_path ?? "kv/{system}/{name}");
  const [auto, setAuto] = useState(policy?.auto_rotate ?? false);
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const confirm = useConfirm();
  const chosen = adapters.find((a) => a.name === adapter);
  const needsDest = !!chosen && chosen.type !== "aws_secretsmanager";
  const save = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await rotation.putPolicy({ kind: kind.trim(), system: system.trim(), max_age_days: Number(maxAge), grace_hours: Number(grace), adapter: adapter || null,
        destination: needsDest ? dest || null : null, dest_path: needsDest ? path : "", auto_rotate: !!adapter && auto });
      toast(policy ? "Policy updated" : "Policy created");
      onClose();
    } catch (err) {
      toast(err instanceof ApiError ? err.message : String(err), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    if (!policy || (await confirm({ title: `Delete the ${policy.kind.replace(/_/g, " ")} policy?`, body: "Secrets of this kind stop being tracked against a maximum age and can no longer be rotated by Tessera.", confirmLabel: "Delete policy", danger: true })) === null) return;
    try {
      await rotation.deletePolicy(policy.id);
      toast("Policy deleted");
      onClose();
    } catch (err) {
      toast(err instanceof ApiError ? err.message : String(err), { kind: "error" });
    }
  };
  return (
    <Drawer
      title={policy ? `${policy.kind.replace(/_/g, " ")} policy` : "New rotation policy"}
      sub="One policy per secret kind and system. A system-specific policy wins over the one for every system."
      onClose={onClose}
      footer={
        <>
          {policy && allowed && <Button variant="danger" icon={<Trash2 size={14} />} onClick={remove}>Delete</Button>}
          <span className="grow" />
          <Button onClick={onClose}>Close</Button>
          <Button variant="primary" type="submit" form="policy-form" disabled={!allowed || busy}>{busy ? "Saving…" : "Save policy"}</Button>
        </>
      }
    >
      <form id="policy-form" className="stack" onSubmit={save}>
        {!allowed && <Callout tone="warn">Changing policies needs the secrets.rotate permission (policy admin) and a fresh phishing-resistant sign-in.</Callout>}
        <Field label="Secret kind" hint="As recorded by the connectors, e.g. access_key, deploy_key, api_token.">
          <input className="input" list="rot-kinds" value={kind} onChange={(e) => setKind(e.target.value)} required disabled={!!policy} maxLength={40} />
          <datalist id="rot-kinds">{kinds.map((k) => <option key={k} value={k} />)}</datalist>
        </Field>
        <Field label="System" hint="Leave empty for every system.">
          <select className="input" value={system} onChange={(e) => setSystem(e.target.value)} disabled={!!policy}>
            <option value="">Any system</option>
            {systems.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </Field>
        <div className="grid g2">
          <Field label="Maximum age (days)"><input className="input" type="number" min={1} max={3650} value={maxAge} onChange={(e) => setMaxAge(e.target.value)} required /></Field>
          <Field label="Grace period (hours)" hint="Between handing the new credential over and disabling the old one."><input className="input" type="number" min={0} max={720} value={grace} onChange={(e) => setGrace(e.target.value)} required /></Field>
        </div>
        <Field label="Adapter" hint="Empty: Tessera only tracks age and tells the owner to rotate by hand.">
          <select className="input" value={adapter} onChange={(e) => setAdapter(e.target.value)}>
            <option value="">None (manual rotation)</option>
            {adapters.map((a) => <option key={a.id} value={a.name}>{a.name} ({ADAPTER_TYPE_LABEL[a.type] ?? a.type})</option>)}
          </select>
        </Field>
        {needsDest && (
          <>
            <Field label="Hand the new credential to" hint="Your vault: the credential is written here and never stored by Tessera.">
              <select className="input" value={dest} onChange={(e) => setDest(e.target.value)} required>
                <option value="">Choose a vault…</option>
                {adapters.filter((a) => DESTINATION_TYPES.includes(a.type)).map((a) => <option key={a.id} value={a.name}>{a.name} ({ADAPTER_TYPE_LABEL[a.type] ?? a.type})</option>)}
              </select>
            </Field>
            <Field label="Path in that vault" hint={<>Vault KV v2: <span className="sys">mount/path</span>. Placeholders: {DEST_PLACEHOLDERS.join(" ")}</>}>
              <input className="input sys" value={path} onChange={(e) => setPath(e.target.value)} required maxLength={256} />
            </Field>
          </>
        )}
        {adapter && (
          <label className="row tight">
            <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} />
            <span>Rotate automatically when a secret passes its maximum age</span>
          </label>
        )}
      </form>
    </Drawer>
  );
}

function AdapterDrawer({ adapter, types, allowed, onClose }: { adapter: RotationAdapter | null; types: RotationAdapterType[]; allowed: boolean; onClose: () => void }) {
  const [name, setName] = useState(adapter?.name ?? "");
  const [type, setType] = useState<RotationAdapterType>(adapter?.type ?? types.find((t) => t !== "fake") ?? "vault");
  const [config, setConfig] = useState<Record<string, string>>(adapter?.config ?? {});
  const [cred, setCred] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const confirm = useConfirm();
  const form = ADAPTER_FIELDS[type];
  const save = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const credential = Object.fromEntries(Object.entries(cred).filter(([, v]) => v.trim() !== ""));
      await rotation.putAdapter(name, { type, config: Object.fromEntries(Object.entries(config).filter(([, v]) => v.trim() !== "")), ...(Object.keys(credential).length ? { credential } : {}) });
      toast(adapter ? "Adapter updated" : "Adapter created");
      onClose();
    } catch (err) {
      toast(err instanceof ApiError ? err.message : String(err), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    if (!adapter || (await confirm({ title: `Delete the ${adapter.name} adapter?`, body: "Its sealed credential is deleted. An adapter that a policy or a job refers to cannot be deleted.", confirmLabel: "Delete adapter", danger: true })) === null) return;
    try {
      await rotation.deleteAdapter(adapter.name);
      toast("Adapter deleted");
      onClose();
    } catch (err) {
      toast(err instanceof ApiError ? err.message : String(err), { kind: "error" });
    }
  };
  return (
    <Drawer
      title={adapter ? adapter.name : "New rotation adapter"}
      sub={adapter ? ADAPTER_TYPE_LABEL[adapter.type] : "Connection to a provider Tessera rotates credentials at, or to a vault it writes them to."}
      onClose={onClose}
      footer={
        <>
          {adapter && allowed && <Button variant="danger" icon={<Trash2 size={14} />} onClick={remove}>Delete</Button>}
          <span className="grow" />
          <Button onClick={onClose}>Close</Button>
          <Button variant="primary" type="submit" form="adapter-form" disabled={!allowed || busy}>{busy ? "Saving…" : "Save adapter"}</Button>
        </>
      }
    >
      <form id="adapter-form" className="stack" onSubmit={save} autoComplete="off">
        {!allowed && <Callout tone="warn">Changing adapters needs the secrets.rotate permission (policy admin) and a fresh phishing-resistant sign-in.</Callout>}
        <Field label="Name" hint="Policies refer to the adapter by this name.">
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} required disabled={!!adapter} maxLength={63} pattern="[A-Za-z0-9][A-Za-z0-9._\-]*" />
        </Field>
        <Field label="Type">
          <select className="input" value={type} onChange={(e) => { setType(e.target.value as RotationAdapterType); setConfig({}); setCred({}); }} disabled={!!adapter}>
            {types.map((t) => <option key={t} value={t}>{ADAPTER_TYPE_LABEL[t] ?? t}</option>)}
          </select>
        </Field>
        {form && <div className="small muted">{form.help}</div>}
        {form?.config.map((f) => (
          <Field key={f.id} label={f.label}>
            <input className="input" value={config[f.id] ?? ""} placeholder={f.placeholder} required={f.required} onChange={(e) => setConfig({ ...config, [f.id]: e.target.value })} />
          </Field>
        ))}
        {form && form.credential.length > 0 && (
          <fieldset className="stack" style={{ border: "1px solid var(--border)", borderRadius: "var(--r-md)", padding: 12 }}>
            <legend className="small">Credential</legend>
            <div className="small faint">{adapter?.credential_set ? "A credential is sealed. Leave these empty to keep it, or enter new values to replace it." : "Sealed with the platform key as soon as you save. It is never shown again."}</div>
            {form.credential.map((f) => (
              <Field key={f.id} label={f.label}>
                <input className="input" type={f.secret ? "password" : "text"} autoComplete="new-password" value={cred[f.id] ?? ""} required={f.required && !adapter?.credential_set} onChange={(e) => setCred({ ...cred, [f.id]: e.target.value })} />
              </Field>
            ))}
          </fieldset>
        )}
      </form>
    </Drawer>
  );
}
