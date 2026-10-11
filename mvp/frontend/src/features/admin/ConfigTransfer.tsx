import { useRef, useState } from "react";
import { Copy, Download, FileUp, KeyRound, ShieldCheck, Trash2, Upload } from "lucide-react";
import { ConfigImport, ImportPlan, PlanAction, SigningKey, TrustedSigner, configTransport, fmtDate, useApi } from "../../api";
import { Badge, Button, Callout, EmptyState, useConfirm, useToast } from "../../components";

const ACTION_TONE: Record<PlanAction, "ok" | "warning" | "critical" | "neutral" | "outline"> = {
  add: "ok", change: "warning", remove: "critical", manual: "outline", unchanged: "neutral",
};
const SECTION: Record<string, string> = { connections: "Connection", overlays: "Readiness overlay", identity_providers: "Sign-in connection" };

/** Live Admin section: export a signed bundle, trust other tenants' keys, preview and apply imports (issue #170). */
export function ConfigTransfer() {
  return (
    <div className="stack">
      <ExportCard />
      <ImportCard />
      <SignersCard />
      <HistoryCard />
    </div>
  );
}

function saveFile(name: string, data: unknown) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

function ExportCard() {
  const { data } = useApi<{ key: SigningKey | null }>("/config/signing-key");
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const key = data?.key;
  const run = async () => {
    setBusy(true);
    try {
      const b = await configTransport.export();
      saveFile(b.file_name, b.bundle);
      toast(`Bundle signed with ${b.kid} and downloaded${b.excluded?.length ? `; ${b.excluded.length} item(s) left out` : ""}`);
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  const copy = async () => {
    if (!key) return;
    await navigator.clipboard?.writeText(JSON.stringify({ kid: key.kid, public_key: key.public_key }));
    toast("Public key copied");
  };
  return (
    <div className="card stack-sm">
      <div className="spread">
        <h2 className="row tight"><Download size={16} aria-hidden /> Export this tenant</h2>
        <Button size="sm" variant="primary" icon={<Download size={13} />} disabled={busy} onClick={run}>{busy ? "Signing…" : "Export bundle"}</Button>
      </div>
      <p className="small muted" style={{ margin: 0 }}>
        The bundle holds connections (with their configuration and owners), readiness overlays and sign-in connections. It never holds secrets:
        sealed credentials and client secrets stay here, and external references such as <code>vault:…</code> travel as they are. Retired connections and the dev IdP are left out.
      </p>
      {key ? (
        <div className="row wrap small" style={{ gap: 8 }}>
          <KeyRound size={14} aria-hidden /> Signing key <code>{key.kid}</code>
          <span className="faint xs sys truncate" style={{ maxWidth: 260 }} title={key.public_key}>{key.public_key}</span>
          <Button size="sm" variant="ghost" icon={<Copy size={13} />} onClick={copy}>Copy public key</Button>
        </div>
      ) : (
        <p className="small faint" style={{ margin: 0 }}>The first export creates this tenant's signing key. Share its public key with the tenants that will import from here.</p>
      )}
    </div>
  );
}

function ImportCard() {
  const [bundle, setBundle] = useState<unknown>(null);
  const [file, setFile] = useState("");
  const [plan, setPlan] = useState<ImportPlan | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [prune, setPrune] = useState(false);
  const [busy, setBusy] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const toast = useToast();
  const confirm = useConfirm();

  const pick = async (f: File | undefined) => {
    if (!f) return;
    setPlan(null);
    setErr(null);
    setFile(f.name);
    let parsed: unknown;
    try {
      parsed = JSON.parse(await f.text());
    } catch {
      setErr("That file is not a Tessera configuration bundle (not JSON).");
      return;
    }
    setBundle(parsed);
    setBusy(true);
    try {
      setPlan(await configTransport.plan(parsed));
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const apply = async () => {
    if (!plan) return;
    const c = plan.counts;
    const ok = await confirm({
      title: "Apply this bundle?",
      body: `${c.add} to add, ${c.change} to change${prune ? `, ${c.remove} to retire` : ""}. Connections arrive as drafts and sign-in connections as pending; nothing is activated.`,
      confirmLabel: "Apply",
      danger: prune && c.remove > 0,
    });
    if (ok === null) return;
    setBusy(true);
    try {
      await configTransport.apply(bundle, plan.hash, prune);
      toast("Bundle applied");
      setPlan(null);
      setBundle(null);
      setFile("");
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  const pending = plan ? plan.counts.add + plan.counts.change + (prune ? plan.counts.remove : 0) : 0;
  return (
    <div className="card stack-sm">
      <div className="spread">
        <h2 className="row tight"><Upload size={16} aria-hidden /> Import a bundle</h2>
        <Button size="sm" icon={<FileUp size={13} />} disabled={busy} onClick={() => input.current?.click()}>Choose file…</Button>
        <input ref={input} type="file" accept=".json,application/json" className="sr-only" aria-label="Bundle file" onChange={(e) => { void pick(e.target.files?.[0]); e.target.value = ""; }} />
      </div>
      <p className="small muted" style={{ margin: 0 }}>
        Tessera checks the signature against your trusted signers and shows what would change before anything is applied. Applying needs a recent phishing-resistant sign-in.
      </p>
      {file && <div className="small">File: <b>{file}</b>{busy && !plan && <span className="faint"> — checking…</span>}</div>}
      {err && <Callout tone="bad">{err}</Callout>}
      {plan && <PlanView plan={plan} prune={prune} />}
      {plan && (
        <div className="spread wrap">
          <label className="row tight small">
            <input type="checkbox" checked={prune} onChange={(e) => setPrune(e.target.checked)} disabled={plan.counts.remove === 0} />
            Also retire the {plan.counts.remove} connection(s) the bundle does not have
          </label>
          <Button variant="primary" icon={<ShieldCheck size={13} />} disabled={busy || plan.refusals.length > 0 || pending === 0} onClick={apply}>
            {pending === 0 ? "Nothing to apply" : `Apply ${pending} change(s)`}
          </Button>
        </div>
      )}
    </div>
  );
}

function PlanView({ plan, prune }: { plan: ImportPlan; prune: boolean }) {
  const c = plan.counts;
  return (
    <div className="stack-sm">
      <div className="small">
        From <b>{plan.source.tenant}</b> ({plan.source.env}{plan.source.instance ? `, ${plan.source.instance}` : ""}), exported {fmtDate(plan.exported_at)} by {plan.source.exported_by}.
        Signed by <b>{plan.signer}</b> <code className="xs">{plan.signer_kid}</code>.
      </div>
      <div className="row wrap" style={{ gap: 6 }}>
        <Badge tone="ok">{c.add} add</Badge><Badge tone="warning">{c.change} change</Badge>
        <Badge tone="critical">{c.remove} remove{prune ? "" : " (not applied)"}</Badge><Badge tone="outline">{c.manual} manual</Badge><Badge>{c.unchanged} unchanged</Badge>
      </div>
      {plan.refusals.length > 0 && (
        <Callout tone="bad">
          <b>This bundle cannot be applied here.</b>
          <ul className="small" style={{ margin: "6px 0 0", paddingLeft: 18 }}>{plan.refusals.map((r) => <li key={r}>{r}</li>)}</ul>
        </Callout>
      )}
      <div className="table-scroll">
        <table>
          <thead><tr><th>Item</th><th>Type</th><th>Change</th><th>Notes</th></tr></thead>
          <tbody>
            {plan.items.map((it) => (
              <tr key={`${it.section}/${it.name}`}>
                <td><b>{it.name}</b>{it.fields && it.fields.length > 0 && <div className="xs faint sys">{it.fields.join(", ")}</div>}</td>
                <td className="small">{SECTION[it.section] ?? it.section}</td>
                <td><Badge tone={ACTION_TONE[it.action]}>{it.action}</Badge></td>
                <td className="small">{it.notes?.join(" ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function SignersCard() {
  const { data, error } = useApi<TrustedSigner[]>("/config/trusted-signers");
  const [paste, setPaste] = useState("");
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const confirm = useConfirm();
  const add = async () => {
    let k: { kid?: string; public_key?: string };
    try {
      k = JSON.parse(paste);
    } catch {
      toast("Paste the key as copied from the exporting tenant: {\"kid\": …, \"public_key\": …}", { kind: "error" });
      return;
    }
    setBusy(true);
    try {
      await configTransport.trust({ kid: k.kid ?? "", public_key: k.public_key ?? "", label: label.trim() });
      setPaste("");
      setLabel("");
      toast("Signer trusted");
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  const remove = async (s: TrustedSigner) => {
    if ((await confirm({ title: `Stop trusting ${s.label}?`, body: "Bundles signed with this key will be refused.", confirmLabel: "Remove", danger: true })) === null) return;
    try {
      await configTransport.untrust(s.kid);
      toast("Signer removed");
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    }
  };
  return (
    <div className="card stack-sm">
      <h2 className="row tight"><KeyRound size={16} aria-hidden /> Trusted signers</h2>
      <p className="small muted" style={{ margin: 0 }}>Only bundles signed by these keys can be imported here. This tenant's own key is not trusted unless you add it.</p>
      {error && <Callout tone="bad">{error}</Callout>}
      {data && data.length === 0 && <EmptyState title="No trusted signers yet">Add the public key of the tenant you import from.</EmptyState>}
      {data && data.length > 0 && (
        <div className="table-scroll">
          <table>
            <thead><tr><th>Label</th><th>Key id</th><th>Added</th><th /></tr></thead>
            <tbody>
              {data.map((s) => (
                <tr key={s.kid}>
                  <td><b>{s.label}</b></td>
                  <td><code className="small">{s.kid}</code></td>
                  <td className="small nowrap">{fmtDate(s.added_at)}</td>
                  <td className="actions-cell"><Button size="sm" variant="ghost" icon={<Trash2 size={13} />} label={`Remove ${s.label}`} onClick={() => remove(s)} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="stack-sm">
        <label className="small">Label
          <input className="input" style={{ width: "100%" }} value={label} onChange={(e) => setLabel(e.target.value)} placeholder="e.g. Larkspur dev" />
        </label>
        <label className="small">Public key
          <textarea className="input sys" rows={2} style={{ width: "100%" }} value={paste} onChange={(e) => setPaste(e.target.value)} placeholder='{"kid":"cfg-…","public_key":"…"}' />
        </label>
        <div><Button size="sm" disabled={busy || !paste.trim() || !label.trim()} onClick={add}>Trust signer</Button></div>
      </div>
    </div>
  );
}

function HistoryCard() {
  const { data } = useApi<ConfigImport[]>("/config/imports");
  if (!data || data.length === 0) return null;
  return (
    <div className="card flush">
      <div className="card-h"><h2>Imports</h2><span className="xs faint tnum">{data.length}</span></div>
      <div className="table-scroll">
        <table>
          <thead><tr><th>Applied</th><th>From</th><th>Changes</th><th>Bundle</th></tr></thead>
          <tbody>
            {data.map((i) => (
              <tr key={i.id}>
                <td className="small nowrap">{fmtDate(i.applied_at)}</td>
                <td className="small">{i.source} <span className="faint xs">· {i.signer_kid}</span></td>
                <td className="small tnum">+{i.summary.add} ~{i.summary.change} −{i.summary.remove}</td>
                <td><code className="xs" title={i.bundle_hash}>{i.bundle_hash.slice(0, 12)}</code></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
