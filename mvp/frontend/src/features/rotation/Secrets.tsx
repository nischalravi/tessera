/** Secret rotation: every secret with its age, policy and rotation status, and the Rotate action. */
import { useState } from "react";
import { Link } from "react-router-dom";
import { RotateCw } from "lucide-react";
import { RotationJob, RotationSecretStatus, fmtDate, relTime, rotation, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, Chip, Column, DataTable, Page, SidePanel, useSelected } from "../../components";
import { MODE_LABEL, SECRET_STATUS_LABEL, SECRET_STATUS_TONE, ageText, secretStatus } from "./model";
import { Facts, OriginText, PlanDrawer, RotationTabs, StateBadge } from "./shared";

const uniq = (xs: string[]) => [...new Set(xs)].sort();
const opts = (xs: string[]) => xs.map((value) => ({ value, label: value.replace(/_/g, " ") }));

export function RotationSecrets() {
  const { data, error, reload } = useApi<RotationSecretStatus[]>(rotation.paths.overview);
  const [selected, setSelected] = useSelected();
  const [plan, setPlan] = useState<{ title: string; ids: number[] } | null>(null);
  const { can } = useSession();
  const allowed = can("secrets.rotate");
  const open = data?.find((r) => String(r.secret_id) === selected);
  const overdue = (data ?? []).filter((r) => secretStatus(r) === "overdue").length;
  const cols: Column<RotationSecretStatus>[] = [
    { id: "name", header: "Secret", sort: (r) => r.name.toLowerCase(), csv: (r) => r.name, cell: (r) => <div><span className="sys name-link">{r.name}</span><div className="xs faint">{r.kind.replace(/_/g, " ")} · {r.account}</div></div> },
    { id: "system", header: "System", sort: (r) => r.system, cell: (r) => <Chip mono>{r.system}</Chip>, hideNarrow: true },
    { id: "owner", header: "Owner", sort: (r) => r.owner?.name ?? "", csv: (r) => r.owner?.name ?? "", cell: (r) => (r.owner ? <span className="small">{r.owner.name}</span> : <Badge tone="critical">No owner</Badge>), hideNarrow: true },
    { id: "age", header: "Age / max", num: true, sort: (r) => r.age_days, csv: (r) => ageText(r), cell: (r) => (r.overdue ? <Badge tone="warning">{ageText(r)}</Badge> : <span className="nowrap">{ageText(r)}</span>) },
    { id: "mode", header: "Rotation", sort: (r) => r.mode, csv: (r) => MODE_LABEL[r.mode], cell: (r) => <span className="small">{MODE_LABEL[r.mode]}{r.adapter && <span className="faint"> · {r.adapter}</span>}</span>, hideNarrow: true },
    { id: "status", header: "Status", sort: (r) => secretStatus(r), csv: (r) => SECRET_STATUS_LABEL[secretStatus(r)], cell: (r) => <Badge tone={SECRET_STATUS_TONE[secretStatus(r)]} dot>{SECRET_STATUS_LABEL[secretStatus(r)]}</Badge> },
    { id: "last", header: "Last job", sort: (r) => r.last_job?.at ?? "", cell: (r) => (r.last_job ? <span className="row tight"><StateBadge state={r.last_job.state} /><span className="xs faint">{relTime(r.last_job.at)}</span></span> : <span className="faint small">never</span>), hideNarrow: true },
  ];
  return (
    <Page
      title="Secret rotation"
      crumbs={[["Identity"], ["Secret rotation"]]}
      count={data ? `${data.length} secrets${overdue ? ` · ${overdue} overdue` : ""}` : undefined}
      sub="Tessera rotates credentials through your own vaults and cloud APIs. The new credential goes straight to your vault and is never stored here; the old one is deleted only after Tessera re-reads it and finds it unused."
      tabs={<RotationTabs />}
    >
      <DataTable<RotationSecretStatus>
        id="rotation-secrets"
        rows={data}
        error={error}
        rowKey={(r) => r.secret_id}
        columns={cols}
        initialSort={["age", -1]}
        searchText={(r) => `${r.name} ${r.system} ${r.kind} ${r.account} ${r.owner?.name ?? ""} ${r.adapter ?? ""}`}
        searchPlaceholder="Search secrets, systems, owners…"
        filters={[
          { id: "status", label: "Status", options: Object.entries(SECRET_STATUS_LABEL).map(([value, label]) => ({ value, label })), get: (r) => secretStatus(r) },
          { id: "system", label: "System", options: opts(uniq((data ?? []).map((r) => r.system))), get: (r) => r.system },
          { id: "kind", label: "Kind", options: opts(uniq((data ?? []).map((r) => r.kind))), get: (r) => r.kind },
          { id: "mode", label: "Rotation", options: Object.entries(MODE_LABEL).map(([value, label]) => ({ value, label })), get: (r) => r.mode },
        ]}
        commands={[]}
        onRefresh={reload}
        bulkActions={allowed ? [{ label: "Rotate…", icon: <RotateCw size={16} />, run: (rs) => setPlan({ title: `Rotate ${rs.length} secret${rs.length === 1 ? "" : "s"}`, ids: rs.map((r) => r.secret_id) }) }] : []}
        rowLabel={(r) => r.name}
        onRowClick={(r) => setSelected(r.secret_id)}
        activeKey={selected}
      />
      {open && (
        <SidePanel
          title={open.name}
          sub={<><Chip mono>{open.system}</Chip><span>{open.kind.replace(/_/g, " ")}</span></>}
          onClose={() => setSelected(null)}
          commands={
            <div className="row">
              <Button size="sm" variant="primary" icon={<RotateCw size={14} />} disabled={!allowed || open.action !== "rotate"} title={!allowed ? "Needs the secrets.rotate permission (policy admin)" : open.action !== "rotate" ? open.reason : undefined}
                onClick={() => setPlan({ title: `Rotate ${open.name}`, ids: [open.secret_id] })}>Rotate…</Button>
            </div>
          }
          footer={<Link to={`/rotation/jobs?secret=${open.secret_id}`}>Jobs for this secret</Link>}
        >
          <SecretPanel s={open} />
        </SidePanel>
      )}
      {plan && <PlanDrawer title={plan.title} secretIds={plan.ids} onClose={() => { setPlan(null); reload(); }} />}
    </Page>
  );
}

function SecretPanel({ s }: { s: RotationSecretStatus }) {
  const { data: jobs } = useApi<RotationJob[]>(rotation.paths.jobs(`?secret_id=${s.secret_id}&limit=5`));
  return (
    <>
      {s.action !== "rotate" && s.reason && <Callout tone={s.action === "blocked" ? "bad" : s.action === "in_flight" ? "info" : "warn"}>{s.reason}</Callout>}
      <Facts
        rows={[
          ["Account", s.account],
          ["Owner", s.owner ? `${s.owner.name}${s.owner.status !== "active" ? ` (${s.owner.status})` : ""}` : "No owner: notifications go to the tenant administrators"],
          ["Age", ageText(s)],
          ["Rotation", `${MODE_LABEL[s.mode]}${s.adapter ? ` through ${s.adapter}` : ""}`],
          ["Status", <Badge key="st" tone={SECRET_STATUS_TONE[secretStatus(s)]} dot>{SECRET_STATUS_LABEL[secretStatus(s)]}</Badge>],
        ]}
      />
      <div>
        <h3 style={{ marginBottom: 6 }}>Recent rotations</h3>
        {!jobs ? <div className="small faint">Loading…</div> : jobs.length === 0 ? <div className="small faint">Never rotated through Tessera.</div> : (
          <table>
            <tbody>
              {jobs.map((j) => (
                <tr key={j.id}>
                  <td><StateBadge state={j.state} /></td>
                  <td><OriginText origin={j.origin} /></td>
                  <td className="small nowrap" style={{ textAlign: "right" }}>{fmtDate(j.created_at)}</td>
                  <td><Link to={`/rotation/jobs?selected=${j.id}`}>Open</Link></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {s.max_age_days != null && <div className="small faint">Policy: rotate when older than {s.max_age_days} days; grace period before the old credential is disabled: see Policies.</div>}
    </>
  );
}

