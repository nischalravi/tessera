import { useMemo } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { FileText, Pencil, Plus, Trash2 } from "lucide-react";
import { JitRequest, fmtDate, relTime, useApi } from "../../api";
import { usePersona } from "../../app/persona";
import { Button, ButtonLink, EmptyState, Loading, Page, PreviewBadge, Status, Tabs, useConfirm, MyAccessTabs } from "../../components";
import { mockRequests, useMockState } from "../../mocks";

interface Row { key: string; what: string; forWhom: string; kind: string; status: string; at: string; by: string; preview: boolean; detail: string }

export function Requests() {
  const [params, setParams] = useSearchParams();
  const tab = (params.get("tab") ?? "history") as "history" | "drafts";
  const { me, actor, persona } = usePersona();
  const { data: jit, error } = useApi<JitRequest[]>("/jit/requests");
  const mock = useMockState();
  const nav = useNavigate();
  const confirm = useConfirm();

  const history = useMemo<Row[] | null>(() => {
    if (!jit) return null;
    const mineOnly = persona !== "admin";
    const rows: Row[] = [
      ...jit
        .filter((r) => !mineOnly || r.identity.id === me?.id)
        .map((r) => ({ key: `j${r.id}`, what: `${r.group.system}:${r.group.name}`, forWhom: r.identity.name, kind: `Just-in-time, ${r.duration_hours} h`, status: r.status, at: r.requested_at, by: r.decided_by ?? "", preview: false, detail: r.justification })),
      ...mock.requests
        .filter((r) => r.status !== "draft" && (!mineOnly || r.requester === actor || r.beneficiaries.some((b) => b.id === me?.id)))
        .map((r) => ({ key: r.id, what: r.items.map((i) => i.name).join(", "), forWhom: r.beneficiaries.map((b) => b.name).join(", "), kind: r.kind === "removal" ? "Removal" : r.durationHours ? `For ${r.durationHours} h` : "Until removed", status: r.status, at: r.createdAt, by: "", preview: true, detail: r.justification })),
    ];
    return rows.sort((a, b) => (a.at < b.at ? 1 : -1));
  }, [jit, mock, me, actor, persona]);

  const drafts = mock.requests.filter((r) => r.status === "draft" && r.requester === actor);

  return (
    <Page tabs={<MyAccessTabs />}
      title="Requests"
      crumbs={[["Access"], ["Requests"]]}
      sub={persona === "admin" ? "Every access request across the organisation, newest first." : "Requests you made or that were made for you, plus drafts you saved."}
      actions={<ButtonLink to="/access/request" variant="primary" icon={<Plus size={15} />}>New request</ButtonLink>}
    >
      <Tabs label="Request views" value={tab} onChange={(v) => setParams(v === "history" ? {} : { tab: v })} tabs={[{ id: "history", label: `History${history ? ` (${history.length})` : ""}` }, { id: "drafts", label: `Drafts (${drafts.length})` }]} />
      {tab === "history" ? (
        <div className="card flush">
          {!history ? <Loading error={error} /> : history.length === 0 ? (
            <EmptyState title="No requests yet" icon={<FileText size={18} />} action={<ButtonLink to="/access/request" size="sm">Browse the catalog</ButtonLink>}>Requests you submit show here with their approval status.</EmptyState>
          ) : (
            <div className="table-scroll">
              <table>
                <thead><tr><th>Access</th><th>For</th><th className="hide-narrow">Type</th><th>Status</th><th className="hide-narrow">Requested</th></tr></thead>
                <tbody>
                  {history.map((r) => (
                    <tr key={r.key}>
                      <td><b className="sys">{r.what}</b> {r.preview && <PreviewBadge />}<div className="xs faint truncate" style={{ maxWidth: 360 }}>{r.detail}</div></td>
                      <td className="small">{r.forWhom}</td>
                      <td className="small hide-narrow">{r.kind}</td>
                      <td className="nowrap"><Status s={r.status} />{r.by && <div className="xs faint">by {r.by}</div>}</td>
                      <td className="small faint nowrap hide-narrow" title={fmtDate(r.at)}>{relTime(r.at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      ) : (
        <div className="card flush">
          {drafts.length === 0 ? (
            <EmptyState title="No drafts" icon={<Pencil size={18} />}>Use “Save draft” on Request access to come back to a request later.</EmptyState>
          ) : (
            <table>
              <thead><tr><th>Items</th><th>For</th><th>Saved</th><th /></tr></thead>
              <tbody>
                {drafts.map((d) => (
                  <tr key={d.id}>
                    <td><b className="sys">{d.items.map((i) => i.name).join(", ")}</b></td>
                    <td className="small">{d.beneficiaries.map((b) => b.name).join(", ")}</td>
                    <td className="small faint">{relTime(d.createdAt)}</td>
                    <td className="actions-cell">
                      <Button size="sm" icon={<Pencil size={14} />} onClick={() => nav(`/access/request?draft=${d.id}`)}>Resume</Button>{" "}
                      <Button size="sm" variant="ghost" icon={<Trash2 size={14} />} label="Delete draft" onClick={async () => { if ((await confirm({ title: "Delete this draft?", confirmLabel: "Delete", danger: true })) !== null) mockRequests.remove(d.id); }} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </Page>
  );
}
