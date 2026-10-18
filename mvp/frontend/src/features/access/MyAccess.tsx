import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Plus, Trash2 } from "lucide-react";
import { ApiError, PathStep, RemovalRequest, ago, fmtDate, removals, removalsPath, useApi } from "../../api";
import { usePersona } from "../../app/persona";
import { Badge, Button, ButtonLink, EmptyState, FilterChips, Loading, Page, useConfirm, useToast, MyAccessTabs } from "../../components";

interface GrantRow {
  key: string;
  label: string;
  account: string;
  jit: boolean;
  expires: string | null;
  privileged: boolean;
  perms: number;
  lastUsed: number | null;
  edgeId: number | null;
  system: string;
  /** why it cannot be removed here: just-in-time ends by itself, a role grant is removed with the role */
  locked: string | null;
}

export function MyAccess() {
  const { me } = usePersona();
  const [params] = useSearchParams();
  const [filter, setFilter] = useState<"all" | "unused" | "privileged">((params.get("filter") as "unused") ?? "all");
  const { data: d, error } = useApi<any>(me ? `/identities/${me.id}` : null);
  const confirm = useConfirm();
  const toast = useToast();
  const { data: mine, reload: reloadRemovals } = useApi<RemovalRequest[]>(removalsPath("mine"));

  const rows = useMemo<GrantRow[]>(() => {
    if (!d) return [];
    return (d.grants as any[]).map((g) => {
      const perms = (d.effective_permissions as any[]).filter((p) => p.paths.some((path: PathStep[]) => path.some((s) => s.key === g.dst)));
      const used = perms.map((p) => p.usage.days_since_used).filter((x: number | null) => x !== null) as number[];
      return {
        key: `${g.src}>${g.dst}`,
        label: g.label,
        account: g.account,
        jit: g.source === "jit",
        expires: g.expires_at,
        privileged: g.privileged,
        perms: perms.length,
        lastUsed: used.length ? Math.min(...used) : null,
        edgeId: g.edge_id,
        system: g.account.split(":")[0],
        locked: g.source === "jit" ? "Just-in-time access ends by itself" : g.source === "role" ? "This access comes from a business role; ask for the role to be removed" : !String(g.dst).startsWith("group:") ? "Only group memberships can be removed here" : null,
      };
    });
  }, [d]);

  // a pending removal is matched on the grant it names: account -> group
  const pendingRemoval = new Set((mine ?? []).filter((q) => q.status === "pending" && q.beneficiary.id === me?.id).map((q) => `account:${q.account.id}>group:${q.group.id}`));
  const shown = rows.filter((r) => filter === "all" || (filter === "unused" ? r.lastUsed === null || r.lastUsed > 60 : r.privileged));

  const requestRemoval = async (r: GrantRow) => {
    const reason = await confirm({
      title: `Request removal of ${r.label}?`,
      body: "Your manager is asked to confirm, then Tessera removes the grant from your access. You can cancel the request while it is pending. If you need the access again later, request it from the catalog.",
      confirmLabel: "Request removal",
      danger: true,
      reason: { label: "Why should it be removed? (your approver sees this)", required: true },
    });
    if (reason === null || r.edgeId === null) return;
    try {
      await removals.submit(r.edgeId, reason);
      toast(`Removal requested for ${r.label}. It is in your requests and your manager's inbox.`, { kind: "ok" });
      reloadRemovals();
    } catch (e) {
      toast(e instanceof ApiError ? e.message : String(e), { kind: "error" });
    }
  };

  return (
    <Page tabs={<MyAccessTabs />}
      title="My access"
      crumbs={[["Access"], ["My access"]]}
      sub={me ? `Everything ${me.name} can use today, how it was granted, and when it was last used.` : undefined}
      actions={<ButtonLink to="/access/request" variant="primary" icon={<Plus size={15} />}>Request access</ButtonLink>}
    >
      {!d ? <Loading error={error} kind="page" /> : (
        <div className="stack">
          <div className="card">
            <div className="stat-row">
              <div className="s"><b>{d.accounts.length}</b><span>accounts</span></div>
              <div className="s"><b>{rows.length}</b><span>grants</span></div>
              <div className="s"><b>{d.risk?.effective ?? 0}</b><span>effective permissions</span></div>
              <div className="s"><b style={{ color: d.risk?.unused ? "var(--warning)" : undefined }}>{d.risk?.unused ?? 0}</b><span>unused 60 days</span></div>
              <div className="s"><b>{d.risk?.privileged ?? 0}</b><span>privileged</span></div>
            </div>
          </div>
          <div className="spread">
            <FilterChips label="Filter access" value={filter} onChange={setFilter} options={[
              { id: "all", label: "All", count: rows.length },
              { id: "unused", label: "Unused 60+ days", count: rows.filter((r) => r.lastUsed === null || r.lastUsed > 60).length },
              { id: "privileged", label: "Privileged", count: rows.filter((r) => r.privileged).length },
            ]} />
            <Link to={`/insights/graph?identity=${d.id}`} className="small">See how it's granted in the access graph</Link>
          </div>
          <div className="card flush">
            {shown.length === 0 ? (
              <EmptyState title={filter === "unused" ? "No unused access" : "Nothing here"}>{filter === "unused" ? "Everything you hold has been used in the last 60 days." : "No access matches this filter."}</EmptyState>
            ) : (
              <div className="table-scroll">
                <table>
                  <thead><tr><th>Access</th><th className="hide-narrow">Account</th><th className="num">Permissions</th><th>Last used</th><th>Granted</th><th /></tr></thead>
                  <tbody>
                    {shown.map((r) => (
                      <tr key={r.key}>
                        <td><b className="sys">{r.label}</b> {r.privileged && <Badge tone="warning">Privileged</Badge>}</td>
                        <td className="sys faint hide-narrow">{r.account}</td>
                        <td className="num">{r.perms}</td>
                        <td className="nowrap">{r.lastUsed === null || r.lastUsed > 60 ? <Badge tone="warning">{ago(r.lastUsed)}</Badge> : ago(r.lastUsed)}</td>
                        <td className="small nowrap">{r.jit ? <Badge tone="info">Just-in-time, until {fmtDate(r.expires)}</Badge> : "Standing"}</td>
                        <td className="actions-cell">
                          {pendingRemoval.has(r.key) ? <Link className="small" to="/access/requests">Removal requested</Link> : (
                            <Button size="sm" variant="ghost" icon={<Trash2 size={14} />} onClick={() => requestRemoval(r)} disabled={r.locked !== null || r.edgeId === null} title={r.locked ?? undefined}>Request removal</Button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </Page>
  );
}
