/**
 * Protection > GitHub & CI tokens (issue #476): the credentials of the connected GitHub organization that
 * non-human work runs on: fine-grained and classic personal access tokens, OAuth app tokens (the GitHub CLI
 * among them) and Actions secrets. Each shows its age, last rotation, owner and risk flags. Only metadata is
 * shown: GitHub never returns a token or secret value. Revoking and rotating are done in GitHub.
 */
import { useState } from "react";
import { KeyRound, RefreshCw } from "lucide-react";
import { GitHubToken, GitHubTokenKind, GitHubTokenList, fmtDate, githubTokens, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Callout, Column, DataTable, EmptyState, Page, Tone, useToast } from "../../components";

const KIND: Record<GitHubTokenKind, string> = {
  fine_grained_pat: "Fine-grained PAT", classic_pat: "Classic PAT", oauth_app_token: "OAuth app token", actions_secret: "Actions secret",
};
const FLAG: Record<string, string> = {
  orphaned: "No owner found", owner_left: "Owner has left", stale_secret: "Not rotated for a long time", no_expiry: "Never expires",
  expired: "Expired", unused: "Unused", high_risk_scope: "High-risk scope", org_wide_secret: "Readable by every repository",
  cli_token: "GitHub CLI token", classic_pat: "Classic token",
};

const riskTone = (r: number): Tone => (r >= 50 ? "critical" : r >= 25 ? "warning" : "neutral");

const cols: Column<GitHubToken>[] = [
  { id: "name", header: "Credential", sort: (t) => t.name, cell: (t) => <span className="name-link">{t.name}</span> },
  { id: "kind", header: "Kind", sort: (t) => t.kind, cell: (t) => <span className="small">{KIND[t.kind]}</span> },
  {
    id: "owner", header: "Owner", sort: (t) => t.owner?.name ?? t.owner_login, csv: (t) => t.owner?.name ?? t.owner_login,
    cell: (t) => <span className="small">{t.owner?.name ?? (t.owner_login ? `${t.owner_login} (unmatched)` : <span className="faint">Organization</span>)}</span>, hideNarrow: true,
  },
  { id: "age", header: "Age (days)", sort: (t) => t.age_days, csv: (t) => String(t.age_days), cell: (t) => <span className="small">{t.age_days}</span> },
  { id: "rotated", header: "Last rotated", sort: (t) => t.last_rotated_at ?? "", csv: (t) => t.last_rotated_at ?? "", cell: (t) => <span className="small nowrap">{t.last_rotated_at ? fmtDate(t.last_rotated_at) : <span className="faint">-</span>}</span>, hideNarrow: true },
  { id: "expires", header: "Expires", sort: (t) => t.expires_at ?? "", csv: (t) => t.expires_at ?? "", cell: (t) => <span className="small nowrap">{t.expires_at ? fmtDate(t.expires_at) : <span className="faint">Never</span>}</span>, hideNarrow: true },
  { id: "used", header: "Last used", sort: (t) => t.last_used_at ?? "", csv: (t) => t.last_used_at ?? "", cell: (t) => <span className="small nowrap">{t.last_used_at ? fmtDate(t.last_used_at) : <span className="faint">Unknown</span>}</span>, hideNarrow: true },
  { id: "scopes", header: "Scopes", csv: (t) => t.scopes.join(" "), cell: (t) => <span className="small">{t.visibility ? `visible to ${t.visibility}` : t.scopes.join(", ") || <span className="faint">-</span>}</span>, hideNarrow: true },
  { id: "risk", header: "Risk", sort: (t) => t.risk, csv: (t) => String(t.risk), cell: (t) => <Badge tone={riskTone(t.risk)}>{t.risk}</Badge> },
  { id: "flags", header: "Flags", csv: (t) => t.flags.join(" "), cell: (t) => <span className="small">{t.flags.map((f) => FLAG[f] ?? f).join(", ") || <span className="faint">-</span>}</span>, hideNarrow: true },
];

export function GitHubTokens() {
  const { data, error, reload } = useApi<GitHubTokenList>(githubTokens.listPath);
  const { can } = useSession();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const sync = async () => {
    setBusy(true);
    try {
      const r = await githubTokens.sync();
      toast(r.status === "failed" ? `Sync failed: ${r.error}` : r.status === "skipped" ? `Not synced: ${r.error}` : "Inventory refreshed", { kind: r.status === "ok" ? "ok" : "error" });
      reload();
    } catch (e: any) {
      toast(String(e.message ?? e), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  const s = data?.summary;
  return (
    <Page title="GitHub & CI tokens" crumbs={[["Protection"], ["GitHub & CI tokens"]]}
      sub="Personal access tokens, OAuth app tokens (including the GitHub CLI) and Actions secrets of the connected GitHub organization, with their age, owner and risk. Names and dates only: no token or secret value is read.">
      {s && <p className="small muted">{s.total} credentials, {s.stale} not rotated for {data?.stale_days} days or more, {s.no_owner} with no owner found, {s.risky} at high risk.</p>}
      {(s?.no_owner ?? 0) > 0 && <Callout tone="warn"><KeyRound size={14} aria-hidden /> {s?.no_owner} credential(s) belong to a GitHub login that matches no identity. Connect GitHub as an account source so each has an accountable owner.</Callout>}
      <DataTable
        id="github-tokens"
        rows={data?.tokens ?? null}
        error={error}
        rowKey={(t) => t.id}
        columns={cols}
        initialSort={["risk", 1]}
        searchText={(t) => `${t.name} ${t.owner_login} ${t.owner?.name ?? ""}`}
        searchPlaceholder="Search credentials or owners…"
        filters={[
          { id: "kind", label: "Kind", options: Object.entries(KIND).map(([value, label]) => ({ value, label })), get: (t) => t.kind },
          { id: "flag", label: "Flag", options: Object.entries(FLAG).map(([value, label]) => ({ value, label })), get: (t) => t.flags.join(" ") },
        ]}
        commands={[can("oauthapps.manage") && { label: busy ? "Syncing…" : "Sync now", icon: <RefreshCw size={16} />, onClick: sync, title: "Read GitHub now (a background job also does this hourly)" }]}
        onRefresh={reload}
        rowLabel={(t) => t.name}
        empty={<EmptyState title="No GitHub credentials yet" icon={<KeyRound size={18} />}>Connect GitHub and set a containment credential on the connection (an organization owner token); the inventory fills on the next sync.</EmptyState>}
      />
    </Page>
  );
}
