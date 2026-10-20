import { Link } from "react-router-dom";
import { Code2, KeyRound } from "lucide-react";
import { AgentRow, McpFinding, PersonBrief, relTime, useMcpFindings } from "../../api";
import { Badge, Callout, Chip, Column, DataTable, EmptyState } from "../../components";
import { opts, uniq } from "./shared";

/** The sponsor of an agent: a status first, because "no active sponsor" is what a reviewer looks for. */
export function SponsorCell({ a }: { a: Pick<AgentRow, "sponsor" | "sponsor_ref" | "sponsor_status"> }) {
  if (a.sponsor_status === "none") {
    return <Badge tone="critical">No sponsor{a.sponsor_ref ? ` (${a.sponsor_ref})` : ""}</Badge>;
  }
  const who = a.sponsor ? <Link to={`/directory/identities/${a.sponsor.id}`}>{a.sponsor.name}</Link> : <span>{a.sponsor_ref}</span>;
  return (
    <span className="small nowrap">
      {who} {a.sponsor_status === "inactive" ? <Badge tone="warning">Inactive</Badge> : <Badge tone="ok">Active</Badge>}
    </span>
  );
}

const SOURCE_LABEL: Record<string, string> = {
  entra: "Entra Agent ID",
  okta: "Okta",
  "aws-agentcore": "AWS AgentCore",
  "github-scan": "GitHub scan",
};
export const sourceLabel = (s: string) => SOURCE_LABEL[s] ?? s;

function Owner({ o }: { o: McpFinding["owner"] }) {
  const person: PersonBrief | null = o.identity;
  if (person) {
    return (
      <div>
        <Link to={`/directory/identities/${person.id}`}>{person.name}</Link>
        <div className="xs faint">via {o.source}</div>
      </div>
    );
  }
  if (o.ref) {
    return (
      <div>
        <span className="mono small">{o.ref}</span>
        <div className="xs faint">via {o.source}, no matching person</div>
      </div>
    );
  }
  return <Badge tone="critical">No owner</Badge>;
}

const columns: Column<McpFinding>[] = [
  {
    id: "where", header: "Repository and file", sort: (r) => `${r.repo}/${r.path}`, csv: (r) => `${r.org}/${r.repo}/${r.path}`,
    cell: (r) => (
      <div style={{ minWidth: 0 }}>
        <span className="name-link">{r.org}/{r.repo}</span>
        <div className="xs faint truncate mono">{r.path} · {r.location}</div>
      </div>
    ),
  },
  {
    id: "kind", header: "Finding", sort: (r) => r.kind, csv: (r) => r.kind,
    cell: (r) => (r.kind === "mcp_server"
      ? <span className="row tight"><Code2 size={14} aria-hidden /> <span>MCP server</span></span>
      : <span className="row tight"><KeyRound size={14} aria-hidden /> <Badge tone="critical">Credential</Badge></span>),
  },
  {
    id: "server", header: "Server", sort: (r) => r.server ?? "", csv: (r) => `${r.server ?? ""} ${r.transport ?? ""} ${r.target ?? ""}`,
    cell: (r) => (
      <div style={{ minWidth: 0 }}>
        <span>{r.server ?? "-"}</span> {r.transport && <Chip mono>{r.transport}</Chip>}
        {r.target && <div className="xs faint truncate">{r.target}</div>}
      </div>
    ),
  },
  {
    id: "secret", header: "Secret type", sort: (r) => r.secret_type ?? "", csv: (r) => `${r.secret_type ?? ""} ${r.fingerprint ?? ""}`,
    cell: (r) => (r.secret_type
      ? <div><span className="small">{r.secret_type.replace(/_/g, " ")}</span><div className="xs faint mono" title="Truncated hash of the secret. The secret itself is never stored.">fp {r.fingerprint}</div></div>
      : <span className="faint">-</span>),
  },
  { id: "owner", header: "Owner", sort: (r) => r.owner.identity?.name ?? r.owner.ref ?? "", csv: (r) => r.owner.identity?.name ?? r.owner.ref ?? "", cell: (r) => <Owner o={r.owner} /> },
  { id: "seen", header: "Last seen", sort: (r) => r.last_seen_at, cell: (r) => <span className="small nowrap">{relTime(r.last_seen_at)}</span>, hideNarrow: true },
];

/** MCP server configurations and agent credentials found in the connected GitHub orgs. */
export function McpFindings() {
  const { data, error, reload } = useMcpFindings();
  return (
    <div className="stack">
      <Callout tone="info">
        Tessera stores where a finding is, the kind of secret and a truncated hash of it. It never keeps the secret itself. Rotate a credential at its source, then it drops off this list on the next scan.
      </Callout>
      <DataTable
        id="mcp-findings"
        rows={data}
        error={error}
        rowKey={(r) => r.id}
        columns={columns}
        initialSort={["kind", -1]}
        searchText={(r) => `${r.org}/${r.repo} ${r.path} ${r.server ?? ""} ${r.target ?? ""} ${r.secret_type ?? ""} ${r.owner.ref ?? ""} ${r.owner.identity?.name ?? ""}`}
        searchPlaceholder="Search repository, server, owner…"
        filters={[
          { id: "kind", label: "Finding", options: [{ value: "mcp_server", label: "MCP server" }, { value: "agent_credential", label: "Credential" }], get: (r) => r.kind },
          { id: "secret", label: "Secret type", options: opts(uniq((data ?? []).map((r) => r.secret_type))), get: (r) => r.secret_type },
          { id: "owner", label: "Linked by", options: opts(["codeowners", "committer", "none"]), get: (r) => r.owner.source },
          { id: "repo", label: "Repository", options: opts(uniq((data ?? []).map((r) => `${r.org}/${r.repo}`))), get: (r) => `${r.org}/${r.repo}` },
        ]}
        onRefresh={reload}
        rowLabel={(r) => `${r.repo}/${r.path}`}
        empty={<EmptyState title="No MCP configs or agent credentials found" icon={<Code2 size={18} />}>Connect a GitHub org (the github-scan connector) to scan for them.</EmptyState>}
      />
    </div>
  );
}
