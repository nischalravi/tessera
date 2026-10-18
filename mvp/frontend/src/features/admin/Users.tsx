import { useState } from "react";
import { UserMinus, UserPlus } from "lucide-react";
import { AdminUser, adminChanges, relTime, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, DataTable, Page, SidePanel, useConfirm, useSelected, useToast } from "../../components";
import { Fact, errText, outcome, when } from "./common";

const ROLES = ["viewer", "operator", "auditor", "policy_admin", "tenant_admin"];
const ADMIN_ROLES = new Set(["policy_admin", "tenant_admin", "break_glass"]);

/** Platform users (the people who sign in to Tessera) and their roles, with the admin-change actions. */
export function Users() {
  const { data, error, reload } = useApi<{ users: AdminUser[] }>("/admin/users");
  const { can } = useSession();
  const [selected, setSelected] = useSelected();
  const rows = data?.users ?? null;
  const current = rows?.find((u) => u.id === selected) ?? null;
  return (
    <Page title="Users" crumbs={[["Settings"], ["Admin", "/admin"], ["Users"]]}
      sub="The people who sign in to Tessera and the roles they hold. Granting an admin role needs a second admin and a cooling-off period; roles from IdP groups never include admin roles.">
      <DataTable
        id="admin-users"
        rows={rows}
        error={error}
        rowKey={(u) => u.id}
        activeKey={selected}
        onRowClick={(u) => setSelected(u.id)}
        onRefresh={reload}
        rowLabel={(u) => u.display_name}
        columns={[
          { id: "name", header: "User", sort: (u) => u.display_name, cell: (u) => <div><b>{u.display_name}</b><div className="xs faint">{u.email ?? "no email"}</div></div> },
          { id: "status", header: "Status", sort: (u) => u.status, cell: (u) => <Badge tone={u.status === "active" ? "ok" : "neutral"} dot>{u.status}</Badge> },
          {
            id: "roles", header: "Roles", cell: (u) => (
              <span className="row tight">{u.roles.length === 0 ? <span className="faint small">none</span> : u.roles.map((r) => <Badge key={`${r.role}:${r.source}`} tone={ADMIN_ROLES.has(r.role) ? "accent" : "outline"} title={`source ${r.source}`}>{r.role}</Badge>)}</span>
            ),
            csv: (u) => u.roles.map((r) => r.role).join(" "),
          },
          { id: "last", header: "Last sign-in", sort: (u) => u.last_login_at ?? "", hideNarrow: true, cell: (u) => <span className="small">{u.last_login_at ? relTime(u.last_login_at.replace("Z", "")) : "never"}</span> },
        ]}
        searchText={(u) => `${u.display_name} ${u.email ?? ""} ${u.status} ${u.roles.map((r) => r.role).join(" ")}`}
        searchPlaceholder="Search users, e-mail or role…"
        filters={[
          { id: "status", label: "Status", options: [{ value: "active", label: "active" }, { value: "disabled", label: "disabled" }], get: (u) => u.status },
          { id: "role", label: "Role", options: ROLES.map((r) => ({ value: r, label: r })), get: (u) => u.roles.map((r) => r.role) },
        ]}
      />
      {current && <UserPanel user={current} canRequest={can("admin.change.request")} canDisable={can("admin.users.disable")} onClose={() => setSelected(null)} onChanged={() => reload?.()} />}
    </Page>
  );
}

function UserPanel({ user, canRequest, canDisable, onClose, onChanged }: { user: AdminUser; canRequest: boolean; canDisable: boolean; onClose: () => void; onChanged: () => void }) {
  const toast = useToast();
  const confirm = useConfirm();
  const [role, setRole] = useState("operator");
  const [busy, setBusy] = useState(false);
  const run = async (f: () => Promise<string>) => {
    setBusy(true);
    try {
      toast(await f());
    } catch (e) {
      toast(errText(e), { kind: "error" });
    } finally {
      setBusy(false);
      onChanged();
    }
  };
  const held = new Set(user.roles.map((r) => r.role));
  const active = user.status === "active" && !user.is_break_glass;
  return (
    <SidePanel title={user.display_name} sub={user.email ?? undefined} onClose={onClose}>
      <div className="stack">
        <div className="grid g2">
          <Fact label="Status">{user.status}{user.disabled_reason ? ` · ${user.disabled_reason}` : ""}</Fact>
          <Fact label="Created">{when(user.created_at)}</Fact>
          <Fact label="Last sign-in">{when(user.last_login_at)}</Fact>
        </div>
        <div>
          <div className="xs faint">Roles</div>
          {user.roles.length === 0 ? <div className="small faint">None</div> : (
            <ul className="small" style={{ margin: 0, paddingLeft: 0, listStyle: "none" }}>
              {user.roles.map((r) => (
                <li key={`${r.role}:${r.source}`} className="row spread" style={{ padding: "4px 0" }}>
                  <span><b>{r.role}</b> <span className="faint">via {r.source}{r.expires_at ? `, until ${when(r.expires_at)}` : ""}</span></span>
                  {canRequest && active && r.source !== "idp_group" && (
                    <Button size="sm" variant="danger" disabled={busy} onClick={async () => {
                      if ((await confirm({ title: `Revoke ${r.role} from ${user.display_name}?`, body: ADMIN_ROLES.has(r.role) ? "Removing an admin role needs a second admin." : "It applies at once and ends their sessions.", confirmLabel: "Request revocation", danger: true })) === null) return;
                      await run(async () => outcome(await adminChanges.submit("role.revoke", { user_id: user.id, role: r.role })));
                    }}>Revoke</Button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
        {canRequest && active && (
          <div className="stack-sm">
            <div className="xs faint">Grant a role</div>
            <div className="row">
              <select className="input" aria-label="Role to grant" value={role} onChange={(e) => setRole(e.target.value)}>
                {ROLES.filter((r) => !held.has(r)).map((r) => <option key={r}>{r}</option>)}
              </select>
              <Button icon={<UserPlus size={14} />} disabled={busy || held.has(role)} onClick={() => run(async () => outcome(await adminChanges.submit("role.grant", { user_id: user.id, role })))}>Request grant</Button>
            </div>
            <p className="xs faint" style={{ margin: 0 }}>policy_admin and tenant_admin need a second admin and wait 24 hours; the other roles apply at once. Roles from IdP groups are managed at the IdP.</p>
          </div>
        )}
        {canDisable && active && (
          <div>
            <Button variant="danger" icon={<UserMinus size={14} />} disabled={busy} onClick={async () => {
              const reason = await confirm({ title: `Disable ${user.display_name}?`, body: "They are signed out at once and cannot sign in again.", confirmLabel: "Disable", danger: true, reason: { label: "Why", required: true } });
              if (reason) await run(async () => { await adminChanges.disableUser(user.id, reason); return "User disabled and signed out."; });
            }}>Disable user</Button>
          </div>
        )}
      </div>
    </SidePanel>
  );
}
