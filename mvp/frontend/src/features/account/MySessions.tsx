import { useState } from "react";
import { MySession, fmtDate, relTime, revokeSession, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { useConfirm } from "../../components/Dialog";
import { Column, DataTable } from "../../components/DataTable";
import { Callout } from "../../components/Feedback";
import { Page } from "../../components/Page";

const KIND: Record<string, string> = { browser: "Browser", cli: "Command line", break_glass: "Break-glass" };

/**
 * My sessions (design §17): the signed-in user's browser and CLI sessions, with sign-out for any
 * of them. Revoking the current one signs you out here.
 */
export function MySessions() {
  const { data, error, reload } = useApi<MySession[]>("/auth/sessions");
  const { signOut } = useSession();
  const confirm = useConfirm();
  const [busy, setBusy] = useState<string | null>(null);
  const [failure, setFailure] = useState<string | null>(null);

  const revoke = async (s: MySession) => {
    const ok = await confirm({
      title: s.current ? "Sign out of this session?" : "Sign out of that session?",
      body: s.current ? "You will need to sign in again." : "The device or browser that holds it is signed out at its next request.",
      confirmLabel: "Sign out",
      danger: true,
    });
    if (ok === null) return;
    setBusy(s.id);
    setFailure(null);
    try {
      await revokeSession(s.id);
      if (s.current) await signOut();
      else reload();
    } catch (e: any) {
      setFailure(String(e.message ?? e));
    } finally {
      setBusy(null);
    }
  };

  const active = data?.filter((s) => s.status === "active") ?? null;
  const ended = (data ?? []).filter((s) => s.status !== "active");
  const ends = (s: MySession) => (s.idle_expires_at < s.absolute_expires_at ? s.idle_expires_at : s.absolute_expires_at);
  const columns: Column<MySession>[] = [
    { id: "kind", header: "Session", cell: (s) => <>{KIND[s.kind] ?? s.kind} {s.current && <Badge tone="ok">This session</Badge>}</>, sort: (s) => s.kind },
    { id: "created", header: "Signed in", cell: (s) => fmtDate(s.created_at), sort: (s) => s.created_at },
    { id: "active", header: "Last active", cell: (s) => relTime(s.last_activity_at), sort: (s) => s.last_activity_at },
    { id: "ends", header: "Ends by", cell: (s) => fmtDate(ends(s)), sort: ends },
    { id: "ip", header: "From", cell: (s) => <span className="mono small">{s.ip_first ?? "unknown"}</span>, sort: (s) => s.ip_first },
    { id: "act", header: "", cell: (s) => (
      <Button variant="ghost" onClick={() => revoke(s)} disabled={busy === s.id} aria-label={`Sign out of the ${KIND[s.kind] ?? s.kind} session from ${fmtDate(s.created_at)}`}>
        {busy === s.id ? "Signing out…" : "Sign out"}
      </Button>
    ) },
  ];
  return (
    <Page title="My sessions" crumbs={[["Account"], ["My sessions"]]} sub="Where you are signed in to Tessera. Sign out of anything you don't recognize.">
      {failure && <Callout tone="bad">{failure}</Callout>}
      <DataTable id="my-sessions" rows={active} error={error} rowKey={(s) => s.id} columns={columns}
        searchText={(s) => `${s.kind} ${s.ip_first ?? ""}`} searchPlaceholder="Search sessions" onRefresh={reload}
        empty={<span>No active sessions.</span>} />
      {ended.length > 0 && (
        <p className="faint small">{ended.length} ended session{ended.length === 1 ? "" : "s"} (signed out, expired or replaced) are kept for the audit trail.</p>
      )}
    </Page>
  );
}
