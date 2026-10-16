import { FormEvent, useId, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { BadgeCheck, LifeBuoy, Plus, RefreshCw, ShieldAlert } from "lucide-react";
import {
  HelpdeskCase,
  HelpdeskFinding,
  HelpdeskMethod,
  cancelHelpdeskCase,
  executeHelpdeskCase,
  fmtDate,
  managerApproveHelpdeskCase,
  secondApproveHelpdeskCase,
  startHelpdeskCase,
  useApi,
  verifyHelpdeskCase,
} from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Chip } from "../../components/Badge";
import type { Tone } from "../../components/Badge";
import { Button } from "../../components/Button";
import { Column, DataTable } from "../../components/DataTable";
import { Callout, EmptyState } from "../../components/Feedback";
import { CommandBar, Page, Tabs } from "../../components/Page";
import { useModal } from "../../components/overlay";
import { SidePanel, useSelected } from "../../components/SidePanel";
import { useToast } from "../../components/Toast";
import { PersonPicker } from "../directory/correlation";

/**
 * Help desk (issue #108): password and MFA resets that run through the IdP only after a
 * verification policy is satisfied. Hiding controls with can() is for usability only: the API
 * enforces helpdesk.reset / helpdesk.approve, the policy and a fresh phishing-resistant sign-in.
 */
type Tab = "cases" | "detections";

const METHOD_LABEL: Record<HelpdeskMethod, string> = {
  push: "Push to a phishing-resistant authenticator",
  callback: "Call-back to the number in HR",
  manager_approval: "Manager approval",
  idv: "Identity verification (IDV)",
};
const STATUS_TONE: Record<HelpdeskCase["status"], Tone> = {
  open: "info", executing: "warning", executed: "ok", failed: "critical", cancelled: "neutral",
};
const KIND_LABEL = { password: "Password", mfa: "MFA" } as const;

export function HelpDesk() {
  const [params, setParams] = useSearchParams();
  const tab = (params.get("tab") ?? "cases") as Tab;
  const { can } = useSession();
  const cases = useApi<{ cases: HelpdeskCase[] }>("/helpdesk/cases");
  const findings = useApi<{ findings: HelpdeskFinding[] }>("/helpdesk/findings");
  const [starting, setStarting] = useState(false);
  const [, setSelected] = useSelected();
  const open = (cases.data?.cases ?? []).filter((c) => c.status === "open" || c.status === "failed").length;
  return (
    <Page
      title="Help desk"
      crumbs={[["Identity"], ["Help desk"]]}
      sub="Reset a password or MFA only after the person is verified. Privileged identities need two verifications and a second approver who is not you."
      commands={
        <CommandBar
          label="Help desk commands"
          items={[
            { label: "New reset case", icon: <Plus size={14} />, onClick: () => setStarting(true), disabled: !can("helpdesk.reset"),
              title: can("helpdesk.reset") ? undefined : "Needs the helpdesk.reset permission" },
            { label: "Refresh", icon: <RefreshCw size={14} />, onClick: () => { cases.reload(); findings.reload(); } },
          ]}
        />
      }
      tabs={
        <Tabs
          label="Help desk sections"
          value={tab}
          onChange={(t) => setParams({ tab: t }, { replace: true })}
          tabs={[
            { id: "cases", label: `Cases${cases.data ? ` (${open} open)` : ""}` },
            { id: "detections", label: `Detections${findings.data ? ` (${findings.data.findings.length})` : ""}` },
          ]}
        />
      }
    >
      {tab === "cases" && <Cases q={cases} />}
      {tab === "detections" && <Detections q={findings} />}
      {starting && (
        <StartDialog
          onClose={() => setStarting(false)}
          onStarted={(c) => { setStarting(false); setParams({ tab: "cases" }, { replace: true }); cases.reload(); setSelected(c.id); }}
        />
      )}
    </Page>
  );
}

type Loaded<T> = { data: T | null; error: string | null; reload: () => void };

function Cases({ q }: { q: Loaded<{ cases: HelpdeskCase[] }> }) {
  const [selected, setSelected] = useSelected();
  const rows = q.data?.cases ?? null;
  const open = rows?.find((c) => c.id === selected);
  const cols: Column<HelpdeskCase>[] = [
    { id: "who", header: "Identity", sort: (r) => r.identity.toLowerCase(),
      cell: (r) => <span className="name-link">{r.identity}{r.privileged && <> <Badge tone="warning">Privileged</Badge></>}</span> },
    { id: "kind", header: "Reset", sort: (r) => r.kind, cell: (r) => <span className="small">{KIND_LABEL[r.kind]}</span> },
    { id: "system", header: "System", sort: (r) => r.system, cell: (r) => <Chip mono>{r.system}</Chip>, hideNarrow: true },
    { id: "status", header: "Status", sort: (r) => r.status, cell: (r) => <Badge tone={STATUS_TONE[r.status]}>{r.status}</Badge> },
    { id: "policy", header: "Verification", sort: (r) => (r.policy.satisfied ? 1 : 0),
      cell: (r) => (r.status === "executed" || r.status === "cancelled" ? <span className="faint">Closed</span>
        : r.policy.satisfied ? <Badge tone="ok">Satisfied</Badge> : <span className="small muted">{r.policy.missing[0]}</span>) },
    { id: "by", header: "Requested by", sort: (r) => r.requested_by, cell: (r) => <span className="small">{r.requested_by}</span>, hideNarrow: true },
    { id: "at", header: "Opened", sort: (r) => r.created_at, cell: (r) => <span className="small nowrap">{fmtDate(r.created_at)}</span> },
  ];
  return (
    <>
      <DataTable
        id="helpdesk-cases"
        rows={rows}
        error={q.error}
        rowKey={(r) => r.id}
        columns={cols}
        searchText={(r) => `${r.identity} ${r.system} ${r.kind} ${r.requested_by}`}
        searchPlaceholder="Search cases…"
        filters={[
          { id: "status", label: "Status", options: ["open", "executing", "executed", "failed", "cancelled"].map((s) => ({ value: s, label: s })), get: (r) => r.status },
          { id: "kind", label: "Reset", options: [{ value: "password", label: "Password" }, { value: "mfa", label: "MFA" }], get: (r) => r.kind },
          { id: "priv", label: "Identity", options: [{ value: "yes", label: "Privileged" }, { value: "no", label: "Standard" }], get: (r) => (r.privileged ? "yes" : "no") },
        ]}
        onRefresh={q.reload}
        rowLabel={(r) => `${r.identity} ${r.kind} reset`}
        onRowClick={(r) => setSelected(r.id)}
        activeKey={selected}
        empty={<EmptyState title="No reset cases" icon={<LifeBuoy size={18} />}>Start a case when someone asks for a password or MFA reset.</EmptyState>}
      />
      {open && <CasePanel c={open} onClose={() => setSelected(null)} onChanged={q.reload} />}
    </>
  );
}

/** Run one action on a case and report the outcome; refreshes the list on success. */
function useAct(onChanged: () => void) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const act = async <T,>(fn: () => Promise<T>, done: string): Promise<T | null> => {
    setBusy(true);
    try {
      const r = await fn();
      toast(done);
      onChanged();
      return r;
    } catch (e: any) {
      // a refused execute carries the policy; the message already says what is missing
      toast(String(e.message ?? e), { kind: "error" });
      onChanged();
      return null;
    } finally {
      setBusy(false);
    }
  };
  return { act, busy };
}

function CasePanel({ c, onClose, onChanged }: { c: HelpdeskCase; onClose: () => void; onChanged: () => void }) {
  const { can } = useSession();
  const { act, busy } = useAct(onChanged);
  const [tap, setTap] = useState<string | null>(null);
  const [evidence, setEvidence] = useState("");
  const [session, setSession] = useState("");
  const live = c.status === "open" || c.status === "failed";
  const canReset = can("helpdesk.reset");
  const canApprove = can("helpdesk.approve");
  const p = c.policy;
  const verify = (method: HelpdeskMethod) =>
    act(() => verifyHelpdeskCase(c.id, { method, evidence: evidence.trim() || undefined,
      number_source: method === "callback" ? "hr" : undefined, session_ref: method === "idv" ? session.trim() : undefined }),
    `${METHOD_LABEL[method]} recorded`);
  const run = async () => {
    const r = await act(() => executeHelpdeskCase(c.id), `Reset run for ${c.identity}`);
    if (r?.temporary_access_pass) setTap(r.temporary_access_pass);
  };
  return (
    <SidePanel title={`${c.identity}: ${KIND_LABEL[c.kind]} reset`} onClose={onClose}
      sub={<span className="small muted"><Badge tone={STATUS_TONE[c.status]}>{c.status}</Badge> · {c.system} · opened by {c.requested_by}</span>}>
      {tap && (
        <Callout tone="warn">
          Temporary access pass for {c.identity}: <b className="sys">{tap}</b>. It is shown once and is not stored. Give it to the verified
          person only; it works once and expires in 60 minutes.
        </Callout>
      )}
      {c.error && <Callout tone="bad">The last attempt failed: {c.error}. The case can be run again.</Callout>}
      {c.findings.length > 0 && (
        <Callout tone="bad" icon={<ShieldAlert size={16} />}>
          Possible account takeover: a new MFA device and a sign-in from a new location within 24 hours of this reset. See Detections.
        </Callout>
      )}
      <p className="small">{c.reason}</p>

      <h3 className="h-sm mt">Verification policy</h3>
      <p className="small muted">
        {c.privileged ? "Privileged identity: two different methods and a second approver who is not the requester." : "One verification method."}
      </p>
      <ul className="plain-list" aria-label="Policy status">
        <li><Badge tone={p.counted_methods.length >= p.required_verifications ? "ok" : "warning"}>{p.counted_methods.length} of {p.required_verifications}</Badge>{" "}
          <span className="small">verification methods{p.counted_methods.length > 0 && `: ${p.counted_methods.map((m) => METHOD_LABEL[m]).join(", ")}`}</span></li>
        {p.needs_second_approver && (
          <li><Badge tone={p.second_approved ? "ok" : "warning"}>{p.second_approved ? "Done" : "Needed"}</Badge>{" "}
            <span className="small">second approver{c.second_approver && `: ${c.second_approver}`}</span></li>
        )}
      </ul>
      {live && !p.satisfied && <Callout tone="neutral">Still needed: {p.missing.join("; ")}.</Callout>}

      {c.verifications.length > 0 && (
        <>
          <h3 className="h-sm mt">Attempts</h3>
          <ul className="plain-list">
            {c.verifications.map((v) => (
              <li key={v.id} className="small">
                <Badge tone={v.outcome === "passed" ? "ok" : "critical"}>{v.outcome}</Badge> {METHOD_LABEL[v.method]}
                <div className="muted">{v.verified_by} · {fmtDate(v.created_at)}{v.evidence && ` · ${v.evidence}`}</div>
              </li>
            ))}
          </ul>
        </>
      )}

      {live && (
        <>
          <h3 className="h-sm mt">Verify</h3>
          {!canReset && <Callout tone="neutral">Recording verifications needs the helpdesk.reset permission.</Callout>}
          <label className="field">
            Note (what you checked)
            <input className="input" value={evidence} maxLength={500} onChange={(e) => setEvidence(e.target.value)}
              placeholder="For a call-back: who you spoke to, on the number from the HR record" />
          </label>
          <div className="row tight mt">
            <Button size="sm" disabled={!canReset || busy} onClick={() => verify("push")}>Send push</Button>
            <Button size="sm" disabled={!canReset || busy || evidence.trim().length < 10} onClick={() => verify("callback")}
              title={evidence.trim().length < 10 ? "Write what you checked first" : undefined}>Record HR call-back</Button>
          </div>
          <p className="small muted">The call-back number must come from the HR record, never from the caller.</p>
          {c.privileged && (
            <div className="row tight mt">
              <input className="input" aria-label="IDV session reference" value={session} maxLength={200} onChange={(e) => setSession(e.target.value)}
                placeholder="IDV session reference" />
              <Button size="sm" disabled={!canReset || busy || !session.trim()} onClick={() => verify("idv")}>Confirm IDV</Button>
            </div>
          )}

          <h3 className="h-sm mt">Approvals</h3>
          {!canApprove && <Callout tone="neutral">Approvals need the helpdesk.approve permission.</Callout>}
          <div className="row tight">
            <Button size="sm" icon={<BadgeCheck size={14} />} disabled={!canApprove || busy}
              onClick={() => act(() => managerApproveHelpdeskCase(c.id, evidence.trim() || undefined), "Manager approval recorded")}>
              I am the manager: approve</Button>
            {c.privileged && (
              <Button size="sm" icon={<BadgeCheck size={14} />} disabled={!canApprove || busy || p.second_approved}
                onClick={() => act(() => secondApproveHelpdeskCase(c.id), "Second approval recorded")}>Approve as second approver</Button>
            )}
          </div>
          <p className="small muted">A manager approval counts only from the identity's manager. You cannot approve a case you opened.</p>

          <div className="row tight mt">
            <Button variant="primary" disabled={!canReset || busy || !p.satisfied} onClick={run}
              title={p.satisfied ? undefined : "The verification policy is not satisfied"}>{busy ? "Working…" : "Run reset"}</Button>
            <Button variant="ghost" disabled={!canReset || busy}
              onClick={async () => { if (await act(() => cancelHelpdeskCase(c.id), "Case cancelled")) onClose(); }}>Cancel case</Button>
          </div>
        </>
      )}

      {c.status === "executed" && (
        <>
          <h3 className="h-sm mt">Result</h3>
          <ul className="plain-list">{c.result.map((s, i) => <li key={i} className="small">{s}</li>)}</ul>
          <p className="small muted">Run by {c.executed_by} · {fmtDate(c.executed_at)}</p>
        </>
      )}
    </SidePanel>
  );
}

function Detections({ q }: { q: Loaded<{ findings: HelpdeskFinding[] }> }) {
  const [, setParams] = useSearchParams();
  const cols: Column<HelpdeskFinding>[] = [
    { id: "at", header: "Detected", sort: (r) => r.created_at, cell: (r) => <span className="small nowrap">{fmtDate(r.created_at)}</span> },
    { id: "rule", header: "Rule", cell: () => <span className="small">New MFA device and new location after a reset</span> },
    { id: "device", header: "New device", sort: (r) => r.detail.device ?? "", cell: (r) => <span className="small">{r.detail.device || "Unknown"}</span> },
    { id: "loc", header: "Sign-in from", sort: (r) => r.detail.location ?? "", cell: (r) => <span className="small">{r.detail.location}</span> },
    { id: "reset", header: "Reset at", sort: (r) => r.detail.reset_at ?? "", cell: (r) => <span className="small nowrap">{fmtDate(r.detail.reset_at)}</span>, hideNarrow: true },
  ];
  return (
    <DataTable
      id="helpdesk-findings"
      rows={q.data?.findings ?? null}
      error={q.error}
      rowKey={(r) => r.id}
      columns={cols}
      searchText={(r) => `${r.detail.device ?? ""} ${r.detail.location ?? ""}`}
      searchPlaceholder="Search detections…"
      onRefresh={q.reload}
      rowLabel={(r) => `Detection ${r.id}`}
      onRowClick={(r) => setParams({ tab: "cases", selected: r.case_id }, { replace: true })}
      empty={<EmptyState title="No detections" icon={<ShieldAlert size={18} />}>
        Fires when, within 24 hours of a reset, a new MFA device appears and a sign-in comes from a new location.</EmptyState>}
    />
  );
}

function StartDialog({ onClose, onStarted }: { onClose: () => void; onStarted: (c: HelpdeskCase) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const [who, setWho] = useState<number | null>(null);
  const [kind, setKind] = useState<"password" | "mfa">("mfa");
  const [system, setSystem] = useState("okta");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useModal(ref, onClose);
  const ready = who != null && reason.trim().length >= 10 && !busy;
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!ready || who == null) return;
    setBusy(true);
    setError(null);
    try {
      onStarted(await startHelpdeskCase({ identity_id: who, kind, system, reason: reason.trim() }));
    } catch (err: any) {
      setError(String(err.message ?? err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="dialog-wrap">
      <div className="overlay" onClick={onClose} aria-hidden />
      <div ref={ref} className="dialog" role="dialog" aria-modal="true" aria-labelledby={titleId}>
        <form onSubmit={submit}>
          <div className="dlg-b">
            <h2 id={titleId}>New reset case</h2>
            <p className="muted">Nothing is reset yet. The case runs only after the verification policy is satisfied.</p>
            <PersonPicker value={who} onChange={setWho} label="Identity to reset" />
            <label className="field mt">
              Reset
              <select className="input" value={kind} onChange={(e) => setKind(e.target.value as "password" | "mfa")}>
                <option value="mfa">MFA (reset factors)</option>
                <option value="password">Password</option>
              </select>
            </label>
            <label className="field mt">
              System
              <select className="input" value={system} onChange={(e) => setSystem(e.target.value)}>
                <option value="okta">Okta</option>
                <option value="entra">Microsoft Entra</option>
                <option value="simulated">Simulated (demo only)</option>
              </select>
            </label>
            <label className="field mt">
              Reason
              <textarea className="input" value={reason} maxLength={500} onChange={(e) => setReason(e.target.value)}
                placeholder="For example: lost phone, caller says they cannot sign in" />
              <span className="hint">10 to 500 characters. Kept in the audit log.</span>
            </label>
            {error && <div className="mt"><Callout tone="bad">{error}</Callout></div>}
          </div>
          <div className="dlg-f">
            <Button onClick={onClose}>Cancel</Button>
            <Button type="submit" variant="primary" disabled={!ready}>{busy ? "Starting…" : "Start case"}</Button>
          </div>
        </form>
      </div>
    </div>
  );
}
