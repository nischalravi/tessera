import { FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { AdminChange, RetentionClass, RetentionView, adminChanges, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, useToast } from "../../components";
import { errText, outcome } from "./common";
import { CLASS_LABEL, describeDays, draftChange, summarize } from "./retentionModel";

/**
 * Admin → Retention (issue #298): how long each data class stays online before the archival job seals it into
 * an archive segment (Admin → Archive). Changing it is an admin change request (retention.update): a second
 * admin approves what the payload says, each with a fresh passkey sign-in, and the server refuses anything
 * below a class's minimum.
 */
export function Retention() {
  const { data, error, reload } = useApi<RetentionView>("/admin/retention");
  const open = useApi<{ change_requests: AdminChange[] }>("/admin/change-requests?status=open");
  const { can } = useSession();
  const toast = useToast();
  const [edits, setEdits] = useState<Partial<Record<RetentionClass, string>>>({});
  const [busy, setBusy] = useState(false);
  if (error) return <Callout tone="bad">{error.message}</Callout>;
  if (!data) return <div className="card"><p className="small muted" style={{ margin: 0 }}>Loading…</p></div>;

  const draft = draftChange(data.settings, edits);
  const errors = Object.keys(draft.errors).length;
  const waiting = (open.data?.change_requests ?? []).filter((c) => c.type === "retention.update");
  const allowed = can("admin.change.request");
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!draft.changed.length || errors) return;
    setBusy(true);
    try {
      toast(outcome(await adminChanges.submit("retention.update", draft.payload)));
      setEdits({});
      reload?.();
      open.reload?.();
    } catch (err) {
      toast(errText(err), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="stack">
      {data.archive.enabled ? (
        <Callout tone="ok">
          Records past their retention are sealed into the archive ({data.archive.location === "remote" ? "an object store" : "a local directory"}) by a job that runs every {Math.round(data.archive.every_seconds / 3600)} hours.
          They leave the online store only after the segment is written, read back and verified. The audit hash chain stays verifiable across the archive.
        </Callout>
      ) : (
        <Callout tone="warn">
          Archiving is not configured on this server (<code>TESSERA_ARCHIVE_DIR</code> or <code>TESSERA_ARCHIVE_URL</code>, and a key-encryption key), so nothing is archived and nothing is removed because of these settings.
        </Callout>
      )}
      {waiting.length > 0 && (
        <Callout tone="neutral">
          {waiting.length === 1 ? "A retention change is" : `${waiting.length} retention changes are`} waiting for a second admin: {waiting.map((c) => c.summary).join("; ")}.{" "}
          <Link to="/admin/change-requests">Open change requests</Link>
        </Callout>
      )}
      <form className="card stack-sm" onSubmit={submit} aria-label="Retention settings">
        <h2>Time online, by kind of record</h2>
        <p className="small muted" style={{ margin: 0 }}>
          Each class has a minimum that cannot be undercut. Changing a setting needs a second admin and a fresh passkey sign-in from both of you, and is recorded in the audit log.
        </p>
        <div className="table-scroll">
          <table>
            <thead>
              <tr><th scope="col">Records</th><th scope="col">Online for</th><th scope="col">Minimum</th><th scope="col" className="hide-narrow">Counted from</th><th scope="col">New value (days)</th></tr>
            </thead>
            <tbody>
              {data.settings.map((s) => {
                const err = draft.errors[s.class];
                return (
                  <tr key={s.class}>
                    <th scope="row"><b>{CLASS_LABEL[s.class] ?? s.label}</b></th>
                    <td>
                      <span className="tnum">{describeDays(s.days)}</span> <span className="xs faint">({s.days} days)</span>{" "}
                      {s.custom ? <Badge tone="info">Set</Badge> : <Badge>Default</Badge>}
                    </td>
                    <td className="small tnum">{describeDays(s.min_days)}</td>
                    <td className="small muted hide-narrow">{s.basis}</td>
                    <td>
                      <input
                        className="input tnum"
                        style={{ width: 110 }}
                        inputMode="numeric"
                        aria-label={`New retention in days: ${s.label}`}
                        aria-invalid={err ? true : undefined}
                        aria-describedby={err ? `ret-err-${s.class}` : undefined}
                        placeholder={String(s.days)}
                        value={edits[s.class] ?? ""}
                        disabled={!allowed}
                        onChange={(e) => setEdits({ ...edits, [s.class]: e.target.value })}
                      />
                      {err && <div id={`ret-err-${s.class}`} className="xs" role="alert" style={{ color: "var(--critical-text, #b42318)" }}>{err}</div>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {!allowed && <p className="small muted" style={{ margin: 0 }}>Your role can read these settings but not request a change.</p>}
        <div className="row wrap" style={{ gap: 8 }}>
          <Button type="submit" variant="primary" disabled={!allowed || busy || errors > 0 || draft.changed.length === 0}>Request change</Button>
          {draft.changed.length > 0 && !errors && <span className="small muted">{summarize(data.settings, draft)}</span>}
          {draft.changed.length > 0 && <Button type="button" size="sm" onClick={() => setEdits({})}>Clear</Button>}
        </div>
      </form>
    </div>
  );
}
