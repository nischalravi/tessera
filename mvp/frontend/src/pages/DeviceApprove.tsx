import { FormEvent, useRef, useState } from "react";
import { ApiError, DeviceRequest, deviceDecide, deviceLookup, fmtDate } from "../api";
import { useSession } from "../app/auth";
import { Button } from "../components/Button";
import { Chip } from "../components/Badge";
import { Callout } from "../components/Feedback";
import { Page } from "../components/Page";
import { formatUserCode, isCompleteUserCode } from "../deviceCode";

/**
 * Approve a command-line sign-in (design §9.3, §17). The CLI shows a code and sends the person
 * here; they type it (there is no pre-filled link), see who is asking and from where, and decide.
 * Approving needs a phishing-resistant sign-in from the last five minutes: when the session's is
 * older the API answers step_up_required and the app's step-up dialog takes over, then offers to
 * resume this approval. Wrong codes are counted by the API (five lock the session out for ten
 * minutes), and nothing about the code or the decision is kept in browser storage beyond the
 * step-up's own pending action.
 */
export default function DeviceApprove() {
  const { session } = useSession();
  const [code, setCode] = useState("");
  const [request, setRequest] = useState<DeviceRequest | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<"approved" | "denied" | null>(null);
  const input = useRef<HTMLInputElement>(null);

  const reset = () => {
    setCode("");
    setRequest(null);
    setDone(null);
    setError(null);
    input.current?.focus();
  };

  const lookup = async (e: FormEvent) => {
    e.preventDefault();
    if (!isCompleteUserCode(code) || busy) return;
    setBusy(true);
    setError(null);
    try {
      setRequest(await deviceLookup(code));
    } catch (err) {
      setRequest(null);
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const decide = async (decision: "approve" | "deny") => {
    if (!request || busy) return;
    setBusy(true);
    setError(null);
    try {
      const r = await deviceDecide(code, decision);
      setDone(r.status);
      setRequest(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Page title="Approve a command-line sign-in" crumbs={[["Account"], ["Command-line sign-in"]]}
      sub="Enter the code your terminal is showing to let tessera-cli sign in as you.">
      <div style={{ maxWidth: 560, display: "grid", gap: 16 }}>
        {done === "approved" && (
          <div role="status" style={{ display: "grid", gap: 12 }}>
            <Callout tone="ok">Approved. Your terminal signs in within a few seconds; you can close this page.</Callout>
            <div><Button onClick={reset}>Approve another</Button></div>
          </div>
        )}
        {done === "denied" && (
          <div role="status" style={{ display: "grid", gap: 12 }}>
            <Callout tone="neutral">Denied. The command-line sign-in was refused and its code no longer works.</Callout>
            <div><Button onClick={reset}>Enter another code</Button></div>
          </div>
        )}

        {!done && !request && (
          <form onSubmit={lookup} style={{ display: "grid", gap: 12 }}>
            <label className="field" htmlFor="device-code">
              Code
              <input id="device-code" ref={input} className="input mono" value={code} autoFocus autoComplete="off" autoCapitalize="characters"
                spellCheck={false} maxLength={9} inputMode="text" placeholder="XXXX-XXXX" style={{ fontSize: 22, letterSpacing: 2, maxWidth: 220 }}
                aria-describedby="device-code-hint" onChange={(e) => setCode(formatUserCode(e.target.value))} />
              <span id="device-code-hint" className="hint">Eight letters, shown as two groups of four.</span>
            </label>
            <div><Button type="submit" variant="primary" disabled={!isCompleteUserCode(code) || busy}>{busy ? "Checking…" : "Continue"}</Button></div>
          </form>
        )}

        {request && (
          <section aria-labelledby="device-request" style={{ display: "grid", gap: 14 }}>
            <h2 id="device-request" style={{ margin: 0, fontSize: 16 }}>{request.client} wants to sign in as you</h2>
            <dl style={{ display: "grid", gridTemplateColumns: "max-content 1fr", gap: "6px 16px", margin: 0 }}>
              <dt className="faint">Signed in here as</dt>
              <dd style={{ margin: 0 }}>{session.user.email ?? session.user.display_name}</dd>
              <dt className="faint">Asked</dt>
              <dd style={{ margin: 0 }}>{fmtDate(request.requested_at)}</dd>
              <dt className="faint">From the network address</dt>
              <dd className="mono" style={{ margin: 0 }}>{request.request_ip || "unknown"}</dd>
              <dt className="faint">Access</dt>
              <dd style={{ margin: 0, display: "flex", gap: 6, flexWrap: "wrap" }}>
                {request.scope.map((s) => <Chip key={s} mono>{s}</Chip>)}
              </dd>
              <dt className="faint">Code works until</dt>
              <dd style={{ margin: 0 }}>{fmtDate(request.expires_at)}</dd>
            </dl>
            <Callout tone="warn">
              Only approve if you just ran <span className="mono">tessera-cli login</span> yourself. Tessera staff will never ask you for this code.
              Approving needs you to have signed in with a passkey in the last {Math.round(request.requires.max_age / 60)} minutes; if you
              have not, you will be asked to sign in again first.
            </Callout>
            <div style={{ display: "flex", gap: 8 }}>
              <Button variant="primary" onClick={() => decide("approve")} disabled={busy}>{busy ? "Working…" : "Approve"}</Button>
              <Button variant="danger" onClick={() => decide("deny")} disabled={busy}>Deny</Button>
              <Button variant="ghost" onClick={reset} disabled={busy}>Not mine, start over</Button>
            </div>
          </section>
        )}

        {error && <div role="alert"><Callout tone="bad">{error}</Callout></div>}
      </div>
    </Page>
  );
}
