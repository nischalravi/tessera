/**
 * The guest's "request renewal" page (/renew#t=...), reached from the reminder email. It has no
 * sign-in and no navigation. The token comes from the URL fragment, leaves the address bar at once
 * and is sent only when the guest presses the button. Whatever the answer, the page says the same
 * thing: the request was received. It does not say whether the link was good or whether the sponsor
 * will agree.
 */
import { useEffect, useRef, useState } from "react";
import { CheckCircle2 } from "lucide-react";
import { requestRenewal } from "../../api";
import { Button } from "../../components/Button";
import { Callout } from "../../components/Feedback";
import { tenantSlug } from "../claim/model";

const TOKEN = /^[A-Za-z0-9_-]{43}$/;

export const renewalTokenFromHash = (hash: string): string => {
  const m = /(?:^#|&)t=([^&]+)/.exec(hash);
  return m && TOKEN.test(m[1]) ? m[1] : "";
};

export default function RenewPage() {
  const slug = tenantSlug(window.location.hostname, import.meta.env.VITE_TESSERA_TENANT as string | undefined);
  const token = useRef("");
  const [state, setState] = useState<"ready" | "sending" | "sent" | "error" | "nolink">("ready");
  const [error, setError] = useState("");
  useEffect(() => {
    token.current = renewalTokenFromHash(window.location.hash);
    window.history.replaceState(null, "", window.location.pathname); // the token never stays in the address bar
    if (!token.current) setState("nolink");
  }, []);
  const send = async () => {
    setState("sending");
    try {
      await requestRenewal(slug, token.current);
      token.current = "";
      setState("sent");
    } catch (e: any) {
      setError(String(e.message ?? e));
      setState("error");
    }
  };
  return (
    <div className="claim-wrap">
      <main className="claim" aria-labelledby="renew-title">
        <p className="claim-brand">Tessera</p>
        <h1 id="renew-title" className="claim-h">Ask for your access to be renewed</h1>
        {state === "nolink" && <Callout tone="info">Open the link from your reminder email to ask for a renewal. If it does not work, ask your sponsor directly.</Callout>}
        {(state === "ready" || state === "sending" || state === "error") && (
          <>
            <p>Your access is about to end. Your sponsor decides whether to renew it; this sends them a request.</p>
            {state === "error" && <Callout tone="bad">{error}</Callout>}
            <Button variant="primary" onClick={send} disabled={state === "sending"}>{state === "sending" ? "Sending…" : "Request renewal"}</Button>
          </>
        )}
        {state === "sent" && (
          <p role="status" className="row tight"><CheckCircle2 size={18} aria-hidden /> We have received your request. If your sponsor agrees, they will renew your access.</p>
        )}
      </main>
    </div>
  );
}
