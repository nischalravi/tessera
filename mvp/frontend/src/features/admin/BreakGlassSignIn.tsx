import { useState } from "react";
import { KeyRound } from "lucide-react";
import { ApiError, breakGlass } from "../../api";
import { SignInFrame } from "../../app/auth";
import { Button, Callout } from "../../components";
import { ceremonyMessage, signWithKey, webauthnSupported } from "./webauthn";

/**
 * The break-glass sign-in page (design §9.6): for when the organization's identity provider is down,
 * misconfigured or compromised. It signs in with a registered hardware key, user verification
 * required. The session is limited to a few emergency actions and lasts 60 minutes; every admin and
 * security contact is told as soon as it starts.
 */
export function BreakGlassSignIn({ slug }: { slug: string }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const supported = webauthnSupported();

  const go = async () => {
    setBusy(true);
    setError(null);
    try {
      const options = await breakGlass.signInOptions(slug);
      const credential = await signWithKey(options);
      await breakGlass.signIn(slug, credential);
      // a full load: the session cookie is new, and the app reads it from the API
      window.location.assign("/admin/break-glass");
    } catch (e) {
      if (e instanceof ApiError) {
        setError(e.status === 404
          ? "Break-glass sign-in is not available for this organization."
          : e.status === 401 ? "The key was not accepted. Use a security key registered for break-glass, and try again."
          : e.message);
      } else {
        setError(ceremonyMessage(e));
      }
      setBusy(false);
    }
  };

  return (
    <SignInFrame>
      <h1 style={{ fontSize: "var(--fs-xl)" }}>Break-glass sign-in</h1>
      <p className="small muted" style={{ margin: 0 }}>
        For <b>{slug}</b>, when your identity provider cannot be used. You need the hardware security key your organization registered for
        break-glass. Everything you do is audited, every admin and security contact is told the moment you sign in, and the session ends
        after 60 minutes.
      </p>
      {!supported && <Callout tone="bad">This browser does not support security keys (WebAuthn). Use a current browser on the organization's Tessera address.</Callout>}
      {error && <Callout tone="bad">{error}</Callout>}
      <div className="row">
        <Button variant="primary" icon={<KeyRound size={14} />} onClick={go} disabled={busy || !supported} autoFocus>
          {busy ? "Waiting for the key…" : "Sign in with a security key"}
        </Button>
        <a className="small" href="/">Back to the normal sign-in</a>
      </div>
      <p className="faint small" style={{ margin: 0 }}>Touch the key when it blinks and enter its PIN or use its fingerprint reader.</p>
    </SignInFrame>
  );
}
