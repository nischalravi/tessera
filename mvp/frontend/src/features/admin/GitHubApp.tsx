import { FormEvent, useState } from "react";
import { Copy } from "lucide-react";
import { GitHubAppInput, GitHubAppSettings, githubApp, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, Loading, Page, useConfirm, useToast } from "../../components";
import { errText, Fact, when } from "./common";
import { GitHubAppForm, changed, checkForm, formOf, inputOf, shortFingerprint, webhookURL } from "./githubAppModel";

/**
 * Settings → GitHub App: the App Tessera posts its policy check run and comment with, and the webhook that runs the check when a pull
 * request is opened or updated (AC-10). Neither secret is ever shown again: the private key by its fingerprint, the webhook secret by
 * the date it was set; a new webhook secret is shown once, when it is made. Registering the App on GitHub is done on GitHub, by a person.
 */
export function GitHubApp() {
  const { data, error, reload } = useApi<GitHubAppSettings>("/policy/github/app");
  return (
    <Page title="GitHub App" crumbs={[["Settings"], ["GitHub App"]]}
      sub="The App that posts Tessera's policy check on pull requests of your access-as-code repository, and runs it when a pull request changes.">
      {!data ? <Loading kind="block" error={error} what="GitHub App settings" /> : <Settings s={data} onSaved={reload} />}
    </Page>
  );
}

function Settings({ s, onSaved }: { s: GitHubAppSettings; onSaved?: () => void }) {
  const { can } = useSession();
  const toast = useToast();
  const confirm = useConfirm();
  const manage = can("connections.manage");
  const [form, setForm] = useState<GitHubAppForm>(() => formOf(s));
  const [busy, setBusy] = useState(false);
  const [shown, setShown] = useState("");
  const errors = checkForm(form, s.key_set);
  const dirty = changed(form, s);
  const url = webhookURL(window.location.origin, s.webhook_path);
  const set = (patch: Partial<GitHubAppForm>) => setForm({ ...form, ...patch });

  const run = async (input: GitHubAppInput, done: string) => {
    setBusy(true);
    try {
      const saved = await githubApp.save(input);
      setShown(saved.webhook_secret ?? "");
      setForm(formOf(saved));
      toast(done);
      onSaved?.();
    } catch (e) {
      toast(errText(e), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  const submit = (ev: FormEvent) => {
    ev.preventDefault();
    if (!manage || busy || !dirty || Object.keys(errors).length) return;
    void run(inputOf(form, s), "GitHub App settings saved");
  };
  const removeKey = async () => {
    const ok = await confirm({
      title: "Remove the private key?", danger: true, confirmLabel: "Remove key",
      body: "Tessera can no longer post checks or read your repository, and the App is turned off until you set a key again.",
    });
    if (ok !== null) await run({ enabled: false, remove_key: true }, "Private key removed");
  };
  const rotate = async () => {
    const ok = await confirm({
      title: s.webhook_secret_set ? "Make a new webhook secret?" : "Make a webhook secret?", confirmLabel: "Make secret",
      body: s.webhook_secret_set
        ? "The current secret stops working at once. Paste the new one into the App's webhook settings on GitHub, or deliveries are refused."
        : "Paste it into the App's webhook settings on GitHub. It is shown once.",
    });
    if (ok !== null) await run({ enabled: s.enabled, rotate_webhook_secret: true }, "New webhook secret made");
  };
  const removeSecret = async () => {
    const ok = await confirm({
      title: "Remove the webhook secret?", danger: true, confirmLabel: "Remove secret",
      body: "Tessera refuses every webhook delivery until a new secret is made. The check can still be run from CI.",
    });
    if (ok !== null) await run({ enabled: s.enabled, remove_webhook_secret: true }, "Webhook secret removed");
  };
  const copy = (text: string, what: string) =>
    navigator.clipboard?.writeText(text).then(() => toast(`${what} copied`), () => toast(`Copy failed: select the ${what.toLowerCase()} and copy it`, { kind: "error" }));

  const field = (id: keyof GitHubAppForm, label: string, hint: string, props: { inputMode?: "numeric"; placeholder?: string } = {}) => (
    <label className="stack-sm" style={{ maxWidth: 420 }}>
      <span className="small"><b>{label}</b></span>
      <input className="input" aria-invalid={errors[id] ? true : undefined} aria-describedby={`gh-${id}-hint`} disabled={!manage}
        value={String(form[id])} onChange={(ev) => set({ [id]: ev.target.value })} {...props} />
      <span id={`gh-${id}-hint`} className={errors[id] ? "xs" : "xs faint"} role={errors[id] ? "alert" : undefined} style={errors[id] ? { color: "var(--critical-text, #b42318)" } : undefined}>{errors[id] ?? hint}</span>
    </label>
  );

  return (
    <div className="stack">
      {!manage && <Callout tone="neutral">Your role can read these settings. Changing them needs the connections.manage permission and a fresh sign-in.</Callout>}
      <form className="card stack-sm" onSubmit={submit} aria-label="GitHub App">
        <div className="row wrap" style={{ gap: 8, alignItems: "center" }}>
          <h2 style={{ margin: 0 }}>The App</h2>
          <Badge tone={s.enabled ? "ok" : "neutral"} dot>{s.enabled ? "On" : "Off"}</Badge>
        </div>
        <label className="row" style={{ gap: 8, alignItems: "center" }}>
          <input type="checkbox" checked={form.enabled} disabled={!manage} onChange={(ev) => set({ enabled: ev.target.checked })} />
          <span className="small"><b>Post checks on pull requests</b></span>
        </label>
        {field("appId", "App ID", "The number on the App's settings page on GitHub.", { inputMode: "numeric" })}
        {field("installationId", "Installation ID", "The number at the end of the installation's URL.", { inputMode: "numeric" })}
        {field("repo", "Repository", "The one repository the App acts on, as owner/name.", { placeholder: "your-org/access-policy" })}
        <div className="stack-sm" style={{ maxWidth: 520 }}>
          <div className="small"><b>Private key</b></div>
          {s.key_set ? (
            <div className="row wrap" style={{ gap: 12, alignItems: "center" }}>
              <Badge tone="ok" dot>Set</Badge>
              <span className="small">Fingerprint <code title={s.key_fingerprint}>{shortFingerprint(s.key_fingerprint)}</code>, set {when(s.key_set_at)}</span>
            </div>
          ) : <Badge tone="warning" dot>Not set</Badge>}
          <label className="stack-sm">
            <span className="xs faint">{s.key_set ? "Paste a new key to replace it. The stored key is never shown." : "Paste the App's private key (the .pem file GitHub gave you)."}</span>
            <textarea className="input" rows={4} spellCheck={false} autoComplete="off" aria-label="Private key (PEM)" aria-invalid={errors.privateKey ? true : undefined}
              aria-describedby={errors.privateKey ? "gh-key-err" : undefined} disabled={!manage} value={form.privateKey} onChange={(ev) => set({ privateKey: ev.target.value })}
              style={{ fontFamily: "var(--mono, monospace)" }} />
          </label>
          {errors.privateKey && <span id="gh-key-err" className="xs" role="alert" style={{ color: "var(--critical-text, #b42318)" }}>{errors.privateKey}</span>}
        </div>
        <div className="row wrap" style={{ gap: 8 }}>
          <Button type="submit" variant="primary" disabled={!manage || busy || !dirty || Object.keys(errors).length > 0}>Save</Button>
          {dirty && <Button size="sm" onClick={() => setForm(formOf(s))}>Reset</Button>}
          {s.key_set && <Button variant="danger" disabled={!manage || busy} onClick={removeKey}>Remove key</Button>}
        </div>
        <p className="xs faint" style={{ margin: 0 }}>
          Permissions the App needs: {Object.entries({ ...s.permissions, contents: "read" }).map(([k, v]) => `${k}: ${v}`).join(", ")}.
          {s.updated_by ? ` Last changed by ${s.updated_by} ${when(s.updated_at)}.` : ""}
        </p>
      </form>

      <section className="card stack-sm" aria-label="Webhook">
        <div className="row wrap" style={{ gap: 8, alignItems: "center" }}>
          <h2 style={{ margin: 0 }}>Webhook</h2>
          <Badge tone={s.webhook_secret_set ? "ok" : "warning"} dot>{s.webhook_secret_set ? "Secret set" : "No secret"}</Badge>
        </div>
        <p className="small muted" style={{ margin: 0 }}>
          With the webhook, Tessera checks a pull request when it is opened, updated or reopened, on the files of the pull request itself. In the App's settings on GitHub
          subscribe to the Pull request event, give it Contents: read-only, set the content type to <code>application/json</code>, and use the URL and secret below.
        </p>
        <Fact label="Webhook URL">
          <span className="row wrap" style={{ gap: 8, alignItems: "center" }}>
            <code style={{ wordBreak: "break-all" }}>{url}</code>
            <Button size="sm" icon={<Copy size={14} />} onClick={() => copy(url, "URL")}>Copy URL</Button>
          </span>
        </Fact>
        <Fact label="Secret">{s.webhook_secret_set ? `Set ${when(s.webhook_secret_set_at)}. It is never shown again.` : "Not set. Every delivery is refused until you make one."}</Fact>
        {shown && (
          <Callout tone="warn">
            <div className="stack-sm">
              <div><b>Copy the secret now. It is shown once.</b> Paste it into the App's webhook settings on GitHub.</div>
              <div className="row wrap" style={{ gap: 8, alignItems: "center" }}>
                <code data-testid="webhook-secret" style={{ wordBreak: "break-all" }}>{shown}</code>
                <Button size="sm" icon={<Copy size={14} />} onClick={() => copy(shown, "Secret")}>Copy secret</Button>
                <Button size="sm" onClick={() => setShown("")}>I have saved it</Button>
              </div>
            </div>
          </Callout>
        )}
        <div className="row wrap" style={{ gap: 8 }}>
          <Button variant="primary" disabled={!manage || busy} onClick={rotate}>{s.webhook_secret_set ? "Rotate secret" : "Make secret"}</Button>
          {s.webhook_secret_set && <Button variant="danger" disabled={!manage || busy} onClick={removeSecret}>Remove secret</Button>}
        </div>
      </section>
    </div>
  );
}
