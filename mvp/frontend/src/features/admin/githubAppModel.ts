import type { GitHubAppInput, GitHubAppSettings } from "../../api";

/** The form of Admin → GitHub App: what is typed, kept as text until it is checked. */
export interface GitHubAppForm {
  enabled: boolean;
  appId: string;
  installationId: string;
  repo: string;
  /** A new private key (PEM), only when the key is being set or replaced. Never filled from the server. */
  privateKey: string;
}

export const formOf = (s: GitHubAppSettings): GitHubAppForm => ({
  enabled: s.enabled, appId: s.app_id, installationId: s.installation_id ? String(s.installation_id) : "", repo: s.repo, privateKey: "",
});

const REPO = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\/[A-Za-z0-9_.-]{1,100}$/;

/** One message per invalid field (the server checks again). Enabling needs every field and a key, stored or typed. */
export function checkForm(f: GitHubAppForm, keySet: boolean): Partial<Record<keyof GitHubAppForm, string>> {
  const e: Partial<Record<keyof GitHubAppForm, string>> = {};
  const app = f.appId.trim(), inst = f.installationId.trim(), repo = f.repo.trim(), key = f.privateKey.trim();
  if (app && !/^\d{1,20}$/.test(app)) e.appId = "The App ID is the number on the App's page.";
  if (inst && !(/^\d{1,15}$/.test(inst) && Number(inst) >= 1)) e.installationId = "The installation ID is a positive number.";
  if (repo && (!REPO.test(repo) || repo.includes(".."))) e.repo = "Write the repository as owner/name.";
  if (key && !/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(key)) e.privateKey = "Paste the whole private key, from the BEGIN line to the END line.";
  if (f.enabled) {
    if (!app && !e.appId) e.appId = "Enabling needs the App ID.";
    if (!inst && !e.installationId) e.installationId = "Enabling needs the installation ID.";
    if (!repo && !e.repo) e.repo = "Enabling needs the repository.";
    if (!key && !keySet) e.privateKey = "Enabling needs the App's private key.";
  }
  return e;
}

/** The PUT body: only what the person changed, plus `enabled`. A blank private key is left out, which keeps the stored one. */
export function inputOf(f: GitHubAppForm, s: GitHubAppSettings): GitHubAppInput {
  const out: GitHubAppInput = { enabled: f.enabled };
  if (f.appId.trim() !== s.app_id) out.app_id = f.appId.trim();
  const inst = f.installationId.trim() === "" ? 0 : Number(f.installationId.trim());
  if (inst !== s.installation_id) out.installation_id = inst;
  if (f.repo.trim() !== s.repo) out.repo = f.repo.trim();
  if (f.privateKey.trim()) out.private_key = f.privateKey.trim();
  return out;
}

/** True when the form differs from what is stored. */
export const changed = (f: GitHubAppForm, s: GitHubAppSettings): boolean => {
  const i = inputOf(f, s);
  return i.enabled !== s.enabled || Object.keys(i).length > 1;
};

/** The URL to give GitHub as the App's webhook URL: Tessera's own address plus the tenant's path. */
export const webhookURL = (origin: string, path: string): string => origin.replace(/\/+$/, "") + path;

/** The key's fingerprint, grouped for reading against the App's page; "" when there is none. */
export const shortFingerprint = (fp: string): string => (fp.length > 24 ? `${fp.slice(0, 24)}…` : fp);
