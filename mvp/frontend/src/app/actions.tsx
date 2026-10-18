/**
 * Actions shared by object pages, list bulk actions and the command palette, so each one
 * behaves the same (same confirm copy, same toast) wherever it is triggered.
 */
import { useNavigate } from "react-router-dom";
import { ApiError, Campaign, DisableRecord, DisableResult, IdentityBrief, api, disableIdentity, enableIdentity, fmtDate, identityDisables } from "../api";
import { useConfirm } from "../components/Dialog";
import { useToast } from "../components/Toast";
import { mockIdentityOps } from "../mocks";
import { usePersona } from "./persona";

const DISABLE_BODY = (
  <>
    <p>Runs the kill switch first: revokes their sessions, refresh tokens and OAuth grants at each connected provider (Okta, Microsoft Entra, Google Workspace, GitHub) and checks each again. Then Tessera sets their accounts and status to disabled, which removes their access from the graph. Everything is audited.</p>
    <p><b>Not done:</b> Tessera does not suspend the account inside the provider. Anything a provider cannot revoke is listed as a manual task, and a failed step is retried automatically. Enable later sets the accounts back, but revoked sessions and grants stay revoked.</p>
  </>
);

function disabledMessage(name: string, r: DisableResult) {
  const c = r.containment;
  const tail = c.status === "retrying" ? "A provider step failed and is being retried: sessions may still be live." : c.status === "manual" ? `${c.manual_tasks.length} manual task(s) remain at the providers.` : "Sessions and grants revoked and verified.";
  return `${name} disabled (${r.disable.accounts.length} account${r.disable.accounts.length === 1 ? "" : "s"}). ${tail}`;
}

export function useIdentityActions() {
  const nav = useNavigate();
  const confirm = useConfirm();
  const toast = useToast();
  const { actor } = usePersona();

  return {
    async disable(i: IdentityBrief) {
      const reason = await confirm({
        title: `Disable ${i.name}?`,
        body: DISABLE_BODY,
        confirmLabel: "Disable",
        danger: true,
        reason: { label: "Reason (kept in the audit log)", required: true, minLength: 10, placeholder: "For example: suspected token theft, ticket SEC-1234" },
      });
      if (reason === null) return false;
      try {
        toast(disabledMessage(i.name, await disableIdentity(i.id, reason)), { kind: "ok" });
        return true;
      } catch (e: any) {
        toast(String(e.message ?? e), { kind: "error" });
        return false;
      }
    },
    async disableMany(xs: IdentityBrief[]) {
      const reason = await confirm({
        title: `Disable ${xs.length} identit${xs.length === 1 ? "y" : "ies"}?`,
        body: DISABLE_BODY,
        confirmLabel: `Disable ${xs.length}`,
        danger: true,
        reason: { label: "Reason (kept in the audit log of each)", required: true, minLength: 10 },
      });
      if (reason === null) return;
      const failed: string[] = [];
      for (const i of xs) {
        try {
          await disableIdentity(i.id, reason);
        } catch (e: any) {
          failed.push(`${i.name}: ${String(e.message ?? e)}`);
          if (e instanceof ApiError && e.status === 401) break; // the sign-in must be refreshed first
        }
      }
      const done = xs.length - failed.length;
      if (failed.length) toast(`${done} of ${xs.length} disabled. ${failed[0]}${failed.length > 1 ? ` (and ${failed.length - 1} more)` : ""}`, { kind: "error" });
      else toast(`${done} identit${done === 1 ? "y" : "ies"} disabled`, { kind: "ok" });
    },
    async enable(i: IdentityBrief) {
      let rec: DisableRecord | undefined;
      try {
        rec = (await identityDisables(i.id)).disables.find((d) => !d.enabled_at);
      } catch (e: any) {
        toast(String(e.message ?? e), { kind: "error" });
        return false;
      }
      if (!rec) {
        toast(`${i.name} was not disabled by Tessera, so there is nothing to enable. Their status comes from the source system.`, { kind: "info" });
        return false;
      }
      const reason = await confirm({
        title: `Enable ${i.name}?`,
        body: (
          <>
            <p>Sets back the {rec.accounts.length} account{rec.accounts.length === 1 ? "" : "s"} Tessera disabled on {fmtDate(rec.disabled_at)}
              {rec.accounts.length ? `: ${rec.accounts.map((a) => `${a.system}:${a.username}`).join(", ")}` : ""}, and their status. An account that was already disabled before, or that something else changed since, is left alone.</p>
            <p><b>Not restored:</b> the sessions, refresh tokens and OAuth grants revoked at the identity providers stay revoked. {i.name} signs in and consents again. Accounts at the providers were never suspended by Tessera, so nothing is re-enabled there.</p>
          </>
        ),
        confirmLabel: "Enable",
        reason: { label: "Reason (kept in the audit log)", required: true, minLength: 10 },
      });
      if (reason === null) return false;
      try {
        const r = await enableIdentity(i.id, reason);
        toast(`${i.name} enabled: ${r.restored.length} account${r.restored.length === 1 ? "" : "s"} restored${r.skipped.length ? `, ${r.skipped.length} left as they were` : ""}. Revoked sessions stay revoked.`, { kind: "ok" });
        return true;
      } catch (e: any) {
        toast(String(e.message ?? e), { kind: "error" });
        return false;
      }
    },
    async resetPassword(i: IdentityBrief) {
      if (i.type !== "human") {
        toast(`${i.name} is a machine identity. Rotate its secret instead.`, { kind: "info" });
        return;
      }
      const ok = await confirm({ title: `Reset password for ${i.name}?`, body: "Sends a reset link through the identity provider and signs them out everywhere. Tessera never sees the password. Preview: no email is sent yet.", confirmLabel: "Send reset link" });
      if (ok === null) return;
      await mockIdentityOps.resetPassword(i.name, actor);
      toast(`Reset link sent to ${i.name} (preview)`);
    },
    requestFor(i: IdentityBrief) {
      nav(`/access/request?for=${i.id}`);
    },
    reviewAccess(i: IdentityBrief) {
      nav(`/governance/reviews?identity=${i.id}`);
    },
    openGraph(i: IdentityBrief) {
      nav(`/insights/graph?identity=${i.id}`);
    },
    open(i: IdentityBrief) {
      nav(`/directory/identities/${i.id}`);
    },
    async startCampaign(days = 60) {
      const ok = await confirm({
        title: "Start an access review?",
        body: `Creates an exception-only campaign. Grants unused for ${days}+ days, violating policy, held by leavers or orphaned machine identities go to reviewers. Everything else is auto-certified from usage evidence.`,
        confirmLabel: "Start review",
      });
      if (ok === null) return;
      const c = await api<Campaign>("/reviews/campaigns", { name: `Exception review (${days}d), ${new Date().toLocaleDateString()}`, unused_days: days });
      toast(`Review started: ${c.items} items need a decision, ${c.auto_certified} auto-certified`);
      nav(`/governance/reviews?campaign=${c.id}`);
    },
  };
}
