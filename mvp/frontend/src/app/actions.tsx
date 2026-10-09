/**
 * Actions shared by object pages, list bulk actions and the command palette, so each one
 * behaves the same (same confirm copy, same toast) wherever it is triggered.
 */
import { useNavigate } from "react-router-dom";
import { Campaign, IdentityBrief, api } from "../api";
import { useConfirm } from "../components/Dialog";
import { useToast } from "../components/Toast";
import { mockIdentityOps } from "../mocks";
import { usePersona } from "./persona";

export function useIdentityActions() {
  const nav = useNavigate();
  const confirm = useConfirm();
  const toast = useToast();
  const { actor } = usePersona();

  return {
    async disable(i: IdentityBrief) {
      const ok = await confirm({
        title: `Disable ${i.name}?`,
        body: "Disables their accounts in every connected system and ends active sessions. You can re-enable them later. Preview: recorded in this browser only until the provisioning API ships.",
        confirmLabel: "Disable",
        danger: true,
      });
      if (ok === null) return false;
      await mockIdentityOps.disable(i.id, i.name, actor);
      toast(`${i.name} disabled (preview)`, { action: { label: "Undo", run: () => { mockIdentityOps.enable(i.id, i.name, actor); toast(`${i.name} re-enabled`); } } });
      return true;
    },
    async disableMany(xs: IdentityBrief[]) {
      const ok = await confirm({ title: `Disable ${xs.length} identities?`, body: "Disables their accounts in every connected system and ends active sessions. Preview: recorded in this browser only.", confirmLabel: `Disable ${xs.length}`, danger: true });
      if (ok === null) return;
      await Promise.all(xs.map((i) => mockIdentityOps.disable(i.id, i.name, actor)));
      toast(`${xs.length} identities disabled (preview)`);
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
