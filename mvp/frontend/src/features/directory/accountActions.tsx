// Disable and enable accounts in their target systems (issue #915): a confirm with a reason, the call, and a toast
// that says what was sent. The account shows "disable pending" until the target's re-read confirms.
import { AccountRow, disableAccounts, enableAccounts } from "../../api";
import { useConfirm } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { accountStateSummary } from "./accountState";

const BODY = (verb: "disable" | "enable") => (
  <>
    <p>
      Tessera asks the target system to {verb} {verb === "disable" ? "each account" : "each account again"} and reads the target back to check.
      The account stays as it is in Tessera, marked {verb} pending, until that re-read agrees. If it does not, a finding is raised in Admin, Provisioning.
    </p>
    <p><b>Not sent:</b> an account in a system Tessera cannot write to is skipped and named in the result.{verb === "enable" ? " Enable also needs a connector that can set an account active again." : ""}</p>
  </>
);

export function useAccountActions(reload?: () => void) {
  const confirm = useConfirm();
  const toast = useToast();
  const run = async (verb: "disable" | "enable", xs: AccountRow[]) => {
    const many = xs.length === 1 ? xs[0].username : `${xs.length} accounts`;
    const reason = await confirm({
      title: `${verb === "disable" ? "Disable" : "Enable"} ${many}?`,
      body: BODY(verb),
      confirmLabel: verb === "disable" ? "Disable" : "Enable",
      danger: verb === "disable",
      reason: { label: "Reason (kept in the audit log of each)", required: true, minLength: 10, placeholder: "For example: leaver cleanup, ticket HR-1042" },
    });
    if (reason === null) return;
    try {
      const names = new Map(xs.map((a) => [a.id, a.username]));
      const ids = xs.map((a) => a.id);
      const out = { results: [] as Awaited<ReturnType<typeof disableAccounts>>["results"] };
      // the API takes at most 100 ids per call
      for (let i = 0; i < ids.length; i += 100) {
        const r = await (verb === "disable" ? disableAccounts : enableAccounts)(ids.slice(i, i + 100), reason);
        out.results.push(...r.results);
      }
      const s = accountStateSummary(verb, out.results, (id) => names.get(id) ?? String(id));
      toast(s.text, { kind: s.ok ? "ok" : "error" });
    } catch (e: any) {
      toast(String(e.message ?? e), { kind: "error" });
    } finally {
      reload?.();
    }
  };
  return {
    disable: (xs: AccountRow[]) => run("disable", xs),
    enable: (xs: AccountRow[]) => run("enable", xs),
  };
}
