import { useCallback } from "react";
import { ApiError, GrpFolder, GrpGroup, groups } from "../../../api";
import { useConfirm, useToast } from "../../../components";
import { errText } from "./hooks";
import { blockerLines, failureSummary, plainReason, purgeBody, purgeTitle, treeOutcome, treeSummary } from "./model";

/** A failure of one item, in plain words: the name, and why it could not be done. */
export function failureOf(name: string, e: unknown): { name: string; message: string } {
  return e instanceof ApiError ? { name, message: plainReason(e.code, e.message, e.body) } : { name, message: errText(e) };
}

/**
 * Permanently delete groups that are already deleted: one confirm, then each in turn. Resolves to null when the
 * person cancelled, else how many went and which could not (and why), already shown in a toast.
 */
export function usePurgeGroups() {
  const confirm = useConfirm();
  const toast = useToast();
  return useCallback(async (list: GrpGroup[], skipped: string[] = []): Promise<{ done: number; failed: { name: string; message: string }[] } | null> => {
    if (list.length === 0) {
      toast(skipped.length ? `Nothing to delete permanently: ${skipped.join(", ")} ${skipped.length === 1 ? "is" : "are"} not a deleted group managed here.` : "Nothing to delete permanently.", { kind: "error" });
      return null;
    }
    const ok = await confirm({ title: purgeTitle(list.length), body: purgeBody(list.length, skipped), confirmLabel: "Delete permanently", danger: true });
    if (ok === null) return null;
    const failed: { name: string; message: string }[] = [];
    let done = 0;
    for (const g of list) {
      try { await groups.purgeGroup(g.id); done++; } catch (e) { failed.push(failureOf(g.name, e)); }
    }
    if (failed.length) toast(`${done ? `Deleted ${done} permanently. ` : ""}Could not delete ${failed.length}: ${failureSummary(failed)}`, { kind: "error" });
    else toast(done === 1 ? "Group deleted permanently" : `${done} groups deleted permanently`);
    return { done, failed };
  }, [confirm, toast]);
}

/**
 * "Delete folder and everything in it…": read the plan, show what goes (or what blocks it), ask for the folder's
 * name, then call the recursive route. A step-up is handled by the API client (the call resumes after the
 * sign-in); a large or populated tree answers with a request for a second admin, which the toast says.
 * Resolves to "deleted", "requested" or null (cancelled or failed).
 */
export function useDeleteTree() {
  const confirm = useConfirm();
  const toast = useToast();
  return useCallback(async (f: GrpFolder): Promise<"deleted" | "requested" | null> => {
    let plan;
    try {
      plan = await groups.folderDeletePlan(f.id);
    } catch (e) {
      toast(errText(e), { kind: "error" });
      return null;
    }
    if (plan.blockers.length) {
      await confirm({
        title: `${f.name} cannot be deleted with everything in it`,
        body: (
          <div className="stack-sm">
            <p>Nothing was changed. These items stand in the way:</p>
            <ul>{blockerLines(plan.blockers, 10).map((l) => <li key={l}>{l}</li>)}</ul>
          </div>
        ),
        confirmLabel: "Close",
      });
      return null;
    }
    const lines = treeSummary(plan);
    const ok = await confirm({
      title: `Delete ${f.name} and everything in it?`,
      body: (
        <div className="stack-sm">
          <p>This permanently deletes the folder{lines.length ? " and" : ""}:</p>
          {lines.length > 0 && <ul>{lines.map((l) => <li key={l}>{l}</li>)}</ul>}
          <p>It cannot be undone. The audit history stays.</p>
          {plan.needs_approval && <p><strong>A second admin must approve this</strong> ({plan.approval_reason}). Nothing is deleted until they do.</p>}
        </div>
      ),
      confirmLabel: plan.needs_approval ? "Request deletion" : "Delete everything",
      danger: true,
      typeToConfirm: f.name,
    });
    if (ok === null) return null;
    try {
      const res = await groups.deleteFolderRecursive(f.id);
      const out = treeOutcome(f.name, res);
      toast(out.message);
      return out.requested ? "requested" : "deleted";
    } catch (e) {
      if (e instanceof ApiError && e.status === 401 && e.code === "step_up_required") return null; // the sign-in dialog resumes it
      toast(`Could not delete ${f.name}: ${failureOf(f.name, e).message}`, { kind: "error" });
      return null;
    }
  }, [confirm, toast]);
}
