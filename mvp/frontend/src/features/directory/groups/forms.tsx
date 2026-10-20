import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Check, CircleAlert, Loader } from "lucide-react";
import { GrpFolder, groups } from "../../../api";
import { Button, Callout, Drawer, useToast } from "../../../components";
import { errText } from "./hooks";
import { TemplateStep, applicationTemplate, extensionProblem, joinPath, splitPath } from "./model";

/** New folder under `parent` (the top level when null). */
export function NewFolderDrawer({ parent, onClose }: { parent: GrpFolder | null; onClose: () => void }) {
  const toast = useToast();
  const nav = useNavigate();
  const [v, setV] = useState({ extension: "", display_extension: "", description: "" });
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const problem = v.extension ? extensionProblem(v.extension) : null;
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (problem || !v.extension) return;
    setBusy(true);
    setErr(null);
    try {
      const f = await groups.createFolder({ parent: parent?.id, extension: v.extension, display_extension: v.display_extension || undefined, description: v.description || undefined });
      toast(`Folder ${f.name} created`);
      onClose();
      nav(`/directory/groups/folders/${f.id}`);
    } catch (x) {
      setErr(errText(x));
      setBusy(false);
    }
  };
  return (
    <Drawer title="New folder" sub={parent ? parent.name || "Top level" : "Top level"} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button type="submit" form="new-folder" variant="primary" disabled={!v.extension || !!problem || busy}>{busy ? "Creating…" : "Create folder"}</Button></>}>
      <form id="new-folder" className="stack" onSubmit={submit}>
        <label className="field"><span>Name</span><input className="input" value={v.extension} onChange={(e) => setV({ ...v, extension: e.target.value })} data-autofocus aria-invalid={!!problem} /><span className="hint">{problem ?? "Letters, digits, \"_\", \"-\" and \".\". The folder's full name is its parents' names and this, joined by \":\"."}</span></label>
        <label className="field"><span>Display name <span className="faint">(optional)</span></span><input className="input" value={v.display_extension} onChange={(e) => setV({ ...v, display_extension: e.target.value })} /></label>
        <label className="field"><span>Description <span className="faint">(optional)</span></span><textarea className="input" value={v.description} onChange={(e) => setV({ ...v, description: e.target.value })} /></label>
        {err && <Callout tone="bad">{err}</Callout>}
      </form>
    </Drawer>
  );
}

/** New basic group in `folder`. Composites are made on the Definition tab. */
export function NewGroupDrawer({ folder, onClose }: { folder: GrpFolder; onClose: () => void }) {
  const toast = useToast();
  const nav = useNavigate();
  const [v, setV] = useState({ extension: "", display_extension: "", description: "", type: "group", requestable: false });
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const problem = v.extension ? extensionProblem(v.extension) : null;
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (problem || !v.extension) return;
    setBusy(true);
    setErr(null);
    try {
      const g = await groups.createGroup({ folder: folder.id, extension: v.extension, display_extension: v.display_extension || undefined, description: v.description || undefined, type: v.type, requestable: v.requestable });
      toast(`Group ${g.name} created`);
      onClose();
      nav(`/directory/groups/${g.id}`);
    } catch (x) {
      setErr(errText(x));
      setBusy(false);
    }
  };
  return (
    <Drawer title="New group" sub={folder.name || "Top level"} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button type="submit" form="new-group" variant="primary" disabled={!v.extension || !!problem || busy}>{busy ? "Creating…" : "Create group"}</Button></>}>
      <form id="new-group" className="stack" onSubmit={submit}>
        <label className="field"><span>Name</span><input className="input" value={v.extension} onChange={(e) => setV({ ...v, extension: e.target.value })} data-autofocus aria-invalid={!!problem} /><span className="hint">{problem ?? "Letters, digits, \"_\", \"-\" and \".\"."}</span></label>
        <label className="field"><span>Display name <span className="faint">(optional)</span></span><input className="input" value={v.display_extension} onChange={(e) => setV({ ...v, display_extension: e.target.value })} /></label>
        <label className="field"><span>Description <span className="faint">(optional)</span></span><textarea className="input" value={v.description} onChange={(e) => setV({ ...v, description: e.target.value })} /></label>
        <label className="field"><span>Kind</span>
          <select className="input" value={v.type} onChange={(e) => setV({ ...v, type: e.target.value })}>
            <option value="group">Group</option>
            <option value="role">Role</option>
          </select>
        </label>
        <label className="row tight"><input type="checkbox" checked={v.requestable} onChange={(e) => setV({ ...v, requestable: e.target.checked })} /><span>People can request membership</span></label>
        {err && <Callout tone="bad">{err}</Callout>}
      </form>
    </Drawer>
  );
}

type StepState = "todo" | "running" | "done" | "failed";

/**
 * New application (G-06): the Deployment Guide layout in one step. The steps run in order; each is its own change, so a
 * failure leaves what was created and says which step stopped. Running it again skips what already exists.
 */
export function NewApplicationDrawer({ parent, onClose }: { parent: GrpFolder | null; onClose: () => void }) {
  const toast = useToast();
  const nav = useNavigate();
  const [app, setApp] = useState("");
  const [state, setState] = useState<StepState[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const problem = app ? extensionProblem(app) : null;
  const steps: TemplateStep[] = app && !problem ? applicationTemplate(app) : [];
  const base = parent?.name ?? "";
  const running = state?.some((s) => s === "running") ?? false;

  const run = async (e: FormEvent) => {
    e.preventDefault();
    if (!steps.length) return;
    setErr(null);
    const st: StepState[] = steps.map(() => "todo");
    setState(st);
    const show = () => setState([...st]);
    const ids = new Map<string, string>(); // relative path -> id
    if (parent) ids.set("", parent.id);
    // what exists already is reused, so a second run after a failure carries on where the first stopped
    const [folderList, groupList] = await Promise.all([groups.listFolders({ limit: 500 }).catch(() => null), groups.listGroups({ q: app, limit: 500 }).catch(() => null)]);
    const haveFolder = new Map((folderList?.items ?? []).map((f) => [f.name, f.id]));
    const haveGroup = new Map((groupList?.items ?? []).map((g) => [g.name, g.id]));
    let first: string | null = null;
    for (let i = 0; i < steps.length; i++) {
      const s = steps[i];
      st[i] = "running";
      show();
      try {
        const { parent: pp, extension } = splitPath(s.path);
        const parentId = ids.get(pp);
        if (s.kind === "folder") {
          const have = haveFolder.get(joinPath(base, s.path));
          const f = have ? { id: have } : await groups.createFolder({ parent: parentId, extension, description: s.description });
          ids.set(s.path, f.id);
          first ??= f.id;
          if (!have && s.types?.length) await groups.setObjectTypes("folder", f.id, s.types).catch(() => undefined);
        } else {
          if (!parentId) throw new Error("its folder was not created");
          const have = haveGroup.get(joinPath(base, s.path));
          const factors = s.composite?.factors.map((p) => ids.get(p) ?? "");
          if (factors?.some((x) => !x)) throw new Error("a group it is built from was not created");
          const g = have ? { id: have } : await groups.createGroup({
            folder: parentId, extension, description: s.description,
            ...(s.composite ? { definition: "composite", composite_op: s.composite.op, factors } : {}),
          });
          ids.set(s.path, g.id);
          if (!have && s.types?.length) await groups.setObjectTypes("group", g.id, s.types).catch(() => undefined);
        }
        st[i] = "done";
        show();
      } catch (x) {
        st[i] = "failed";
        show();
        setErr(`Stopped at ${joinPath(base, s.path)}: ${errText(x)}`);
        return;
      }
    }
    toast(`Application ${app} created`);
    onClose();
    if (first) nav(`/directory/groups/folders/${first}`);
  };

  return (
    <Drawer title="New application" sub={`Standard groups for an application, under ${base || "the top level"}`} onClose={onClose}
      footer={<><Button onClick={onClose}>Close</Button><Button type="submit" form="new-app" variant="primary" disabled={!steps.length || running}>{running ? "Creating…" : "Create structure"}</Button></>}>
      <form id="new-app" className="stack" onSubmit={run}>
        <label className="field"><span>Application name</span><input className="input" value={app} onChange={(e) => setApp(e.target.value)} data-autofocus aria-invalid={!!problem} disabled={running} /><span className="hint">{problem ?? "Used in every name below, for example payroll."}</span></label>
        {steps.length > 0 && (
          <ol className="stack-sm" style={{ listStyle: "none", padding: 0 }} aria-label="What will be created">
            {steps.map((s, i) => (
              <li key={s.path} className="row tight small" style={{ paddingLeft: Math.min(splitPath(s.path).parent.split(":").length - 1, 4) * 12 }}>
                <span aria-hidden style={{ width: 16 }}>{state?.[i] === "done" ? <Check size={14} /> : state?.[i] === "running" ? <Loader size={14} /> : state?.[i] === "failed" ? <CircleAlert size={14} /> : null}</span>
                <span className="sys">{splitPath(s.path).extension}</span>
                <span className="faint">{s.kind === "folder" ? "folder" : s.composite ? `${s.composite.op === "union" ? "union of" : "allow minus deny:"} composite group` : "group"}</span>
                {state?.[i] && <span className="sr-only">{state[i]}</span>}
              </li>
            ))}
          </ol>
        )}
        <p className="small faint">Reference groups hold the cohorts that may use the application, the <em>allow</em> composite adds hand-made exceptions, and the policy group is allow minus deny.</p>
        {err && <Callout tone="bad">{err}</Callout>}
      </form>
    </Drawer>
  );
}
