import { useState } from "react";
import { ChevronRight, Plus, Workflow as WorkflowIcon } from "lucide-react";
import { usePersona } from "../../app/persona";
import { Badge, Button, Callout, Page, PreviewBadge, useToast, GovernanceTabs } from "../../components";
import { WORKFLOWS, Workflow, mockObjects } from "../../mocks";
import { PreviewFormDrawer } from "../directory/shared";

function Card({ w }: { w: Workflow }) {
  const { actor } = usePersona();
  const toast = useToast();
  const [on, setOn] = useState(w.enabled);
  const toggle = async () => {
    setOn(!on);
    await mockObjects.save("workflow", w.name, actor, "update");
    toast(`${w.name} ${on ? "paused" : "enabled"} (preview)`);
  };
  return (
    <div className="card stack-sm">
      <div className="spread">
        <b>{w.name}</b>
        <label className="row tight small">
          <input type="checkbox" role="switch" checked={on} onChange={toggle} aria-label={`${w.name} enabled`} />
          {on ? "On" : "Off"}
        </label>
      </div>
      <div className="small muted">When: {w.trigger}</div>
      <ol className="row tight" style={{ listStyle: "none", padding: 0, margin: 0 }} aria-label="Steps">
        {w.steps.map((s, i) => (
          <li key={s} className="row tight">
            {i > 0 && <ChevronRight size={12} aria-hidden className="faint" />}
            <span className="chip">{s}</span>
          </li>
        ))}
      </ol>
      <div className="spread xs faint">
        <span>Applies to {w.appliesTo.toLowerCase()}</span>
        <Badge tone="outline">SLA {w.sla}</Badge>
      </div>
    </div>
  );
}

export function Workflows() {
  const [create, setCreate] = useState(false);
  return (
    <Page tabs={<GovernanceTabs />}
      title="Workflows"
      badge={<PreviewBadge />}
      crumbs={[["Access"], ["Access reviews", "/governance/reviews"], ["Workflows"]]}
      sub="Who approves what, in which order, and what happens when nobody answers. One place for request, review and lifecycle routing."
      actions={<Button variant="primary" icon={<Plus size={15} />} onClick={() => setCreate(true)}>New workflow</Button>}
    >
      <div className="stack">
        <Callout icon={<WorkflowIcon size={16} />}>
          Today the API routes every just-in-time request to any approver and every review item to the identity's manager. These workflows show the routing Tessera will enforce once the workflow engine ships. Toggles are saved in this browser only.
        </Callout>
        <div className="grid g2">{WORKFLOWS.map((w) => <Card key={w.id} w={w} />)}</div>
      </div>
      {create && (
        <PreviewFormDrawer title="New workflow" kind="workflow" onClose={() => setCreate(false)}
          fields={[
            { id: "name", label: "Name", required: true, placeholder: "e.g. Contractor access" },
            { id: "trigger", label: "When", required: true, options: ["Access request", "Access request, privileged", "SoD exception", "HRIS joiner", "HRIS mover", "HRIS leaver", "Review item escalated"] },
            { id: "steps", label: "Approval steps", textarea: true, placeholder: "One per line, e.g. Manager approves" },
            { id: "sla", label: "Escalate after", options: ["4 hours", "1 business day", "2 business days", "5 business days"] },
          ]}
        />
      )}
    </Page>
  );
}
