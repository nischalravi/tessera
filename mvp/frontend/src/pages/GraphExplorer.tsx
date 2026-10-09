import cytoscape, { Core } from "cytoscape";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useApi } from "../api";
import { Loading, Page, TypeBadge } from "../components/ui";

interface GNode { id: string; kind: string; label: string; system: string | null; privileged: boolean; type?: string; status?: string; tags: string[]; environment?: string | null }
interface GEdge { source: string; target: string; relation: string; source_kind: string; edge_id: number | null }

const KIND_COLOR: Record<string, string> = {
  identity: "#2563eb", account: "#059669", group: "#a21caf", perm: "#ea580c", resource: "#475569",
};
const TYPE_COLOR: Record<string, string> = { human: "#2563eb", service: "#0e7490", ai_agent: "#7c3aed" };
const KIND_ORDER: Record<string, number> = { identity: 0, account: 1, group: 2, perm: 3, resource: 4 };

/** Layered left-to-right layout: column = longest distance from an identity. */
function layered(nodes: GNode[], edges: GEdge[]) {
  const level = new Map<string, number>();
  nodes.forEach((n) => level.set(n.id, n.kind === "identity" ? 0 : KIND_ORDER[n.kind] ?? 1));
  for (let iter = 0; iter < nodes.length; iter++) {
    let changed = false;
    for (const e of edges) {
      const want = (level.get(e.source) ?? 0) + 1;
      if (want > (level.get(e.target) ?? 0) && want < 12) {
        level.set(e.target, want);
        changed = true;
      }
    }
    if (!changed) break;
  }
  // permissions and resources get their own aligned columns at the right
  const groupMax = Math.max(1, ...nodes.filter((n) => n.kind === "group" || n.kind === "account").map((n) => level.get(n.id)!));
  nodes.forEach((n) => {
    if (n.kind === "perm") level.set(n.id, groupMax + 1);
    if (n.kind === "resource") level.set(n.id, groupMax + 2);
    if (n.kind === "identity") level.set(n.id, 0);
  });
  const cols = new Map<number, GNode[]>();
  nodes.forEach((n) => {
    const l = level.get(n.id)!;
    if (!cols.has(l)) cols.set(l, []);
    cols.get(l)!.push(n);
  });
  const pos: Record<string, { x: number; y: number }> = {};
  [...cols.entries()].forEach(([l, ns]) => {
    ns.sort((a, b) => a.label.localeCompare(b.label));
    ns.forEach((n, i) => (pos[n.id] = { x: l * 260, y: (i - (ns.length - 1) / 2) * 40 }));
  });
  return pos;
}

function GraphCanvas({ nodes, edges, focus, onSelect }: { nodes: GNode[]; edges: GEdge[]; focus?: string | null; onSelect: (n: GNode | null) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  useEffect(() => {
    if (!ref.current) return;
    const pos = layered(nodes, edges);
    const cy = cytoscape({
      container: ref.current,
      elements: [
        ...nodes.map((n) => ({
          data: { ...n, color: n.kind === "identity" ? TYPE_COLOR[n.type ?? "human"] : KIND_COLOR[n.kind], short: n.label.length > 38 ? n.label.slice(0, 36) + "…" : n.label },
          position: pos[n.id],
          classes: [n.kind, n.privileged ? "priv" : "", n.tags.includes("pii") ? "pii" : "", n.status && n.status !== "active" ? "inactive" : ""].join(" "),
        })),
        ...edges.map((e) => ({ data: { id: `${e.source}>${e.target}`, ...e }, classes: e.source_kind === "jit" ? "jit" : e.relation })),
      ],
      layout: { name: "preset" },
      wheelSensitivity: 0.25,
      style: [
        { selector: "node", style: { "background-color": "data(color)", label: "data(short)", "font-size": 11, color: "#111827", "text-valign": "bottom", "text-margin-y": 4, width: 18, height: 18, "text-background-color": "#ffffff", "text-background-opacity": 0.85, "text-background-padding": "1px" } },
        { selector: "node.identity", style: { width: 30, height: 30, "font-weight": "bold", "font-size": 12 } },
        { selector: "node.account", style: { shape: "round-rectangle", width: 22, height: 16 } },
        { selector: "node.group", style: { shape: "hexagon", width: 22, height: 20 } },
        { selector: "node.perm", style: { shape: "round-diamond", width: 18, height: 18 } },
        { selector: "node.resource", style: { shape: "barrel", width: 22, height: 22 } },
        { selector: "node.priv", style: { "border-width": 3, "border-color": "#dc2626" } },
        { selector: "node.pii", style: { "border-width": 3, "border-color": "#f59e0b" } },
        { selector: "node.inactive", style: { opacity: 0.4 } },
        { selector: "node:selected", style: { "overlay-color": "#4f46e5", "overlay-opacity": 0.2, "overlay-padding": 6 } },
        { selector: "edge", style: { width: 1.5, "line-color": "#cbd5e1", "target-arrow-color": "#cbd5e1", "target-arrow-shape": "triangle", "curve-style": "bezier", "arrow-scale": 0.8 } },
        { selector: "edge.maps_to", style: { "line-style": "dashed" } },
        { selector: "edge.jit", style: { "line-color": "#7c3aed", "target-arrow-color": "#7c3aed", width: 2.5 } },
        { selector: ".faded", style: { opacity: 0.12 } },
        { selector: "edge.hl", style: { "line-color": "#4f46e5", "target-arrow-color": "#4f46e5", width: 2.5 } },
      ],
    });
    const highlight = (id: string | null) => {
      cy.elements().removeClass("faded hl");
      if (!id) return;
      const n = cy.getElementById(id);
      if (n.empty()) return;
      const keep = n.union(n.predecessors()).union(n.successors());
      cy.elements().not(keep).addClass("faded");
      keep.edges().addClass("hl");
    };
    cy.on("tap", "node", (evt) => {
      highlight(evt.target.id());
      onSelect(evt.target.data() as GNode);
    });
    cy.on("tap", (evt) => {
      if (evt.target === cy) {
        highlight(null);
        onSelect(null);
      }
    });
    cy.fit(undefined, 30);
    if (cy.zoom() < 0.6) {
      cy.zoom(0.6);
      cy.center();
    }
    if (focus) highlight(focus);
    cyRef.current = cy;
    return () => cy.destroy();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes, edges, focus]);
  return <div ref={ref} className="cy" />;
}

export default function GraphExplorer() {
  const [params, setParams] = useSearchParams();
  const identity = params.get("identity");
  const resource = params.get("resource");
  const perm = params.get("perm");
  const { data: idents } = useApi<any[]>("/identities");
  const { data: resources } = useApi<any[]>("/resources");
  const mode = resource ? "resource" : "identity";
  const defaultId = useMemo(() => idents?.find((i) => i.name === "Alice Okafor")?.id, [idents]);
  const effectiveId = identity ?? (resource ? null : defaultId ? String(defaultId) : null);
  const path = resource ? `/graph?resource_id=${resource}` : effectiveId ? `/graph?identity_id=${effectiveId}${perm ? `&perm_key=${encodeURIComponent(perm)}` : ""}` : null;
  const { data, error } = useApi<{ nodes: GNode[]; edges: GEdge[] }>(path);
  const [sel, setSel] = useState<GNode | null>(null);

  return (
    <Page
      title="Graph explorer"
      sub="Identity → account → group/role → permission → resource. Click a node to trace everything upstream and downstream of it."
      actions={
        <>
          <div className="seg">
            <button className={mode === "identity" ? "on" : ""} onClick={() => setParams(defaultId ? { identity: String(defaultId) } : {})}>By identity</button>
            <button className={mode === "resource" ? "on" : ""} onClick={() => resources && setParams({ resource: String(resources.find((r) => r.name === "s3://customer-pii")?.id ?? resources[0].id) })}>Who can access…</button>
          </div>
          {mode === "identity" ? (
            <select value={effectiveId ?? ""} onChange={(e) => setParams({ identity: e.target.value })}>
              {(idents ?? []).slice().sort((a, b) => a.name.localeCompare(b.name)).map((i) => (
                <option key={i.id} value={i.id}>{i.name} ({i.type})</option>
              ))}
            </select>
          ) : (
            <select value={resource ?? ""} onChange={(e) => setParams({ resource: e.target.value })}>
              {(resources ?? []).map((r) => (
                <option key={r.id} value={r.id}>{r.name} ({r.identities_with_access} identities)</option>
              ))}
            </select>
          )}
          {perm && <button onClick={() => setParams({ identity: effectiveId ?? "" })}>Show all permissions</button>}
        </>
      }
    >
      <div className="grid" style={{ gridTemplateColumns: "1fr 280px" }}>
        <div className="card flush">
          <div className="graph-wrap">
            {data ? <GraphCanvas nodes={data.nodes} edges={data.edges} focus={perm} onSelect={setSel} /> : <Loading error={error} />}
          </div>
        </div>
        <div className="stack">
          <div className="card">
            <h3>Legend</h3>
            <div className="legend" style={{ flexDirection: "column", gap: 6 }}>
              <span><i style={{ background: TYPE_COLOR.human }} />Human · <i style={{ background: TYPE_COLOR.service }} />Service · <i style={{ background: TYPE_COLOR.ai_agent }} />AI agent</span>
              <span><i style={{ background: KIND_COLOR.account }} />Account</span>
              <span><i style={{ background: KIND_COLOR.group }} />Group / role (dashed edge = role mapping)</span>
              <span><i style={{ background: KIND_COLOR.perm }} />Permission</span>
              <span><i style={{ background: KIND_COLOR.resource }} />Resource</span>
              <span><i style={{ background: "white", border: "2px solid #dc2626" }} />Privileged · <i style={{ background: "white", border: "2px solid #f59e0b" }} />PII</span>
              <span><i style={{ background: "#7c3aed" }} />JIT (time-bound) grant</span>
            </div>
          </div>
          <div className="card">
            <h3>Selection</h3>
            {!sel && <div className="muted small">Click a node.</div>}
            {sel && (
              <div className="stack small">
                <div><b style={{ fontSize: 14 }}>{sel.label}</b></div>
                <div className="row">
                  <span className="badge">{sel.kind}</span>
                  {sel.system && <span className="chip sys">{sel.system}</span>}
                  {sel.type && <TypeBadge type={sel.type} />}
                  {sel.privileged && <span className="badge warn">privileged</span>}
                  {sel.environment && <span className="chip">{sel.environment}</span>}
                  {sel.tags.map((t) => <span key={t} className="chip">{t}</span>)}
                </div>
                {sel.kind === "identity" && <Link to={`/identities/${sel.id.split(":")[1]}`}>Open identity →</Link>}
                {sel.kind === "resource" && <a onClick={() => setParams({ resource: sel.id.split(":")[1] })} style={{ cursor: "pointer" }}>Who can access this? →</a>}
              </div>
            )}
          </div>
          {data && <div className="small muted">{data.nodes.length} nodes · {data.edges.length} edges</div>}
        </div>
      </div>
    </Page>
  );
}
