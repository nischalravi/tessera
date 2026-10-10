import cytoscape, { Core } from "cytoscape";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Maximize, Minus, Plus } from "lucide-react";
import { IdentityRow, ResourceRow, useApi } from "../../api";
import { useTheme } from "../../app/theme";
import { Badge, Button, Chip, Loading, Page, Segmented, TypeBadge } from "../../components";

interface GNode { id: string; kind: string; label: string; system: string | null; privileged: boolean; type?: string; status?: string; tags: string[]; environment?: string | null }
interface GEdge { source: string; target: string; relation: string; source_kind: string; edge_id: number | null }

const KIND_ORDER: Record<string, number> = { identity: 0, account: 1, group: 2, perm: 3, resource: 4 };
const FIT_PADDING = 32;

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

/** Graph colours come from the CSS tokens so the canvas follows the light/dark theme. */
function palette() {
  const cs = getComputedStyle(document.documentElement);
  const v = (n: string) => cs.getPropertyValue(n).trim();
  return {
    human: v("--kind-human"), service: v("--kind-service"), ai_agent: v("--kind-agent"),
    account: v("--g-account"), group: v("--g-group"), perm: v("--g-perm"), resource: v("--g-resource"),
    edge: v("--g-edge"), labelBg: v("--g-label-bg"), text: v("--text"), accent: v("--accent"), critical: v("--critical"), warning: v("--warning"),
  };
}

function GraphCanvas({ nodes, edges, focus, onSelect }: { nodes: GNode[]; edges: GEdge[]; focus?: string | null; onSelect: (n: GNode | null) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const { resolved } = useTheme();
  const select = useRef(onSelect);
  select.current = onSelect;

  useEffect(() => {
    if (!ref.current) return;
    const c = palette();
    const pos = layered(nodes, edges);
    const color = (n: GNode) => (n.kind === "identity" ? c[(n.type ?? "human") as "human"] ?? c.human : c[n.kind as "account"] ?? c.resource);
    const cy = cytoscape({
      container: ref.current,
      elements: [
        ...nodes.map((n) => ({
          data: { ...n, color: color(n), short: n.label.length > 38 ? n.label.slice(0, 36) + "…" : n.label },
          position: pos[n.id],
          classes: [n.kind, n.privileged ? "priv" : "", n.tags.includes("pii") ? "pii" : "", n.status && n.status !== "active" ? "inactive" : ""].join(" "),
        })),
        ...edges.map((e) => ({ data: { id: `${e.source}>${e.target}`, ...e }, classes: e.source_kind === "jit" ? "jit" : e.relation })),
      ],
      layout: { name: "preset" },
      minZoom: 0.08,
      maxZoom: 2.5,
      wheelSensitivity: 0.25,
      style: [
        { selector: "node", style: { "background-color": "data(color)", label: "data(short)", "font-size": 11, "font-family": "Segoe UI, -apple-system, BlinkMacSystemFont, Helvetica Neue, Arial, sans-serif", color: c.text, "text-valign": "bottom", "text-margin-y": 4, width: 18, height: 18, "text-background-color": c.labelBg, "text-background-opacity": 0.85, "text-background-padding": "1px", "min-zoomed-font-size": 7 } },
        { selector: "node.identity", style: { width: 30, height: 30, "font-weight": "bold", "font-size": 12 } },
        { selector: "node.account", style: { shape: "round-rectangle", width: 22, height: 16 } },
        { selector: "node.group", style: { shape: "hexagon", width: 22, height: 20 } },
        { selector: "node.perm", style: { shape: "round-diamond", width: 18, height: 18 } },
        { selector: "node.resource", style: { shape: "barrel", width: 22, height: 22 } },
        { selector: "node.priv", style: { "border-width": 3, "border-color": c.critical } },
        { selector: "node.pii", style: { "border-width": 3, "border-color": c.warning } },
        { selector: "node.inactive", style: { opacity: 0.45 } },
        { selector: "node:selected", style: { "overlay-color": c.accent, "overlay-opacity": 0.22, "overlay-padding": 6 } },
        { selector: "edge", style: { width: 1.5, "line-color": c.edge, "target-arrow-color": c.edge, "target-arrow-shape": "triangle", "curve-style": "bezier", "arrow-scale": 0.8 } },
        { selector: "edge.maps_to", style: { "line-style": "dashed" } },
        { selector: "edge.jit", style: { "line-color": c.ai_agent, "target-arrow-color": c.ai_agent, width: 2.5 } },
        { selector: ".faded", style: { opacity: 0.12 } },
        { selector: "edge.hl", style: { "line-color": c.accent, "target-arrow-color": c.accent, width: 2.5 } },
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
      select.current(evt.target.data() as GNode);
    });
    cy.on("tap", (evt) => {
      if (evt.target === cy) {
        highlight(null);
        select.current(null);
      }
    });
    // #32: always fit the whole graph to the canvas. The old code clamped zoom to >= 0.6 after
    // fitting, which pushed large graphs off-screen.
    cy.fit(undefined, FIT_PADDING);
    if (focus) highlight(focus);
    cyRef.current = cy;

    // refit when the canvas changes size (window resize, sidebar collapse, side panel wrap)
    let raf = 0;
    const ro = new ResizeObserver(() => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        cy.resize();
        cy.fit(undefined, FIT_PADDING);
      });
    });
    ro.observe(ref.current);
    return () => {
      ro.disconnect();
      cancelAnimationFrame(raf);
      cy.destroy();
      cyRef.current = null;
    };
  }, [nodes, edges, focus, resolved]);

  const zoom = (f: number) => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.zoom({ level: cy.zoom() * f, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  };
  return (
    <>
      <div className="graph-tools">
        <Button size="sm" icon={<Plus size={14} />} label="Zoom in" onClick={() => zoom(1.25)} />
        <Button size="sm" icon={<Minus size={14} />} label="Zoom out" onClick={() => zoom(0.8)} />
        <Button size="sm" icon={<Maximize size={14} />} label="Fit to screen" onClick={() => cyRef.current?.fit(undefined, FIT_PADDING)} />
      </div>
      <div ref={ref} className="cy" role="img" aria-label={`Access graph with ${nodes.length} nodes and ${edges.length} edges. Use the identity and resource pickers to change it.`} />
    </>
  );
}

export default function GraphExplorer() {
  const [params, setParams] = useSearchParams();
  const identity = params.get("identity");
  const resource = params.get("resource");
  const perm = params.get("perm");
  const { data: idents } = useApi<IdentityRow[]>("/identities");
  const { data: resources } = useApi<ResourceRow[]>("/resources");
  const mode = resource ? "resource" : "identity";
  const defaultId = useMemo(() => idents?.find((i) => i.name === "Alice Okafor")?.id ?? idents?.[0]?.id, [idents]);
  const effectiveId = identity ?? (resource ? null : defaultId ? String(defaultId) : null);
  const path = resource ? `/graph?resource_id=${resource}` : effectiveId ? `/graph?identity_id=${effectiveId}${perm ? `&perm_key=${encodeURIComponent(perm)}` : ""}` : null;
  const { data, error } = useApi<{ nodes: GNode[]; edges: GEdge[] }>(path);
  const [sel, setSel] = useState<GNode | null>(null);
  useEffect(() => setSel(null), [path]);
  const sorted = useMemo(() => (idents ?? []).slice().sort((a, b) => a.name.localeCompare(b.name)), [idents]);

  const setMode = (m: "identity" | "resource") => {
    if (m === "identity") setParams(defaultId ? { identity: String(defaultId) } : {});
    else if (resources?.length) setParams({ resource: String(resources.find((r) => r.name === "s3://customer-pii")?.id ?? resources[0].id) });
  };

  return (
    <Page
      title="Access graph"
      crumbs={[["Protection"], ["Access graph"]]}
      sub="Identity, account, group or role, permission, resource. Select a node to trace everything upstream and downstream of it."
      actions={
        <>
          <Segmented label="Graph mode" value={mode} onChange={setMode} options={[["identity", "By identity"], ["resource", "Who can access…"]]} />
          {mode === "identity" ? (
            <select className="input" aria-label="Identity" value={effectiveId ?? ""} onChange={(e) => setParams({ identity: e.target.value })}>
              {sorted.map((i) => <option key={i.id} value={i.id}>{i.name} ({i.type.replace("_", " ")})</option>)}
            </select>
          ) : (
            <select className="input" aria-label="Resource" value={resource ?? ""} onChange={(e) => setParams({ resource: e.target.value })}>
              {(resources ?? []).map((r) => <option key={r.id} value={r.id}>{r.name} ({r.identities_with_access} identities)</option>)}
            </select>
          )}
          {perm && <Button onClick={() => setParams({ identity: effectiveId ?? "" })}>Show all permissions</Button>}
        </>
      }
    >
      <div className="graph-layout">
        <div className="card flush">
          <div className="graph-wrap">
            {data ? <GraphCanvas nodes={data.nodes} edges={data.edges} focus={perm} onSelect={setSel} /> : <Loading error={error} />}
          </div>
        </div>
        <div className="stack">
          <div className="card stack-sm">
            <h3>Selection</h3>
            {!sel && <div className="muted small">Select a node to see its details and trace its paths.</div>}
            {sel && (
              <div className="stack-sm small">
                <b style={{ fontSize: "var(--fs-lg)", wordBreak: "break-word" }}>{sel.label}</b>
                <div className="row tight">
                  <Badge>{sel.kind}</Badge>
                  {sel.system && <Chip mono>{sel.system}</Chip>}
                  {sel.type && <TypeBadge type={sel.type} />}
                  {sel.privileged && <Badge tone="warning">Privileged</Badge>}
                  {sel.environment && <Chip>{sel.environment}</Chip>}
                  {sel.tags.map((t) => <Chip key={t}>{t}</Chip>)}
                </div>
                {sel.kind === "identity" && <Link to={`/directory/identities/${sel.id.split(":")[1]}`}>Open identity</Link>}
                {sel.kind === "resource" && <button className="btn sm" onClick={() => setParams({ resource: sel.id.split(":")[1] })}>Who can access this?</button>}
                {sel.kind === "group" && <Link to={`/directory/entitlements/${sel.id.split(":")[1]}`}>Open entitlement</Link>}
              </div>
            )}
          </div>
          <div className="card stack-sm">
            <h3>Legend</h3>
            <div className="legend">
              <span><i style={{ background: "var(--kind-human)" }} />Person <i style={{ background: "var(--kind-service)", marginLeft: 8 }} />Service <i style={{ background: "var(--kind-agent)", marginLeft: 8 }} />AI agent</span>
              <span><i style={{ background: "var(--g-account)" }} />Account</span>
              <span><i style={{ background: "var(--g-group)" }} />Group or role (dashed edge: role mapping)</span>
              <span><i style={{ background: "var(--g-perm)" }} />Permission</span>
              <span><i style={{ background: "var(--g-resource)" }} />Resource</span>
              <span><i style={{ border: "2px solid var(--critical)" }} />Privileged <i style={{ border: "2px solid var(--warning)", marginLeft: 8 }} />PII</span>
              <span><i style={{ background: "var(--kind-agent)" }} />Just-in-time grant</span>
            </div>
          </div>
          {data && <div className="xs faint tnum">{data.nodes.length} nodes · {data.edges.length} edges · scroll to zoom, drag to pan</div>}
        </div>
      </div>
    </Page>
  );
}
