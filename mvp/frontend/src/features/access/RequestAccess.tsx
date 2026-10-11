import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Layers, Minus, Plus, Search, ShieldAlert, ShoppingCart, Timer, X } from "lucide-react";
import { CatalogView, ConnectorRow, Group, IdentityRow, Risk, SimResult, api, simulate, submitRequest, useApi } from "../../api";
import { usePersona } from "../../app/persona";
import { Badge, Button, Callout, EmptyState, FilterChips, Loading, Page, PreviewBadge, Segmented, Skeleton, useToast } from "../../components";
import { BusinessRole, ROLES, RequestTarget, mockRequests, useMockState } from "../../mocks";

type CatalogKind = "all" | "role" | "entitlement" | "privileged";
type Who = "me" | "other" | "many";

/** A catalog card: a real catalog item (catalogId) or a Preview business role. */
interface CatalogItem {
  key: string; target: RequestTarget; title: string; system: string | null; description: string; privileged: boolean;
  catalogId?: string; risk?: Risk; defaultHours?: number | null; maxHours?: number | null; owner?: string; role?: BusinessRole;
}

const DURATIONS: [string, number | null][] = [["Until removed", null], ["1 hour", 1], ["4 hours", 4], ["8 hours", 8], ["24 hours", 24], ["72 hours", 72], ["7 days", 168], ["30 days", 720], ["90 days", 2160]];

/** The requestable catalog (GET /api/catalog) plus the Preview business roles. */
function useCatalog() {
  const { data: view, error } = useApi<CatalogView>("/catalog");
  const items = useMemo<CatalogItem[] | null>(() => {
    if (!view) return null;
    const ents: CatalogItem[] = view.items.filter((c) => c.id).map((c) => ({
      key: `g${c.group.id}`,
      target: { kind: "group", groupId: c.group.id, name: `${c.group.system}:${c.group.name}`, system: c.group.system, privileged: c.group.privileged, jit: false },
      title: `${c.group.system}:${c.group.name}`,
      system: c.group.system,
      description: c.description || `${c.group.kind.replace(/_/g, " ")} in ${c.group.system}`,
      privileged: c.group.privileged,
      catalogId: c.id!,
      risk: c.risk,
      defaultHours: c.default_hours,
      maxHours: c.max_hours,
      owner: c.owner?.name,
    }));
    const roles: CatalogItem[] = ROLES.map((r) => ({ key: r.id, target: { kind: "role", roleId: r.id, name: r.name }, title: r.name, system: null, description: r.description, privileged: r.risk === "high", role: r }));
    return [...roles, ...ents];
  }, [view]);
  return { items, view, error };
}

const hoursLabel = (h: number) => (h % 24 === 0 && h >= 48 ? `${h / 24} days` : `${h} h`);

/** Group ids a cart item adds (roles expand to their real underlying groups). */
function groupIdsFor(item: CatalogItem, groups: Group[]): Group[] {
  if (item.target.kind === "group") {
    const id = item.target.groupId;
    return groups.filter((g) => g.id === id);
  }
  const names = new Set((item.role?.entitlements ?? []).filter((e) => !e.includes("(JIT)")));
  return groups.filter((g) => names.has(`${g.system}:${g.name}`));
}

interface Preview { name: string; sim: SimResult | null; missing: string[]; error?: string }

function RiskPreview({ beneficiaries, cart, groups }: { beneficiaries: { id: number; name: string }[]; cart: CatalogItem[]; groups: Group[] }) {
  const [previews, setPreviews] = useState<Preview[] | null>(null);
  const sig = beneficiaries.map((b) => b.id).join(",") + "|" + cart.map((c) => c.key).join(",");
  useEffect(() => {
    if (!beneficiaries.length || !cart.length) {
      setPreviews([]);
      return;
    }
    let alive = true;
    setPreviews(null);
    const t = setTimeout(async () => {
      const out: Preview[] = [];
      for (const b of beneficiaries.slice(0, 5)) {
        try {
          const d = await api<any>(`/identities/${b.id}`);
          const edges: { src: string; dst: string }[] = [];
          const missing: string[] = [];
          for (const item of cart) {
            for (const g of groupIdsFor(item, groups)) {
              const acct = d.accounts.find((a: any) => a.system === g.system && a.status === "active");
              if (acct) edges.push({ src: `account:${acct.id}`, dst: `group:${g.id}` });
              else missing.push(g.system);
            }
          }
          out.push({ name: b.name, sim: edges.length ? await simulate({ add_edges: edges }) : null, missing: [...new Set(missing)] });
        } catch (e: any) {
          out.push({ name: b.name, sim: null, missing: [], error: e.message });
        }
      }
      if (alive) setPreviews(out);
    }, 250);
    return () => {
      alive = false;
      clearTimeout(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sig]);

  if (!cart.length || !beneficiaries.length) return null;
  if (!previews) return <div className="stack-sm" role="status" aria-label="Checking policy"><Skeleton /><Skeleton w="70%" /></div>;
  return (
    <div className="stack-sm">
      {previews.map((p) => {
        const s = p.sim?.summary;
        const intro = p.sim?.violations.introduced ?? [];
        const privAdded = p.sim?.identities.flatMap((i) => i.added).filter((x) => x.privileged).length ?? 0;
        const level = intro.length ? "high" : privAdded ? "medium" : "low";
        return (
          <div key={p.name} className={`callout ${level === "high" ? "bad" : level === "medium" ? "warn" : "ok"}`}>
            <ShieldAlert size={16} />
            <div className="grow small">
              <b>{p.name}: {level === "high" ? "policy conflict" : level === "medium" ? "privileged access" : "low risk"}</b>
              {p.error ? <div>{p.error}</div> : (
                <>
                  {s && <div>Adds {s.permissions_added} permission(s){privAdded ? `, ${privAdded} privileged` : ""}.</div>}
                  {intro.map((v) => <div key={v.key}>Conflicts with <b>{v.policy_name}</b>: {v.message}</div>)}
                  {p.missing.length > 0 && <div>No account yet in {p.missing.join(", ")}. One would be created on approval.</div>}
                  {level === "high" && <div>Approval goes to a risk owner, who must pick a mitigating control.</div>}
                </>
              )}
            </div>
          </div>
        );
      })}
      {beneficiaries.length > 5 && <div className="xs faint">Showing the first 5 of {beneficiaries.length} people.</div>}
    </div>
  );
}

export function RequestAccess() {
  const [params, setParams] = useSearchParams();
  const { actor } = usePersona();
  const toast = useToast();
  const nav = useNavigate();
  const { items: catalog, view, error: catalogError } = useCatalog();
  const me = view?.me ?? null;
  const { data: groups } = useApi<Group[]>("/groups");
  const { data: idents } = useApi<IdentityRow[]>("/identities?status=active");
  const { data: conns } = useApi<ConnectorRow[]>("/connectors");

  const [q, setQ] = useState(params.get("q") ?? "");
  const [kind, setKind] = useState<CatalogKind>("all");
  const [system, setSystem] = useState("");
  const [cart, setCart] = useState<CatalogItem[]>([]);
  // ?for=12 or ?for=12,15 (request on behalf of one or several people)
  const forParam = params.get("for");
  const forIds = useMemo(() => (forParam ? forParam.split(",").map(Number).filter(Boolean) : []), [forParam]);
  const [who, setWho] = useState<Who>(forIds.length > 1 ? "many" : forIds.length ? "other" : "me");
  const [others, setOthers] = useState<number[]>(forIds);
  const [duration, setDuration] = useState<number | null>(null);
  const [justification, setJustification] = useState("");
  const [busy, setBusy] = useState(false);
  const [draftId, setDraftId] = useState<string | undefined>();

  useEffect(() => {
    if (forIds.length) {
      setWho(forIds.length > 1 ? "many" : "other");
      setOthers(forIds);
    }
  }, [forIds]);

  // ?add=g12,role-backend pre-fills the cart (from Directory bulk actions and object pages)
  const addParam = params.get("add");
  useEffect(() => {
    if (!addParam || !catalog) return;
    const keys = addParam.split(",");
    setCart((xs) => [...xs, ...catalog.filter((c) => keys.includes(c.key) && !xs.some((x) => x.key === c.key))]);
  }, [addParam, catalog]);

  // resume a saved draft (?draft=id)
  const mock = useMockState();
  const draftParam = params.get("draft");
  useEffect(() => {
    if (!draftParam || !catalog) return;
    const d = mock.requests.find((r) => r.id === draftParam);
    if (!d) return;
    const key = (t: RequestTarget) => (t.kind === "group" ? `g${t.groupId}` : t.roleId);
    setCart(catalog.filter((c) => d.items.some((t) => key(t) === c.key)));
    setJustification(d.justification);
    setDuration(d.durationHours);
    setDraftId(d.id);
    if (me && !(d.beneficiaries.length === 1 && d.beneficiaries[0].id === me.id)) {
      setWho(d.beneficiaries.length > 1 ? "many" : "other");
      setOthers(d.beneficiaries.map((b) => b.id));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draftParam, catalog]);

  // the longest duration every item in the cart allows (null: no limit)
  const maxHours = cart.reduce<number | null>((m, c) => (c.maxHours == null ? m : m == null ? c.maxHours : Math.min(m, c.maxHours)), null);
  useEffect(() => {
    if (duration != null && maxHours != null && duration > maxHours) setDuration(null);
  }, [maxHours, duration]);
  // nobody to request for: a sign-in without a person, and no right to request for others
  useEffect(() => {
    if (view && !view.me && who === "me") setWho("other");
  }, [view, who]);

  const beneficiaries = useMemo(() => {
    if (who === "me") return me ? [{ id: me.id, name: me.name }] : [];
    return (idents ?? []).filter((i) => others.includes(i.id)).map((i) => ({ id: i.id, name: i.name }));
  }, [who, me, idents, others]);

  const results = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (catalog ?? []).filter((c) =>
      (kind === "all" || (kind === "role" && c.target.kind === "role") || (kind === "entitlement" && c.target.kind === "group") || (kind === "privileged" && c.privileged)) &&
      (!system || c.system === system || (c.role?.entitlements.some((e) => e.startsWith(system + ":")) ?? false)) &&
      (!needle || `${c.title} ${c.description}`.toLowerCase().includes(needle)),
    );
  }, [catalog, q, kind, system]);

  const inCart = (c: CatalogItem) => cart.some((x) => x.key === c.key);
  const toggle = (c: CatalogItem) => setCart((xs) => (inCart(c) ? xs.filter((x) => x.key !== c.key) : [...xs, c]));

  const payload = () => ({
    id: draftId,
    requester: actor,
    beneficiaries,
    items: cart.map((c) => c.target),
    durationHours: duration,
    justification,
    kind: "grant" as const,
  });

  const saveDraft = () => {
    const d = mockRequests.saveDraft(payload());
    setDraftId(d.id);
    toast("Draft saved. Find it under Requests.", { action: { label: "Open", run: () => nav("/access/requests?tab=drafts") } });
  };

  const submit = async () => {
    setBusy(true);
    try {
      const real = cart.filter((c) => c.catalogId);
      const roles = cart.filter((c) => !c.catalogId);
      let n = 0;
      if (real.length) {
        const res = await submitRequest({
          beneficiary_ids: beneficiaries.map((b) => b.id),
          catalog_item_ids: real.map((c) => c.catalogId!),
          justification: justification.trim(),
          duration_hours: duration,
        });
        n += res.lines.length;
      }
      if (roles.length) {
        await mockRequests.submit({ ...payload(), items: roles.map((c) => c.target) });
        n += roles.length * beneficiaries.length;
      } else if (draftId) mockRequests.remove(draftId);
      toast(`Submitted ${n} request${n === 1 ? "" : "s"}. Approvers can see ${n === 1 ? "it" : "them"} now.`);
      setCart([]);
      setJustification("");
      setDraftId(undefined);
      nav("/access/requests");
    } catch (e: any) {
      toast(`Couldn't submit: ${e.message}`, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };

  const canSubmit = cart.length > 0 && beneficiaries.length > 0 && justification.trim().length >= 5 && !busy;
  const kinds: { id: CatalogKind; label: string; count?: number }[] = [
    { id: "all", label: "All", count: catalog?.length },
    { id: "role", label: "Roles", count: catalog?.filter((c) => c.target.kind === "role").length },
    { id: "entitlement", label: "Entitlements", count: catalog?.filter((c) => c.target.kind === "group").length },
    { id: "privileged", label: "Privileged", count: catalog?.filter((c) => c.privileged).length },
  ];

  return (
    <Page title="Request access" crumbs={[["Access"], ["Request access"]]} sub="Find what you need, add it to your request, and see policy conflicts before you submit. Time-limited access is removed automatically when it ends.">
      <div className="split request-split">
        <div className="stack">
          <div className="row">
            <label className="input-icon" style={{ flex: "1 1 260px" }}>
              <Search size={14} />
              <span className="sr-only">Search the catalog</span>
              <input className="input" style={{ width: "100%" }} value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search roles, entitlements and apps…" autoFocus />
            </label>
            <select className="input" value={system} onChange={(e) => setSystem(e.target.value)} aria-label="Application">
              <option value="">All applications</option>
              {(conns ?? []).map((c) => <option key={c.system} value={c.system}>{c.name.replace(/ - demo$/, "")}</option>)}
            </select>
          </div>
          <FilterChips label="Catalog type" value={kind} onChange={setKind} options={kinds} />
          {!catalog ? <Loading error={catalogError} /> : results.length === 0 ? (
            <div className="card"><EmptyState title="Nothing in the catalog matches" icon={<Search size={18} />}>Try a system name like “snowflake”, or a job like “analyst”. If what you need isn't listed, ask the application owner to make it requestable.</EmptyState></div>
          ) : (
            <div className="catalog">
              {results.map((c) => (
                <div key={c.key} className={`cat-item ${inCart(c) ? "in-cart" : ""}`}>
                  <div className="spread" style={{ alignItems: "flex-start" }}>
                    <span className="cat-name">{c.target.kind === "group" ? <span className="sys" style={{ fontSize: 13 }}>{c.title}</span> : c.title}</span>
                    {c.target.kind === "role" ? <span className="row tight"><Badge tone="accent"><Layers size={11} /> Role</Badge></span> : null}
                  </div>
                  <p className="small muted">{c.description}</p>
                  {c.role && <div className="row tight">{c.role.entitlements.slice(0, 4).map((e) => <span key={e} className="chip sys">{e}</span>)}</div>}
                  <div className="cat-foot">
                    <span className="row tight">
                      {c.privileged && <Badge tone="warning">Privileged</Badge>}
                      {c.risk && c.risk !== "low" && !c.privileged && <Badge tone="outline">{c.risk} risk</Badge>}
                      {c.defaultHours != null && <Badge tone="info"><Timer size={11} /> {hoursLabel(c.defaultHours)}{c.maxHours != null ? `, up to ${hoursLabel(c.maxHours)}` : ""}</Badge>}
                      {c.role && <PreviewBadge />}
                    </span>
                    <Button size="sm" variant={inCart(c) ? "default" : "primary"} icon={inCart(c) ? <Minus size={14} /> : <Plus size={14} />} onClick={() => toggle(c)} aria-pressed={inCart(c)} aria-label={`${inCart(c) ? "Remove" : "Add"} ${c.title}`}>
                      {inCart(c) ? "Remove" : "Add"}
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <aside className="card side-panel" aria-label="Your request">
          <div className="stack">
            <h2 className="row tight"><ShoppingCart size={16} aria-hidden /> Your request {cart.length > 0 && <Badge tone="accent">{cart.length}</Badge>}</h2>
            <div className="field">
              Request for
              <Segmented label="Request for" value={who} onChange={(v) => { setWho(v); if (v === "me") setParams({}); }}
                options={[...(me ? [["me", "Me"] as ["me", string]] : []), ...(view?.can_request_for_others ? [["other", "Someone else"], ["many", "Several people"]] as [Who, string][] : [])]} />
            </div>
            {view && !me && !view.can_request_for_others && <Callout tone="warn">Your sign-in is not linked to a person in the directory, and you can't request for others. Ask an administrator.</Callout>}
            {who !== "me" && (
              <div className="field">
                {who === "other" ? "Person" : "People"}
                <select
                  className="input"
                  value=""
                  onChange={(e) => {
                    const id = Number(e.target.value);
                    if (!id) return;
                    setOthers(who === "other" ? [id] : [...new Set([...others, id])]);
                  }}
                  aria-label="Add a person"
                >
                  <option value="">{who === "other" && others.length ? "Change person…" : "Add a person…"}</option>
                  {(idents ?? []).slice().sort((a, b) => a.name.localeCompare(b.name)).map((i) => <option key={i.id} value={i.id}>{i.name}{i.type !== "human" ? " (machine)" : ""}</option>)}
                </select>
                <div className="row tight">
                  {beneficiaries.map((b) => (
                    <span key={b.id} className="chip">{b.name}<button className="btn ghost sm icon" style={{ height: 18, width: 18 }} aria-label={`Remove ${b.name}`} onClick={() => setOthers(others.filter((x) => x !== b.id))}><X size={12} /></button></span>
                  ))}
                </div>
              </div>
            )}
            {cart.length === 0 ? (
              <p className="small muted">Nothing added yet. Add roles or entitlements from the catalog.</p>
            ) : (
              <ul className="steps">
                {cart.map((c) => (
                  <li key={c.key} className="step" style={{ padding: "6px 8px" }}>
                    <span className="grow small"><b className={c.target.kind === "group" ? "sys" : ""}>{c.title}</b>{c.defaultHours != null && <span className="faint"> · {hoursLabel(c.defaultHours)} by default</span>}</span>
                    <Button size="sm" variant="ghost" icon={<X size={14} />} label={`Remove ${c.title}`} onClick={() => toggle(c)} />
                  </li>
                ))}
              </ul>
            )}
            <label className="field">
              Duration
              <select className="input" value={duration === null ? "" : String(duration)} onChange={(e) => setDuration(e.target.value ? Number(e.target.value) : null)}>
                {DURATIONS.filter(([, h]) => h === null || maxHours === null || h <= maxHours).map(([l, h]) => <option key={l} value={h === null ? "" : h}>{h === null ? "Each item's default" : l}</option>)}
              </select>
              <span className="hint">{maxHours != null ? `Items in this request allow at most ${hoursLabel(maxHours)}.` : "Items without a default stay until removed."}</span>
            </label>
            <label className="field">
              Justification
              <textarea className="input" value={justification} onChange={(e) => setJustification(e.target.value)} placeholder="What do you need it for? Include a ticket if there is one." />
              <span className="hint">Approvers see this. At least a few words.</span>
            </label>
            {groups && <RiskPreview beneficiaries={beneficiaries} cart={cart} groups={groups} />}
            {cart.some((c) => !c.catalogId) && <Callout tone="neutral">Business roles are a Preview: role requests are recorded in this browser only. Entitlements go to the real approval queue.</Callout>}
            <div className="row" style={{ justifyContent: "flex-end" }}>
              <Button onClick={saveDraft} disabled={!cart.length}>Save draft</Button>
              <Button variant="primary" onClick={submit} disabled={!canSubmit}>{busy ? "Submitting…" : `Submit${beneficiaries.length > 1 ? ` for ${beneficiaries.length}` : ""}`}</Button>
            </div>
          </div>
        </aside>
      </div>
    </Page>
  );
}
