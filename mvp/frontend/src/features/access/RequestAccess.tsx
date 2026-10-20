import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Layers, Minus, Plus, Search, ShieldAlert, ShoppingCart, Timer, X } from "lucide-react";
import { AnswersByQuestionnaire, BusinessRole, CatalogView, QuestionnaireNeed, ConnectorRow, Group, IdentityRow, DraftItem, RequestDraft, Risk, RequestSettingsView, RolesView, SimResult, api, draftPath, neededPath, requestDrafts, requestSettingsPath, roles as roleApi, simulate, submitRequest, useApi } from "../../api";
import { DEFAULT_REQUEST_SETTINGS, attachmentError, defaultDurationLabel, durationChoices, durationRequired, effectiveMaxHours, forOthersNote, justificationError, justificationHint, parseAttachments } from "./requestSettings";
import { SodWarning } from "./SodWarning";
import { QuestionnaireForm, formReady } from "./QuestionnaireForm";
import { answersPayload, mergeNeeds } from "../governance/questionnaireModel";
import { Badge, Button, Callout, EmptyState, FilterChips, Loading, Page, Segmented, Skeleton, useToast } from "../../components";

/** What a catalog card stands for: one group (an entitlement) or one business role. */
type RequestTarget = { kind: "group"; groupId: number; name: string; system: string; privileged: boolean; jit: boolean } | { kind: "role"; roleId: string; name: string };

type CatalogKind = "all" | "role" | "entitlement" | "privileged";
type Who = "me" | "other" | "many";

/** A catalog card: a catalog item (catalogId) or a requestable business role (role). */
interface CatalogItem {
  key: string; target: RequestTarget; title: string; system: string | null; description: string; privileged: boolean;
  catalogId?: string; risk?: Risk; defaultHours?: number | null; maxHours?: number | null; owner?: string; role?: BusinessRole;
}

const DURATIONS: [string, number | null][] = [["Until removed", null], ["1 hour", 1], ["4 hours", 4], ["8 hours", 8], ["24 hours", 24], ["72 hours", 72], ["7 days", 168], ["30 days", 720], ["90 days", 2160]];

/** The requestable catalog (GET /api/catalog) plus the requestable business roles (GET /api/roles). */
function useCatalog() {
  const { data: view, error } = useApi<CatalogView>("/catalog");
  const { data: rv, error: rolesError } = useApi<RolesView>("/roles");
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
    const roles: CatalogItem[] = (rv?.roles ?? []).filter((r) => r.status === "active" && r.requestable).map((r) => ({
      key: r.id, target: { kind: "role", roleId: r.id, name: r.name }, title: r.name, system: null, description: r.description,
      privileged: r.risk === "high", risk: r.risk, owner: r.owner?.name, role: r,
    }));
    return [...roles, ...ents];
  }, [view, rv]);
  return { items, view, error: error ?? rolesError };
}

const hoursLabel = (h: number) => (h % 24 === 0 && h >= 48 ? `${h / 24} days` : `${h} h`);

/** Group ids a cart item adds (roles expand to their real underlying groups). */
function groupIdsFor(item: CatalogItem, groups: Group[]): Group[] {
  if (item.target.kind === "group") {
    const id = item.target.groupId;
    return groups.filter((g) => g.id === id);
  }
  const ids = new Set((item.role?.entitlements ?? []).map((e) => e.id));
  return groups.filter((g) => ids.has(g.id));
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
  const [attachmentText, setAttachmentText] = useState("");
  const [busy, setBusy] = useState(false);
  // the tenant's request settings (Admin → Request settings); the server enforces them on submit
  const { data: rs } = useApi<RequestSettingsView>(requestSettingsPath);
  const set = rs ?? DEFAULT_REQUEST_SETTINGS;
  const [draftId, setDraftId] = useState<string | undefined>();
  // the questionnaires the cart asks (Governance → Questionnaires): the items', and each role's; null while loading
  const [answers, setAnswers] = useState<AnswersByQuestionnaire>({});
  const [asked, setAsked] = useState<{ items: QuestionnaireNeed[]; roles: Record<string, QuestionnaireNeed[]> } | null>({ items: [], roles: {} });

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
  const draftParam = params.get("draft");
  const { data: draft, error: draftError } = useApi<RequestDraft>(draftParam ? draftPath(draftParam) : null);
  useEffect(() => {
    if (draftError) toast(`That draft couldn't be opened: ${draftError.message}`, { kind: "error" });
  }, [draftError]);
  useEffect(() => {
    if (!draft || !catalog || draft.id !== draftParam) return;
    const key = (t: DraftItem) => (t.kind === "group" ? `g${t.group_id}` : t.role_id);
    // an item that is no longer requestable is not put back in the cart
    setCart(catalog.filter((c) => draft.items.some((t) => key(t) === c.key)));
    setJustification(draft.justification);
    setDuration(draft.duration_hours);
    setDraftId(draft.id);
    if (me && !(draft.beneficiaries.length === 1 && draft.beneficiaries[0].id === me.id)) {
      setWho(draft.beneficiaries.length > 1 ? "many" : "other");
      setOthers(draft.beneficiaries.map((b) => b.id));
    }
    const gone = draft.unavailable + draft.items.filter((t) => !catalog.some((c) => c.key === key(t))).length;
    if (gone > 0) toast(`${gone} item${gone === 1 ? "" : "s"} or ${gone === 1 ? "person" : "people"} in this draft ${gone === 1 ? "is" : "are"} no longer available and ${gone === 1 ? "was" : "were"} left out.`, { kind: "info" });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft, catalog]);

  // the longest duration every item in the cart allows (null: no limit)
  const itemMaxHours = cart.reduce<number | null>((m, c) => (c.maxHours == null ? m : m == null ? c.maxHours : Math.min(m, c.maxHours)), null);
  const maxHours = effectiveMaxHours(itemMaxHours, set);
  const catalogCart = cart.filter((c) => c.catalogId);
  const itemsHaveDefaults = catalogCart.length > 0 && catalogCart.every((c) => c.defaultHours != null);
  const askSig = catalogCart.map((c) => c.catalogId).join(",") + "|" + cart.filter((c) => !c.catalogId).map((c) => c.role!.id).join(",");
  useEffect(() => {
    const itemIds = catalogCart.map((c) => c.catalogId!);
    const roleIds = cart.filter((c) => !c.catalogId).map((c) => c.role!.id);
    if (!itemIds.length && !roleIds.length) {
      setAsked({ items: [], roles: {} });
      return;
    }
    let alive = true;
    setAsked(null);
    (async () => {
      try {
        const get = async (q: Parameters<typeof neededPath>[0]) => (await api<{ questionnaires: QuestionnaireNeed[] }>(neededPath(q))).questionnaires;
        const items = itemIds.length ? await get({ catalogItemIds: itemIds }) : [];
        const roles: Record<string, QuestionnaireNeed[]> = {};
        for (const id of roleIds) roles[id] = await get({ roleId: id });
        if (alive) setAsked({ items, roles });
      } catch {
        if (alive) setAsked({ items: [], roles: {} }); // the server asks again on submit
      }
    })();
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [askSig]);
  const needs = mergeNeeds([asked?.items ?? [], ...Object.values(asked?.roles ?? {})]);
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
      (!system || c.system === system || (c.role?.entitlements.some((e) => e.system === system) ?? false)) &&
      (!needle || `${c.title} ${c.description}`.toLowerCase().includes(needle)),
    );
  }, [catalog, q, kind, system]);

  const inCart = (c: CatalogItem) => cart.some((x) => x.key === c.key);
  const toggle = (c: CatalogItem) => setCart((xs) => (inCart(c) ? xs.filter((x) => x.key !== c.key) : [...xs, c]));

  const draftInput = () => ({
    beneficiary_ids: beneficiaries.map((b) => b.id),
    items: cart.map((c) => (c.target.kind === "group" ? { kind: "group" as const, group_id: c.target.groupId } : { kind: "role" as const, role_id: c.target.roleId })),
    duration_hours: duration,
    justification: justification.trim(),
  });

  const saveDraft = async () => {
    try {
      const d = await requestDrafts.save(draftInput(), draftId);
      setDraftId(d.id);
      toast("Draft saved. Find it under Requests.", { action: { label: "Open", run: () => nav("/access/requests?tab=drafts") } });
    } catch (e: any) {
      toast(`Couldn't save the draft: ${e.message}`, { kind: "error" });
    }
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
          ...(set.attachments_allowed && attachments.length ? { attachments } : {}),
          answers: answersPayload(asked?.items ?? [], answers),
        });
        n += res.lines.length;
      }
      // a role is requested per person (one approval assigns the whole bundle)
      for (const c of roles) {
        for (const b of beneficiaries) {
          await roleApi.request(c.role!.id, b.id, justification.trim(), answersPayload(asked?.roles[c.role!.id] ?? [], answers));
          n++;
        }
      }
      if (draftId) await requestDrafts.remove(draftId).catch(() => undefined); // the request is in; a draft left behind is harmless
      toast(`Submitted ${n} request${n === 1 ? "" : "s"}. Approvers can see ${n === 1 ? "it" : "them"} now.`);
      setCart([]);
      setAnswers({});
      setJustification("");
      setDraftId(undefined);
      nav("/access/requests");
    } catch (e: any) {
      toast(`Couldn't submit: ${e.message}`, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };

  const attachments = parseAttachments(attachmentText);
  const justError = justificationError(set, justification, rs?.max_justification_length);
  const attachError = attachmentError(set, attachments);
  const needsDuration = catalogCart.length > 0 && duration === null && durationRequired(set, itemsHaveDefaults);
  const answersReady = asked !== null && formReady(needs, answers);
  const canSubmit = cart.length > 0 && beneficiaries.length > 0 && !justError && !attachError && !needsDuration && answersReady && !busy;
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
                  {c.role && <div className="row tight">{c.role.entitlements.slice(0, 4).map((e) => <span key={e.id} className="chip sys">{e.system}:{e.name}</span>)}{c.role.entitlements.length > 4 && <span className="chip">+{c.role.entitlements.length - 4}</span>}</div>}
                  <div className="cat-foot">
                    <span className="row tight">
                      {c.privileged && <Badge tone="warning">Privileged</Badge>}
                      {c.risk && c.risk !== "low" && !c.privileged && <Badge tone="outline">{c.risk} risk</Badge>}
                      {c.defaultHours != null && <Badge tone="info"><Timer size={11} /> {hoursLabel(c.defaultHours)}{c.maxHours != null ? `, up to ${hoursLabel(c.maxHours)}` : ""}</Badge>}
                      {c.role?.held && <Badge tone="ok">You hold it</Badge>}
                      {c.role?.pending && <Badge tone="info">You asked for it</Badge>}
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
            {forOthersNote(set) && <p className="small muted">{forOthersNote(set)}</p>}
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
              <select className="input" value={duration === null ? "" : String(duration)} onChange={(e) => setDuration(e.target.value ? Number(e.target.value) : null)} aria-describedby="req-duration-hint">
                {durationChoices(DURATIONS, itemMaxHours, set, itemsHaveDefaults).map(([l, h]) => <option key={l} value={h === null ? "" : h}>{h === null ? defaultDurationLabel(set, hoursLabel) : l}</option>)}
              </select>
              <span className="hint" id="req-duration-hint">{maxHours != null ? `Requests here last at most ${hoursLabel(maxHours)}.${needsDuration ? " Choose a duration." : ""}` : set.default_hours != null ? `Items without a default get ${hoursLabel(set.default_hours)}.` : "Items without a default stay until removed."}</span>
            </label>
            <label className="field">
              Justification
              <textarea className="input" maxLength={rs?.max_justification_length ?? 1000} value={justification} onChange={(e) => setJustification(e.target.value)} placeholder="What do you need it for? Include a ticket if there is one." aria-describedby="req-just-hint" aria-invalid={!!justError && justification.trim() !== ""} />
              <span className="hint" id="req-just-hint">{justification.trim() !== "" && justError ? justError : justificationHint(set)}</span>
            </label>
            {set.attachments_allowed && (
              <label className="field">
                Attachments (optional)
                <textarea className="input" rows={2} value={attachmentText} onChange={(e) => setAttachmentText(e.target.value)} placeholder="One reference per line: a ticket or document link" aria-describedby="req-att-hint" aria-invalid={!!attachError} />
                <span className="hint" id="req-att-hint">{attachError ?? `Links or ids, at most ${rs?.max_attachments ?? 5}. Approvers see them. Files are not uploaded.`}</span>
              </label>
            )}
            {cart.length > 0 && asked === null && <p className="small muted" role="status">Checking what approvers ask…</p>}
            {needs.length > 0 && <QuestionnaireForm needs={needs} value={answers} onChange={setAnswers} disabled={busy} />}
            {needs.length > 0 && !answersReady && <p className="hint" role="status">Answer the required questions to submit.</p>}
            <SodWarning beneficiaryIds={beneficiaries.map((b) => b.id)} catalogIds={cart.flatMap((c) => (c.catalogId ? [c.catalogId] : []))} durationHours={duration} />
            {groups && <RiskPreview beneficiaries={beneficiaries} cart={cart} groups={groups} />}
            {cart.some((c) => !c.catalogId) && <Callout tone="neutral">A role is one request per person: approving it grants every entitlement in the role.</Callout>}
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
