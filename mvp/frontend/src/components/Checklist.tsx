import { ReactNode, useId, useMemo, useRef, useState } from "react";
import { ChevronDown, ChevronRight, CircleAlert, CircleCheck, CircleDashed, CircleMinus, CircleSlash, Clock, ExternalLink, Lock } from "lucide-react";
import { Checklist as ChecklistData, ChecklistItem, ItemStatus, Level } from "../api";
import { Badge, Tone } from "./Badge";
import { Button } from "./Button";
import { FilterChips } from "./Page";
import { useModal } from "./overlay";

export const CATEGORY_LABEL: Record<string, string> = {
  access: "Credentials and access", ownership: "Ownership", transport: "Transport", scope: "Scope", identity_keys: "Identity keys",
  account_status: "Account status", groups: "Groups", change_tracking: "Change tracking", data_quality: "Data quality",
  topology: "Topology", write_back: "Write-back",
};

export const LEVEL_LABEL: Record<Level, string> = { required: "Required", recommended: "Recommended", optional: "Optional" };
const LEVEL_TONE: Record<Level, Tone> = { required: "critical", recommended: "warning", optional: "outline" };
const VERIFY_LABEL = { attestation: "Attest", live: "Live check", data: "Data check" };

/** Status icon and text: state is never conveyed by colour alone. */
export function ItemStatusLabel({ item }: { item: Pick<ChecklistItem, "status" | "blocked_by"> }) {
  const s = item.status;
  const meta: Record<ItemStatus, [ReactNode, string]> = {
    pass: [<CircleCheck size={15} color="var(--ok)" aria-hidden />, "Pass"],
    fail: [<CircleAlert size={15} color="var(--critical)" aria-hidden />, "Fail"],
    pending: [<CircleDashed size={15} color="var(--text-3)" aria-hidden />, "Pending"],
    blocked: [<Lock size={15} color="var(--text-3)" aria-hidden />, `Blocked by ${item.blocked_by?.join(", ") ?? "a dependency"}`],
    stale: [<Clock size={15} color="var(--warning)" aria-hidden />, "Stale"],
    skipped: [<CircleMinus size={15} color="var(--warning)" aria-hidden />, "Skipped"],
    not_applicable: [<CircleSlash size={15} color="var(--text-3)" aria-hidden />, "N/A"],
  };
  const [icon, label] = meta[s];
  return <span className={`st-label st-${s}`}>{icon}<span>{label}</span></span>;
}

export function LevelBadge({ level }: { level: Level }) {
  return <Badge tone={LEVEL_TONE[level]}>{LEVEL_LABEL[level]}</Badge>;
}

/** A dialog asking for a note or reason with a minimum length (and optionally a date). */
export function ReasonDialog({ title, body, label, minLength, confirmLabel, date, onCancel, onSubmit }: {
  title: string;
  body?: ReactNode;
  label: string;
  minLength: number;
  confirmLabel: string;
  date?: { label: string; hint?: string };
  onCancel: () => void;
  onSubmit: (text: string, date?: string) => Promise<void> | void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const id = useId();
  const [text, setText] = useState("");
  const [day, setDay] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useModal(ref, onCancel);
  const short = text.trim().length < minLength;
  return (
    <div className="dialog-wrap">
      <div className="overlay" onClick={onCancel} aria-hidden />
      <div ref={ref} className="dialog" role="dialog" aria-modal="true" aria-labelledby={id}>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            if (short) return;
            setBusy(true);
            setErr(null);
            try {
              await onSubmit(text.trim(), day || undefined);
            } catch (x) {
              setErr((x as Error).message);
              setBusy(false);
            }
          }}
        >
          <div className="dlg-b stack-sm">
            <h2 id={id}>{title}</h2>
            {body && <div className="muted small">{body}</div>}
            <label className="field">
              {label}
              <textarea className="input" data-autofocus value={text} onChange={(e) => setText(e.target.value)} aria-describedby={`${id}-n`} minLength={minLength} required />
              <span id={`${id}-n`} className={`hint ${short && text ? "err" : ""}`}>
                {text.trim().length < minLength ? `At least ${minLength} characters (${text.trim().length} so far).` : "Recorded with your name in the audit log."}
              </span>
            </label>
            {date && (
              <label className="field">
                {date.label}
                <input type="date" className="input" value={day} onChange={(e) => setDay(e.target.value)} />
                {date.hint && <span className="hint">{date.hint}</span>}
              </label>
            )}
            {err && <div className="err" role="alert">{err}</div>}
          </div>
          <div className="dlg-f">
            <Button onClick={onCancel}>Cancel</Button>
            <Button type="submit" variant="primary" disabled={short || busy}>{busy ? "Saving…" : confirmLabel}</Button>
          </div>
        </form>
      </div>
    </div>
  );
}

type ChecklistFilter = "all" | "blocking" | Level | "skipped";

const isBlocking = (i: ChecklistItem) =>
  i.applicable && ((i.level === "required" && i.status !== "pass") || (i.level === "recommended" && i.status !== "pass" && i.status !== "skipped"));

function ItemRow({ item, open, onToggle, onAttest, onSkip, onUnskip, focus }: {
  item: ChecklistItem;
  open: boolean;
  onToggle: () => void;
  onAttest?: (i: ChecklistItem) => void;
  onSkip?: (i: ChecklistItem) => void;
  onUnskip?: (i: ChecklistItem) => void;
  focus?: boolean;
}) {
  const statusId = useId();
  const attestable = item.applicable && item.verify.some((v) => v.kind === "attestation");
  const attestPart = item.parts.find((p) => p.kind === "attestation");
  const attested = attestPart?.status === "pass";
  const depsBlocked = (item.blocked_by?.length ?? 0) > 0;
  return (
    <li className={`cl-item ${focus ? "focus" : ""}`} aria-describedby={statusId}>
      <div className="cl-row">
        {attestable && onAttest ? (
          <input
            type="checkbox"
            checked={attested}
            disabled={attested || depsBlocked}
            title={depsBlocked ? `Blocked by ${item.blocked_by!.join(", ")}` : attested ? "Attested" : "Attest with a note"}
            aria-label={`Attest ${item.title}`}
            onChange={() => onAttest(item)}
          />
        ) : <span className="cl-spacer" aria-hidden />}
        <button type="button" className="cl-title" aria-expanded={open} onClick={onToggle}>
          {open ? <ChevronDown size={14} aria-hidden /> : <ChevronRight size={14} aria-hidden />}
          <span className="grow">{item.title}</span>
        </button>
        <span id={statusId}><ItemStatusLabel item={item} /></span>
      </div>
      <div className="cl-meta">
        <LevelBadge level={item.level} />
        {item.template_level && item.template_level !== item.level && <Badge tone="info" title={`Raised by the tenant overlay from ${item.template_level}`}>Raised</Badge>}
        {item.verify.map((v, i) => <span key={i} className="chip">{VERIFY_LABEL[v.kind]}</span>)}
        {item.parts.some((p) => p.simulated) && <Badge tone="info" title="Evidence from the simulated demo scenario">Simulated</Badge>}
        <code className="xs faint">{item.id}</code>
      </div>
      {open && (
        <div className="cl-detail small stack-sm">
          <p><b>Why it matters.</b> {item.why}</p>
          {!item.applicable && <p className="faint">Not applicable: {item.reason}</p>}
          {item.reason && item.applicable && item.status !== "pass" && <p><b>Status.</b> {item.reason}</p>}
          <div>
            <b>How it is verified.</b>
            <ul className="cl-parts">
              {item.parts.length === 0 && item.verify.map((v, i) => <li key={i}>{VERIFY_LABEL[v.kind]}{v.check ? `: ${v.check}` : ""}</li>)}
              {item.parts.map((p, i) => (
                <li key={i}>
                  {VERIFY_LABEL[p.kind]}{p.check ? <> · <code>{p.check}</code></> : ""}: <ItemStatusLabel item={{ status: p.status }} />
                  {p.message && <span className="faint"> {p.message}</span>}
                  {p.reason && p.status !== "pass" && <span className="faint"> ({p.reason})</span>}
                </li>
              ))}
            </ul>
          </div>
          {item.attestation && <p>Attested by {item.attestation.actor}: “{item.attestation.note}”{item.attestation.stale && <Badge tone="warning">Stale</Badge>}</p>}
          {item.skip && <p>Skipped by {item.skip.actor}: “{item.skip.reason}”. Review by {item.skip.review_by.slice(0, 10)}{item.skip.expired && " (expired)"}.</p>}
          <p><b>Fix.</b> {item.remediation.hint} {item.remediation.link && <a href={item.remediation.link} target="_blank" rel="noreferrer noopener" className="row tight" style={{ display: "inline-flex" }}>Documentation <ExternalLink size={12} aria-hidden /></a>}</p>
          {item.depends_on && item.depends_on.length > 0 && <p className="faint">Depends on {item.depends_on.join(", ")}.</p>}
          <div className="row">
            {item.level === "recommended" && item.applicable && item.status !== "pass" && !item.skip && onSkip && <Button size="sm" onClick={() => onSkip(item)}>Skip…</Button>}
            {item.skip && onUnskip && <Button size="sm" onClick={() => onUnskip(item)}>Un-skip</Button>}
          </div>
        </div>
      )}
    </li>
  );
}

/**
 * The checklist panel (§10.2): progress per level, filter chips, items grouped by category.
 * Attestation items are real checkboxes that open a note dialog; Recommended items can be
 * skipped with a reason; Required items have no skip control.
 */
export function ChecklistPanel({ data, score, onAttest, onSkip, onUnskip, focusItem }: {
  data: ChecklistData;
  score?: ReactNode;
  onAttest?: (i: ChecklistItem) => void;
  onSkip?: (i: ChecklistItem) => void;
  onUnskip?: (i: ChecklistItem) => void;
  focusItem?: string | null;
}) {
  const [filter, setFilter] = useState<ChecklistFilter>("all");
  const [open, setOpen] = useState<Set<string>>(() => new Set(focusItem ? [focusItem] : []));
  const items = data.items;
  const counts = useMemo(() => ({
    all: items.length,
    blocking: items.filter(isBlocking).length,
    required: items.filter((i) => i.level === "required").length,
    recommended: items.filter((i) => i.level === "recommended").length,
    optional: items.filter((i) => i.level === "optional").length,
    skipped: items.filter((i) => i.status === "skipped").length,
  }), [items]);
  const shown = items.filter((i) => filter === "all" ? true : filter === "blocking" ? isBlocking(i) : filter === "skipped" ? i.status === "skipped" : i.level === filter);
  const byCat = data.categories.map((c) => [c, shown.filter((i) => i.category === c)] as const).filter(([, xs]) => xs.length > 0);
  const p = data.progress;
  const toggle = (id: string) => setOpen((s) => {
    const n = new Set(s);
    if (n.has(id)) n.delete(id);
    else n.add(id);
    return n;
  });
  return (
    <section className="card checklist" aria-label="Readiness checklist">
      <div className="cl-head">
        <div className="spread">
          <h2>Checklist</h2>
          {score}
        </div>
        <div className="small muted tnum">
          Required {p.required.pass}/{p.required.total} · Recommended {p.recommended.pass}/{p.recommended.total}
          {p.recommended.skipped ? ` (+${p.recommended.skipped} skipped)` : ""} · Optional {p.optional.pass}/{p.optional.total}
        </div>
        <FilterChips<ChecklistFilter>
          label="Filter checklist items"
          value={filter}
          onChange={setFilter}
          options={[
            { id: "all", label: "All", count: counts.all },
            { id: "blocking", label: "Blocking", count: counts.blocking },
            { id: "required", label: "Required", count: counts.required },
            { id: "recommended", label: "Recommended", count: counts.recommended },
            { id: "optional", label: "Optional", count: counts.optional },
            { id: "skipped", label: "Skipped", count: counts.skipped },
          ]}
        />
      </div>
      <div className="cl-body">
        {byCat.length === 0 && <p className="small faint" style={{ padding: 12 }}>Nothing in this filter.</p>}
        {byCat.map(([cat, xs]) => (
          <div key={cat} className="cl-cat">
            <h3>{CATEGORY_LABEL[cat] ?? cat} <span className="faint">{xs.filter((i) => i.status === "pass").length}/{xs.length}</span></h3>
            <ul className="cl-list">
              {xs.map((i) => (
                <ItemRow key={i.id} item={i} open={open.has(i.id)} onToggle={() => toggle(i.id)} onAttest={onAttest} onSkip={onSkip} onUnskip={onUnskip} focus={focusItem === i.id} />
              ))}
            </ul>
          </div>
        ))}
      </div>
    </section>
  );
}
