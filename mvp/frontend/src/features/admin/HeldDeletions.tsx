import { useState } from "react";
import { Check, Trash2 } from "lucide-react";
import { DeletionHold, DeletionHoldItem, deletionGuard, fmtDate, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, DataTable, SidePanel, useConfirm, useSelected, useToast } from "../../components";
import { Fact, errText } from "./common";
import { CATEGORY_LABEL, HOLD_LABEL, HOLD_TONE, SOURCE_LABEL, holdTitle, windowText } from "./deletionGuardModel";

const when = (s: string | null) => (s ? fmtDate(s.replace("Z", "")) : "—");

const ITEM_LABEL: Record<DeletionHoldItem["status"], string> = {
  held: "Held", released: "Deleted", discarded: "Kept", gone: "Already gone", failed: "Refused",
};

/**
 * Admin → Held deletions: what the deletion guard stopped when a category passed its threshold (Admin → Deletion
 * guard). A different admin than the one whose request was held can release it (everything, or only the items
 * ticked: the rest is then discarded) with a fresh passkey sign-in, or discard it. A release re-checks each item
 * and does not count against the window again. A hold nobody decides on expires and is discarded.
 */
export function HeldDeletions() {
  const { data, error, reload } = useApi<{ holds: DeletionHold[] }>("/admin/deletion-holds?limit=500");
  const [selected, setSelected] = useSelected();
  const rows = data?.holds ?? null;
  return (
    <div className="stack">
      <DataTable
        id="held-deletions"
        rows={rows}
        error={error}
        onRefresh={reload}
        rowKey={(h) => h.id}
        initialSort={["created", -1]}
        onRowClick={(h) => setSelected(h.id)}
        activeKey={selected ?? undefined}
        rowLabel={(h) => holdTitle(h)}
        columns={[
          { id: "what", header: "Held", sort: (h) => h.category, csv: (h) => holdTitle(h), cell: (h) => <><b>{h.item_count} {CATEGORY_LABEL[h.category].toLowerCase()}</b> <span className="small faint">from {(SOURCE_LABEL[h.source] ?? h.source).toLowerCase()}{h.source_id ? ` ${h.source_id}` : ""}</span></> },
          { id: "status", header: "State", sort: (h) => h.status, cell: (h) => <Badge tone={HOLD_TONE[h.status]} dot>{HOLD_LABEL[h.status]}</Badge> },
          { id: "by", header: "Requested by", hideNarrow: true, sort: (h) => h.actor_name ?? h.actor, cell: (h) => <span className="small">{h.actor_name || h.actor || "—"}</span> },
          { id: "created", header: "Held at", hideNarrow: true, sort: (h) => h.created_at, cell: (h) => <span className="small nowrap">{when(h.created_at)}</span> },
          { id: "expires", header: "Expires", hideNarrow: true, sort: (h) => h.expires_at, cell: (h) => <span className="small nowrap">{h.status === "held" ? when(h.expires_at) : "—"}</span> },
        ]}
        searchText={(h) => `${holdTitle(h)} ${h.category} ${h.status} ${h.actor_name ?? ""} ${h.id}`}
        searchPlaceholder="Search category, source or person…"
        chips={2}
        filters={[
          { id: "status", label: "State", options: Object.entries(HOLD_LABEL).map(([value, label]) => ({ value, label })), get: (h) => h.status },
          { id: "category", label: "Category", options: Object.entries(CATEGORY_LABEL).map(([value, label]) => ({ value, label })), get: (h) => h.category },
        ]}
        empty="Nothing is held. A deletion that passes a threshold in Admin → Deletion guard appears here."
      />
      {selected && <HoldPanel id={selected} onClose={() => setSelected(null)} onChanged={() => reload?.()} />}
    </div>
  );
}

function HoldPanel({ id, onClose, onChanged }: { id: string; onClose: () => void; onChanged: () => void }) {
  const { data: h, error, reload } = useApi<DeletionHold>(`/admin/deletion-holds/${encodeURIComponent(id)}`);
  const { can, session } = useSession();
  const toast = useToast();
  const confirm = useConfirm();
  const [ticked, setTicked] = useState<number[]>([]);
  const [busy, setBusy] = useState(false);
  if (error) return <SidePanel title="Held deletion" onClose={onClose}><Callout tone="bad">{error.message}</Callout></SidePanel>;
  if (!h) return <SidePanel title="Held deletion" onClose={onClose}><p className="small muted">Loading…</p></SidePanel>;

  const items = h.items ?? [];
  const open = h.status === "held";
  const allowed = can("admin.change.approve");
  const mine = h.actor !== "" && h.actor === session.user.id;
  const heldItems = items.filter((i) => i.status === "held");
  const partial = ticked.length > 0 && ticked.length < heldItems.length;
  const done = () => { reload?.(); onChanged(); };

  const approve = async () => {
    const n = ticked.length === 0 ? heldItems.length : ticked.length;
    const ok = await confirm({
      title: ticked.length === 0 ? `Delete all ${n} held ${n === 1 ? "item" : "items"}?` : `Delete ${n} of ${heldItems.length} held items and discard the rest?`,
      body: "Each item is checked again and deleted only if it still exists and can still be deleted. This does not count against the threshold again, and it is recorded in the audit log.",
      confirmLabel: "Approve and delete", danger: true,
    });
    if (ok === null) return;
    setBusy(true);
    try {
      const r = await deletionGuard.approve(h.id, ticked.length === 0 ? undefined : ticked);
      toast(`Released: ${r.released} deleted${r.gone ? `, ${r.gone} already gone` : ""}${r.failed ? `, ${r.failed} refused` : ""}${r.discarded ? `, ${r.discarded} discarded` : ""}.`);
      setTicked([]);
      done();
    } catch (e) {
      toast(errText(e), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  const discard = async () => {
    const ok = await confirm({ title: "Discard the held deletions?", body: "Nothing is deleted: the held items stay as they are.", confirmLabel: "Discard" });
    if (ok === null) return;
    setBusy(true);
    try {
      await deletionGuard.discard(h.id);
      toast("Discarded: nothing was deleted.");
      done();
    } catch (e) {
      toast(errText(e), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  const toggle = (ord: number) => setTicked(ticked.includes(ord) ? ticked.filter((o) => o !== ord) : [...ticked, ord]);
  const r = h.reason;

  return (
    <SidePanel
      title={`${h.item_count} ${CATEGORY_LABEL[h.category].toLowerCase()} held`}
      sub={<span className="row tight"><Badge tone={HOLD_TONE[h.status]} dot>{HOLD_LABEL[h.status]}</Badge> <span className="small faint">{when(h.created_at)}</span></span>}
      onClose={onClose}
      commands={open && allowed ? (
        <>
          <Button size="sm" variant="primary" icon={<Check size={13} />} disabled={busy || mine} onClick={approve}>{partial ? `Approve ${ticked.length}` : "Approve all"}</Button>
          <Button size="sm" icon={<Trash2 size={13} />} disabled={busy} onClick={discard}>Discard</Button>
        </>
      ) : undefined}
    >
      <div className="stack-sm">
        {open && mine && <Callout tone="warn">This is your own held request. A different admin must approve it; you can still discard it.</Callout>}
        {open && !allowed && <Callout tone="neutral">Your role can read held deletions but not decide on them.</Callout>}
        <Callout tone="neutral">
          {CATEGORY_LABEL[h.category]}: {r.attempted ?? h.item_count} attempted, {r.applied ?? 0} applied, {h.item_count} held. The threshold was {r.limit ?? "—"} {windowText(r.window_minutes ?? 60)} and {r.used_before ?? 0} had been used when this arrived.
          {h.mode === "hold_all" && " The category holds the whole batch when it passes the threshold."}
        </Callout>
        <dl className="kv small">
          <dt>From</dt><dd>{SOURCE_LABEL[h.source] ?? h.source}{h.source_id ? ` (${h.source_id})` : ""}</dd>
          <dt>Requested by</dt><dd>{h.actor_name || h.actor || "No person: a worker did it"}</dd>
          <dt>Expires</dt><dd>{open ? `${when(h.expires_at)} (then it is discarded)` : "—"}</dd>
          {h.resolved_at && <><dt>Decided</dt><dd>{when(h.resolved_at)}{h.note ? `: ${h.note}` : ""}</dd></>}
          <dt>Correlation</dt><dd><code className="xs" style={{ wordBreak: "break-all" }}>{h.correlation_id}</code></dd>
        </dl>
        <Fact label={open ? "Held items (tick some to approve only those)" : "Items"}>
          <ul className="plain" style={{ margin: 0, padding: 0, listStyle: "none" }}>
            {items.map((i) => (
              <li key={i.ord} className="row tight" style={{ padding: "2px 0" }}>
                {open && i.status === "held" && allowed ? (
                  <label className="row tight">
                    <input type="checkbox" checked={ticked.includes(i.ord)} onChange={() => toggle(i.ord)} aria-label={`Approve ${i.label}`} />
                    <span className="small">{i.label}</span>
                  </label>
                ) : <span className="small">{i.label}</span>}
                {i.status !== "held" && <Badge tone={i.status === "released" ? "ok" : i.status === "failed" ? "critical" : "neutral"}>{ITEM_LABEL[i.status]}</Badge>}
                {i.note && <span className="xs faint">{i.note}</span>}
              </li>
            ))}
          </ul>
        </Fact>
        <p className="small muted" style={{ margin: 0 }}>Approving needs a fresh passkey sign-in and is recorded in the audit log together with who asked for the deletion.</p>
      </div>
    </SidePanel>
  );
}
