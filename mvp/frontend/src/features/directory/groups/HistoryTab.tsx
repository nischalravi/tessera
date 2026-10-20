import { FormEvent, useState } from "react";
import { GrpGroup, PitMember, PitMembers, groups } from "../../../api";
import { Button, Callout, EmptyState, Loading, Segmented } from "../../../components";
import { fmtWhen } from "./common";
import { errText } from "./hooks";
import { diffMembers, isFuture, toInstant } from "./model";

type Mode = "asof" | "compare" | "window";

type Result =
  | { mode: "asof"; at: string; answer: PitMembers }
  | { mode: "window"; from: string; to: string; answer: PitMembers }
  | { mode: "compare"; a: string; b: string; added: PitMember[]; removed: PitMember[]; kept: number; partial: boolean };

/**
 * History (point in time): who was a member at a date, who joined and left between two dates, and everyone who was a
 * member at any time in a window. Answers come from the group's recorded events, not from today's members.
 */
export function HistoryTab({ g }: { g: GrpGroup }) {
  const [mode, setMode] = useState<Mode>("asof");
  const [t1, setT1] = useState("");
  const [t2, setT2] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [res, setRes] = useState<Result | null>(null);

  const needTwo = mode !== "asof";
  const bad = isFuture(t1) || (needTwo && isFuture(t2)) ? "History cannot look into the future." : null;
  const ready = !!toInstant(t1) && (!needTwo || !!toInstant(t2)) && !bad && (!needTwo || Date.parse(toInstant(t1)!) < Date.parse(toInstant(t2)!));

  const run = async (e: FormEvent) => {
    e.preventDefault();
    if (!ready) return;
    const a = toInstant(t1)!;
    const b = needTwo ? toInstant(t2)! : "";
    setBusy(true);
    setErr(null);
    try {
      if (mode === "asof") setRes({ mode, at: a, answer: await groups.asOf(g.id, a) });
      else if (mode === "window") setRes({ mode, from: a, to: b, answer: await groups.between(g.id, a, b) });
      else {
        const [x, y] = await Promise.all([groups.asOf(g.id, a), groups.asOf(g.id, b)]);
        setRes({ mode, a, b, ...diffMembers(x.items, y.items), partial: x.total > x.items.length || y.total > y.items.length });
      }
    } catch (x) {
      setErr(errText(x));
      setRes(null);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="stack">
      <Segmented<Mode> label="History view" value={mode} onChange={(m) => { setMode(m); setRes(null); setErr(null); }}
        options={[["asof", "Members on a date"], ["compare", "Compare two dates"], ["window", "Anyone in a period"]]} />
      <form className="row" onSubmit={run}>
        <label className="field grow"><span>{mode === "asof" ? "Date and time" : "From"}</span><input className="input" type="datetime-local" value={t1} onChange={(e) => setT1(e.target.value)} /></label>
        {needTwo && <label className="field grow"><span>{mode === "compare" ? "To" : "Until"}</span><input className="input" type="datetime-local" value={t2} onChange={(e) => setT2(e.target.value)} /></label>}
        <Button type="submit" variant="primary" disabled={!ready || busy}>{busy ? "Looking…" : "Show"}</Button>
      </form>
      {bad && <Callout tone="bad">{bad}</Callout>}
      {needTwo && t1 && t2 && toInstant(t1) && toInstant(t2) && Date.parse(toInstant(t1)!) >= Date.parse(toInstant(t2)!) && <Callout tone="bad">The second date must be after the first.</Callout>}
      {mode === "window" && <p className="small faint">A period is at most 366 days.</p>}
      {err && <Callout tone="bad">{err}</Callout>}
      {busy && <Loading kind="block" />}
      {!res && !busy && !err && <EmptyState title="Pick a date">The group's changes are recorded, so you can see its members as they were.</EmptyState>}

      {res?.mode === "asof" && (
        <section className="stack-sm" aria-live="polite">
          {res.answer.group === null ? <Callout tone="neutral">This group did not exist at {fmtWhen(res.at)}.</Callout> : (
            <p><strong>{res.answer.total.toLocaleString("en-US")}</strong> {res.answer.total === 1 ? "member" : "members"} on {fmtWhen(res.at)}{res.answer.group.status && res.answer.group.status !== "active" ? ` (the group was ${res.answer.group.status})` : ""}.</p>
          )}
          <MemberTable items={res.answer.items} caption={`Members of ${g.name} on ${fmtWhen(res.at)}`} />
        </section>
      )}
      {res?.mode === "window" && (
        <section className="stack-sm" aria-live="polite">
          <p><strong>{res.answer.total.toLocaleString("en-US")}</strong> {res.answer.total === 1 ? "interval" : "intervals"} between {fmtWhen(res.from)} and {fmtWhen(res.to)}.</p>
          <MemberTable items={res.answer.items} caption={`Membership intervals of ${g.name}`} intervals />
        </section>
      )}
      {res?.mode === "compare" && (
        <section className="stack-sm" aria-live="polite">
          <p><strong>{res.added.length}</strong> joined, <strong>{res.removed.length}</strong> left, {res.kept} stayed, from {fmtWhen(res.a)} to {fmtWhen(res.b)}.</p>
          {res.partial && <Callout tone="warn">This group had more than 500 members on one of the dates, so the comparison covers the first 500 of each.</Callout>}
          {res.added.length > 0 && <MemberTable items={res.added} caption="Joined" />}
          {res.removed.length > 0 && <MemberTable items={res.removed} caption="Left" />}
          {res.added.length === 0 && res.removed.length === 0 && <Callout tone="neutral">The members were the same on both dates.</Callout>}
        </section>
      )}
      <p className="small faint">The history shows changes to membership. A timeline of each change with its cause is part of the audit log.</p>
    </div>
  );
}

function MemberTable({ items, caption, intervals }: { items: PitMember[]; caption: string; intervals?: boolean }) {
  if (items.length === 0) return <p className="small faint">{caption}: nobody.</p>;
  return (
    <div className="table-scroll">
      <table>
        <caption className="sr-only">{caption}</caption>
        <thead><tr><th scope="col">Name</th>{intervals ? <><th scope="col">From</th><th scope="col">Until</th></> : <th scope="col">Member since</th>}</tr></thead>
        <tbody>
          {items.map((m, i) => (
            <tr key={`${m.identity_id ?? m.group_id}-${i}`}>
              <td>{m.name}{m.group_id ? <span className="faint small"> (group)</span> : null}</td>
              <td>{fmtWhen(m.start_at)}</td>
              {intervals && <td>{m.end_at ? fmtWhen(m.end_at) : "Still a member"}</td>}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
