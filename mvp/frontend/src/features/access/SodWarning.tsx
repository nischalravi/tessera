import { useEffect, useState } from "react";
import { ShieldAlert } from "lucide-react";
import { SodSimulation, sod } from "../../api";
import { Callout } from "../../components";
import { sodWarning } from "../governance/sodModel";

const MAX_PAIRS = 50;

/**
 * "If this request were granted, which SoD risks would it trigger" (issue #298), asked of the
 * server as the cart changes. Advisory: it never blocks the Submit button, and a failed check says so.
 */
export function SodWarning({ beneficiaryIds, catalogIds, durationHours }: { beneficiaryIds: number[]; catalogIds: string[]; durationHours: number | null }) {
  const [sim, setSim] = useState<SodSimulation | null>(null);
  const [failed, setFailed] = useState(false);
  const sig = `${beneficiaryIds.join(",")}|${catalogIds.join(",")}|${durationHours ?? ""}`;
  const tooMany = beneficiaryIds.length * catalogIds.length > MAX_PAIRS;
  useEffect(() => {
    setSim(null);
    setFailed(false);
    if (!beneficiaryIds.length || !catalogIds.length || tooMany) return;
    let alive = true;
    const t = setTimeout(() => {
      sod.simulate(beneficiaryIds, catalogIds, durationHours ?? undefined)
        .then((s) => alive && setSim(s))
        .catch(() => alive && setFailed(true));
    }, 300);
    return () => {
      alive = false;
      clearTimeout(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sig]);
  if (tooMany) return <Callout tone="neutral">Separation of duties is not checked for more than {MAX_PAIRS} person-item pairs at once. Approvers still see conflicts.</Callout>;
  if (failed) return <Callout tone="neutral">Couldn't check separation of duties. You can still submit; approvers see conflicts.</Callout>;
  const w = sodWarning(sim);
  if (!w) return null;
  return (
    <div className={`callout ${w.tone}`} role="alert">
      <ShieldAlert size={16} aria-hidden />
      <div className="grow small">
        <b>{w.title}</b>
        {w.lines.slice(0, 5).map((l, i) => <div key={i}>{l}</div>)}
        {w.lines.length > 5 && <div className="faint">and {w.lines.length - 5} more</div>}
        <div>You can still submit; the approver will see the conflict and may ask for a mitigating control or refuse.</div>
      </div>
    </div>
  );
}
