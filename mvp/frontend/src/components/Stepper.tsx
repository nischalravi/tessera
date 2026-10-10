import { useEffect, useRef } from "react";
import { Check } from "lucide-react";

export interface Step {
  id: string;
  label: string;
  /** One line under the label, e.g. which checklist items the step satisfies. */
  sub?: string;
  done?: boolean;
  disabled?: boolean;
  /** Why the step is disabled (shown as its title). */
  reason?: string;
}

/** Vertical wizard steps. The current step carries aria-current="step". */
export function Stepper({ steps, current, onSelect, label = "Steps" }: { steps: Step[]; current: string; onSelect: (id: string) => void; label?: string }) {
  const ref = useRef<HTMLOListElement>(null);
  // on narrow screens the steps scroll horizontally: keep the current one visible
  useEffect(() => {
    const el = ref.current?.querySelector<HTMLElement>('[aria-current="step"]');
    const list = ref.current;
    if (el && list && list.scrollWidth > list.clientWidth) list.scrollLeft = el.offsetLeft - list.offsetLeft - 8;
  }, [current]);
  return (
    <ol ref={ref} className="stepper" aria-label={label}>
      {steps.map((s, i) => {
        const cur = s.id === current;
        return (
          <li key={s.id} className={`${cur ? "current" : ""} ${s.done ? "done" : ""}`}>
            <button
              type="button"
              aria-current={cur ? "step" : undefined}
              disabled={s.disabled}
              title={s.disabled ? s.reason : undefined}
              onClick={() => onSelect(s.id)}
            >
              <span className="st-n" aria-hidden>{s.done ? <Check size={13} /> : i + 1}</span>
              <span className="st-t">
                <span className="st-l">{s.label}</span>
                {s.sub && <span className="st-s">{s.sub}</span>}
                <span className="sr-only">{s.done ? ", done" : s.disabled ? `, not available yet: ${s.reason ?? ""}` : ""}</span>
              </span>
            </button>
          </li>
        );
      })}
    </ol>
  );
}
