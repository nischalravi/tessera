import { useId, useState } from "react";
import type { AnswerValue, AnswersByQuestionnaire, Question, QuestionnaireNeed } from "../../api";
import { answerError, maxLength, needsError } from "../governance/questionnaireModel";

/**
 * The form for the questionnaires a request or a review decision asks (issue #298). One fieldset per
 * questionnaire, one labelled control per question: native inputs, so the keyboard and screen readers
 * work as they do everywhere; a single column, so it fits 360px. Required questions say so in words,
 * not only with a mark. A problem shows once the person has touched the question. The server checks
 * every answer again against the version in force.
 */
export function QuestionnaireForm({ needs, value, onChange, disabled }: {
  needs: QuestionnaireNeed[];
  value: AnswersByQuestionnaire;
  onChange: (v: AnswersByQuestionnaire) => void;
  disabled?: boolean;
}) {
  const set = (nid: string, qid: string, v: AnswerValue) => onChange({ ...value, [nid]: { ...(value[nid] ?? {}), [qid]: v } });
  return (
    <div className="stack">
      {needs.map((n) => (
        <fieldset key={n.id} className="stack-sm" style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }} disabled={disabled}>
          <legend><h3 className="h-sm">{n.title}</h3></legend>
          {n.description && <p className="small muted">{n.description}</p>}
          {n.questions.map((q) => <Ask key={q.id} q={q} value={value[n.id]?.[q.id]} onChange={(v) => set(n.id, q.id, v)} />)}
        </fieldset>
      ))}
    </div>
  );
}

function Ask({ q, value, onChange }: { q: Question; value: AnswerValue | undefined; onChange: (v: AnswerValue) => void }) {
  const id = useId();
  const [touched, setTouched] = useState(false);
  const err = touched ? answerError(q, value) : null;
  const hintId = `${id}-hint`;
  const required = <span className="faint small"> ({q.required ? "required" : "optional"})</span>;
  const hint = (extra?: string) => (
    <span className={`hint ${err ? "err" : ""}`} id={hintId} role={err ? "alert" : undefined}>{err ?? [q.help, extra].filter(Boolean).join(" ")}</span>
  );
  const common = { "aria-describedby": hintId, "aria-invalid": !!err, onBlur: () => setTouched(true) };
  const options = q.options ?? [];

  switch (q.type) {
    case "short_text":
      return (
        <label className="field">{q.text}{required}
          <input className="input" type="text" value={typeof value === "string" ? value : ""} maxLength={maxLength(q)} onChange={(e) => onChange(e.target.value)} {...common} />
          {hint()}
        </label>
      );
    case "long_text":
      return (
        <label className="field">{q.text}{required}
          <textarea className="input" rows={4} value={typeof value === "string" ? value : ""} maxLength={maxLength(q)} onChange={(e) => onChange(e.target.value)} {...common} />
          {hint(`At most ${maxLength(q)} characters.`)}
        </label>
      );
    case "date":
      return (
        <label className="field">{q.text}{required}
          <input className="input" type="date" value={typeof value === "string" ? value : ""} onChange={(e) => onChange(e.target.value)} style={{ maxWidth: 220 }} {...common} />
          {hint()}
        </label>
      );
    case "single_choice":
      if (options.length > 6) {
        return (
          <label className="field">{q.text}{required}
            <select className="input" value={typeof value === "string" ? value : ""} onChange={(e) => onChange(e.target.value)} {...common}>
              <option value="">Choose…</option>
              {options.map((o) => <option key={o} value={o}>{o}</option>)}
            </select>
            {hint()}
          </label>
        );
      }
      return (
        <fieldset className="field" style={{ border: 0, padding: 0, margin: 0 }} aria-describedby={hintId} onBlur={() => setTouched(true)}>
          <legend>{q.text}{required}</legend>
          {options.map((o) => (
            <label key={o} className="row tight" style={{ fontWeight: 400 }}>
              <input type="radio" name={id} checked={value === o} onChange={() => { onChange(o); setTouched(true); }} /> {o}
            </label>
          ))}
          {hint()}
        </fieldset>
      );
    case "multi_choice": {
      const chosen = Array.isArray(value) ? value : [];
      return (
        <fieldset className="field" style={{ border: 0, padding: 0, margin: 0 }} aria-describedby={hintId} onBlur={() => setTouched(true)}>
          <legend>{q.text}{required}</legend>
          {options.map((o) => (
            <label key={o} className="row tight" style={{ fontWeight: 400 }}>
              <input type="checkbox" checked={chosen.includes(o)} onChange={(e) => onChange(e.target.checked ? [...chosen, o] : chosen.filter((x) => x !== o))} /> {o}
            </label>
          ))}
          {hint("Choose any that apply.")}
        </fieldset>
      );
    }
    case "yes_no":
      return (
        <fieldset className="field" style={{ border: 0, padding: 0, margin: 0 }} aria-describedby={hintId} onBlur={() => setTouched(true)}>
          <legend>{q.text}{required}</legend>
          <div className="row">
            {([[true, "Yes"], [false, "No"]] as const).map(([b, l]) => (
              <label key={l} className="row tight" style={{ fontWeight: 400 }}>
                <input type="radio" name={id} checked={value === b} onChange={() => { onChange(b); setTouched(true); }} /> {l}
              </label>
            ))}
          </div>
          {hint()}
        </fieldset>
      );
  }
}

/** Whether every required question of every questionnaire has an answer and none is invalid. */
export const formReady = (needs: QuestionnaireNeed[], v: AnswersByQuestionnaire): boolean => needsError(needs, v) === null;
