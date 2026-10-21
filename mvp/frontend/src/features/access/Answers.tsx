import type { AnsweredQuestionnaire } from "../../api";
import { fmtDate } from "../../api";
import { answerText } from "../governance/questionnaireModel";

/**
 * The answers a requester gave, beside the questions as they were asked, for the approvers (issue #298).
 * The version and the SHA-256 are the ones the audit event of the request records.
 */
export function AnswersView({ answered }: { answered: AnsweredQuestionnaire[] }) {
  if (answered.length === 0) return null;
  return (
    <>
      {answered.map((a) => (
        <section key={a.questionnaire_id} className="stack-sm" aria-label={`Answers: ${a.title}`}>
          <h3 className="mt">{a.title}</h3>
          <p className="xs faint">
            Version {a.version}, answered by {a.answered_by} on {fmtDate(a.answered_at)}.{" "}
            <span title={a.answers_hash}>Hash {a.answers_hash.slice(0, 12)}…</span>
          </p>
          {a.items.length === 0 ? <p className="small muted">No questions were answered.</p> : (
            <dl className="kv">
              {a.items.map((i) => <div key={i.question_id} style={{ display: "contents" }}><dt>{i.text}</dt><dd style={{ whiteSpace: "pre-wrap" }}>{answerText(i.answer)}</dd></div>)}
            </dl>
          )}
        </section>
      ))}
    </>
  );
}
