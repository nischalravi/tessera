import { ReactNode } from "react";
import { FlaskConical } from "lucide-react";

export type Tone = "neutral" | "critical" | "warning" | "ok" | "info" | "accent" | "human" | "service" | "ai_agent" | "outline";

export function Badge({ tone = "neutral", dot, children, title }: { tone?: Tone; dot?: boolean; children: ReactNode; title?: string }) {
  return (
    <span className={`badge ${tone === "neutral" ? "" : tone}`} title={title}>
      {dot && <span className="dot" aria-hidden />}
      {children}
    </span>
  );
}

/** Marks UI that runs against the typed mock layer in src/mocks/ rather than a backend endpoint. */
export function PreviewBadge({ what }: { what?: string }) {
  return (
    <span className="preview-badge" title={what ?? "Preview: this runs against demo data in the browser. No backend endpoint exists yet."}>
      <FlaskConical size={11} aria-hidden />
      Preview
    </span>
  );
}

export function Chip({ children, mono }: { children: ReactNode; mono?: boolean }) {
  return <span className={`chip ${mono ? "sys" : ""}`}>{children}</span>;
}
