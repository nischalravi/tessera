/**
 * Types for the Preview mock layer.
 *
 * Everything in src/mocks/ stands in for backend endpoints that do not exist yet. UI built on
 * it shows a "Preview" badge. When an endpoint ships, replace the mock call with a function in
 * src/api.ts that returns the same type, and remove the badge.
 */

export interface Workflow {
  id: string;
  name: string;
  trigger: string;
  steps: string[];
  appliesTo: string;
  enabled: boolean;
  sla: string;
}

export interface AdminSection {
  id: string;
  title: string;
  icon: string;
  summary: string;
  /** What the page will do once it is backed by an API. */
  will: string[];
  keywords: string[];
  /** Backed by a real endpoint today. */
  live?: boolean;
}
