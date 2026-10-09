/**
 * Types for the Preview mock layer.
 *
 * Everything in src/mocks/ stands in for backend endpoints that do not exist yet. UI built on
 * it shows a "Preview" badge. When an endpoint ships, replace the mock call with a function in
 * src/api.ts that returns the same type, and remove the badge.
 */

export interface BusinessRole {
  id: string;
  name: string;
  description: string;
  owner: string;
  /** Real group/role names from the connected systems (system:name) that the role bundles. */
  entitlements: string[];
  /** Department the role is a birthright for, if any. */
  birthright?: string;
  members: number;
  risk: "low" | "medium" | "high";
  updated: string;
}

export interface OrgUnit {
  id: string;
  name: string;
  parent: string | null;
  /** Matches identity.department for membership counts. */
  department: string | null;
  owner: string;
  costCenter: string;
}

export interface Workflow {
  id: string;
  name: string;
  trigger: string;
  steps: string[];
  appliesTo: string;
  enabled: boolean;
  sla: string;
}

export type RequestTarget = { kind: "group"; groupId: number; name: string; system: string; privileged: boolean; jit: boolean } | { kind: "role"; roleId: string; name: string };

export interface AccessRequestDraft {
  id: string;
  createdAt: string;
  status: "draft" | "submitted" | "approved" | "denied";
  requester: string;
  beneficiaries: { id: number; name: string }[];
  items: RequestTarget[];
  durationHours: number | null;
  justification: string;
  /** Removal requests come from My access. */
  kind: "grant" | "removal";
  /** JIT request ids created through the real API for JIT-eligible items. */
  jitIds?: number[];
}

export interface DelegationItem {
  id: string;
  from: string;
  to: string;
  scope: string;
  until: string;
  reason: string;
  status: "pending" | "accepted" | "declined";
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
