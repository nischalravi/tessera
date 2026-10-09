import { ChartLine, House, Inbox, KeyRound, LucideIcon, Settings, ShieldCheck, Users } from "lucide-react";

export interface NavPage {
  path: string;
  label: string;
  /** Extra words the palette and global search match on. */
  keywords?: string;
  preview?: boolean;
}

export interface NavSection {
  id: string;
  label: string;
  icon: LucideIcon;
  path: string;
  children?: NavPage[];
}

/** The single source of truth for the sidebar, breadcrumbs and the command palette's page list. */
export const NAV: NavSection[] = [
  { id: "home", label: "Home", icon: House, path: "/" },
  { id: "inbox", label: "Inbox", icon: Inbox, path: "/inbox" },
  {
    id: "access", label: "Access", icon: KeyRound, path: "/access",
    children: [
      { path: "/access/request", label: "Request access", keywords: "catalog cart ask new access role entitlement" },
      { path: "/access/mine", label: "My access", keywords: "what i have entitlements remove" },
      { path: "/access/requests", label: "Requests", keywords: "history drafts status submitted" },
      { path: "/access/jit", label: "Just-in-time", keywords: "jit elevation temporary privileged break glass" },
    ],
  },
  {
    id: "directory", label: "Directory", icon: Users, path: "/directory",
    children: [
      { path: "/directory/people", label: "People", keywords: "users employees humans identities" },
      { path: "/directory/machine", label: "Machine identities & agents", keywords: "nhi service accounts api keys ai agents bots secrets" },
      { path: "/directory/accounts", label: "Accounts", keywords: "system accounts usernames" },
      { path: "/directory/roles", label: "Roles", keywords: "business roles birthright", preview: true },
      { path: "/directory/entitlements", label: "Entitlements", keywords: "groups permissions aws roles snowflake okta" },
      { path: "/directory/apps", label: "Applications & systems", keywords: "apps endpoints connectors resources" },
      { path: "/directory/orgs", label: "Organizations", keywords: "departments org units cost centers", preview: true },
      { path: "/directory/groups", label: "Groups", keywords: "okta groups teams" },
    ],
  },
  {
    id: "insights", label: "Insights", icon: ChartLine, path: "/insights",
    children: [
      { path: "/insights/risk", label: "Risk overview", keywords: "dashboard kpi metrics" },
      { path: "/insights/graph", label: "Access graph", keywords: "graph explorer paths who can access" },
      { path: "/insights/least-privilege", label: "Least privilege", keywords: "unused recommendations right size revoke" },
      { path: "/insights/sod", label: "SoD conflicts", keywords: "segregation separation of duties toxic combination" },
    ],
  },
  {
    id: "governance", label: "Governance", icon: ShieldCheck, path: "/governance",
    children: [
      { path: "/governance/policies", label: "Policies & violations", keywords: "policy as code yaml simulation what-if" },
      { path: "/governance/reviews", label: "Access reviews", keywords: "certification campaigns attestation" },
      { path: "/governance/lifecycle", label: "Lifecycle", keywords: "joiner mover leaver jml hris workday onboarding offboarding" },
      { path: "/governance/workflows", label: "Workflows", keywords: "approval routing escalation", preview: true },
    ],
  },
  { id: "admin", label: "Admin", icon: Settings, path: "/admin" },
];

export function allPages(): (NavPage & { section: string })[] {
  return NAV.flatMap((s) => (s.children ? s.children.map((c) => ({ ...c, section: s.label })) : [{ path: s.path, label: s.label, section: "" }]));
}

export function sectionFor(pathname: string) {
  return NAV.find((s) => (s.path === "/" ? pathname === "/" : pathname === s.path || pathname.startsWith(s.path + "/")));
}
