import {
  AppWindow, BadgeCheck, BellRing, Bot, Building2, CalendarClock, ChartLine, ClipboardCheck, House, Inbox, KeyRound, Layers, LucideIcon, Network, Plug, Plus, Settings, ShieldCheck, SlidersHorizontal, Timer, UserCheck, UserPlus, Users, UsersRound,
} from "lucide-react";

export interface NavPage {
  path: string;
  label: string;
  /** Extra words the palette and global search match on. */
  keywords?: string;
  preview?: boolean;
}

export interface RailItem extends NavPage {
  id: string;
  icon: LucideIcon;
  /** Other paths that light this item up (sub-pages and tabs that live under it). */
  also?: string[];
  /** Paths under `also` that belong to a different item. */
  except?: string[];
  /** Pages reachable from this item's tabs; listed in the palette, not in the rail. */
  pages?: NavPage[];
}

export interface RailGroup {
  label?: string;
  items: RailItem[];
}

/** The single source of truth for the left rail, breadcrumbs and the command palette's page list. */
export const RAIL: RailGroup[] = [
  {
    items: [
      { id: "home", label: "Home", icon: House, path: "/", keywords: "overview tenant monitoring recommendations" },
      { id: "inbox", label: "Inbox", icon: Inbox, path: "/inbox", keywords: "approvals tasks queue" },
    ],
  },
  {
    label: "Identity",
    items: [
      { id: "users", label: "Users", icon: Users, path: "/directory/people", keywords: "people employees humans identities" },
      { id: "workers", label: "Contractors & guests", icon: CalendarClock, path: "/directory/workers", keywords: "contractors partners vendors interns guests temporary accounts expiry end date sponsor expiring" },
      { id: "machine", label: "Machine identities & agents", icon: Bot, path: "/directory/machine", keywords: "nhi service accounts api keys ai agents bots secrets" },
      {
        id: "groups", label: "Groups", icon: UsersRound, path: "/directory/groups", also: ["/directory/entitlements"], keywords: "okta groups teams",
        pages: [{ path: "/directory/entitlements", label: "Entitlements", keywords: "groups permissions aws roles snowflake okta" }],
      },
      { id: "apps", label: "Applications", icon: AppWindow, path: "/directory/apps", keywords: "apps systems endpoints connectors resources" },
      { id: "ownership", label: "Ownership", icon: UserCheck, path: "/directory/ownership", keywords: "owners backup owner orphaned unowned accountable purpose" },
      {
        id: "accounts", label: "Accounts", icon: KeyRound, path: "/directory/accounts", also: ["/directory/matches"], keywords: "system accounts usernames",
        pages: [{ path: "/directory/matches", label: "Account matches", keywords: "correlation link merge unmerge duplicate orphan uncorrelated" }],
      },
      { id: "roles", label: "Roles", icon: Layers, path: "/directory/roles", keywords: "business roles birthright drift" },
      { id: "orgs", label: "Organizations", icon: Building2, path: "/directory/orgs", keywords: "departments org units cost centers" },
    ],
  },
  {
    label: "Access",
    items: [
      { id: "request", label: "Request access", icon: Plus, path: "/access/request", keywords: "catalog cart ask new access role entitlement" },
      {
        id: "mine", label: "My access", icon: BadgeCheck, path: "/access/mine", also: ["/access/requests"], keywords: "what i have entitlements remove",
        pages: [{ path: "/access/requests", label: "My requests", keywords: "history drafts status submitted" }],
      },
      { id: "guests", label: "Guests I sponsor", icon: UserPlus, path: "/access/guests", keywords: "guest sponsor invite visitor contractor volunteer partner sponsorship bulk csv approve transfer" },
      { id: "jit", label: "Just-in-time", icon: Timer, path: "/access/jit", keywords: "jit elevation temporary privileged break glass" },
      {
        id: "reviews", label: "Access reviews", icon: ClipboardCheck, path: "/governance/reviews", also: ["/governance/lifecycle", "/governance/workflows"], keywords: "certification campaigns attestation",
        pages: [
          { path: "/governance/lifecycle", label: "Lifecycle", keywords: "joiner mover leaver jml hris workday onboarding offboarding" },
          { path: "/governance/workflows", label: "Workflows", keywords: "approval routing escalation" },
        ],
      },
    ],
  },
  {
    label: "Protection",
    items: [
      { id: "alerts", label: "Alerts", icon: BellRing, path: "/alerts", keywords: "alerting notifications incidents detections break glass sign-in failures webhook slack teams email" },
      { id: "policies", label: "Policies & SoD", icon: ShieldCheck, path: "/governance/policies", keywords: "policy as code yaml simulation what-if violations" },
      { id: "abac", label: "Attribute policies", icon: SlidersHorizontal, path: "/governance/attributes", keywords: "abac attribute conditions department location birthright eligibility simulate" },
      { id: "graph", label: "Access graph", icon: Network, path: "/insights/graph", keywords: "graph explorer paths who can access" },
      {
        id: "insights", label: "Insights", icon: ChartLine, path: "/insights/risk", also: ["/insights"], except: ["/insights/graph"], keywords: "risk dashboard kpi metrics",
        pages: [
          { path: "/insights/least-privilege", label: "Least privilege", keywords: "unused recommendations right size revoke" },
          { path: "/insights/sod", label: "SoD conflicts", keywords: "segregation separation of duties toxic combination" },
          { path: "/insights/aws", label: "AWS access", keywords: "aws effective permissions can who can policy change simulate diff pull request" },
          { path: "/insights/deployment-health", label: "Deployment health", keywords: "readiness checklist deployment gaps connection setup reconciliation orphans missed" },
        ],
      },
    ],
  },
  {
    label: "Settings",
    items: [
      { id: "connections", label: "Connections", icon: Plug, path: "/admin/connections", keywords: "connectors sync okta aws github snowflake workday active directory ldap entra readiness wizard" },
      { id: "admin", label: "Admin", icon: Settings, path: "/admin", except: ["/admin/connections"], keywords: "settings configuration audit jobs" },
    ],
  },
];

const under = (pathname: string, p: string) => pathname === p || pathname.startsWith(p + "/");

/** True when `pathname` belongs to the rail item. */
export function isActive(item: RailItem, pathname: string) {
  if (item.path === "/") return pathname === "/";
  if (item.except?.some((p) => under(pathname, p))) return false;
  return under(pathname, item.path) || !!item.also?.some((p) => under(pathname, p));
}

export function railItemFor(pathname: string) {
  for (const g of RAIL) for (const i of g.items) if (isActive(i, pathname)) return { group: g.label, item: i };
  if (under(pathname, "/directory/identities")) return { group: "Identity", item: RAIL[1].items[0] };
  return null;
}

export function allPages(): (NavPage & { section: string })[] {
  return RAIL.flatMap((g) => g.items.flatMap((i) => [{ path: i.path, label: i.label, keywords: i.keywords, preview: i.preview, section: g.label ?? "" }, ...(i.pages ?? []).map((p) => ({ ...p, section: i.label }))]));
}
