import {
  AppWindow, BadgeCheck, BellRing, Bot, Building2, CalendarClock, ChartLine, ClipboardCheck, FileArchive, FileUp, House, Inbox, KeyRound, Layers, LifeBuoy, LockKeyhole, type LucideIcon, Network, Plug, Plus, Radio, RotateCw, Settings, ShieldAlert, ShieldCheck, ShieldHalf, SlidersHorizontal, Timer, UserCheck, UserPlus, Users, UsersRound,
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
  /** The permission the page needs; the rail hides the item from a session without it (the server still decides). */
  perm?: string;
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
      {
        id: "users", label: "Users", icon: Users, path: "/directory/people", also: ["/directory/identity-matches"], keywords: "people employees humans identities",
        pages: [{ path: "/directory/identity-matches", label: "Identity matches", keywords: "match review queue duplicate guest invitation existing person link merge second reviewer four eyes reverification" }],
      },
      { id: "workers", label: "Contractors & guests", icon: CalendarClock, path: "/directory/workers", keywords: "contractors partners vendors interns guests temporary accounts expiry end date sponsor expiring" },
      { id: "machine", label: "Machine identities & agents", icon: Bot, path: "/directory/machine", keywords: "nhi service accounts api keys ai agents bots secrets" },
      {
        id: "groups", label: "Groups", icon: UsersRound, path: "/directory/groups", also: ["/directory/entitlements"], keywords: "okta groups teams",
        pages: [{ path: "/directory/entitlements", label: "Entitlements", keywords: "groups permissions aws roles snowflake okta" }],
      },
      {
        id: "rotation", label: "Secret rotation", icon: RotateCw, path: "/rotation/secrets", also: ["/rotation"], keywords: "credentials vault rotate keys tokens api keys aws iam secrets manager hashicorp github deploy key vendor compromised breach",
        pages: [
          { path: "/rotation/jobs", label: "Rotation jobs", keywords: "rotate history failed retry verify old credential" },
          { path: "/rotation/policies", label: "Rotation policies & adapters", keywords: "max age grace period vault aws github adapter" },
          { path: "/rotation/vendor", label: "Vendor compromised", keywords: "breach bulk rotate integration incident" },
        ],
      },
      { id: "apps", label: "Applications", icon: AppWindow, path: "/directory/apps", keywords: "apps systems endpoints connectors resources" },
      { id: "ownership", label: "Ownership", icon: UserCheck, path: "/directory/ownership", keywords: "owners backup owner orphaned unowned accountable purpose" },
      {
        id: "accounts", label: "Accounts", icon: KeyRound, path: "/directory/accounts", also: ["/directory/matches"], keywords: "system accounts usernames",
        pages: [{ path: "/directory/matches", label: "Account matches", keywords: "correlation link merge unmerge duplicate orphan uncorrelated" }],
      },
      { id: "helpdesk", label: "Help desk", icon: LifeBuoy, path: "/helpdesk", keywords: "password reset mfa reset verification call-back push idv manager approval takeover" },
      { id: "roles", label: "Roles", icon: Layers, path: "/directory/roles", keywords: "business roles birthright drift" },
      { id: "orgs", label: "Organizations", icon: Building2, path: "/directory/orgs", keywords: "departments org units cost centers" },
    ],
  },
  {
    label: "Access",
    items: [
      { id: "request", label: "Request access", icon: Plus, path: "/access/request", also: ["/access/request/service-account"], keywords: "catalog cart ask new access role entitlement service account create change transfer owner",
        pages: [{ path: "/access/request/service-account", label: "Service account request", keywords: "create change transfer service account machine identity owner backup owner" }] },
      {
        id: "mine", label: "My access", icon: BadgeCheck, path: "/access/mine", also: ["/access/requests"], keywords: "what i have entitlements remove",
        pages: [{ path: "/access/requests", label: "My requests", keywords: "history drafts status submitted" }],
      },
      { id: "guests", label: "Guests I sponsor", icon: UserPlus, path: "/access/guests", perm: "guests.sponsor", keywords: "guest sponsor invite visitor contractor volunteer partner sponsorship bulk csv approve transfer" },
      { id: "jit", label: "Just-in-time", icon: Timer, path: "/access/jit", keywords: "jit elevation temporary privileged break glass" },
      {
        id: "reviews", label: "Access reviews", icon: ClipboardCheck, path: "/governance/reviews", also: ["/governance/lifecycle", "/governance/guest-lifecycle", "/governance/terms", "/governance/questionnaires", "/governance/workflows", "/governance/drift"], keywords: "certification campaigns attestation",
        pages: [
          { path: "/governance/lifecycle", label: "Lifecycle", keywords: "joiner mover leaver jml hris workday onboarding offboarding" },
          { path: "/governance/guest-lifecycle", label: "Guest lifecycle", keywords: "guest sponsorship expiry renewal reminder transfer sponsor leaver conversion deprovision grace retention purge step-up" },
          { path: "/governance/terms", label: "Guest terms", keywords: "guest terms of use acceptable use privacy notice acceptance consent version grace recovery" },
          { path: "/governance/questionnaires", label: "Questionnaires", keywords: "forms questions why do you need this justification risk privileged request review decision answers approvers version" },
          { path: "/governance/drift", label: "Drift", keywords: "intended observed rogue orphan stale missing reconciliation remediation" },
          { path: "/governance/workflows", label: "Workflows", keywords: "approval routing escalation" },
          { path: "/governance/review-types", label: "Review types", keywords: "campaign configuration application owner entitlement owner role owner organization owner service account user manager reviewer fallback incomplete escalate revoke keep" },
        ],
      },
    ],
  },
  {
    label: "Protection",
    items: [
      { id: "alerts", label: "Alerts", icon: BellRing, path: "/alerts", keywords: "alerting notifications incidents detections break glass sign-in failures webhook slack teams email" },
      { id: "oauthapps", label: "OAuth apps", icon: AppWindow, path: "/security/oauth-apps", keywords: "third-party oauth apps grants scopes consent connected apps vendor breach revoke salesloft drift gainsight token theft saas risk" },
      { id: "policies", label: "Policies & SoD", icon: ShieldCheck, path: "/governance/policies", keywords: "policy as code yaml simulation what-if violations" },
      { id: "agentauth", label: "Agent authorization", icon: LockKeyhole, path: "/agents/authorization", also: ["/agent-authorization"], keywords: "mcp oauth tokens agents delegation act token exchange consent clients resource servers decisions kill switch" },
      { id: "mitigations", label: "Mitigating controls", icon: ShieldHalf, path: "/governance/mitigations", keywords: "sod mitigation control accept risk expiring approve evidence separation of duties" },
      { id: "abac", label: "Attribute policies", icon: SlidersHorizontal, path: "/governance/attributes", keywords: "abac attribute conditions department location birthright eligibility simulate" },
      { id: "graph", label: "Access graph", icon: Network, path: "/insights/graph", keywords: "graph explorer paths who can access as of date point in time" },
      { id: "evidence", label: "Evidence packs", icon: FileArchive, path: "/governance/evidence", keywords: "audit evidence soc 2 sox itgc iso 27001 pci dss compliance export manifest auditor" },
      {
        id: "insights", label: "Insights", icon: ChartLine, path: "/insights/risk", also: ["/insights"], except: ["/insights/graph"], keywords: "risk dashboard kpi metrics",
        pages: [
          { path: "/insights/least-privilege", label: "Least privilege", keywords: "unused recommendations right size revoke" },
          { path: "/insights/sod", label: "SoD conflicts", keywords: "segregation separation of duties toxic combination" },
          { path: "/insights/aws", label: "AWS access", keywords: "aws effective permissions can who can policy change simulate diff pull request" },
          { path: "/insights/mfa", label: "MFA posture", keywords: "mfa multi-factor passkey fido2 webauthn phishing-resistant authentication methods okta entra sso bypass local password coverage" },
          { path: "/insights/deployment-health", label: "Deployment health", keywords: "readiness checklist deployment gaps connection setup reconciliation orphans missed" },
        ],
      },
    ],
  },
  {
    label: "Settings",
    items: [
      { id: "connections", label: "Connections", icon: Plug, path: "/admin/connections", keywords: "connectors sync okta aws github snowflake workday active directory ldap entra readiness wizard" },
      { id: "conditional-access", label: "Conditional access", icon: ShieldAlert, path: "/admin/conditional-access", keywords: "network location ip range device posture compliant managed step-up deny report-only policy sign-in trusted proxy" },
      { id: "flat-files", label: "Flat-file apps", icon: FileUp, path: "/admin/flat-files", keywords: "csv import upload disconnected applications no connector manual tasks column mapping sftp" },
      { id: "signals", label: "Shared Signals", icon: Radio, path: "/admin/shared-signals", keywords: "ssf caep risc transmitter okta revoke session propagate push poll set events" },
      {
        id: "admin", label: "Admin", icon: Settings, path: "/admin", except: ["/admin/connections", "/admin/shared-signals", "/admin/flat-files", "/admin/conditional-access"], keywords: "settings configuration audit jobs",
        pages: [{ path: "/admin/guests", label: "Guests and external identities", keywords: "guest settings matching lifecycle terms sponsor codes populations recovery cases sponsor policy" },
          { path: "/admin/retention", label: "Retention", keywords: "log retention audit events campaigns requests job runs outbox keep online days minimum floor archive two admins" },
          { path: "/admin/deletion-guard", label: "Deletion guard", keywords: "deletion threshold window safety net mass delete hold excess limit count percent groups folders members accounts identities loader connector mistake two admins" },
          { path: "/admin/held-deletions", label: "Held deletions", keywords: "held deletions approve release discard partial threshold second admin expire alert" },
          { path: "/admin/archive", label: "Archive", keywords: "archive segments sealed verify export restore read-only retention audit hash chain" },
          { path: "/admin/event-sinks", label: "Group event sinks", keywords: "streaming sqs sns rabbitmq kafka cloudevents queue topic dead letter outbox" },
          { path: "/admin/step-up", label: "Step-up per action", keywords: "step-up assurance phishing-resistant fresh sign-in sensitive actions floor max age acr multi-factor" },
          { path: "/admin/sod-page", label: "SoD page", keywords: "sod conflicts columns filters risk function entitlement ruleset mitigating control business process reviewers" },
          { path: "/account/preferences", label: "My preferences", keywords: "time zone date format locale landing page language my account" },
          { path: "/admin/request-settings", label: "Request settings", keywords: "access request justification duration maximum default attachments history visibility request for others manager" }],
      },
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

/** The rail without the entries the session lacks the permission for; empty groups drop out. */
export function visibleRail(can: (permission: string) => boolean): RailGroup[] {
  return RAIL.map((g) => ({ ...g, items: g.items.filter((i) => !i.perm || can(i.perm)) })).filter((g) => g.items.length > 0);
}

export function railItemFor(pathname: string) {
  for (const g of RAIL) for (const i of g.items) if (isActive(i, pathname)) return { group: g.label, item: i };
  if (under(pathname, "/directory/identities")) return { group: "Identity", item: RAIL[1].items[0] };
  return null;
}

export function allPages(): (NavPage & { section: string })[] {
  return RAIL.flatMap((g) => g.items.flatMap((i) => [{ path: i.path, label: i.label, keywords: i.keywords, preview: i.preview, section: g.label ?? "" }, ...(i.pages ?? []).map((p) => ({ ...p, section: i.label }))]));
}
