import type { AdminSection, DelegationItem, OrgUnit, Workflow } from "./types";

export const ORGS: OrgUnit[] = [
  { id: "org-root", name: "Larkspur Labs", parent: null, department: null, owner: "Rosalind Haverford", costCenter: "CC-1000" },
  { id: "org-exec", name: "Executive", parent: "org-root", department: "Executive", owner: "Rosalind Haverford", costCenter: "CC-1010" },
  { id: "org-eng", name: "Engineering", parent: "org-root", department: "Engineering", owner: "Caspian Arkwright", costCenter: "CC-2000" },
  { id: "org-data", name: "Data", parent: "org-root", department: "Data", owner: "Sana Iyer", costCenter: "CC-2100" },
  { id: "org-sec", name: "Security", parent: "org-root", department: "Security", owner: "Thandiwe Mokoena", costCenter: "CC-2200" },
  { id: "org-fin", name: "Finance", parent: "org-root", department: "Finance", owner: "Beatrix Pemberton", costCenter: "CC-3000" },
  { id: "org-sales", name: "Sales", parent: "org-root", department: "Sales", owner: "Yara Castellanos", costCenter: "CC-4000" },
  { id: "org-support", name: "Support", parent: "org-root", department: "Support", owner: "Esme Thornbury", costCenter: "CC-4100" },
  { id: "org-people", name: "People", parent: "org-root", department: "People", owner: "Mireille Delacroix", costCenter: "CC-5000" },
];

export const WORKFLOWS: Workflow[] = [
  { id: "wf-low", name: "Low-risk request", trigger: "Access request, risk low", steps: ["Manager approves", "Auto-provision", "Verify by re-aggregation"], appliesTo: "Non-privileged groups and roles", enabled: true, sla: "2 business days" },
  { id: "wf-priv", name: "Privileged request", trigger: "Access request, privileged or high risk", steps: ["Manager approves", "Resource owner approves", "Security approves", "Time-bound grant (JIT)"], appliesTo: "Privileged roles, prod, PII", enabled: true, sla: "4 hours" },
  { id: "wf-sod", name: "SoD exception", trigger: "Request introduces an SoD conflict", steps: ["Risk owner accepts", "Select mitigating control", "Set expiry"], appliesTo: "SoD policies", enabled: true, sla: "3 business days" },
  { id: "wf-mover", name: "Mover micro-review", trigger: "HRIS mover event", steps: ["New manager reviews retained access", "Remove unreviewed after 14 days"], appliesTo: "All movers", enabled: false, sla: "14 days" },
  { id: "wf-owner", name: "Machine identity owner change", trigger: "Owner leaves or changes team", steps: ["Reassign owner", "Rotate secrets", "Owner certifies scopes"], appliesTo: "Service accounts and AI agents", enabled: true, sla: "5 business days" },
];

export const DELEGATIONS: DelegationItem[] = [
  { id: "dlg-1", from: "Kofi Mensah", to: "Ingrid Lindqvist", scope: "Access reviews for Backend team", until: "2026-10-24", reason: "Kofi is on leave for two weeks", status: "pending" },
  { id: "dlg-2", from: "Sana Iyer", to: "Thandiwe Mokoena", scope: "Approvals for snowflake:ACCOUNTADMIN", until: "2026-10-15", reason: "Quarter-end freeze cover", status: "pending" },
];

export const ADMIN_SECTIONS: AdminSection[] = [
  { id: "connections", title: "Connections & integrations", icon: "Plug", summary: "Source and target systems, sync status and connector health.", will: ["Add a connector (Okta, AWS, GitHub, Snowflake, Workday, SCIM, CSV)", "Schedule full and delta syncs", "Show per-connector record counts and last run"], keywords: ["connector", "okta", "aws", "github", "snowflake", "workday", "sync", "scim", "endpoint"], live: true },
  { id: "authentication", title: "Authentication", icon: "Fingerprint", summary: "Single sign-on for Tessera itself: SAML/OIDC identity provider, OAuth clients, session policy.", will: ["Configure SAML 2.0 or OIDC sign-in", "Map IdP groups to Tessera roles", "Set session lifetime and step-up for destructive actions"], keywords: ["sso", "saml", "oidc", "oauth", "idp", "login", "mfa"] },
  { id: "identity-rules", title: "Identity rules", icon: "UserCog", summary: "Correlation, authoritative sources and attribute mapping.", will: ["Choose the authoritative source per attribute", "Edit correlation rules (external ID, then email)", "Set dormancy thresholds per identity type"], keywords: ["correlation", "attribute", "mapping", "dormant", "authoritative", "birthright"] },
  { id: "notifications", title: "Notifications", icon: "Bell", summary: "The in-app inbox and email for requests, approvals, reviews and expiring access, with a setting per kind of event for each person.", will: ["Per-tenant SMTP relay and a chat workspace", "Edit approval, reminder and escalation templates", "Set reminder cadence and escalation SLAs"], keywords: ["email", "smtp", "slack", "teams", "template", "reminder", "bell", "inbox", "digest"], live: true },
  { id: "email-delivery", title: "Email delivery", icon: "Mail", summary: "What happened to each email Tessera sent: the relay's answer, the queue id and the full SMTP transaction of every attempt.", will: ["Bounce and delivery-status (DSN) processing", "Per-tenant SMTP relay settings", "Resend or suppress an address"], keywords: ["email", "smtp", "delivery", "bounce", "invite", "claim", "postmark", "queue", "transcript"], live: true },
  { id: "branding", title: "Branding & labels", icon: "Palette", summary: "Logo, product name in emails, and the words your organisation uses.", will: ["Upload a logo for emails and the sign-in page", "Rename objects (e.g. 'entitlement' to 'permission set')", "Set the default language"], keywords: ["logo", "label", "rename", "theme", "language"] },
  { id: "jobs", title: "Jobs", icon: "Clock", summary: "Scheduled and background work: connector syncs, JIT expiry sweeper, campaign generation.", will: ["See every job's last run, duration and result", "Run a job now or pause it", "Alert on failures"], keywords: ["schedule", "cron", "sync", "sweeper", "background", "task"], live: true },
  { id: "audit", title: "Audit log", icon: "ScrollText", summary: "Every API call and every change Tessera made or recorded, in a tamper-evident hash chain.", will: ["Filter by actor, target and date range on the server", "Per-event inclusion proofs for evidence packs", "Signed-in actors with their authentication context (after sign-in lands)"], keywords: ["audit", "evidence", "log", "history", "compliance"], live: true },
  { id: "certificates", title: "Certificates", icon: "FileBadge", summary: "Signing and encryption certificates for SAML and connector mTLS.", will: ["Upload or rotate certificates", "Warn 30 days before expiry"], keywords: ["certificate", "tls", "mtls", "saml", "signing", "expiry"] },
  { id: "config-transfer", title: "Export / import configuration", icon: "ArrowLeftRight", summary: "Move policies, roles, workflows and settings between environments.", will: ["Export configuration as a versioned bundle", "Diff and import a bundle into another tenant"], keywords: ["export", "import", "configuration", "migrate", "transport", "bundle"] },
  { id: "api-keys", title: "API keys", icon: "KeySquare", summary: "Keys for automation and CI that call the Tessera API.", will: ["Create scoped, expiring API keys", "Show last use and rotate or revoke keys"], keywords: ["api", "token", "key", "automation", "ci"] },
];
