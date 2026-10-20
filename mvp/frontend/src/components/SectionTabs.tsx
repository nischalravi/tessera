/** Tab strips for rail items that hold several pages (Insights, Access reviews, My access, Groups). */
import { PreviewBadge } from "./Badge";
import { LinkTabs } from "./Page";

export const InsightsTabs = () => (
  <LinkTabs
    label="Insights"
    tabs={[
      { to: "/insights/risk", label: "Risk overview" },
      { to: "/insights/least-privilege", label: "Least privilege" },
      { to: "/insights/sod", label: "SoD conflicts" },
      { to: "/insights/aws", label: "AWS access" },
      { to: "/insights/mfa", label: "MFA posture" },
      { to: "/insights/deployment-health", label: "Deployment health" },
    ]}
  />
);

export const GovernanceTabs = () => (
  <LinkTabs
    label="Governance"
    tabs={[
      { to: "/governance/reviews", label: "Access reviews" },
      { to: "/governance/lifecycle", label: "Lifecycle" },
      { to: "/governance/drift", label: "Drift" },
      { to: "/governance/guest-lifecycle", label: "Guest lifecycle" },
      { to: "/governance/terms", label: "Guest terms" },
      { to: "/governance/workflows", label: <>Workflows <PreviewBadge /></> },
    ]}
  />
);

export const MyAccessTabs = () => (
  <LinkTabs
    label="My access"
    tabs={[
      { to: "/access/mine", label: "My access" },
      { to: "/access/requests", label: "My requests" },
    ]}
  />
);

export const RoleTabs = () => (
  <LinkTabs
    label="Roles"
    tabs={[
      { to: "/directory/roles", label: "Roles", end: true },
      { to: "/directory/roles/mining", label: "Mining" },
    ]}
  />
);

export const GroupTabs = () => (
  <LinkTabs
    label="Groups"
    tabs={[
      { to: "/directory/groups", label: "Groups" },
      { to: "/directory/entitlements", label: "All entitlements" },
    ]}
  />
);
