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

export const GroupTabs = () => (
  <LinkTabs
    label="Groups"
    tabs={[
      { to: "/directory/groups", label: "Groups" },
      { to: "/directory/entitlements", label: "All entitlements" },
    ]}
  />
);
