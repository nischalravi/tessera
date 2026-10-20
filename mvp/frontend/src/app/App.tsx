import { ComponentType, Suspense, lazy } from "react";
import { Navigate, Route, Routes, useLocation, useParams } from "react-router-dom";
import { ConfirmProvider } from "../components/Dialog";
import { PageSkeleton } from "../components/Feedback";
import { ToastProvider } from "../components/Toast";
import { SessionProvider, useSession } from "./auth";
import { PaletteProvider } from "./CommandPalette";
import { PersonaProvider } from "./persona";
import { Shell } from "./Shell";
import { ThemeProvider } from "./theme";

/**
 * Every route is its own chunk, so the first load is just the shell and the page you land on.
 * `named` adapts modules that export several pages by name.
 */
const named = <M extends Record<string, unknown>, K extends keyof M>(load: () => Promise<M>, key: K) =>
  lazy(async () => ({ default: (await load())[key] as ComponentType }));

const access = () => import("../features/access");
const directory = () => import("../features/directory/Lists");
const objects = () => import("../features/directory/ObjectPages");
const admin = () => import("../features/admin/Admin");
const connections = () => import("../features/admin/connections");
const conditionalAccess = () => import("../features/admin/access");

const Home = named(() => import("../features/home/Home"), "Home");
const Inbox = named(() => import("../features/inbox/Inbox"), "Inbox");
const Notifications = named(() => import("../features/notifications/Notifications"), "Notifications");
const RequestAccess = named(access, "RequestAccess");
const MyAccess = named(access, "MyAccess");
const Requests = named(access, "Requests");
const JIT = named(access, "JIT");
const Guests = named(access, "Guests");
const DirectoryLayout = named(directory, "DirectoryLayout");
const People = named(directory, "People");
const Machine = named(directory, "Machine");
const Accounts = named(directory, "Accounts");
const Matches = named(() => import("../features/directory/Matches"), "Matches");
const roles = () => import("../features/roles/Roles");
const Roles = named(roles, "Roles");
const Workers = named(() => import("../features/lifecycle/Workers"), "Workers");
const Entitlements = named(directory, "Entitlements");
const Apps = named(directory, "Apps");
const Orgs = named(directory, "Orgs");
const Groups = named(directory, "Groups");
const Ownership = named(() => import("../features/directory/Ownership"), "Ownership");
const IdentityPage = named(() => import("../features/directory/IdentityPage"), "IdentityPage");
const RolePage = named(roles, "RolePage");
const EntitlementPage = named(objects, "EntitlementPage");
const AppPage = named(objects, "AppPage");
const OrgPage = named(objects, "OrgPage");
const AwsAccess = named(() => import("../features/insights/AwsAccess"), "AwsAccess");
const HelpDesk = named(() => import("../features/helpdesk/HelpDesk"), "HelpDesk");
const RiskOverview = named(() => import("../features/insights/RiskOverview"), "RiskOverview");
// cytoscape is the heaviest dependency; it only loads with the graph
const GraphExplorer = lazy(() => import("../features/insights/GraphExplorer"));
const AgentAuthorization = named(() => import("../features/agents/AgentAuthorization"), "AgentAuthorization");
const LeastPrivilege = named(() => import("../features/insights/LeastPrivilege"), "LeastPrivilege");
const SodConflicts = named(() => import("../features/insights/SodConflicts"), "SodConflicts");
const DeploymentHealth = named(() => import("../features/insights/DeploymentHealth"), "DeploymentHealth");
const Alerts = named(() => import("../features/alerts/Alerts"), "Alerts");
const Policies = named(() => import("../features/governance/Policies"), "Policies");
const Mitigations = named(() => import("../features/governance/Mitigations"), "Mitigations");
const AttributePolicies = named(() => import("../features/governance/AttributePolicies"), "AttributePolicies");
const Reviews = named(() => import("../features/governance/Reviews"), "Reviews");
const Lifecycle = named(() => import("../features/governance/Lifecycle"), "Lifecycle");
const Drift = named(() => import("../features/governance/Drift"), "Drift");
const Workflows = named(() => import("../features/governance/Workflows"), "Workflows");
const EvidencePacks = named(() => import("../features/governance/EvidencePacks"), "EvidencePacks");
const Admin = named(admin, "Admin");
const FlatFiles = named(() => import("../features/admin/FlatFiles"), "FlatFiles");
const ConnectionsList = named(connections, "ConnectionsList");
const NewConnection = named(connections, "NewConnection");
const ConnectionDetail = named(connections, "ConnectionDetail");
const ValidationResults = named(connections, "ValidationResults");
const ReconReport = named(connections, "ReconReport");
const AgentsList = named(connections, "AgentsList");
const ConditionalAccess = named(conditionalAccess, "ConditionalAccess");
const AdminSectionPage = named(admin, "AdminSectionPage");
const SharedSignals = named(() => import("../features/admin/SharedSignals"), "SharedSignals");
const MySessions = named(() => import("../features/account/MySessions"), "MySessions");
const DeviceApprove = lazy(() => import("../pages/DeviceApprove"));
const AdminUsers = named(() => import("../features/admin/Users"), "Users");
const IdpConnections = named(() => import("../features/admin/IdpConnections"), "IdpConnections");
const ChangeRequests = named(() => import("../features/admin/ChangeRequests"), "ChangeRequests");
const ApiClients = named(() => import("../features/admin/ApiClients"), "ApiClients");
const PlatformHealth = named(() => import("../features/admin/PlatformHealth"), "PlatformHealth");
const ChangeBanner = named(() => import("../features/admin/ChangeBanner"), "ChangeBanner");
const BreakGlass = named(() => import("../features/admin/BreakGlass"), "BreakGlass");
const BreakGlassNotice = named(() => import("../features/admin/BreakGlass"), "BreakGlassNotice");

/**
 * The persistent banner of pending and cooling-off admin changes and unexplained break-glass sign-ins
 * (design §15.2, §15.4), for admins only; a break-glass session also sees what it may do and its time left.
 */
function AdminBanner() {
  const { can, session } = useSession();
  return can("admin.read") ? (
    <Suspense fallback={null}>
      {session.active_roles.includes("break_glass") && <BreakGlassNotice />}
      <ChangeBanner />
    </Suspense>
  ) : null;
}

/** Redirect an old route to its new home, keeping the query string (e.g. /graph?identity=5). */
function Moved({ to }: { to: string }) {
  const { search } = useLocation();
  const params = useParams();
  const path = to.replace(/:(\w+)/g, (_, k) => params[k] ?? "");
  return <Navigate to={path + search} replace />;
}

// the guest's claim page: public, outside the admin shell and its sign-in
const ClaimPage = lazy(() => import("../public/claim/ClaimPage"));

export default function App() {
  const { pathname } = useLocation();
  if (pathname === "/claim") {
    return (
      <ThemeProvider>
        <Suspense fallback={<PageSkeleton />}>
          <ClaimPage />
        </Suspense>
      </ThemeProvider>
    );
  }
  return (
    <ThemeProvider>
      <ToastProvider>
        <ConfirmProvider>
          <SessionProvider>
          <PersonaProvider>
            <PaletteProvider>
              <Shell>
                <AdminBanner />
                <Suspense fallback={<PageSkeleton />}>
                  <Routes>
                    <Route path="/" element={<Home />} />
                    {/* signed in already: the sign-in page (and its error) has nothing left to do */}
                    <Route path="/login" element={<Navigate to="/" replace />} />
                    <Route path="/sessions" element={<MySessions />} />
                    {/* where `tessera-cli login` sends you (design §9.3): type the code, decide */}
                    <Route path="/device" element={<DeviceApprove />} />
                    <Route path="/inbox" element={<Inbox />} />
                    <Route path="/notifications" element={<Notifications />} />

                    <Route path="/access" element={<Navigate to="/access/request" replace />} />
                    <Route path="/access/request" element={<RequestAccess />} />
                    <Route path="/access/mine" element={<MyAccess />} />
                    <Route path="/access/requests" element={<Requests />} />
                    <Route path="/access/jit" element={<JIT />} />
                    <Route path="/access/guests" element={<Guests />} />

                    <Route path="/directory" element={<DirectoryLayout />}>
                      <Route index element={<Navigate to="/directory/people" replace />} />
                      <Route path="people" element={<People />} />
                      <Route path="machine" element={<Machine />} />
                      <Route path="accounts" element={<Accounts />} />
                      <Route path="matches" element={<Matches />} />
                      <Route path="roles" element={<Roles />} />
                      <Route path="workers" element={<Workers />} />
                      <Route path="entitlements" element={<Entitlements />} />
                      <Route path="apps" element={<Apps />} />
                      <Route path="orgs" element={<Orgs />} />
                      <Route path="groups" element={<Groups />} />
                      <Route path="ownership" element={<Ownership />} />
                    </Route>
                    <Route path="/helpdesk" element={<HelpDesk />} />
                    <Route path="/directory/identities/:id" element={<IdentityPage />} />
                    <Route path="/directory/roles/:id" element={<RolePage />} />
                    <Route path="/directory/entitlements/:id" element={<EntitlementPage />} />
                    <Route path="/directory/apps/:system" element={<AppPage />} />
                    <Route path="/directory/orgs/:id" element={<OrgPage />} />

                    <Route path="/insights" element={<Navigate to="/insights/risk" replace />} />
                    <Route path="/insights/risk" element={<RiskOverview />} />
                    <Route path="/insights/graph" element={<GraphExplorer />} />
                    <Route path="/insights/least-privilege" element={<LeastPrivilege />} />
                    <Route path="/insights/sod" element={<SodConflicts />} />
                    <Route path="/insights/aws" element={<AwsAccess />} />
                    <Route path="/insights/deployment-health" element={<DeploymentHealth />} />
                    <Route path="/insights/deployment" element={<Moved to="/insights/deployment-health" />} />

                    <Route path="/agents/authorization" element={<AgentAuthorization />} />
                    <Route path="/agent-authorization" element={<Moved to="/agents/authorization" />} />

                    <Route path="/governance" element={<Navigate to="/governance/policies" replace />} />
                    <Route path="/alerts" element={<Alerts />} />
                    <Route path="/governance/policies" element={<Policies />} />
                    <Route path="/governance/mitigations" element={<Mitigations />} />
                    <Route path="/governance/attributes" element={<AttributePolicies />} />
                    <Route path="/governance/reviews" element={<Reviews />} />
                    <Route path="/governance/lifecycle" element={<Lifecycle />} />
                    <Route path="/governance/drift" element={<Drift />} />
                    <Route path="/governance/workflows" element={<Workflows />} />
                    <Route path="/governance/evidence" element={<EvidencePacks />} />

                    <Route path="/admin" element={<Admin />} />
                    <Route path="/admin/connections" element={<ConnectionsList />} />
                    <Route path="/admin/connections/new" element={<NewConnection />} />
                    <Route path="/admin/connections/agents" element={<AgentsList />} />
                    <Route path="/admin/connections/:id" element={<ConnectionDetail />} />
                    <Route path="/admin/connections/:id/validation/:run" element={<ValidationResults />} />
                    <Route path="/admin/connections/:id/reconciliation/:run" element={<ReconReport />} />
                    <Route path="/admin/shared-signals" element={<SharedSignals />} />
                    <Route path="/admin/flat-files" element={<FlatFiles />} />
                    <Route path="/admin/conditional-access" element={<ConditionalAccess />} />
                    <Route path="/admin/users" element={<AdminUsers />} />
                    <Route path="/admin/authentication" element={<IdpConnections />} />
                    <Route path="/admin/change-requests" element={<ChangeRequests />} />
                    <Route path="/admin/api-clients" element={<ApiClients />} />
                    <Route path="/admin/break-glass" element={<BreakGlass />} />
                    <Route path="/admin/platform-health" element={<PlatformHealth />} />
                    <Route path="/admin/:section" element={<AdminSectionPage />} />

                    {/* routes from the previous UI */}
                    <Route path="/identities" element={<Moved to="/directory/people" />} />
                    <Route path="/identities/:id" element={<Moved to="/directory/identities/:id" />} />
                    <Route path="/graph" element={<Moved to="/insights/graph" />} />
                    <Route path="/nhi" element={<Moved to="/directory/machine" />} />
                    <Route path="/least-privilege" element={<Moved to="/insights/least-privilege" />} />
                    <Route path="/policies" element={<Moved to="/governance/policies" />} />
                    <Route path="/reviews" element={<Moved to="/governance/reviews" />} />
                    <Route path="/jit" element={<Moved to="/access/jit" />} />
                    <Route path="/lifecycle" element={<Moved to="/governance/lifecycle" />} />
                    <Route path="/dashboard" element={<Moved to="/insights/risk" />} />
                    <Route path="/directory/users" element={<Moved to="/directory/people" />} />
                    <Route path="*" element={<Navigate to="/" replace />} />
                  </Routes>
                </Suspense>
              </Shell>
            </PaletteProvider>
          </PersonaProvider>
          </SessionProvider>
        </ConfirmProvider>
      </ToastProvider>
    </ThemeProvider>
  );
}
