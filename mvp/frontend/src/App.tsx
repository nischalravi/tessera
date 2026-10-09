import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Identities from "./pages/Identities";
import IdentityDetail from "./pages/IdentityDetail";
import GraphExplorer from "./pages/GraphExplorer";
import NHI from "./pages/NHI";
import LeastPrivilege from "./pages/LeastPrivilege";
import JIT from "./pages/JIT";
import Policies from "./pages/Policies";
import Reviews from "./pages/Reviews";
import Lifecycle from "./pages/Lifecycle";

const NAV: ([string, string, string] | string)[] = [
  "Overview",
  ["/", "◧", "Dashboard"],
  ["/identities", "◉", "Identities"],
  ["/graph", "⌬", "Graph explorer"],
  ["/nhi", "⚙", "NHI & AI agents"],
  "Govern",
  ["/least-privilege", "✂", "Least privilege"],
  ["/policies", "§", "Policies & violations"],
  ["/reviews", "✓", "Access reviews"],
  "Operate",
  ["/jit", "⏱", "Just-in-time access"],
  ["/lifecycle", "⇄", "Joiner / mover / leaver"],
];

export default function App() {
  return (
    <div className="app">
      <aside className="side">
        <div className="brand">
          <div className="logo"><i /><i /><i /><i /></div>
          <div>
            Tessera
            <small>Identity governance</small>
          </div>
        </div>
        <nav className="nav">
          {NAV.map((n) =>
            typeof n === "string" ? (
              <div key={n} className="sec">{n}</div>
            ) : (
              <NavLink key={n[0]} to={n[0]} end={n[0] === "/"}>
                <span className="ico">{n[1]}</span>
                {n[2]}
              </NavLink>
            ),
          )}
        </nav>
        <div className="foot">Demo tenant: Larkspur Labs (fictional)<br />Connectors: Workday · Okta · AWS · GitHub · Snowflake</div>
      </aside>
      <main className="main">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/identities" element={<Identities />} />
          <Route path="/identities/:id" element={<IdentityDetail />} />
          <Route path="/graph" element={<GraphExplorer />} />
          <Route path="/nhi" element={<NHI />} />
          <Route path="/least-privilege" element={<LeastPrivilege />} />
          <Route path="/policies" element={<Policies />} />
          <Route path="/reviews" element={<Reviews />} />
          <Route path="/jit" element={<JIT />} />
          <Route path="/lifecycle" element={<Lifecycle />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </main>
    </div>
  );
}
