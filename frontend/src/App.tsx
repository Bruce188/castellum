import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { ForcePasswordRotation } from './components/ForcePasswordRotation';
import { Login } from './components/Login';
import { Sidebar } from './components/Sidebar';
import { TopologyPage } from './pages/TopologyPage';
import { ScansPage } from './pages/ScansPage';
import { ThreatsPage } from './pages/ThreatsPage';
import { CvesPage } from './pages/CvesPage';
import { AttackGraphPage } from './pages/AttackGraphPage';
import { AuditPage } from './pages/AuditPage';
import { SettingsPage } from './pages/SettingsPage';
import { clearAuth, useAuth } from './hooks/useAuth';
import './index.css';

/**
 * Authenticated shell — sidebar + topbar + routed main pane.
 *
 * Exported separately from the default {@link App} so tests can mount the shell
 * inside a `MemoryRouter` without spinning up a `BrowserRouter` that owns the
 * jsdom `window.history` instance.
 */
export function AppShell() {
  const auth = useAuth();
  const isAdmin = auth.roles?.includes('ADMIN') ?? false;
  return (
    <div className="flex h-screen">
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0">
        <div className="flex items-center justify-end gap-3 px-4 py-2 border-b border-gray-200 bg-white text-sm text-gray-600">
          <span>{auth.username}</span>
          <button
            type="button"
            onClick={() => clearAuth()}
            className="px-2 py-1 border border-gray-300 rounded hover:bg-gray-100"
          >
            Sign out
          </button>
        </div>
        <div className="flex-1 min-h-0">
          <Routes>
            <Route path="/" element={<TopologyPage />} />
            <Route path="/scans" element={<ScansPage />} />
            <Route path="/threats" element={<ThreatsPage />} />
            <Route path="/cves" element={<CvesPage />} />
            <Route path="/attack-graph" element={<AttackGraphPage isAdmin={isAdmin} />} />
            <Route path="/audit" element={<AuditPage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Routes>
        </div>
      </div>
    </div>
  );
}

/**
 * Root component. Short-circuits to {@link Login} when no JWT is present;
 * otherwise mounts the routed {@link AppShell} inside a {@link BrowserRouter}.
 */
function App() {
  const auth = useAuth();
  if (!auth.token) return <Login />;
  // First-login flow: render the rotation overlay in place of the routed app.
  // No BrowserRouter / Routes are mounted, so no navigation can match.
  if (auth.mustChangePassword) return <ForcePasswordRotation />;
  return (
    <BrowserRouter>
      <AppShell />
    </BrowserRouter>
  );
}

export default App;
