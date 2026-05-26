import { NavLink } from 'react-router-dom';

/**
 * Castellum primary navigation rail.
 *
 * Renders 7 top-level routes — Topology, Scans, Threats, CVEs, Attack Graph,
 * Audit, Settings — as {@link NavLink} entries so the router applies
 * active-state styling automatically. Fixed-width column with a dark slate
 * background; designed to sit to the left of the main content pane inside an
 * `App` shell that uses `flex h-screen`.
 */
const NAV_ITEMS: Array<{ to: string; label: string; end?: boolean }> = [
  { to: '/', label: 'Topology', end: true },
  { to: '/scans', label: 'Scans' },
  { to: '/threats', label: 'Threats' },
  { to: '/cves', label: 'CVEs' },
  { to: '/attack-graph', label: 'Attack Graph' },
  { to: '/audit', label: 'Audit' },
  { to: '/settings', label: 'Settings' },
];

export function Sidebar() {
  return (
    <nav
      aria-label="Primary"
      className="w-48 shrink-0 h-full bg-slate-900 text-slate-100 flex flex-col"
    >
      <div className="px-4 py-4 border-b border-slate-700">
        <span className="text-lg font-semibold tracking-tight">Castellum</span>
      </div>
      <ul className="flex flex-col py-2">
        {NAV_ITEMS.map(item => (
          <li key={item.to}>
            <NavLink
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                [
                  'block px-4 py-2 text-sm',
                  isActive
                    ? 'bg-slate-700 text-white border-l-2 border-blue-400'
                    : 'text-slate-300 hover:bg-slate-800 hover:text-white border-l-2 border-transparent',
                ].join(' ')
              }
            >
              {item.label}
            </NavLink>
          </li>
        ))}
      </ul>
    </nav>
  );
}
