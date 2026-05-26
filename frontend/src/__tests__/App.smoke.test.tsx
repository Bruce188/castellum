import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock Cytoscape before importing App so jsdom canvas errors are suppressed.
vi.mock('../components/TopologyView', () => ({
  TopologyView: () => <div data-testid="topology-canvas" />,
}));

// Mock EmptyCorpusBanner so App.smoke tests don't need feeds/status network call.
vi.mock('../components/EmptyCorpusBanner', () => ({
  EmptyCorpusBanner: () => <div data-testid="empty-corpus-banner" />,
}));

// Mock AuditLogPanel so App.smoke tests don't need audit API network call.
vi.mock('../components/AuditLogPanel', () => ({
  default: () => <div data-testid="audit-log-panel" />,
}));

// Mock ThreatsDashboard so App.smoke tests don't need /api/risk/top + /api/risk/feeds/status.
vi.mock('../components/ThreatsDashboard', () => ({
  ThreatsDashboard: () => <div data-testid="threats-dashboard" />,
}));

import App from '../App';

// A minimal JWT with payload { "roles": ["ADMIN"] } — not a real signed token;
// the frontend only decodes it for UI role-gating (signature not verified client-side).
const FAKE_ADMIN_JWT = 'header.eyJyb2xlcyI6WyJBRE1JTiJdfQ.sig';

describe('<App /> smoke', () => {
  beforeEach(() => {
    // Set a fake auth token so App renders the authenticated shell (not <Login />).
    localStorage.setItem('castellum.jwt', FAKE_ADMIN_JWT);
    localStorage.setItem('castellum.user', 'admin');

    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      const emptyPage = JSON.stringify({ content: [], totalElements: 0, totalPages: 0, number: 0, size: 200 });
      if (url.includes('/api/devices') || url.includes('/api/scans')) {
        return new Response(emptyPage, {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
    }));
  });

  afterEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it('renders the topology canvas and a submit button', () => {
    render(<App />);
    expect(screen.getByTestId('topology-canvas')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /scan/i })).toBeInTheDocument();
  });

  it('empty-state notice text is selectable (pointer-events-auto)', async () => {
    render(<App />);
    const notice = await screen.findByText(/No devices yet/);
    expect(notice).toBeInTheDocument();
    // The <p> tag itself must carry pointer-events-auto so users can copy the snippet.
    expect(notice).toHaveClass('pointer-events-auto');
  });

  it('EmptyCorpusBanner placeholder is rendered inside the authenticated shell', () => {
    // The mock renders a placeholder; this test asserts it is mounted inside App
    // when auth token is present. Heavy logic lives in EmptyCorpusBanner.test.tsx.
    render(<App />);
    expect(screen.getByTestId('empty-corpus-banner')).toBeInTheDocument();
  });
});
