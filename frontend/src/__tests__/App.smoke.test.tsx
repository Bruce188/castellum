import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock Cytoscape before importing App so jsdom canvas errors are suppressed.
vi.mock('../components/TopologyView', () => ({
  TopologyView: () => <div data-testid="topology-canvas" />,
}));

import App from '../App';

describe('<App /> smoke', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/api/devices')) {
        return new Response(JSON.stringify({ content: [], totalElements: 0, totalPages: 0, number: 0, size: 200 }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
    }));
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
});
