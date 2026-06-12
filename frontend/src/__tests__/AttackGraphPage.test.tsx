import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { AttackGraphPage } from '../pages/AttackGraphPage';
import { api } from '../api/client';
import { EDGE_STYLES } from '../components/topologyConstants';

vi.mock('../api/client', () => ({
  api: {
    listDevices: vi.fn(),
    deviceRisk: vi.fn(),
    deviceRisksBatch: vi.fn(),
    shortestPath: vi.fn(),
  },
}));

// Skip Cytoscape — jsdom has no canvas. The page-level test only cares about
// controls + breakdown text + the highlightPath prop forwarded into the view.
vi.mock('../components/TopologyView', () => ({
  TopologyView: ({ highlightPath }: { highlightPath?: { nodeIds: number[] } | null }) => (
    <div
      data-testid="topology-canvas"
      data-highlight-nodes={highlightPath?.nodeIds?.join(',') ?? ''}
    />
  ),
}));

const listDevices = vi.mocked(api.listDevices);
const deviceRisk = vi.mocked(api.deviceRisk);
const deviceRisksBatch = vi.mocked(api.deviceRisksBatch);
const shortestPath = vi.mocked(api.shortestPath);

const DEVICES_PAGE = {
  content: [
    { id: 1, ipAddress: '10.0.0.1', hostname: 'attacker-foothold', macAddress: null, firstSeen: null, lastSeen: null, criticality: 'HIGH' as const, discoveryScope: 'HOME' as const, lastSeenIface: null, discoverySource: null, serviceCount: 0, osName: null, osAccuracy: null, osCpe: null, publishesHostPort: false, deviceRole: 'UNKNOWN' as const, originHostIp: 'local', originHostName: null, networkName: null },
    { id: 2, ipAddress: '10.0.0.5', hostname: 'pivot-host', macAddress: null, firstSeen: null, lastSeen: null, criticality: 'MEDIUM' as const, discoveryScope: 'HOME' as const, lastSeenIface: null, discoverySource: null, serviceCount: 0, osName: null, osAccuracy: null, osCpe: null, publishesHostPort: false, deviceRole: 'UNKNOWN' as const, originHostIp: 'local', originHostName: null, networkName: null },
    { id: 3, ipAddress: '172.16.0.10', hostname: 'crown-jewels', macAddress: null, firstSeen: null, lastSeen: null, criticality: 'CRITICAL' as const, discoveryScope: 'HOME' as const, lastSeenIface: null, discoverySource: null, serviceCount: 0, osName: null, osAccuracy: null, osCpe: null, publishesHostPort: false, deviceRole: 'UNKNOWN' as const, originHostIp: 'local', originHostName: null, networkName: null },
  ],
  totalElements: 3, totalPages: 1, number: 0, size: 200,
};

beforeEach(() => {
  listDevices.mockReset();
  deviceRisk.mockReset();
  deviceRisksBatch.mockReset();
  shortestPath.mockReset();
  listDevices.mockResolvedValue(DEVICES_PAGE);
  deviceRisk.mockResolvedValue({ deviceId: 1, score: '5.0', topCveIds: [] });
  deviceRisksBatch.mockResolvedValue(
    new Map(DEVICES_PAGE.content.map(d => [d.id, { deviceId: d.id, score: '5.0', topCveIds: [] }]))
  );
});

describe('<AttackGraphPage />', () => {
  it('renders ADMIN-required notice for VIEWER and never lists devices', () => {
    render(<AttackGraphPage isAdmin={false} />);
    expect(screen.getByTestId('attack-graph-admin-required')).toBeInTheDocument();
    expect(listDevices).not.toHaveBeenCalled();
    expect(screen.queryByTestId('attack-graph-compute-btn')).not.toBeInTheDocument();
  });

  it('ADMIN picks 2 devices, clicks compute, sees highlighted topology + numbered step list with CVE', async () => {
    shortestPath.mockResolvedValueOnce({
      from: 1,
      to: 3,
      pathFound: true,
      totalHops: 2,
      cumulativeRisk: '7.50',
      hops: [
        {
          deviceId: 2, ipAddress: '10.0.0.5',
          edgeType: 'SAME_SUBNET',
          attackTechniqueId: null, attackTechniqueName: null,
          edgeRisk: '1.00', cumulativeRisk: '1.00',
          cveId: null,
        },
        {
          deviceId: 3, ipAddress: '172.16.0.10',
          edgeType: 'EXPLOITABLE_VULN',
          attackTechniqueId: 'T1190', attackTechniqueName: 'Exploit Public-Facing Application',
          edgeRisk: '6.50', cumulativeRisk: '7.50',
          cveId: 'CVE-2024-12345',
        },
      ],
    });

    render(<AttackGraphPage isAdmin={true} />);
    await waitFor(() => expect(listDevices).toHaveBeenCalled());

    // Pick FROM = device 1 via the dropdown
    fireEvent.focus(screen.getByTestId('attack-graph-from-input'));
    await waitFor(() => expect(screen.getByTestId('attack-graph-from-option-1')).toBeInTheDocument());
    fireEvent.mouseDown(screen.getByTestId('attack-graph-from-option-1'));

    // Pick TO = device 3
    fireEvent.focus(screen.getByTestId('attack-graph-to-input'));
    await waitFor(() => expect(screen.getByTestId('attack-graph-to-option-3')).toBeInTheDocument());
    fireEvent.mouseDown(screen.getByTestId('attack-graph-to-option-3'));

    fireEvent.click(screen.getByTestId('attack-graph-compute-btn'));

    await waitFor(() => expect(shortestPath).toHaveBeenCalledWith({ from: 1, to: 3 }));
    await waitFor(() => expect(screen.getByTestId('attack-graph-breakdown')).toBeInTheDocument());

    // AC1: step list rendered
    const step1 = screen.getByTestId('attack-graph-step-1');
    const step2 = screen.getByTestId('attack-graph-step-2');
    expect(step1.textContent).toContain('attacker-foothold');
    expect(step1.textContent).toContain('pivot-host');
    expect(step1.textContent).toContain('SAME_SUBNET');
    expect(step2.textContent).toContain('pivot-host');
    expect(step2.textContent).toContain('crown-jewels');
    expect(step2.textContent).toContain('EXPLOITABLE_VULN');

    // AC4: CVE + technique surfaced for the EXPLOITABLE_VULN step
    expect(step2.textContent).toContain('CVE-2024-12345');
    expect(step2.textContent).toContain('T1190');
    expect(step2.textContent).toContain('Exploit Public-Facing Application');

    // AC1 (overlay): highlight propagated to the mocked TopologyView
    const canvas = screen.getByTestId('topology-canvas');
    expect(canvas.getAttribute('data-highlight-nodes')).toBe('1,2,3');
  });

  it('renders friendly "no reachable path" message when pathFound=false (AC3)', async () => {
    shortestPath.mockResolvedValueOnce({
      from: 1, to: 3, pathFound: false, totalHops: 0,
      cumulativeRisk: null, hops: [],
    });

    render(<AttackGraphPage isAdmin={true} />);
    await waitFor(() => expect(listDevices).toHaveBeenCalled());

    fireEvent.focus(screen.getByTestId('attack-graph-from-input'));
    await waitFor(() => expect(screen.getByTestId('attack-graph-from-option-1')).toBeInTheDocument());
    fireEvent.mouseDown(screen.getByTestId('attack-graph-from-option-1'));
    fireEvent.focus(screen.getByTestId('attack-graph-to-input'));
    await waitFor(() => expect(screen.getByTestId('attack-graph-to-option-3')).toBeInTheDocument());
    fireEvent.mouseDown(screen.getByTestId('attack-graph-to-option-3'));

    fireEvent.click(screen.getByTestId('attack-graph-compute-btn'));

    await waitFor(() => expect(screen.getByTestId('attack-graph-no-path')).toBeInTheDocument());
    expect(screen.getByTestId('attack-graph-no-path').textContent).toMatch(/No reachable attack path/i);
    // No breakdown or highlight when no path
    expect(screen.queryByTestId('attack-graph-breakdown')).not.toBeInTheDocument();
    const canvas = screen.getByTestId('topology-canvas');
    expect(canvas.getAttribute('data-highlight-nodes')).toBe('');
  });

  it('compute button is disabled until both devices are picked and they differ', async () => {
    render(<AttackGraphPage isAdmin={true} />);
    await waitFor(() => expect(listDevices).toHaveBeenCalled());

    const btn = screen.getByTestId('attack-graph-compute-btn') as HTMLButtonElement;
    expect(btn.disabled).toBe(true);

    fireEvent.focus(screen.getByTestId('attack-graph-from-input'));
    await waitFor(() => expect(screen.getByTestId('attack-graph-from-option-1')).toBeInTheDocument());
    fireEvent.mouseDown(screen.getByTestId('attack-graph-from-option-1'));
    expect(btn.disabled).toBe(true); // still no "to"

    fireEvent.focus(screen.getByTestId('attack-graph-to-input'));
    await waitFor(() => expect(screen.getByTestId('attack-graph-to-option-1')).toBeInTheDocument());
    fireEvent.mouseDown(screen.getByTestId('attack-graph-to-option-1'));
    // Same device on both sides — still disabled, warning shown
    await waitFor(() => expect(screen.getByTestId('attack-graph-same-device')).toBeInTheDocument());
    expect(btn.disabled).toBe(true);
  });

  it('attackGraph_admin_rendersRiskTierKey', async () => {
    render(<AttackGraphPage isAdmin={true} />);
    await waitFor(() => expect(listDevices).toHaveBeenCalled());
    expect(screen.getByTestId('risk-tier-key')).toBeInTheDocument();
    const tiers = ['low', 'med', 'high', 'crit', 'unknown'] as const;
    for (const t of tiers) {
      expect(screen.getByTestId(`tier-swatch-${t}`)).toBeInTheDocument();
    }
  });

  it('attackGraph_admin_rendersEdgeKeyForDrawnStrokes', async () => {
    render(<AttackGraphPage isAdmin={true} />);
    await waitFor(() => expect(listDevices).toHaveBeenCalled());
    expect(screen.getByTestId('attack-graph-edge-key')).toBeInTheDocument();
    expect(screen.getByText(/Subnet link/i)).toBeInTheDocument();
    expect(screen.getByText(/Gateway hub/i)).toBeInTheDocument();
    expect(screen.getByText(/Docker bridge/i)).toBeInTheDocument();
    expect(screen.getByText(/Attack path/i)).toBeInTheDocument();
    const attackSwatch = screen.getByTestId('edge-swatch-attackPath');
    expect(attackSwatch).toHaveStyle({ backgroundColor: EDGE_STYLES.attackPath.color });
  });

  it('attackGraph_viewer_hidesLegend', () => {
    render(<AttackGraphPage isAdmin={false} />);
    expect(screen.getByTestId('attack-graph-admin-required')).toBeInTheDocument();
    expect(screen.queryByTestId('risk-tier-key')).toBeNull();
    expect(screen.queryByTestId('attack-graph-edge-key')).toBeNull();
  });

  it('surfaces API errors inline', async () => {
    shortestPath.mockRejectedValueOnce(new Error('500 Internal Server Error'));
    render(<AttackGraphPage isAdmin={true} />);
    await waitFor(() => expect(listDevices).toHaveBeenCalled());

    fireEvent.focus(screen.getByTestId('attack-graph-from-input'));
    await waitFor(() => expect(screen.getByTestId('attack-graph-from-option-1')).toBeInTheDocument());
    fireEvent.mouseDown(screen.getByTestId('attack-graph-from-option-1'));
    fireEvent.focus(screen.getByTestId('attack-graph-to-input'));
    await waitFor(() => expect(screen.getByTestId('attack-graph-to-option-3')).toBeInTheDocument());
    fireEvent.mouseDown(screen.getByTestId('attack-graph-to-option-3'));
    fireEvent.click(screen.getByTestId('attack-graph-compute-btn'));

    await waitFor(() => expect(screen.getByTestId('attack-graph-error')).toBeInTheDocument());
    expect(screen.getByTestId('attack-graph-error').textContent).toContain('500');
  });

  it('renders a specific degrade notice when the backend rejects with GRAPH_TOO_LARGE', async () => {
    // Shape matches the client contract for non-OK responses: the rejection
    // carries the HTTP status and the parsed JSON error body.
    shortestPath.mockRejectedValueOnce(Object.assign(new Error('503 Service Unavailable'), {
      status: 503,
      body: {
        error: 'GRAPH_TOO_LARGE',
        message: 'device count 6200 exceeds castellum.graph.max-devices=5000',
      },
    }));

    render(<AttackGraphPage isAdmin={true} />);
    await waitFor(() => expect(listDevices).toHaveBeenCalled());

    fireEvent.focus(screen.getByTestId('attack-graph-from-input'));
    await waitFor(() => expect(screen.getByTestId('attack-graph-from-option-1')).toBeInTheDocument());
    fireEvent.mouseDown(screen.getByTestId('attack-graph-from-option-1'));
    fireEvent.focus(screen.getByTestId('attack-graph-to-input'));
    await waitFor(() => expect(screen.getByTestId('attack-graph-to-option-3')).toBeInTheDocument());
    fireEvent.mouseDown(screen.getByTestId('attack-graph-to-option-3'));
    fireEvent.click(screen.getByTestId('attack-graph-compute-btn'));

    await waitFor(() => expect(screen.getByTestId('attack-graph-error')).toBeInTheDocument());
    const text = screen.getByTestId('attack-graph-error').textContent ?? '';
    // NOT the generic raw passthrough...
    expect(text).not.toBe('503 Service Unavailable');
    // ...but a specific explanation: the graph exceeds the device limit...
    expect(text).toMatch(/too large|exceed/i);
    expect(text).toMatch(/device/i);
    expect(text).toMatch(/limit|max/i);
    // ...with an actionable suggestion (narrow the fleet / raise the limit).
    expect(text).toMatch(/narrow|reduce|raise|increase|refine/i);
  });

  it('keeps generic error text for a 503 that does NOT carry the GRAPH_TOO_LARGE code', async () => {
    shortestPath.mockRejectedValueOnce(Object.assign(new Error('503 Service Unavailable'), {
      status: 503,
      body: { error: 'discovery_unavailable', message: 'collector offline' },
    }));

    render(<AttackGraphPage isAdmin={true} />);
    await waitFor(() => expect(listDevices).toHaveBeenCalled());

    fireEvent.focus(screen.getByTestId('attack-graph-from-input'));
    await waitFor(() => expect(screen.getByTestId('attack-graph-from-option-1')).toBeInTheDocument());
    fireEvent.mouseDown(screen.getByTestId('attack-graph-from-option-1'));
    fireEvent.focus(screen.getByTestId('attack-graph-to-input'));
    await waitFor(() => expect(screen.getByTestId('attack-graph-to-option-3')).toBeInTheDocument());
    fireEvent.mouseDown(screen.getByTestId('attack-graph-to-option-3'));
    fireEvent.click(screen.getByTestId('attack-graph-compute-btn'));

    await waitFor(() => expect(screen.getByTestId('attack-graph-error')).toBeInTheDocument());
    const text = screen.getByTestId('attack-graph-error').textContent ?? '';
    expect(text).toContain('503');
    // The degrade copy is reserved for GRAPH_TOO_LARGE.
    expect(text).not.toMatch(/too large|exceed/i);
  });

  it('appends the backend detail to the degrade copy when the 503 body carries a message', async () => {
    shortestPath.mockRejectedValueOnce(Object.assign(new Error('503 Service Unavailable'), {
      status: 503,
      body: {
        error: 'GRAPH_TOO_LARGE',
        message: 'device count 6200 exceeds castellum.graph.max-devices=5000',
      },
    }));

    render(<AttackGraphPage isAdmin={true} />);
    await waitFor(() => expect(listDevices).toHaveBeenCalled());

    fireEvent.focus(screen.getByTestId('attack-graph-from-input'));
    await waitFor(() => expect(screen.getByTestId('attack-graph-from-option-1')).toBeInTheDocument());
    fireEvent.mouseDown(screen.getByTestId('attack-graph-from-option-1'));
    fireEvent.focus(screen.getByTestId('attack-graph-to-input'));
    await waitFor(() => expect(screen.getByTestId('attack-graph-to-option-3')).toBeInTheDocument());
    fireEvent.mouseDown(screen.getByTestId('attack-graph-to-option-3'));
    fireEvent.click(screen.getByTestId('attack-graph-compute-btn'));

    await waitFor(() => expect(screen.getByTestId('attack-graph-error')).toBeInTheDocument());
    const text = screen.getByTestId('attack-graph-error').textContent ?? '';
    // The composed degrade copy is present...
    expect(text).toMatch(/too large/i);
    expect(text).toMatch(/narrow|raise/i);
    // ...AND the backend's actionable numbers ride along.
    expect(text).toContain('device count 6200 exceeds castellum.graph.max-devices=5000');
  });

  it('keeps the composed degrade copy unchanged when the 503 body has no message', async () => {
    shortestPath.mockRejectedValueOnce(Object.assign(new Error('503 Service Unavailable'), {
      status: 503,
      body: { error: 'GRAPH_TOO_LARGE' },
    }));

    render(<AttackGraphPage isAdmin={true} />);
    await waitFor(() => expect(listDevices).toHaveBeenCalled());

    fireEvent.focus(screen.getByTestId('attack-graph-from-input'));
    await waitFor(() => expect(screen.getByTestId('attack-graph-from-option-1')).toBeInTheDocument());
    fireEvent.mouseDown(screen.getByTestId('attack-graph-from-option-1'));
    fireEvent.focus(screen.getByTestId('attack-graph-to-input'));
    await waitFor(() => expect(screen.getByTestId('attack-graph-to-option-3')).toBeInTheDocument());
    fireEvent.mouseDown(screen.getByTestId('attack-graph-to-option-3'));
    fireEvent.click(screen.getByTestId('attack-graph-compute-btn'));

    await waitFor(() => expect(screen.getByTestId('attack-graph-error')).toBeInTheDocument());
    const text = screen.getByTestId('attack-graph-error').textContent ?? '';
    expect(text).toMatch(/too large/i);
    // No detail parenthetical when the backend supplied no message.
    expect(text).not.toContain('(');
  });

  it('renders the degrade copy when the device load itself rejects with GRAPH_TOO_LARGE', async () => {
    listDevices.mockRejectedValueOnce(Object.assign(new Error('503 Service Unavailable'), {
      status: 503,
      body: {
        error: 'GRAPH_TOO_LARGE',
        message: 'device count 6200 exceeds castellum.graph.max-devices=5000',
      },
    }));

    render(<AttackGraphPage isAdmin={true} />);

    await waitFor(() => expect(screen.getByTestId('attack-graph-error')).toBeInTheDocument());
    const text = screen.getByTestId('attack-graph-error').textContent ?? '';
    // The load path goes through the same translation as compute — never the
    // raw passthrough message.
    expect(text).not.toBe('503 Service Unavailable');
    expect(text).toMatch(/too large/i);
    expect(text).toContain('device count 6200');
  });
});
