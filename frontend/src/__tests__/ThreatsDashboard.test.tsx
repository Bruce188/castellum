import { describe, it, expect, beforeEach, beforeAll, afterAll, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { ThreatsDashboard } from '../components/ThreatsDashboard';
import { api } from '../api/client';

vi.mock('../api/client', () => ({
  api: {
    topRisk: vi.fn(),
    feedsStatus: vi.fn(),
  },
}));

const NOW = new Date('2026-05-25T12:00:00Z').getTime();

describe('<ThreatsDashboard />', () => {
  beforeAll(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.setSystemTime(NOW);
  });
  afterAll(() => {
    vi.useRealTimers();
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('shows loading state then top-10 table on success', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 1, hostname: 'host-1', ipAddress: '10.0.0.1', criticality: 'HIGH', score: '8.50', kevCount: 1 },
      { deviceId: 2, hostname: null, ipAddress: '10.0.0.2', criticality: 'MEDIUM', score: '6.30', kevCount: 0 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });

    render(<ThreatsDashboard />);
    await screen.findByText('host-1');
    expect(screen.getByText('8.50')).toBeInTheDocument();
    expect(screen.getByText('HIGH')).toBeInTheDocument();
    // Device with null hostname falls back to ipAddress
    expect(screen.getByText('10.0.0.2')).toBeInTheDocument();
    expect(screen.getByText('6.30')).toBeInTheDocument();
  });

  it('renders KEV-flagged total across the fleet', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 1, hostname: 'h1', ipAddress: '10.0.0.1', criticality: 'HIGH', score: '8.50', kevCount: 2 },
      { deviceId: 2, hostname: 'h2', ipAddress: '10.0.0.2', criticality: 'MEDIUM', score: '6.30', kevCount: 3 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: null, rowCount: 0 },
      kev: { lastIngestedAt: null, entryCount: 0 },
      nvd: { lastModified: null, rowCount: 0 },
    });

    render(<ThreatsDashboard />);
    await screen.findByText(/KEV-flagged CVEs/i);
    // 2 + 3 = 5
    const kevBlock = screen.getByText(/KEV-flagged CVEs/i).parentElement!;
    expect(kevBlock.textContent).toContain('5');
  });

  it('renders green freshness badge when feeds are fresh (<7d)', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });

    render(<ThreatsDashboard />);
    const badge = await screen.findByTestId('freshness-badge');
    expect(badge.className).toMatch(/green/);
  });

  it('renders amber freshness badge for 7-30 day-old EPSS', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-10', rowCount: 100 }, // 15 days old
      kev: { lastIngestedAt: '2026-05-10T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-10T00:00:00Z', rowCount: 42 },
    });

    render(<ThreatsDashboard />);
    const badge = await screen.findByTestId('freshness-badge');
    expect(badge.className).toMatch(/yellow|amber/);
  });

  it('renders red freshness badge when EPSS scoreDate is null', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: null, rowCount: 0 },
      kev: { lastIngestedAt: null, entryCount: 0 },
      nvd: { lastModified: null, rowCount: 0 },
    });

    render(<ThreatsDashboard />);
    const badge = await screen.findByTestId('freshness-badge');
    expect(badge.className).toMatch(/red/);
  });

  it('shows empty state when topRisk returns []', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });

    render(<ThreatsDashboard />);
    await waitFor(() => screen.getByText(/No devices ranked/i));
  });

  it('shows error message when topRisk fails', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('boom'));
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: null, rowCount: 0 },
      kev: { lastIngestedAt: null, entryCount: 0 },
      nvd: { lastModified: null, rowCount: 0 },
    });

    render(<ThreatsDashboard />);
    await waitFor(() => screen.getByText(/boom/));
  });
});
