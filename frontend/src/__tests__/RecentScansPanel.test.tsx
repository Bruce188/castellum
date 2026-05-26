import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useParams } from 'react-router-dom';
import { RecentScansPanel } from '../components/RecentScansPanel';
import { api } from '../api/client';

vi.mock('../api/client', () => ({
  api: {
    listScans: vi.fn(),
  },
}));

const listScans = vi.mocked(api.listScans);

function ScanDetailSentinel() {
  const { id } = useParams<{ id: string }>();
  return <div>detail-{id}</div>;
}

describe('<RecentScansPanel /> navigation', () => {
  beforeEach(() => {
    listScans.mockReset();
  });

  it('clicking a scan row navigates to /scans/:id', async () => {
    listScans.mockResolvedValue({
      content: [
        {
          id: 42, cidr: '10.0.0.0/24', scanType: 'PING_SWEEP',
          status: 'COMPLETE', requestedAt: new Date().toISOString(),
          completedAt: null, retryCount: 0,
        },
      ],
      totalElements: 1, totalPages: 1, number: 0, size: 10,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any);

    render(
      <MemoryRouter initialEntries={['/']}>
        <Routes>
          <Route path="/" element={<RecentScansPanel latestSubmittedId={null} />} />
          <Route path="/scans/:id" element={<ScanDetailSentinel />} />
        </Routes>
      </MemoryRouter>
    );

    const row = await screen.findByTestId('scan-row-42');
    fireEvent.click(row);
    await waitFor(() => {
      expect(screen.getByText('detail-42')).toBeInTheDocument();
    });
  });
});
