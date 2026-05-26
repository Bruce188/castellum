import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ScanPolicyPanel } from '../components/ScanPolicyPanel';
import { api } from '../api/client';

vi.mock('../api/client', () => ({
  api: {
    listScanPolicies: vi.fn(),
    createScanPolicy: vi.fn(),
    disableScanPolicy: vi.fn(),
    enableScanPolicy: vi.fn(),
    deleteScanPolicy: vi.fn(),
  },
}));

const listScanPolicies = vi.mocked(api.listScanPolicies);
const createScanPolicy = vi.mocked(api.createScanPolicy);
const disableScanPolicy = vi.mocked(api.disableScanPolicy);
const deleteScanPolicy = vi.mocked(api.deleteScanPolicy);

beforeEach(() => {
  listScanPolicies.mockReset();
  createScanPolicy.mockReset();
  disableScanPolicy.mockReset();
  deleteScanPolicy.mockReset();
  vi.spyOn(window, 'confirm').mockReturnValue(true);
});

describe('<ScanPolicyPanel />', () => {
  it('VIEWER sees ADMIN-required notice and does not fetch policies', () => {
    render(<ScanPolicyPanel isAdmin={false} />);
    expect(screen.getByText(/ADMIN role required/i)).toBeInTheDocument();
    expect(listScanPolicies).not.toHaveBeenCalled();
  });

  it('ADMIN sees the policy table populated from listScanPolicies()', async () => {
    listScanPolicies.mockResolvedValueOnce({
      content: [
        {
          id: 1, name: 'nightly', cronExpression: '0 0 2 * * *',
          cidr: '10.0.0.0/24', scanType: 'PING_SWEEP', enabled: true,
          createdAt: '2026-05-26T00:00:00Z', lastTriggeredAt: null,
        },
      ],
      totalElements: 1,
      totalPages: 1,
      number: 0,
      size: 50,
    });

    render(<ScanPolicyPanel isAdmin={true} />);

    await waitFor(() => {
      expect(screen.getByTestId('policy-row-nightly')).toBeInTheDocument();
    });
  });

  it('submits the create-policy form and reloads', async () => {
    listScanPolicies
      .mockResolvedValueOnce({ content: [], totalElements: 0, totalPages: 1, number: 0, size: 50 })
      .mockResolvedValueOnce({
        content: [
          {
            id: 5, name: 'lab-policy', cronExpression: '0 0 * * * *',
            cidr: '192.168.1.0/24', scanType: 'PING_SWEEP', enabled: true,
            createdAt: '2026-05-26T00:00:00Z', lastTriggeredAt: null,
          },
        ],
        totalElements: 1, totalPages: 1, number: 0, size: 50,
      });
    createScanPolicy.mockResolvedValueOnce({
      id: 5, name: 'lab-policy', cronExpression: '0 0 * * * *',
      cidr: '192.168.1.0/24', scanType: 'PING_SWEEP', enabled: true,
      createdAt: '2026-05-26T00:00:00Z', lastTriggeredAt: null,
    });

    render(<ScanPolicyPanel isAdmin={true} />);
    await waitFor(() => expect(listScanPolicies).toHaveBeenCalledTimes(1));

    fireEvent.change(screen.getByTestId('policy-name-input'), { target: { value: 'lab-policy' } });
    fireEvent.click(screen.getByTestId('policy-create-btn'));

    await waitFor(() => {
      expect(createScanPolicy).toHaveBeenCalledWith({
        name: 'lab-policy',
        cronExpression: '0 0 * * * *',
        cidr: '192.168.1.0/24',
        scanType: 'PING_SWEEP',
        enabled: true,
      });
      expect(listScanPolicies).toHaveBeenCalledTimes(2);
    });
  });

  it('disable button invokes api.disableScanPolicy', async () => {
    listScanPolicies.mockResolvedValue({
      content: [
        {
          id: 7, name: 'to-disable', cronExpression: '0 0 * * * *',
          cidr: '10.0.0.0/24', scanType: 'PING_SWEEP', enabled: true,
          createdAt: '2026-05-26T00:00:00Z', lastTriggeredAt: null,
        },
      ],
      totalElements: 1, totalPages: 1, number: 0, size: 50,
    });
    disableScanPolicy.mockResolvedValueOnce({
      id: 7, name: 'to-disable', cronExpression: '0 0 * * * *',
      cidr: '10.0.0.0/24', scanType: 'PING_SWEEP', enabled: false,
      createdAt: '2026-05-26T00:00:00Z', lastTriggeredAt: null,
    });

    render(<ScanPolicyPanel isAdmin={true} />);
    await waitFor(() => expect(screen.getByTestId('policy-toggle-to-disable')).toBeInTheDocument());

    fireEvent.click(screen.getByTestId('policy-toggle-to-disable'));

    await waitFor(() => expect(disableScanPolicy).toHaveBeenCalledWith(7));
  });

  it('delete button invokes api.deleteScanPolicy after confirm', async () => {
    listScanPolicies.mockResolvedValue({
      content: [
        {
          id: 9, name: 'to-delete', cronExpression: '0 0 * * * *',
          cidr: '10.0.0.0/24', scanType: 'PING_SWEEP', enabled: true,
          createdAt: '2026-05-26T00:00:00Z', lastTriggeredAt: null,
        },
      ],
      totalElements: 1, totalPages: 1, number: 0, size: 50,
    });
    deleteScanPolicy.mockResolvedValueOnce(undefined);

    render(<ScanPolicyPanel isAdmin={true} />);
    await waitFor(() => expect(screen.getByTestId('policy-delete-to-delete')).toBeInTheDocument());

    fireEvent.click(screen.getByTestId('policy-delete-to-delete'));

    await waitFor(() => expect(deleteScanPolicy).toHaveBeenCalledWith(9));
  });
});
