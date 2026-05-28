import { render, screen, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import { CveDetailPanel } from '../components/CveDetailPanel';
import { api } from '../api/client';
import type { CveDetailDto, CveAffectedDevice } from '../api/types';

vi.mock('../api/client', () => ({
  api: {
    cveDetail: vi.fn(),
    listAffectedDevices: vi.fn(),
  },
}));

const cveDetail: CveDetailDto = {
  cveId: 'CVE-2020-15778',
  published: null,
  lastModified: '2024-01-15T00:00:00Z',
  vulnStatus: 'Analyzed',
  description: 'OpenSSH scp client vulnerability.',
  cvssV31Score: '7.8',
  cvssV31Vector: null,
  cvssV30Score: null,
  cvssV30Vector: null,
  cvssV2Score: null,
  cvssV2Vector: null,
  fetchedAt: null,
  rawJson: JSON.stringify({
    vulnerabilities: [{
      cve: {
        references: [
          { url: 'https://example.com/advisory', source: 'NVD' },
        ]
      }
    }]
  }),
  kev: true,
  epssScore: '0.42',
  compositeScore: '8.50',
};

const affectedDevices: CveAffectedDevice[] = [
  { deviceId: 42, hostname: 'host-1', ipAddress: '10.0.0.42',
    matchedPort: 22, matchedService: 'openssh', matchedVersion: '8.2' },
];

describe('<CveDetailPanel />', () => {
  beforeEach(() => {
    vi.mocked(api.cveDetail).mockResolvedValue(cveDetail);
    vi.mocked(api.listAffectedDevices).mockResolvedValue(affectedDevices);
  });

  it('renders nothing when cveId is null', () => {
    const { container } = render(
      <MemoryRouter><CveDetailPanel cveId={null} onClose={() => {}} /></MemoryRouter>
    );
    expect(container).toBeEmptyDOMElement();
  });

  it('calls cveDetail exactly once on open and shows description', async () => {
    render(
      <MemoryRouter>
        <CveDetailPanel cveId="CVE-2020-15778" onClose={() => {}} />
      </MemoryRouter>
    );
    await waitFor(() => {
      expect(screen.getByText('OpenSSH scp client vulnerability.')).toBeInTheDocument();
    });
    expect(vi.mocked(api.cveDetail)).toHaveBeenCalledTimes(1);
    expect(vi.mocked(api.cveDetail)).toHaveBeenCalledWith('CVE-2020-15778');
  });

  it('renders KEV badge and CVSS score', async () => {
    render(
      <MemoryRouter>
        <CveDetailPanel cveId="CVE-2020-15778" onClose={() => {}} />
      </MemoryRouter>
    );
    await waitFor(() => expect(screen.getByText('KEV')).toBeInTheDocument());
    expect(screen.getByText('7.8')).toBeInTheDocument();
  });

  it('renders affected device list from reverse endpoint', async () => {
    render(
      <MemoryRouter>
        <CveDetailPanel cveId="CVE-2020-15778" onClose={() => {}} />
      </MemoryRouter>
    );
    await waitFor(() => {
      expect(screen.getByText('host-1')).toBeInTheDocument();
    });
    expect(screen.getByText('10.0.0.42')).toBeInTheDocument();
    expect(vi.mocked(api.listAffectedDevices)).toHaveBeenCalledWith('CVE-2020-15778');
  });

  it('renders zero-affected message when list is empty', async () => {
    vi.mocked(api.listAffectedDevices).mockResolvedValue([]);
    render(
      <MemoryRouter>
        <CveDetailPanel cveId="CVE-2020-15778" onClose={() => {}} />
      </MemoryRouter>
    );
    await waitFor(() => {
      expect(screen.getByText(/no affected devices/i)).toBeInTheDocument();
    });
  });

  it('renders a parsed reference link from rawJson', async () => {
    render(
      <MemoryRouter>
        <CveDetailPanel cveId="CVE-2020-15778" onClose={() => {}} />
      </MemoryRouter>
    );
    await waitFor(() => {
      expect(screen.getByRole('link', { name: /example\.com\/advisory/i })).toBeInTheDocument();
    });
  });

  it('renders canonical NVD link when rawJson references are absent', async () => {
    vi.mocked(api.cveDetail).mockResolvedValue({ ...cveDetail, rawJson: '{}' });
    render(
      <MemoryRouter>
        <CveDetailPanel cveId="CVE-2020-15778" onClose={() => {}} />
      </MemoryRouter>
    );
    await waitFor(() => {
      expect(screen.getByRole('link', { name: /nvd\.nist\.gov/i })).toBeInTheDocument();
    });
  });

  it('calls onClose when close button is clicked', async () => {
    const handleClose = vi.fn();
    render(
      <MemoryRouter>
        <CveDetailPanel cveId="CVE-2020-15778" onClose={handleClose} />
      </MemoryRouter>
    );
    await waitFor(() => expect(screen.getByLabelText('Close CVE panel')).toBeInTheDocument());
    screen.getByLabelText('Close CVE panel').click();
    expect(handleClose).toHaveBeenCalledTimes(1);
  });
});
