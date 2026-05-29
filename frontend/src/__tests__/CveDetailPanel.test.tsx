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

const cveDetailWithVector: CveDetailDto = {
  ...cveDetail,
  cvssV31Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
  cvssV31Score: '7.8',
};

const affectedDevices: CveAffectedDevice[] = [
  { deviceId: 42, hostname: 'host-1', ipAddress: '10.0.0.42',
    matchedPort: 22, matchedService: 'openssh', matchedVersion: '8.2',
    matchedCpe: null, matchedRangeStart: null, matchedRangeEnd: null },
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

  it('affected-node link href navigates to /cves?deviceId=<id>', async () => {
    render(
      <MemoryRouter>
        <CveDetailPanel cveId="CVE-2020-15778" onClose={() => {}} />
      </MemoryRouter>
    );
    await waitFor(() => expect(screen.getByText('host-1')).toBeInTheDocument());
    const link = screen.getByRole('link', { name: /host-1/i });
    expect(link.getAttribute('href')).toBe('/cves?deviceId=42');
  });

  it('listAffectedDevices is called exactly once per open', async () => {
    vi.mocked(api.listAffectedDevices).mockClear();
    render(
      <MemoryRouter>
        <CveDetailPanel cveId="CVE-2020-15778" onClose={() => {}} />
      </MemoryRouter>
    );
    await waitFor(() => expect(screen.getByText('host-1')).toBeInTheDocument());
    expect(vi.mocked(api.listAffectedDevices)).toHaveBeenCalledTimes(1);
  });

  it('renders EPSS as percentage and composite score', async () => {
    // epssScore '0.42' renders as "42.0%" via (Number * 100).toFixed(1)
    // compositeScore '8.50' renders as "8.50" via Number().toFixed(2)
    render(
      <MemoryRouter>
        <CveDetailPanel cveId="CVE-2020-15778" onClose={() => {}} />
      </MemoryRouter>
    );
    await waitFor(() => expect(screen.getByText(/42\.0%/)).toBeInTheDocument());
    expect(screen.getByText(/8\.50/)).toBeInTheDocument();
  });

  it('parseReferences throw-path: invalid rawJson renders NVD fallback without throwing', async () => {
    vi.mocked(api.cveDetail).mockResolvedValue({ ...cveDetail, rawJson: 'corrupted{not-json' });
    render(
      <MemoryRouter>
        <CveDetailPanel cveId="CVE-2020-15778" onClose={() => {}} />
      </MemoryRouter>
    );
    await waitFor(() => {
      expect(screen.getByRole('link', { name: /nvd\.nist\.gov/i })).toBeInTheDocument();
    });
  });

  it('hostname null fallback: link label shows ipAddress when hostname is null', async () => {
    vi.mocked(api.listAffectedDevices).mockResolvedValue([
      { deviceId: 99, hostname: null, ipAddress: '192.168.1.99',
        matchedPort: 443, matchedService: 'nginx', matchedVersion: '1.18',
        matchedCpe: null, matchedRangeStart: null, matchedRangeEnd: null },
    ]);
    render(
      <MemoryRouter>
        <CveDetailPanel cveId="CVE-2020-15778" onClose={() => {}} />
      </MemoryRouter>
    );
    await waitFor(() => {
      expect(screen.getByRole('link', { name: '192.168.1.99' })).toBeInTheDocument();
    });
  });

  // --- NEW FAILING TESTS (red phase) ---

  it('listAffectedDevices rejects but cveDetail resolves: CVE body still renders and shows affected-devices error notice', async () => {
    vi.mocked(api.listAffectedDevices).mockRejectedValueOnce(new Error('500 Internal Server Error'));
    render(
      <MemoryRouter>
        <CveDetailPanel cveId="CVE-2020-15778" onClose={() => {}} />
      </MemoryRouter>
    );
    // CVE description must still appear despite the affected-devices failure
    await waitFor(() => {
      expect(screen.getByText('OpenSSH scp client vulnerability.')).toBeInTheDocument();
    });
    // An inline notice about the affected-devices failure must appear
    expect(screen.getByText(/couldn'?t load affected devices/i)).toBeInTheDocument();
  });

  it('cveDetail rejects: panel wrapper, header, close button, and visible error body are present', async () => {
    vi.mocked(api.cveDetail).mockRejectedValueOnce(new Error('404 Not Found'));
    render(
      <MemoryRouter>
        <CveDetailPanel cveId="CVE-2020-15778" onClose={() => {}} />
      </MemoryRouter>
    );
    // The aside wrapper must remain
    expect(screen.getByTestId('cve-detail-panel')).toBeInTheDocument();
    // Close button must remain
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /close cve panel/i })).toBeInTheDocument();
    });
    // A visible error body — NOT a header-only panel
    expect(screen.getByText(/couldn'?t load cve detail/i)).toBeInTheDocument();
  });

  it('sparse-but-resolved detail: no-enrichment copy and NVD fallback link both present', async () => {
    const sparseDetail: CveDetailDto = {
      cveId: 'CVE-2020-15778',
      published: null,
      lastModified: '2024-01-15T00:00:00Z',
      vulnStatus: null,
      description: null,
      cvssV31Score: null,
      cvssV31Vector: null,
      cvssV30Score: null,
      cvssV30Vector: null,
      cvssV2Score: null,
      cvssV2Vector: null,
      fetchedAt: null,
      rawJson: '{}',
      kev: false,
      epssScore: null,
      compositeScore: null,
    };
    vi.mocked(api.cveDetail).mockResolvedValueOnce(sparseDetail);
    render(
      <MemoryRouter>
        <CveDetailPanel cveId="CVE-2020-15778" onClose={() => {}} />
      </MemoryRouter>
    );
    // No-enrichment copy must appear
    await waitFor(() => {
      expect(screen.getByText(/no additional detail/i)).toBeInTheDocument();
    });
    // NVD fallback link must still appear
    expect(screen.getByRole('link', { name: /nvd\.nist\.gov/i })).toBeInTheDocument();
  });

  // --- F2: CVSS vector human-readable breakdown (red phase) ---

  it('renders the decoded CVSS breakdown alongside the preserved score chip when a vector is present', async () => {
    vi.mocked(api.cveDetail).mockResolvedValue(cveDetailWithVector);
    render(
      <MemoryRouter>
        <CveDetailPanel cveId="CVE-2020-15778" onClose={() => {}} />
      </MemoryRouter>
    );
    // Decoded breakdown is shown (AC2).
    await screen.findByText('Attack Vector');
    expect(screen.getByText('Attack Vector')).toBeInTheDocument();
    // PRESERVE: the existing CVSS score chip still renders (augment, not replace).
    expect(screen.getByText('7.8')).toBeInTheDocument();
  });

  // --- AC1: matched CPE product+version and version range display ---

  it('AC1: renders matched CPE and version range when evidence is present', async () => {
    vi.mocked(api.listAffectedDevices).mockResolvedValue([
      {
        deviceId: 42,
        hostname: 'pg-host',
        ipAddress: '10.0.0.42',
        matchedPort: 5432,
        matchedService: 'postgresql',
        matchedVersion: '16.0',
        matchedCpe: 'cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*',
        matchedRangeStart: '14.0 (incl.)',
        matchedRangeEnd: '17.0 (excl.)',
      },
    ]);
    render(
      <MemoryRouter>
        <CveDetailPanel cveId="CVE-2020-15778" onClose={() => {}} />
      </MemoryRouter>
    );
    await waitFor(() => {
      expect(screen.getByTestId('matched-cpe')).toBeInTheDocument();
    });
    expect(screen.getByTestId('matched-cpe')).toHaveTextContent('cpe:2.3:a:postgresql:postgresql:*');
    expect(screen.getByTestId('matched-range')).toHaveTextContent('14.0 (incl.)');
    expect(screen.getByTestId('matched-range')).toHaveTextContent('17.0 (excl.)');
  });

  it('AC1: does not render matched CPE/range elements when evidence is null', async () => {
    vi.mocked(api.listAffectedDevices).mockResolvedValue([
      {
        deviceId: 42,
        hostname: 'host-1',
        ipAddress: '10.0.0.42',
        matchedPort: 22,
        matchedService: 'openssh',
        matchedVersion: '8.2',
        matchedCpe: null,
        matchedRangeStart: null,
        matchedRangeEnd: null,
      },
    ]);
    render(
      <MemoryRouter>
        <CveDetailPanel cveId="CVE-2020-15778" onClose={() => {}} />
      </MemoryRouter>
    );
    await waitFor(() => {
      expect(screen.getByText('host-1')).toBeInTheDocument();
    });
    expect(screen.queryByTestId('matched-cpe')).not.toBeInTheDocument();
    expect(screen.queryByTestId('matched-range')).not.toBeInTheDocument();
  });

  it('does not crash and leaks no metric labels for the null-vector fixture, score chip preserved', async () => {
    vi.mocked(api.cveDetail).mockResolvedValue(cveDetail);
    render(
      <MemoryRouter>
        <CveDetailPanel cveId="CVE-2020-15778" onClose={() => {}} />
      </MemoryRouter>
    );
    // Panel body renders without crashing.
    await waitFor(() => {
      expect(screen.getByText('OpenSSH scp client vulnerability.')).toBeInTheDocument();
    });
    // PRESERVE: score chip still shows.
    expect(screen.getByText('7.8')).toBeInTheDocument();
    // AC3: no decoded metric label leaks when the vector is null.
    expect(screen.queryByText('Attack Vector')).toBeNull();
  });
});
