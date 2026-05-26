import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { WhyScorePanel } from '../components/WhyScorePanel';
import type { DeviceRiskDto } from '../api/types';

const riskWithComponents: DeviceRiskDto = {
  deviceId: 1,
  score: '7.50',
  topCveIds: ['CVE-2020-15778'],
  components: {
    cvssMax: '7.80',
    epssMax: '0.4500',
    kevPresent: true,
    criticalityWeight: '0.50',
  },
};

describe('<WhyScorePanel />', () => {
  it('renders nothing when risk is null', () => {
    const { container } = render(<WhyScorePanel risk={null} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('renders nothing when components are absent', () => {
    const { container } = render(
      <WhyScorePanel risk={{ deviceId: 1, score: '0.00', topCveIds: [] }} />
    );
    expect(container).toBeEmptyDOMElement();
  });

  it('displays CVSS_max, EPSS_max, KEV_present, criticality_weight, and composite score', () => {
    render(<WhyScorePanel risk={riskWithComponents} />);
    expect(screen.getByText('7.80')).toBeInTheDocument();
    expect(screen.getByText('0.4500')).toBeInTheDocument();
    expect(screen.getByText('yes')).toBeInTheDocument();
    expect(screen.getByText('0.50')).toBeInTheDocument();
    // Composite headline score
    expect(screen.getByText('7.50')).toBeInTheDocument();
  });

  it('renders "no" when kevPresent is false', () => {
    render(
      <WhyScorePanel
        risk={{
          ...riskWithComponents,
          components: { ...riskWithComponents.components!, kevPresent: false },
        }}
      />
    );
    expect(screen.getByText('no')).toBeInTheDocument();
  });

  it('shows formula description', () => {
    render(<WhyScorePanel risk={riskWithComponents} />);
    expect(screen.getByText(/Why this score/i)).toBeInTheDocument();
  });
});
