import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { TopologyLegend } from '../components/TopologyLegend';
import type { DiscoveryScope } from '../api/types';
// RiskTierKey is rendered inside TopologyLegend after Task 2 GREEN

const allTrue: Record<DiscoveryScope, boolean> = {
  HOME: true,
  DOCKER_BRIDGE: true,
  LINK_LOCAL: true,
  LOOPBACK: true,
  PUBLIC: true,
};

describe('<TopologyLegend />', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('topologyLegend_rendersFiveCheckboxesAllCheckedByDefault', () => {
    render(<TopologyLegend visibility={allTrue} onChange={vi.fn()} />);
    const boxes = screen.getAllByRole('checkbox');
    expect(boxes).toHaveLength(5);
    boxes.forEach(b => expect(b).toBeChecked());
  });

  it('topologyLegend_uncheckingFiresOnChangeWithMergedMap', () => {
    const onChange = vi.fn();
    render(<TopologyLegend visibility={allTrue} onChange={onChange} />);
    const loopback = screen.getByRole('checkbox', { name: /loopback/i });
    fireEvent.click(loopback);
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange).toHaveBeenCalledWith({
      HOME: true,
      DOCKER_BRIDGE: true,
      LINK_LOCAL: true,
      LOOPBACK: false,
      PUBLIC: true,
    });
  });

  it('topologyLegend_reflectsExternalVisibilityState', () => {
    const partial: Record<DiscoveryScope, boolean> = {
      HOME: true,
      DOCKER_BRIDGE: true,
      LINK_LOCAL: true,
      LOOPBACK: false,
      PUBLIC: true,
    };
    render(<TopologyLegend visibility={partial} onChange={vi.fn()} />);
    expect(screen.getByRole('checkbox', { name: /loopback/i })).not.toBeChecked();
    expect(screen.getByRole('checkbox', { name: /home/i })).toBeChecked();
  });

  it('topologyLegend_rendersRiskTierKeyWithFiveSwatches', () => {
    render(<TopologyLegend visibility={allTrue} onChange={vi.fn()} />);
    expect(screen.getByTestId('risk-tier-key')).toBeInTheDocument();
    const tiers = ['low', 'med', 'high', 'crit', 'unknown'] as const;
    for (const t of tiers) {
      expect(screen.getByTestId(`tier-swatch-${t}`)).toBeInTheDocument();
    }
    expect(screen.getByText(/^Critical$/)).toBeInTheDocument();
    expect(screen.getByText(/^Unknown$/)).toBeInTheDocument();
  });

  it('topologyLegend_tierKeyAddsNoCheckboxes_countStaysFive', () => {
    // Regression guard: adding the tier-key section must NOT add any <input> elements.
    // The 5 scope checkboxes remain the only interactive controls. This case may pass
    // before GREEN (no tier rows yet) — it is the guard that must stay green after GREEN.
    render(<TopologyLegend visibility={allTrue} onChange={vi.fn()} />);
    expect(screen.getAllByRole('checkbox')).toHaveLength(5);
  });

  it('topologyLegend_rootTestidStillResolves', () => {
    render(<TopologyLegend visibility={allTrue} onChange={vi.fn()} />);
    expect(screen.getByTestId('topology-legend')).toBeInTheDocument();
  });
});
