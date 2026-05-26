import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { TopologyLegend } from '../components/TopologyLegend';
import type { DiscoveryScope } from '../api/types';

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
});
