import type { DiscoveryScope } from '../api/types';

/**
 * Border-color map keyed by {@link DiscoveryScope}. Consumed by
 * {@link TopologyView}'s per-scope cytoscape style block to override the
 * default {@code node} border on non-HOME devices. HOME devices retain
 * the default `#1f2937` border (risk tier still drives the fill).
 */
export const scopeBorderColor: Record<DiscoveryScope, string> = {
  HOME: '#1f2937',
  DOCKER_BRIDGE: '#2563eb',
  LINK_LOCAL: '#64748b',
  LOOPBACK: '#cbd5e1',
  PUBLIC: '#ea580c',
};

/**
 * Chip-background-color map keyed by {@link DiscoveryScope}. Consumed by
 * {@link DeviceDetailPanel} and {@link TopologyLegend}. Same palette as
 * {@link scopeBorderColor} so the legend swatch, the topology border,
 * and the detail-panel chip stay visually aligned.
 */
export const scopeChipColor: Record<DiscoveryScope, string> = {
  HOME: '#1f2937',
  DOCKER_BRIDGE: '#2563eb',
  LINK_LOCAL: '#64748b',
  LOOPBACK: '#cbd5e1',
  PUBLIC: '#ea580c',
};
