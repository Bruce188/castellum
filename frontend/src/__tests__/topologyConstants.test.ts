import { describe, it, expect } from 'vitest';
import { EDGE_STYLES } from '../components/topologyConstants';
import { scopeBorderColor } from '../lib/scopeColors';

describe('EDGE_STYLES tokens', () => {
  it('edgeStyles_matchTheFourDrawnStrokes', () => {
    expect(EDGE_STYLES.subnet).toEqual({ color: '#9ca3af', style: 'straight', width: 1, opacity: 0.5 });
    expect(EDGE_STYLES.gateway).toEqual({ color: '#9ca3af', style: 'solid', width: 2, opacity: 0.7 });
    expect(EDGE_STYLES.dockerBridge).toEqual({ color: scopeBorderColor.DOCKER_BRIDGE, style: 'dashed', width: 2, opacity: 0.8 });
    expect(EDGE_STYLES.attackPath).toEqual({ color: '#dc2626', style: 'dashed', width: 3, opacity: 1 });

    // anti-drift anchor: attack-path color is the exact value Task 4's legend imports
    expect(EDGE_STYLES.attackPath.color).toBe('#dc2626');
  });
});
