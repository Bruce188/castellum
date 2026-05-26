import type { Device } from '../api/types';

export interface SubnetEdge {
  data: {
    id: string;
    source: string;
    target: string;
    kind: 'same_subnet';
  };
}

export function ipv4Slash24(ip: string): string | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  for (const p of parts) {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
  }
  return `${parts[0]}.${parts[1]}.${parts[2]}`;
}

export function buildSubnetEdges(devices: Device[]): SubnetEdge[] {
  if (devices.length === 0) return [];
  const groups = new Map<string, Device[]>();
  for (const d of devices) {
    const key = ipv4Slash24(d.ipAddress);
    if (key === null) continue;
    const list = groups.get(key) ?? [];
    list.push(d);
    groups.set(key, list);
  }
  const edges: SubnetEdge[] = [];
  for (const list of groups.values()) {
    if (list.length < 2) continue;
    list.sort((a, b) => a.id - b.id);
    const root = list[0];
    for (let i = 1; i < list.length; i++) {
      const peer = list[i];
      edges.push({
        data: {
          id: `e-${root.id}-${peer.id}`,
          source: String(root.id),
          target: String(peer.id),
          kind: 'same_subnet',
        },
      });
    }
  }
  return edges;
}
