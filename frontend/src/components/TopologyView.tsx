import { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';
// @ts-expect-error - cose-bilkent has no shipped types
import coseBilkent from 'cytoscape-cose-bilkent';
import type { Device, DeviceRiskDto } from '../api/types';
import { toRiskTier, tierColor } from '../lib/riskTier';
import { buildSubnetEdges } from '../lib/subnetEdges';

cytoscape.use(coseBilkent);

interface Props {
  devices: Device[];
  risksById: Map<number, DeviceRiskDto>;
  onNodeClick: (deviceId: number) => void;
  onBackgroundClick: () => void;
}

export function TopologyView({ devices, risksById, onNodeClick, onBackgroundClick }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const onNodeClickRef = useRef(onNodeClick);
  const onBgClickRef = useRef(onBackgroundClick);

  // Keep latest callbacks without re-initializing cytoscape on every render.
  useEffect(() => { onNodeClickRef.current = onNodeClick; }, [onNodeClick]);
  useEffect(() => { onBgClickRef.current = onBackgroundClick; }, [onBackgroundClick]);

  // Init effect — runs ONCE on mount; instance lives in cyRef and is reused for every prop update.
  useEffect(() => {
    if (!containerRef.current) return;

    const cy = cytoscape({
      container: containerRef.current,
      elements: [],
      style: [
        { selector: 'node', style: { label: 'data(label)', 'font-size': 12, 'text-valign': 'bottom' as const, 'text-halign': 'center' as const, width: 30, height: 30, 'border-width': 1, 'border-color': '#1f2937' } },
        { selector: 'node.risk-low',     style: { 'background-color': tierColor.low } },
        { selector: 'node.risk-med',     style: { 'background-color': tierColor.med } },
        { selector: 'node.risk-high',    style: { 'background-color': tierColor.high } },
        { selector: 'node.risk-crit',    style: { 'background-color': tierColor.crit } },
        { selector: 'node.risk-unknown', style: { 'background-color': tierColor.unknown } },
        { selector: 'edge', style: { 'line-color': '#9ca3af', 'curve-style': 'straight' as const, opacity: 0.5, width: 1 } },
      ],
    });

    cy.on('tap', 'node', evt => {
      const id = Number(evt.target.id());
      if (Number.isInteger(id)) onNodeClickRef.current(id);
    });
    cy.on('tap', evt => {
      if (evt.target === cy) onBgClickRef.current();
    });

    cyRef.current = cy;
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, []);

  // Sync effect — patches the existing cytoscape instance in place rather than tearing it down.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    const nodes = devices.map(d => {
      const risk = risksById.get(d.id);
      const score = risk ? Number(risk.score) : null;
      const tier = toRiskTier(score);
      return {
        data: {
          id: String(d.id),
          label: d.hostname ?? d.ipAddress,
          ip: d.ipAddress,
          riskTier: tier,
        },
        classes: `risk-${tier}`,
      };
    });

    const edges = buildSubnetEdges(devices);

    cy.elements().remove();
    cy.add([...nodes, ...edges]);
    cy.layout(({
      name: 'cose-bilkent',
      idealEdgeLength: 100,
      nodeRepulsion: 4500,
      animate: false,
      randomize: false,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    }) as any).run();
  }, [devices, risksById]);

  return (
    <div
      ref={containerRef}
      data-testid="topology-canvas"
      className="w-full h-full"
    />
  );
}
