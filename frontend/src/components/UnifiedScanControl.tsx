import { useState, useEffect, useRef } from 'react';
import { api } from '../api/client';
import { runUnifiedScan } from '../lib/unifiedScan';
import type { UnifiedScanProgress, StageId, StageState, StageContext } from '../lib/unifiedScan';
import { makeNmapStage } from '../lib/nmapScanStage';
import { runOtSweep, DEFAULT_SWEEP_CONFIG } from '../lib/otSweep';
import { OT_PROTOCOLS } from '../lib/otProtocols';
import { ScanTriggerForm } from './ScanTriggerForm';
import { OtProbePanel } from './OtProbePanel';

interface Props {
  isAdmin?: boolean;
}

const STAGE_IDS: StageId[] = ['PING_SWEEP', 'SERVICE_DETECT', 'OS_FINGERPRINT', 'OT_ICS_SWEEP', 'DOCKER_DISCOVERY'];

/** Map a stage id to its runner kind (drives the per-stage status display). */
function kindFor(id: StageId): 'nmap' | 'ot' | 'docker' {
  if (id === 'OT_ICS_SWEEP') return 'ot';
  if (id === 'DOCKER_DISCOVERY') return 'docker';
  return 'nmap';
}

export function UnifiedScanControl({ isAdmin = true }: Props) {
  const [cidr, setCidr] = useState('192.168.1.0/24');
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<UnifiedScanProgress | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  // Pre-fill CIDR from the active network interface (mirror ScanTriggerForm).
  useEffect(() => {
    let cancelled = false;
    api.getActiveCidr().then((r) => {
      if (cancelled) return;
      if (r?.cidr) setCidr(r.cidr);
    }).catch(() => {});
    return () => { cancelled = true; };
  }, []);

  async function handleScan() {
    if (!isAdmin || running) return;

    const controller = new AbortController();
    abortRef.current = controller;
    setRunning(true);

    // Build the 4 stage defs.
    const nmapDeps = {
      triggerScan: api.triggerScan,
      getScanDetail: api.getScanDetail,
    };

    const otStageRunner = async (ctx: { cidr: string; signal?: AbortSignal; report: (p: { otCompleted?: number; otTotal?: number }) => void }) => {
      const page = await api.listDevices();
      const hosts = page.content.map((d) => d.ipAddress);

      const probeFn = (
        host: string,
        protocol: import('../api/types').OtProtocol,
        port: number,
        sig?: AbortSignal,
      ) => api.probeOtOnce(host, protocol, port, sig);

      await runOtSweep(
        hosts,
        OT_PROTOCOLS,
        probeFn,
        DEFAULT_SWEEP_CONFIG,
        (p) => {
          ctx.report({ otCompleted: p.completed, otTotal: p.total });
        },
        ctx.signal,
      );
    };

    // Stage ordering: PING_SWEEP must finish first. The backend scopes SERVICE_DETECT to the
    // alive hosts PING_SWEEP discovered, so SERVICE_DETECT (and the other port-enumerating /
    // device-list-driven stages) depend on PING_SWEEP and start only once it is COMPLETE.
    // This also prevents the four nmap/OT stages from hammering the host in parallel.
    const deps = {
      stages: [
        {
          id: 'PING_SWEEP' as StageId,
          kind: 'nmap' as const,
          run: makeNmapStage('PING_SWEEP', nmapDeps),
        },
        {
          id: 'SERVICE_DETECT' as StageId,
          kind: 'nmap' as const,
          run: makeNmapStage('SERVICE_DETECT', nmapDeps),
          dependsOn: ['PING_SWEEP' as StageId],
        },
        {
          id: 'OS_FINGERPRINT' as StageId,
          kind: 'nmap' as const,
          run: makeNmapStage('OS_FINGERPRINT', nmapDeps),
          dependsOn: ['PING_SWEEP' as StageId],
        },
        {
          id: 'OT_ICS_SWEEP' as StageId,
          kind: 'ot' as const,
          run: otStageRunner,
          dependsOn: ['PING_SWEEP' as StageId],
        },
        {
          // Docker discovery is host-local (ignores CIDR): it enumerates running containers
          // off the local daemon so the "Scan this network" button surfaces them too.
          id: 'DOCKER_DISCOVERY' as StageId,
          kind: 'docker' as const,
          run: async (ctx: StageContext) => { await api.discoverDocker(ctx.signal); },
        },
      ],
    };

    // Initialize progress with all stages pending so rows render immediately.
    const initialStages: StageState[] = STAGE_IDS.map((id) => ({
      id,
      kind: kindFor(id),
      status: 'pending',
    }));
    setProgress({
      stages: initialStages,
      completedStages: 0,
      totalStages: STAGE_IDS.length,
      overall: 0,
    });

    try {
      await runUnifiedScan(cidr, deps, (p) => setProgress(p), controller.signal);
    } catch {
      // Errors are captured per-stage; runUnifiedScan itself does not throw.
    } finally {
      abortRef.current = null;
      setRunning(false);
    }
  }

  function handleStop() {
    abortRef.current?.abort();
  }

  const overall = progress?.overall ?? 0;
  const stages = progress?.stages ?? STAGE_IDS.map((id) => ({
    id,
    kind: kindFor(id),
    status: 'pending' as const,
  }));

  return (
    <div>
      {/* Primary scan controls */}
      <div className="flex items-center gap-2 px-4 py-3 border-b border-gray-200 bg-white">
        <label className="text-sm font-medium">
          CIDR
          <input
            type="text"
            value={cidr}
            onChange={(e) => setCidr(e.target.value)}
            placeholder="e.g. 192.168.1.0/24"
            className="ml-2 px-2 py-1 border border-gray-300 rounded text-sm w-44"
          />
        </label>
        <button
          type="button"
          data-testid="unified-scan-btn"
          disabled={!isAdmin || running}
          onClick={handleScan}
          className="px-4 py-2 text-sm font-medium rounded bg-indigo-600 text-white hover:bg-indigo-700 disabled:bg-indigo-300 disabled:cursor-not-allowed"
        >
          {running ? 'Scanning…' : 'Scan this network'}
        </button>
        {running && (
          <button
            type="button"
            data-testid="unified-scan-stop-btn"
            onClick={handleStop}
            className="px-4 py-2 text-sm font-medium rounded bg-red-600 text-white hover:bg-red-700"
          >
            Stop
          </button>
        )}
      </div>

      {/* AC3 — progress bar + per-stage rows (always rendered once we have stage state) */}
      <div className="px-4 py-3 border-b border-gray-200">
        <progress
          data-testid="unified-progress"
          max={1}
          value={overall}
          className="w-full mb-3"
        />
        <div className="space-y-1">
          {stages.map((stage) => (
            <div
              key={stage.id}
              data-testid={`unified-stage-${stage.id}`}
              className="flex items-center gap-2 text-sm"
            >
              <span className="font-mono text-xs text-gray-700 w-36">{stage.id}</span>
              <span className="text-xs text-gray-500">
                {stage.status === 'pending' && 'pending'}
                {stage.status === 'running' && (
                  stage.kind === 'ot' && stage.otTotal != null
                    ? `${stage.otCompleted ?? 0}/${stage.otTotal}`
                    : stage.chunksTotal != null && stage.chunksTotal > 1
                      ? `${stage.chunksDone ?? 0}/${stage.chunksTotal} chunks`
                      : stage.scanStatus ?? 'running'
                )}
                {stage.status === 'complete' && 'complete'}
                {stage.status === 'failed' && `failed${stage.error ? `: ${stage.error}` : ''}`}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* AC4 — advanced per-type controls under a disclosure toggle */}
      <details data-testid="unified-advanced-toggle" className="px-4 py-3">
        <summary className="text-sm font-medium text-gray-700 cursor-pointer select-none">
          Advanced — per-type scan controls
        </summary>
        <div className="mt-3 space-y-4">
          <ScanTriggerForm />
          <OtProbePanel isAdmin={isAdmin} />
        </div>
      </details>
    </div>
  );
}
