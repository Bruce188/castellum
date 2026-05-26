import { useState } from 'react';
import { ScanTriggerForm } from '../components/ScanTriggerForm';
import { RecentScansPanel } from '../components/RecentScansPanel';

/**
 * Scans page — pairs the scan-trigger form with the live-polling recent scans panel.
 */
export function ScansPage() {
  const [lastScanId, setLastScanId] = useState<number | undefined>(undefined);
  return (
    <div className="flex flex-col h-full overflow-auto">
      <ScanTriggerForm onScanSubmitted={setLastScanId} />
      <RecentScansPanel latestSubmittedId={lastScanId} />
    </div>
  );
}
