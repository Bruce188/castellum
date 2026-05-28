import { useState } from 'react';
import { api } from '../api/client';

interface Props {
  isAdmin: boolean;
}

/**
 * "Download STIX bundle" — calls POST /api/threat-intel/export and triggers
 * a browser download via Blob URL + an anchor with the {@code download}
 * attribute set to a stable filename. VIEWER sees a notice and does not
 * touch the backend.
 */
export function StixExportPanel({ isAdmin }: Props) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastFilename, setLastFilename] = useState<string | null>(null);
  const [preview, setPreview] = useState<string | null>(null);

  if (!isAdmin) {
    return (
      <section
        aria-label="STIX bundle export"
        className="mt-6 border border-gray-200 rounded p-4 bg-gray-50"
      >
        <h2 className="text-base font-semibold text-gray-800 mb-2">STIX bundle export</h2>
        <p className="text-sm text-gray-600">ADMIN role required.</p>
      </section>
    );
  }

  async function handlePreview() {
    setBusy(true);
    setError(null);
    try {
      const text = await api.exportStixBundleText();
      setPreview(JSON.stringify(JSON.parse(text), null, 2));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'preview failed');
    } finally {
      setBusy(false);
    }
  }

  async function handleDownload() {
    setBusy(true);
    setError(null);
    try {
      const blob = await api.exportStixBundle();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const filename = `castellum-stix-bundle.json`;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      // Revoke after the click to free the object URL.
      setTimeout(() => URL.revokeObjectURL(url), 0);
      setLastFilename(filename);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'download failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <section
      aria-label="STIX bundle export"
      className="mt-6 border border-gray-200 rounded p-4 bg-white"
    >
      <h2 className="text-base font-semibold text-gray-800 mb-3">STIX bundle export</h2>
      <p className="text-sm text-gray-600 mb-3">
        Downloads the current device-and-vulnerability inventory as a STIX 2.1
        JSON bundle. The bundle is generated on-demand from the live database.
      </p>
      <div className="flex gap-2">
        <button
          type="button"
          data-testid="stix-download-btn"
          onClick={handleDownload}
          disabled={busy}
          className="px-3 py-1 bg-blue-600 text-white rounded text-sm hover:bg-blue-700 disabled:opacity-50"
        >
          {busy ? 'Building bundle…' : 'Download STIX bundle'}
        </button>
        <button
          type="button"
          data-testid="stix-preview-btn"
          onClick={handlePreview}
          disabled={busy}
          className="px-3 py-1 bg-gray-600 text-white rounded text-sm hover:bg-gray-700 disabled:opacity-50"
        >
          {busy ? 'Loading…' : 'Preview bundle'}
        </button>
      </div>
      {lastFilename && !error && (
        <p className="mt-2 text-sm text-green-700" role="status">
          Downloaded: <code>{lastFilename}</code>
        </p>
      )}
      {error && (
        <p className="mt-2 text-sm text-red-600" role="alert">
          {error}
        </p>
      )}
      {preview && !error && (
        <pre
          data-testid="stix-preview"
          className="mt-3 p-3 bg-gray-100 rounded text-xs overflow-auto max-h-96 border border-gray-300"
        >
          {preview}
        </pre>
      )}
    </section>
  );
}
