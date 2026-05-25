/**
 * Settings page — placeholder. Integration configuration (STIX export targets,
 * MISP push credentials, scan-policy defaults) is delivered by later features.
 */
export function SettingsPage() {
  return (
    <div className="h-full overflow-auto p-6">
      <h1 className="text-xl font-semibold text-gray-800 mb-2">Settings</h1>
      <p className="text-sm text-gray-600 max-w-prose">
        Integration configuration is coming in a later feature. For now, environment
        variables on the backend drive feed sync intervals and scanner defaults.
      </p>
    </div>
  );
}
