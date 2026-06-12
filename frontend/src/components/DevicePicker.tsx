import { useMemo, useState, useId } from 'react';
import type { Device } from '../api/types';

interface Props {
  devices: Device[];
  value: number | null;
  onChange: (id: number | null) => void;
  placeholder?: string;
  /** Used to disambiguate test-ids when two pickers live on the same page. */
  testId?: string;
  label?: string;
}

/**
 * Max options rendered in the dropdown so an unfiltered fleet of thousands
 * does not blow up the DOM. When matches exceed it, an overflow footer tells
 * the operator how many are hidden.
 */
const OPTION_RENDER_CAP = 50;

/**
 * Autocomplete combo box that filters a device list by hostname OR IPv4 address.
 *
 * <p>Usage: pair with a parent component owning the device list and the
 * currently selected id. The picker maintains its own input string and
 * dropdown-visible state; it commits a selection upward via {@link Props#onChange}.
 *
 * <p>Filtering is case-insensitive on hostname and substring-match on IP. The
 * dropdown is capped at {@link OPTION_RENDER_CAP} entries; an overflow footer
 * shows how many matches are hidden.
 */
export function DevicePicker({ devices, value, onChange, placeholder, testId, label }: Props) {
  const reactId = useId();
  const idPrefix = testId ?? `device-picker-${reactId}`;
  const selected = useMemo(
    () => devices.find(d => d.id === value) ?? null,
    [devices, value]
  );
  const [query, setQuery] = useState<string>('');
  const [open, setOpen] = useState<boolean>(false);

  // Display the selected device's hostname/IP when no query is being typed,
  // so the field shows the current selection at rest.
  const displayValue = open
    ? query
    : selected
      ? selected.hostname
        ? `${selected.hostname} (${selected.ipAddress})`
        : selected.ipAddress
      : '';

  const lowerQuery = query.toLowerCase();
  const { matches, matchCount } = useMemo(() => {
    if (!open) return { matches: [] as Device[], matchCount: 0 };
    const filtered = query.length === 0
      ? devices
      : devices.filter(d =>
          (d.hostname?.toLowerCase().includes(lowerQuery) ?? false) ||
          d.ipAddress.toLowerCase().includes(lowerQuery)
        );
    return { matches: filtered.slice(0, OPTION_RENDER_CAP), matchCount: filtered.length };
  }, [devices, lowerQuery, open, query.length]);

  function commit(id: number | null) {
    onChange(id);
    setOpen(false);
    setQuery('');
  }

  return (
    <div className="relative w-full">
      {label && (
        <label className="block text-xs font-medium text-gray-700 mb-1" htmlFor={idPrefix}>
          {label}
        </label>
      )}
      <div className="flex items-center gap-1">
        <input
          id={idPrefix}
          data-testid={`${idPrefix}-input`}
          type="text"
          className="flex-1 px-3 py-2 border border-gray-300 rounded text-sm"
          placeholder={placeholder ?? 'Search by hostname or IP'}
          value={displayValue}
          onFocus={() => setOpen(true)}
          onBlur={() => {
            // Defer close so onClick on a row fires before we collapse.
            setTimeout(() => setOpen(false), 120);
          }}
          onChange={e => {
            setQuery(e.target.value);
            if (!open) setOpen(true);
          }}
        />
        {selected && (
          <button
            type="button"
            data-testid={`${idPrefix}-clear`}
            className="text-xs px-2 py-1 border border-gray-300 rounded hover:bg-gray-100"
            onMouseDown={e => {
              // Prevent the input's blur from racing the click handler.
              e.preventDefault();
            }}
            onClick={() => commit(null)}
          >
            Clear
          </button>
        )}
      </div>
      {open && matches.length > 0 && (
        <ul
          data-testid={`${idPrefix}-list`}
          className="absolute z-10 mt-1 w-full max-h-60 overflow-auto bg-white border border-gray-300 rounded shadow"
        >
          {matches.map(d => (
            <li key={d.id}>
              <button
                type="button"
                data-testid={`${idPrefix}-option-${d.id}`}
                className="w-full text-left px-3 py-1.5 text-sm hover:bg-gray-100"
                onMouseDown={e => {
                  // Mousedown fires before blur, so the input doesn't collapse the list
                  // before the click registers.
                  e.preventDefault();
                  commit(d.id);
                }}
              >
                <span className="font-mono">{d.ipAddress}</span>
                {d.hostname && <span className="text-gray-500"> — {d.hostname}</span>}
              </button>
            </li>
          ))}
          {matchCount > matches.length && (
            <li
              data-testid={`${idPrefix}-overflow`}
              className="sticky bottom-0 bg-white px-3 py-1.5 text-xs text-gray-500 border-t border-gray-100"
            >
              Showing {matches.length} of {matchCount} matches — refine your search to see the rest
            </li>
          )}
        </ul>
      )}
      {open && matches.length === 0 && query.length > 0 && (
        <div
          data-testid={`${idPrefix}-empty`}
          className="absolute z-10 mt-1 w-full bg-white border border-gray-300 rounded shadow px-3 py-2 text-xs text-gray-500"
        >
          No matches
        </div>
      )}
    </div>
  );
}
