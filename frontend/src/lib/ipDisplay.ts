/**
 * Display helpers for device IP addresses.
 *
 * The backend (PlaceholderIp.java) persists MAC-only LLDP neighbors under a
 * synthetic placeholder IP of the form `mac:aa-bb-cc-dd-ee-ff` (literal `mac:`
 * prefix + dash-separated lowercase MAC). Placeholder strings must never be
 * rendered to the user as if they were IPs — they display as "no IP" instead.
 */

/**
 * Sentinel prefix marking a backend MAC-placeholder key. Must stay in sync with
 * `PlaceholderIp.PREFIX` in the backend
 * (backend/src/main/java/io/castellum/discovery/PlaceholderIp.java).
 */
export const MAC_PLACEHOLDER_PREFIX = 'mac:';

/** True when `ip` is a backend MAC-placeholder key (starts with `mac:`). */
export function isMacPlaceholder(ip: string): boolean {
  return ip.startsWith(MAC_PLACEHOLDER_PREFIX);
}

/** Render-safe IP: MAC placeholders become the exact label "no IP"; real IPs pass through. */
export function displayIp(ip: string): string {
  return isMacPlaceholder(ip) ? 'no IP' : ip;
}
