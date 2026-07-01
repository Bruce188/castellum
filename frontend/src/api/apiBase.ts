/**
 * Base origin for REST calls. Empty string = same-origin (relative `/api/...`),
 * which is how the packaged app is served: the backend hosts both the SPA and the
 * API on one origin, so the browser calls back to whatever origin served the page.
 *
 * Override at BUILD time via VITE_API_BASE_URL only for a split-origin / CDN deploy
 * (set it to the API's public origin). Never hardcode a host:port default here —
 * Vite inlines this value at build time, so a literal `localhost` would be frozen
 * into the shipped bundle and every user's browser would call their own machine.
 */
export const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? '') as string;
