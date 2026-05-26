/**
 * Feed-freshness tier helper.
 *
 * Maps an ISO8601 timestamp (or LocalDate string, or null) onto a traffic-light tier
 * based on age relative to the current wall clock:
 *
 * | Age relative to now              | Tier    | UX cue                           |
 * |----------------------------------|---------|----------------------------------|
 * | < 7 days                         | green   | feed is fresh                    |
 * | >= 7 days and < 30 days          | amber   | feed is stale but still usable   |
 * | >= 30 days OR null OR unparseable| red     | feed is stale or absent          |
 *
 * Thresholds are exported as constants so other helpers can quote them in tooltips
 * without re-importing magic numbers.
 *
 * Why hard-coded thresholds? The backend `feeds/status` endpoint does not currently
 * expose freshness thresholds in its payload — the Castellum convention is that
 * 7/30 days are operator-tunable defaults documented in the security playbook. Until
 * those thresholds become configurable server-side, this module is the single point
 * of definition. If/when the backend exposes them, swap the constants for a fetch.
 */

export type FreshnessTier = 'green' | 'amber' | 'red';

export const FRESHNESS_GREEN_DAYS = 7;
export const FRESHNESS_AMBER_DAYS = 30;

const MS_PER_DAY = 1000 * 60 * 60 * 24;

/**
 * Pure function. Given an ISO8601 timestamp / LocalDate string / null, return the
 * traffic-light tier for feed freshness. Null and unparseable inputs collapse to red.
 */
export function freshnessTier(input: string | null | undefined): FreshnessTier {
  if (input === null || input === undefined || input === '') return 'red';
  const parsed = Date.parse(input);
  if (Number.isNaN(parsed)) return 'red';
  const ageDays = (Date.now() - parsed) / MS_PER_DAY;
  if (ageDays < FRESHNESS_GREEN_DAYS) return 'green';
  if (ageDays < FRESHNESS_AMBER_DAYS) return 'amber';
  return 'red';
}

/** Tailwind utility classes for the traffic-light dot color, indexed by tier. */
export const FRESHNESS_DOT_CLASSES: Record<FreshnessTier, string> = {
  green: 'bg-green-500',
  amber: 'bg-yellow-500',
  red: 'bg-red-500',
};

/** Tailwind utility classes for the badge background + text, indexed by tier. */
export const FRESHNESS_BADGE_CLASSES: Record<FreshnessTier, string> = {
  green: 'bg-green-100 text-green-800 border-green-300',
  amber: 'bg-yellow-100 text-yellow-800 border-yellow-300',
  red: 'bg-red-100 text-red-800 border-red-300',
};
