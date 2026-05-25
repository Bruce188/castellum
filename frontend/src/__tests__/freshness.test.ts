import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { freshnessTier, FRESHNESS_GREEN_DAYS, FRESHNESS_AMBER_DAYS } from '../lib/freshness';

// Pin a deterministic "now" so the test does not become time-flaky.
const NOW = new Date('2026-05-25T12:00:00Z').getTime();

describe('freshnessTier()', () => {
  beforeAll(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });
  afterAll(() => {
    vi.useRealTimers();
  });

  it('returns "red" for null input (no data ever seen)', () => {
    expect(freshnessTier(null)).toBe('red');
  });

  it('returns "green" for a date less than 7 days ago', () => {
    const threeDaysAgo = new Date(NOW - 3 * 24 * 60 * 60 * 1000).toISOString();
    expect(freshnessTier(threeDaysAgo)).toBe('green');
  });

  it('returns "amber" for a date between 7 and 30 days ago', () => {
    const fourteenDaysAgo = new Date(NOW - 14 * 24 * 60 * 60 * 1000).toISOString();
    expect(freshnessTier(fourteenDaysAgo)).toBe('amber');
  });

  it('returns "red" for a date 30+ days ago', () => {
    const sixtyDaysAgo = new Date(NOW - 60 * 24 * 60 * 60 * 1000).toISOString();
    expect(freshnessTier(sixtyDaysAgo)).toBe('red');
  });

  it('accepts a LocalDate-only string (no time component)', () => {
    // EPSS feed reports scoreDate as YYYY-MM-DD; ensure parser tolerates it.
    expect(freshnessTier('2026-05-24')).toBe('green');
  });

  it('returns "red" for an invalid date string', () => {
    expect(freshnessTier('not-a-date')).toBe('red');
  });

  it('exposes thresholds as exported constants', () => {
    expect(FRESHNESS_GREEN_DAYS).toBe(7);
    expect(FRESHNESS_AMBER_DAYS).toBe(30);
  });
});
