import { describe, it, expect } from 'vitest';
import { parseCvssV31Vector, severityBand } from '../lib/cvss';

// Pure, time-independent parser — no fake timers (unlike freshness.test.ts).

describe('parseCvssV31Vector()', () => {
  it('decodes the worked-example vector into 8 ordered labeled metric/value pairs', () => {
    const decoded = parseCvssV31Vector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H');
    expect(decoded).not.toBeNull();
    expect(decoded!.metrics).toHaveLength(8);
    expect(decoded!.metrics.map((m) => m.key)).toEqual([
      'AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A',
    ]);
    expect(decoded!.metrics[0]).toEqual({
      key: 'AV', label: 'Attack Vector', value: 'N', valueLabel: 'Network',
    });
    // Availability (last metric) decodes to High.
    expect(decoded!.metrics[7].valueLabel).toBe('High');
    // Spot-checks on the documented mappings.
    expect(decoded!.metrics.find((m) => m.key === 'PR')!.valueLabel).toBe('None');
    expect(decoded!.metrics.find((m) => m.key === 'S')!.valueLabel).toBe('Unchanged');
  });

  it('decodes the all-impact-High vector with Confidentiality/Integrity/Availability all High', () => {
    const decoded = parseCvssV31Vector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(decoded).not.toBeNull();
    expect(decoded!.metrics.find((m) => m.key === 'C')!.valueLabel).toBe('High');
    expect(decoded!.metrics.find((m) => m.key === 'I')!.valueLabel).toBe('High');
    expect(decoded!.metrics.find((m) => m.key === 'A')!.valueLabel).toBe('High');
  });

  it('decodes Scope=Changed for the all-impact-High Scope:Changed variant', () => {
    const decoded = parseCvssV31Vector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
    expect(decoded).not.toBeNull();
    expect(decoded!.metrics.find((m) => m.key === 'S')!.valueLabel).toBe('Changed');
    expect(decoded!.metrics.find((m) => m.key === 'C')!.valueLabel).toBe('High');
    expect(decoded!.metrics.find((m) => m.key === 'I')!.valueLabel).toBe('High');
    expect(decoded!.metrics.find((m) => m.key === 'A')!.valueLabel).toBe('High');
  });

  it('returns null for a garbage string', () => {
    expect(parseCvssV31Vector('garbage')).toBeNull();
  });

  it('returns null for a not-a-vector string', () => {
    expect(parseCvssV31Vector('not-a-vector')).toBeNull();
  });

  it('returns null when a metric value is not in its allowed set (AV:Z)', () => {
    expect(parseCvssV31Vector('CVSS:3.1/AV:Z')).toBeNull();
  });

  it('returns null when the CVSS:3.1 prefix is absent', () => {
    expect(parseCvssV31Vector('AV:N/AC:L')).toBeNull();
  });

  it('returns null for null input', () => {
    expect(parseCvssV31Vector(null)).toBeNull();
  });

  it('returns null for undefined input', () => {
    expect(parseCvssV31Vector(undefined)).toBeNull();
  });

  it('returns null for an empty string', () => {
    expect(parseCvssV31Vector('')).toBeNull();
  });
});

describe('severityBand()', () => {
  it('maps 0.0 to None', () => {
    expect(severityBand('0.0')).toBe('None');
  });

  it('maps 3.9 to Low', () => {
    expect(severityBand('3.9')).toBe('Low');
  });

  it('maps 4.0 to Medium', () => {
    expect(severityBand('4.0')).toBe('Medium');
  });

  it('maps 6.9 to Medium', () => {
    expect(severityBand('6.9')).toBe('Medium');
  });

  it('maps 7.0 to High', () => {
    expect(severityBand('7.0')).toBe('High');
  });

  it('maps 8.9 to High', () => {
    expect(severityBand('8.9')).toBe('High');
  });

  it('maps 9.0 to Critical', () => {
    expect(severityBand('9.0')).toBe('Critical');
  });

  it('maps 10.0 to Critical', () => {
    expect(severityBand('10.0')).toBe('Critical');
  });

  it('returns null for null', () => {
    expect(severityBand(null)).toBeNull();
  });

  it('returns null for an empty string', () => {
    expect(severityBand('')).toBeNull();
  });

  it('returns null for a non-numeric string', () => {
    expect(severityBand('abc')).toBeNull();
  });
});
