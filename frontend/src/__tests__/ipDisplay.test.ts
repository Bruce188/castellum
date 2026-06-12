import { describe, it, expect } from 'vitest';
import { isMacPlaceholder, displayIp } from '../lib/ipDisplay';

describe('isMacPlaceholder', () => {
  it('returns true for the canonical mac: placeholder form', () => {
    expect(isMacPlaceholder('mac:aa-bb-cc-dd-ee-ff')).toBe(true);
  });

  it('returns true for any other dash-separated lowercase MAC behind the mac: prefix', () => {
    expect(isMacPlaceholder('mac:00-11-22-33-44-55')).toBe(true);
  });

  it('returns false for normal IPv4 strings', () => {
    expect(isMacPlaceholder('192.168.1.10')).toBe(false);
    expect(isMacPlaceholder('10.0.0.1')).toBe(false);
  });

  it('returns false for IPv6 strings', () => {
    expect(isMacPlaceholder('fe80::1')).toBe(false);
    expect(isMacPlaceholder('2001:db8::1')).toBe(false);
  });

  it('returns false for strings merely containing "mac" outside the prefix position', () => {
    expect(isMacPlaceholder('macbook-pro')).toBe(false);
    expect(isMacPlaceholder('host-mac:aa-bb-cc-dd-ee-ff')).toBe(false);
    expect(isMacPlaceholder('192.168.1.mac')).toBe(false);
  });
});

describe('displayIp', () => {
  it('returns exactly "no IP" for a mac: placeholder', () => {
    expect(displayIp('mac:aa-bb-cc-dd-ee-ff')).toBe('no IP');
  });

  it('returns exactly "no IP" for any other mac: placeholder', () => {
    expect(displayIp('mac:00-11-22-33-44-55')).toBe('no IP');
  });

  it('returns IPv4 input unchanged', () => {
    expect(displayIp('192.168.1.10')).toBe('192.168.1.10');
  });

  it('returns IPv6 input unchanged', () => {
    expect(displayIp('fe80::1')).toBe('fe80::1');
    expect(displayIp('2001:db8::1')).toBe('2001:db8::1');
  });

  it('returns non-placeholder strings containing "mac" unchanged', () => {
    expect(displayIp('macbook-pro')).toBe('macbook-pro');
  });
});
