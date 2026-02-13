// This test suite verifies strict Linkwarden whitelist validation and matching behavior.

import { describe, expect, it } from 'vitest';
import { AppError } from '../src/utils/errors.js';
import { assertBaseUrlWhitelisted, normalizeWhitelistEntry } from '../src/utils/whitelist.js';
import type { LinkwardenWhitelistEntry } from '../src/types/domain.js';

function toStored(entries: Array<{ type: 'domain' | 'ip' | 'cidr'; value: string }>): LinkwardenWhitelistEntry[] {
  const now = new Date().toISOString();
  return entries.map((entry, index) => ({
    id: index + 1,
    type: entry.type,
    value: entry.value,
    createdAt: now
  }));
}

describe('whitelist helpers', () => {
  it('normalizes valid domain/ip/cidr entries', () => {
    expect(normalizeWhitelistEntry('domain', 'Example.COM')).toEqual({
      type: 'domain',
      value: 'example.com'
    });
    expect(normalizeWhitelistEntry('ip', '192.168.1.15')).toEqual({
      type: 'ip',
      value: '192.168.1.15'
    });
    expect(normalizeWhitelistEntry('cidr', '192.168.1.0/24')).toEqual({
      type: 'cidr',
      value: '192.168.1.0/24'
    });
    expect(normalizeWhitelistEntry('domain', 'linkwarden')).toEqual({
      type: 'domain',
      value: 'linkwarden'
    });
  });

  it('rejects wildcard and allow-all style whitelist entries', () => {
    expect(() => normalizeWhitelistEntry('domain', '*.example.com')).toThrowError(AppError);
    expect(() => normalizeWhitelistEntry('cidr', '0.0.0.0/0')).toThrowError(AppError);
    expect(() => normalizeWhitelistEntry('cidr', '::/0')).toThrowError(AppError);
  });

  it('allows matching exact domain and blocks non-listed domain', () => {
    const entries = toStored([{ type: 'domain', value: 'linkwarden.local' }]);
    expect(() => assertBaseUrlWhitelisted('http://linkwarden.local:3000', entries)).not.toThrow();
    expect(() => assertBaseUrlWhitelisted('http://other.local:3000', entries)).toThrowError(AppError);
  });

  it('allows matching ip and cidr entries for ip-based hosts', () => {
    const entries = toStored([
      { type: 'ip', value: '192.168.123.10' },
      { type: 'cidr', value: '192.168.123.0/24' }
    ]);

    expect(() => assertBaseUrlWhitelisted('http://192.168.123.10:3000', entries)).not.toThrow();
    expect(() => assertBaseUrlWhitelisted('http://192.168.123.77:3000', entries)).not.toThrow();
    expect(() => assertBaseUrlWhitelisted('http://10.0.0.5:3000', entries)).toThrowError(AppError);
  });
});
