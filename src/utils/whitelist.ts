// This module validates and enforces Linkwarden base URL allowlists for domain, IP, and CIDR entries.

import { BlockList, isIP } from 'node:net';
import { AppError } from './errors.js';
import type { LinkwardenWhitelistEntry, WhitelistType } from '../types/domain.js';

// This helper validates one domain value with conservative exact-host matching rules.
function isValidDomain(value: string): boolean {
  if (!value || value.includes('*') || value.length > 253) {
    return false;
  }

  const normalized = value.trim().toLowerCase();
  return (
    /^[a-z0-9.-]+$/.test(normalized) &&
    !normalized.startsWith('.') &&
    !normalized.endsWith('.') &&
    !normalized.includes('..')
  );
}

// This helper validates one CIDR string and rejects allow-all ranges.
function isValidCidr(value: string): boolean {
  const [ip, prefixRaw] = value.split('/');
  if (!ip || !prefixRaw) {
    return false;
  }

  const ipVersion = isIP(ip);
  if (ipVersion === 0) {
    return false;
  }

  const prefix = Number(prefixRaw);
  if (!Number.isInteger(prefix)) {
    return false;
  }

  if (ipVersion === 4) {
    if (prefix < 1 || prefix > 32) {
      return false;
    }
    if (ip === '0.0.0.0' && prefix === 0) {
      return false;
    }
  }

  if (ipVersion === 6) {
    if (prefix < 1 || prefix > 128) {
      return false;
    }
    if (ip === '::' && prefix === 0) {
      return false;
    }
  }

  return true;
}

// This function validates a whitelist entry and normalizes stored values.
export function normalizeWhitelistEntry(type: WhitelistType, value: string): { type: WhitelistType; value: string } {
  const normalizedValue = value.trim().toLowerCase();

  if (type === 'domain') {
    if (!isValidDomain(normalizedValue)) {
      throw new AppError(400, 'invalid_whitelist', `Invalid domain whitelist value: ${value}`);
    }

    return { type, value: normalizedValue };
  }

  if (type === 'ip') {
    if (isIP(normalizedValue) === 0) {
      throw new AppError(400, 'invalid_whitelist', `Invalid IP whitelist value: ${value}`);
    }

    return { type, value: normalizedValue };
  }

  if (!isValidCidr(normalizedValue)) {
    throw new AppError(400, 'invalid_whitelist', `Invalid CIDR whitelist value: ${value}`);
  }

  return { type, value: normalizedValue };
}

// This function validates one Linkwarden base URL against the configured whitelist.
export function assertBaseUrlWhitelisted(baseUrl: string, whitelist: LinkwardenWhitelistEntry[]): void {
  if (whitelist.length === 0) {
    throw new AppError(400, 'invalid_whitelist', 'Whitelist cannot be empty.');
  }

  const host = new URL(baseUrl).hostname.toLowerCase();
  const ipVersion = isIP(host);
  const matcher = new BlockList();

  for (const entry of whitelist) {
    if (entry.type === 'cidr') {
      const [ip, prefixRaw] = entry.value.split('/');
      const entryVersion = isIP(ip);
      if (entryVersion === 4 || entryVersion === 6) {
        matcher.addSubnet(ip, Number(prefixRaw), entryVersion === 6 ? 'ipv6' : 'ipv4');
      }
    }
  }

  for (const entry of whitelist) {
    if (entry.type === 'domain' && ipVersion === 0 && host === entry.value) {
      return;
    }

    if (entry.type === 'ip' && ipVersion !== 0 && host === entry.value) {
      return;
    }

    if (entry.type === 'cidr' && ipVersion !== 0 && matcher.check(host, ipVersion === 6 ? 'ipv6' : 'ipv4')) {
      return;
    }
  }

  throw new AppError(403, 'base_url_not_whitelisted', `Base URL host ${host} is not allowed by whitelist.`);
}
