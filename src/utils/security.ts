// This module contains token generation and hashing helpers used by API key and session auth.

import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import type { UserRole } from '../types/domain.js';

export interface PasswordHashRecord {
  salt: string;
  hash: string;
  kdf: 'scrypt';
  params: string;
}

export interface SessionCookieOptions {
  secure: boolean;
  maxAgeSeconds: number;
}

// This function computes a deterministic SHA-256 token hash for database lookup.
export function hashApiToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

// This function creates a new random API token and a short key identifier for auditing.
export function generateApiToken(): { token: string; keyId: string } {
  const keyId = randomBytes(6).toString('hex');
  const secret = randomBytes(24).toString('base64url');
  return {
    keyId,
    token: `lwk_${keyId}.${secret}`
  };
}

// This function creates one random session token that is only stored hashed server-side.
export function generateSessionToken(): string {
  return `lws_${randomBytes(30).toString('base64url')}`;
}

// This function creates one random CSRF token used by the double-submit cookie strategy.
export function generateCsrfToken(): string {
  return randomBytes(20).toString('base64url');
}

// This function hashes a plaintext password using scrypt with per-user random salt.
export function hashPassword(password: string): PasswordHashRecord {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });

  return {
    salt: salt.toString('base64'),
    hash: hash.toString('base64'),
    kdf: 'scrypt',
    params: 'N=16384,r=8,p=1,len=64'
  };
}

// This function validates a plaintext password against a stored scrypt hash record.
export function verifyPassword(password: string, record: PasswordHashRecord): boolean {
  const salt = Buffer.from(record.salt, 'base64');
  const expected = Buffer.from(record.hash, 'base64');
  const candidate = scryptSync(password, salt, expected.length, { N: 16384, r: 8, p: 1 });

  if (candidate.length !== expected.length) {
    return false;
  }

  return timingSafeEqual(candidate, expected);
}

// This function serializes one cookie string with strict defaults for secure auth handling.
export function serializeCookie(name: string, value: string, options: SessionCookieOptions): string {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/',
    `Max-Age=${options.maxAgeSeconds}`,
    'SameSite=Strict'
  ];

  if (options.secure) {
    parts.push('Secure');
  }

  if (name === 'mcp_session') {
    parts.push('HttpOnly');
  }

  return parts.join('; ');
}

// This function creates one cookie string that removes a previously set cookie value.
export function serializeExpiredCookie(name: string, secure: boolean): string {
  const parts = [`${name}=`, 'Path=/', 'Max-Age=0', 'SameSite=Strict'];

  if (secure) {
    parts.push('Secure');
  }

  if (name === 'mcp_session') {
    parts.push('HttpOnly');
  }

  return parts.join('; ');
}

// This function parses a Cookie header into a key/value object for downstream auth checks.
export function parseCookies(headerValue: string | undefined): Record<string, string> {
  if (!headerValue) {
    return {};
  }

  const pairs = headerValue.split(';');
  const result: Record<string, string> = {};

  for (const pair of pairs) {
    const [rawName, ...rest] = pair.trim().split('=');
    if (!rawName || rest.length === 0) {
      continue;
    }

    result[rawName] = decodeURIComponent(rest.join('='));
  }

  return result;
}

// This helper checks whether a role may access admin-only web routes.
export function isAdminRole(role: UserRole): boolean {
  return role === 'admin';
}
