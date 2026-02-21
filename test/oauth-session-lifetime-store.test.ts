// This test suite verifies runtime OAuth session-lifetime rebasing behavior for active refresh tokens.

import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, describe, expect, it } from 'vitest';
import { SqliteStore } from '../src/db/database.js';
import { hashApiToken } from '../src/utils/security.js';

const tempDirs: string[] = [];

// This helper creates one isolated SQLite store for deterministic OAuth token tests.
function createStore(): SqliteStore {
  const dir = mkdtempSync(join(tmpdir(), 'linkwarden-mcp-oauth-lifetime-store-'));
  tempDirs.push(dir);
  return new SqliteStore(join(dir, 'state.db'));
}

// This helper inserts one synthetic OAuth token row with configurable refresh expiry.
function createOAuthTokenFixture(store: SqliteStore, userId: number, tokenSuffix: string, refreshExpiresAt: string): string {
  const accessTokenHash = hashApiToken(`access-${tokenSuffix}`);
  const refreshTokenHash = hashApiToken(`refresh-${tokenSuffix}`);
  store.createOAuthToken({
    tokenId: `tok-${tokenSuffix}`,
    accessTokenHash,
    refreshTokenHash,
    userId,
    clientId: 'test-client',
    scope: 'mcp.read offline_access',
    resource: 'https://example.com/mcp',
    accessExpiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    refreshExpiresAt
  });
  return refreshTokenHash;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0, tempDirs.length)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe('oauth session lifetime rebasing', () => {
  it('updates only active refresh tokens and supports permanent expiry', () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'oauth-lifetime-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: false
    });

    const activeHash = createOAuthTokenFixture(store, userId, 'active', '2030-01-01T00:00:00.000Z');
    const revokedHash = createOAuthTokenFixture(store, userId, 'revoked', '2030-01-01T00:00:00.000Z');
    createOAuthTokenFixture(store, userId, 'expired', '2020-01-01T00:00:00.000Z');
    store.consumeOAuthRefreshToken(revokedHash);

    const affectedCount = store.rebaseActiveOAuthRefreshExpiries('permanent', '2026-02-20T12:00:00.000Z');
    expect(affectedCount).toBe(1);

    const activeRecord = store.getOAuthRefreshToken(activeHash);
    expect(activeRecord?.refreshExpiresAt).toBe('9999-12-31T23:59:59.000Z');
    expect(store.getOAuthRefreshToken(revokedHash)).toBeNull();
  });

  it('rebases active refresh tokens to finite day presets deterministically', () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'oauth-finite-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: false
    });

    const refreshHash = createOAuthTokenFixture(store, userId, 'finite', '2035-01-01T00:00:00.000Z');
    const nowIso = '2026-02-20T12:00:00.000Z';
    const expectedExpiry = new Date(Date.parse(nowIso) + 30 * 24 * 60 * 60 * 1000).toISOString();

    const affectedCount = store.rebaseActiveOAuthRefreshExpiries(30, nowIso);
    expect(affectedCount).toBe(1);

    const record = store.getOAuthRefreshToken(refreshHash);
    expect(record?.refreshExpiresAt).toBe(expectedExpiry);
  });
});
