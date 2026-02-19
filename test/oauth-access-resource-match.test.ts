// This test suite verifies OAuth access token auth accepts equivalent resource URLs after normalization.

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { SqliteStore } from '../src/db/database.js';
import { hashApiToken } from '../src/utils/security.js';

const tempDirs: string[] = [];

// This helper creates one isolated SQLite store for auth resource matching tests.
function createStore(): SqliteStore {
  const dir = mkdtempSync(join(tmpdir(), 'linkwarden-mcp-oauth-resource-'));
  tempDirs.push(dir);
  return new SqliteStore(join(dir, 'state.db'));
}

afterEach(() => {
  for (const dir of tempDirs.splice(0, tempDirs.length)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe('oauth access resource matching', () => {
  it('accepts stored oauth token resources with trailing slash and host-case differences', () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'oauth-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: false
    });

    const rawAccessToken = 'lwa_test_token_1234567890';
    const now = Date.now();
    store.createOAuthToken({
      tokenId: 'tok_case_1',
      accessTokenHash: hashApiToken(rawAccessToken),
      refreshTokenHash: hashApiToken('lwr_refresh_token_1234567890'),
      userId,
      clientId: 'client-case',
      scope: 'mcp.read offline_access',
      resource: 'HTTPS://LWMCP.ROCKEN.DIGITAL/mcp/',
      accessExpiresAt: new Date(now + 60_000).toISOString(),
      refreshExpiresAt: new Date(now + 3_600_000).toISOString()
    });

    const principal = store.authenticateOAuthAccessToken(hashApiToken(rawAccessToken), [
      'https://lwmcp.rocken.digital/mcp'
    ]);

    expect(principal).not.toBeNull();
    expect(principal?.username).toBe('oauth-user');
  });
});
