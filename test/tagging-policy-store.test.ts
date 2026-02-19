// This test suite verifies governed-tagging policy defaults and per-user preference persistence in the SQLite store.

import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, describe, expect, it } from 'vitest';
import { SqliteStore } from '../src/db/database.js';

const tempDirs: string[] = [];

// This helper creates one isolated store instance backed by a temporary SQLite file.
function createStore(): SqliteStore {
  const dir = mkdtempSync(join(tmpdir(), 'linkwarden-mcp-store-'));
  tempDirs.push(dir);
  return new SqliteStore(join(dir, 'state.db'));
}

afterEach(() => {
  for (const dir of tempDirs.splice(0, tempDirs.length)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe('tagging policy store', () => {
  it('returns default global tagging policy when app_state has no policy row', () => {
    const store = createStore();
    expect(store.getGlobalTaggingPolicy()).toEqual({
      fetchMode: 'optional',
      allowUserFetchModeOverride: false,
      inferenceProvider: 'builtin',
      inferenceModel: null,
      blockedTagNames: [],
      similarityThreshold: 0.88,
      fetchTimeoutMs: 3000,
      fetchMaxBytes: 131072
    });
  });

  it('stores per-user tagging preferences and supports global fetch-mode reset', () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'alice',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: false
    });

    const defaults = store.getUserSettings(userId);
    expect(defaults.taggingStrictness).toBe('very_strict');
    expect(defaults.fetchMode).toBe('optional');
    expect(defaults.queryTimeZone).toBeNull();

    store.setUserTaggingPreferences(userId, {
      taggingStrictness: 'medium',
      fetchMode: 'always',
      queryTimeZone: 'Europe/Berlin'
    });
    const updated = store.getUserSettings(userId);
    expect(updated.taggingStrictness).toBe('medium');
    expect(updated.fetchMode).toBe('always');
    expect(updated.queryTimeZone).toBe('Europe/Berlin');

    const customPolicy = {
      fetchMode: 'never' as const,
      allowUserFetchModeOverride: false,
      inferenceProvider: 'mistral' as const,
      inferenceModel: 'mistral-small-latest',
      blockedTagNames: ['tracking'],
      similarityThreshold: 0.9,
      fetchTimeoutMs: 2500,
      fetchMaxBytes: 100000
    };
    store.setGlobalTaggingPolicy(customPolicy);
    expect(store.getGlobalTaggingPolicy()).toEqual({
      ...customPolicy
    });

    const resetCount = store.resetAllUserFetchModes('never');
    expect(resetCount).toBeGreaterThan(0);
    expect(store.getUserSettings(userId).fetchMode).toBe('never');
  });
});
