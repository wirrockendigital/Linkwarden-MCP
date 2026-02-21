// This test suite verifies 404-monitor defaults, persistence, and run-state updates in SQLite store.

import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, describe, expect, it } from 'vitest';
import { SqliteStore } from '../src/db/database.js';

const tempDirs: string[] = [];

// This helper creates one isolated SQLite store for each test case.
function createStore(): SqliteStore {
  const dir = mkdtempSync(join(tmpdir(), 'linkwarden-mcp-404-monitor-store-'));
  tempDirs.push(dir);
  return new SqliteStore(join(dir, 'state.db'));
}

afterEach(() => {
  for (const dir of tempDirs.splice(0, tempDirs.length)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe('link 404 monitor store', () => {
  it('returns deterministic defaults for 404-monitor settings', () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'monitor-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: false
    });

    const settings = store.getUserLink404MonitorSettings(userId);
    expect(settings.enabled).toBe(false);
    expect(settings.interval).toBe('monthly');
    expect(settings.toDeleteAfter).toBe('after_1_year');
    expect(settings.lastRunAt).toBeNull();
    expect(settings.lastStatus).toBeNull();
    expect(settings.lastError).toBeNull();
  });

  it('persists periodic interval and to-delete escalation presets', () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'monitor-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: true
    });

    const updated = store.setUserLink404MonitorSettings(userId, {
      enabled: true,
      interval: 'biweekly',
      toDeleteAfter: 'after_6_months'
    });
    expect(updated.enabled).toBe(true);
    expect(updated.interval).toBe('biweekly');
    expect(updated.toDeleteAfter).toBe('after_6_months');
  });

  it('updates run-state fields deterministically', () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'monitor-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: true
    });

    store.setUserLink404MonitorRunState(userId, 'success', null);

    const settings = store.getUserLink404MonitorSettings(userId);
    expect(settings.lastStatus).toBe('success');
    expect(settings.lastRunAt).not.toBeNull();
    expect(settings.lastError).toBeNull();
  });
});
