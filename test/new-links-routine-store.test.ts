// This test suite verifies new-links routine defaults, persistence, and cursor/run-state updates in SQLite store.

import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, describe, expect, it } from 'vitest';
import { SqliteStore } from '../src/db/database.js';

const tempDirs: string[] = [];

// This helper creates one isolated SQLite store for each test case.
function createStore(): SqliteStore {
  const dir = mkdtempSync(join(tmpdir(), 'linkwarden-mcp-new-links-store-'));
  tempDirs.push(dir);
  return new SqliteStore(join(dir, 'state.db'));
}

afterEach(() => {
  for (const dir of tempDirs.splice(0, tempDirs.length)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe('new-links routine store', () => {
  it('returns deterministic defaults for new routine settings', () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'routine-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: false
    });

    const settings = store.getUserNewLinksRoutineSettings(userId);
    expect(settings.enabled).toBe(false);
    expect(settings.intervalMinutes).toBe(15);
    expect(settings.batchSize).toBe(200);
    expect(settings.modules).toEqual(['governed_tagging', 'normalize_urls', 'dedupe']);
    expect(settings.cursor).toBeNull();
    expect(settings.backfillRequested).toBe(false);
    expect(settings.backfillConfirmed).toBe(false);
  });

  it('sets first-enable cursor to now and supports explicit backfill confirmation', () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'routine-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: false
    });

    const enabled = store.setUserNewLinksRoutineSettings(userId, {
      enabled: true,
      intervalMinutes: 20,
      batchSize: 150,
      modules: ['normalize_urls', 'governed_tagging']
    });
    expect(enabled.enabled).toBe(true);
    expect(enabled.intervalMinutes).toBe(20);
    expect(enabled.batchSize).toBe(150);
    expect(enabled.modules).toEqual(['normalize_urls', 'governed_tagging']);
    expect(enabled.cursor).not.toBeNull();
    expect(enabled.cursor?.linkId).toBe(0);

    const requested = store.setUserNewLinksRoutineSettings(userId, {
      requestBackfill: true
    });
    expect(requested.backfillRequested).toBe(true);
    expect(requested.backfillConfirmed).toBe(false);
    expect(requested.cursor).not.toBeNull();

    const confirmed = store.setUserNewLinksRoutineSettings(userId, {
      confirmBackfill: true
    });
    expect(confirmed.backfillRequested).toBe(true);
    expect(confirmed.backfillConfirmed).toBe(true);
    expect(confirmed.cursor).toBeNull();
  });

  it('updates cursor and run-state fields deterministically', () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'routine-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: false
    });

    store.updateUserNewLinksRoutineCursor(userId, {
      createdAt: '2026-02-17T12:00:00.000Z',
      linkId: 42
    });
    store.setUserNewLinksRoutineRunState(userId, 'success', null);

    const settings = store.getUserNewLinksRoutineSettings(userId);
    expect(settings.cursor).toEqual({
      createdAt: '2026-02-17T12:00:00.000Z',
      linkId: 42
    });
    expect(settings.lastStatus).toBe('success');
    expect(settings.lastRunAt).not.toBeNull();
    expect(settings.lastError).toBeNull();
  });
});
