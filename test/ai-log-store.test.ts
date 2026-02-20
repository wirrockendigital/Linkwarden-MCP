// This test suite verifies AI change-log persistence, filtering, conflict detection, and retention pruning in SQLite store.

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { SqliteStore } from '../src/db/database.js';

const tempDirs: string[] = [];

// This helper creates one isolated SQLite-backed store for deterministic AI log tests.
function createStore(): SqliteStore {
  const dir = mkdtempSync(join(tmpdir(), 'linkwarden-mcp-ai-log-store-'));
  tempDirs.push(dir);
  return new SqliteStore(join(dir, 'state.db'));
}

// This helper creates one deterministic user that owns all test records.
function createUser(store: SqliteStore, username: string): number {
  return store.createUser({
    username,
    role: 'user',
    passwordSalt: 'salt',
    passwordHash: 'hash',
    passwordKdf: 'scrypt',
    passwordIterations: 16384,
    writeModeEnabled: true
  });
}

afterEach(() => {
  for (const dir of tempDirs.splice(0, tempDirs.length)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe('ai log store', () => {
  it('stores and filters AI change-log rows deterministically', () => {
    const store = createStore();
    const userId = createUser(store, 'ai-log-filter-user');
    const operationId = 'op-filter-0001';
    store.createOperation({
      id: operationId,
      userId,
      toolName: 'linkwarden_mutate_links',
      summary: { changed: 1 },
      undoUntil: '2099-01-01T00:00:00.000Z'
    });
    store.insertOperationItems(operationId, [
      {
        itemType: 'link',
        itemId: 101,
        before: {
          title: 'Before',
          url: 'https://example.com/before',
          collectionId: 1,
          tagIds: [1],
          pinned: false,
          archived: false
        },
        after: {
          title: 'After',
          url: 'https://example.com/after',
          collectionId: 2,
          tagIds: [1, 2],
          pinned: false,
          archived: false
        }
      }
    ]);
    store.appendAiChangeLogEntries({
      userId,
      operationId,
      toolName: 'linkwarden_mutate_links',
      changedAt: '2026-02-20T10:00:00.000Z',
      entries: [
        {
          operationItemId: 101,
          actionType: 'move_collection',
          linkId: 101,
          linkTitle: 'After',
          urlBefore: 'https://example.com/before',
          urlAfter: 'https://example.com/after',
          collectionFromId: 1,
          collectionFromName: 'Inbox',
          collectionToId: 2,
          collectionToName: 'Archive',
          tagsAdded: ['AI Chat'],
          tagsRemoved: []
        }
      ]
    });

    const listed = store.listAiChangeLog(
      userId,
      {
        q: 'archive',
        actionTypes: ['move_collection'],
        toolNames: ['linkwarden_mutate_links'],
        collectionToId: 2
      },
      {
        limit: 25,
        offset: 0
      },
      {
        sortBy: 'changedAt',
        sortDir: 'desc'
      }
    );

    expect(listed.total).toBe(1);
    expect(listed.items).toHaveLength(1);
    expect(listed.items[0].actionType).toBe('move_collection');
    expect(listed.items[0].collectionFromName).toBe('Inbox');
    expect(listed.items[0].collectionToName).toBe('Archive');
  });

  it('marks older selected change as conflict when newer open change exists for the same link', () => {
    const store = createStore();
    const userId = createUser(store, 'ai-log-conflict-user');
    const oldOperationId = 'op-conflict-old';
    const newOperationId = 'op-conflict-new';

    store.createOperation({
      id: oldOperationId,
      userId,
      toolName: 'linkwarden_mutate_links',
      summary: { changed: 1 },
      undoUntil: '2099-01-01T00:00:00.000Z'
    });
    store.insertOperationItems(oldOperationId, [
      {
        itemType: 'link',
        itemId: 777,
        before: {
          title: 'Old',
          url: 'https://example.com/old',
          collectionId: 11,
          tagIds: [],
          pinned: false,
          archived: false
        },
        after: {
          title: 'Old updated',
          url: 'https://example.com/old-updated',
          collectionId: 11,
          tagIds: [],
          pinned: false,
          archived: false
        }
      }
    ]);
    store.appendAiChangeLogEntries({
      userId,
      operationId: oldOperationId,
      toolName: 'linkwarden_mutate_links',
      changedAt: '2026-02-20T08:00:00.000Z',
      entries: [
        {
          operationItemId: 777,
          actionType: 'update_link',
          linkId: 777,
          linkTitle: 'Old updated',
          urlBefore: 'https://example.com/old',
          urlAfter: 'https://example.com/old-updated'
        }
      ]
    });

    store.createOperation({
      id: newOperationId,
      userId,
      toolName: 'linkwarden_mutate_links',
      summary: { changed: 1 },
      undoUntil: '2099-01-01T00:00:00.000Z'
    });
    store.insertOperationItems(newOperationId, [
      {
        itemType: 'link',
        itemId: 777,
        before: {
          title: 'Old updated',
          url: 'https://example.com/old-updated',
          collectionId: 11,
          tagIds: [],
          pinned: false,
          archived: false
        },
        after: {
          title: 'Newest',
          url: 'https://example.com/newest',
          collectionId: 11,
          tagIds: [],
          pinned: false,
          archived: false
        }
      }
    ]);
    store.appendAiChangeLogEntries({
      userId,
      operationId: newOperationId,
      toolName: 'linkwarden_mutate_links',
      changedAt: '2026-02-20T09:00:00.000Z',
      entries: [
        {
          operationItemId: 777,
          actionType: 'update_link',
          linkId: 777,
          linkTitle: 'Newest',
          urlBefore: 'https://example.com/old-updated',
          urlAfter: 'https://example.com/newest'
        }
      ]
    });

    const listed = store.listAiChangeLog(
      userId,
      {},
      { limit: 50, offset: 0 },
      { sortBy: 'changedAt', sortDir: 'asc' }
    );
    expect(listed.total).toBe(2);
    const oldest = listed.items.find((row) => row.operationId === oldOperationId);
    expect(oldest).toBeDefined();

    const candidates = store.getAiChangeUndoCandidates(userId, [oldest!.id]);
    expect(candidates).toHaveLength(1);
    expect(candidates[0].hasNewerOpenChange).toBe(true);
  });

  it('prunes AI log rows according to configured retention days', () => {
    const store = createStore();
    const userId = createUser(store, 'ai-log-prune-user');
    const operationId = 'op-prune-0001';
    store.createOperation({
      id: operationId,
      userId,
      toolName: 'linkwarden_mutate_links',
      summary: { changed: 1 },
      undoUntil: '2099-01-01T00:00:00.000Z'
    });
    store.insertOperationItems(operationId, [
      {
        itemType: 'link',
        itemId: 901,
        before: {
          title: 'Legacy',
          url: 'https://example.com/legacy',
          collectionId: 1,
          tagIds: [],
          pinned: false,
          archived: false
        },
        after: {
          title: 'Legacy',
          url: 'https://example.com/legacy',
          collectionId: 1,
          tagIds: [],
          pinned: false,
          archived: false
        }
      }
    ]);
    store.appendAiChangeLogEntries({
      userId,
      operationId,
      toolName: 'linkwarden_mutate_links',
      changedAt: '2000-01-01T00:00:00.000Z',
      entries: [
        {
          operationItemId: 901,
          actionType: 'update_link',
          linkId: 901,
          linkTitle: 'Legacy',
          urlBefore: 'https://example.com/legacy',
          urlAfter: 'https://example.com/legacy'
        }
      ]
    });

    const pruned = store.pruneAiChangeLog(userId, 30);
    expect(pruned).toBe(1);
    const listed = store.listAiChangeLog(
      userId,
      {},
      { limit: 25, offset: 0 },
      { sortBy: 'changedAt', sortDir: 'desc' }
    );
    expect(listed.total).toBe(0);
  });
});
