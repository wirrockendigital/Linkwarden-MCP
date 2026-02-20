// This test suite verifies per-user archive collection resolution and soft-delete ARCHIVE_TAG behavior.

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AppError } from '../src/utils/errors.js';
import { SqliteStore } from '../src/db/database.js';
import type { LinkCollection, LinkItem, LinkTag } from '../src/types/domain.js';

let activeClient: FakeLinkwardenClient | null = null;

// This mock injects a deterministic fake Linkwarden client into tool execution.
vi.mock('../src/linkwarden/runtime.js', () => ({
  createUserLinkwardenClient: () => {
    if (!activeClient) {
      throw new Error('Fake client was not configured for this test case.');
    }
    return activeClient;
  }
}));

import { executeTool } from '../src/mcp/tools.js';

const tempDirs: string[] = [];

interface FakeLinkwardenClient {
  getLink: (id: number) => Promise<LinkItem>;
  getCollection: (id: number) => Promise<LinkCollection>;
  listAllCollections: () => Promise<LinkCollection[]>;
  createCollection: (input: { name: string; parentId?: number | null }) => Promise<LinkCollection>;
  listAllTags: () => Promise<LinkTag[]>;
  createTag: (name: string) => Promise<LinkTag>;
  updateLink: (
    id: number,
    updates: { collectionId?: number; tagIds?: number[]; archived?: boolean }
  ) => Promise<LinkItem>;
}

interface FakeState {
  links: LinkItem[];
  collections: LinkCollection[];
  tags: LinkTag[];
  createCollectionCalls: Array<{ name: string; parentId?: number | null }>;
  createTagCalls: string[];
  updateLinkCalls: Array<{ id: number; updates: { collectionId?: number; tagIds?: number[]; archived?: boolean } }>;
  failCreateCollectionWith?: AppError;
}

// This helper builds one isolated SQLite store for each test case.
function createStore(): SqliteStore {
  const dir = mkdtempSync(join(tmpdir(), 'linkwarden-mcp-archive-resolution-'));
  tempDirs.push(dir);
  return new SqliteStore(join(dir, 'state.db'));
}

// This helper creates one MCP runtime context bound to a real store-backed user.
function createContext(store: SqliteStore, userId: number): any {
  const logger = {
    info: () => undefined,
    warn: () => undefined,
    error: () => undefined,
    debug: () => undefined,
    child: () => logger
  };

  return {
    actor: 'test#key1',
    principal: {
      userId,
      username: 'archive-user',
      role: 'user',
      apiKeyId: 'key1',
      toolScopes: ['*'],
      collectionScopes: []
    },
    configStore: {
      getRuntimeConfig: () => ({
        requestTimeoutMs: 10_000,
        maxRetries: 0,
        retryBaseDelayMs: 50,
        planTtlHours: 24
      }),
      decryptSecret: () => 'token-value'
    },
    db: store,
    logger
  };
}

// This helper returns one valid Linkwarden link object with deterministic defaults.
function makeLink(id: number, collectionId: number): LinkItem {
  return {
    id,
    title: `Link ${id}`,
    url: `https://example.com/${id}`,
    description: null,
    tags: [],
    collection: {
      id: collectionId,
      name: 'Inbox',
      parentId: null
    },
    pinned: false,
    archived: false,
    createdAt: '2026-02-20T12:00:00.000Z',
    updatedAt: '2026-02-20T12:00:00.000Z'
  };
}

// This helper builds one mutable fake client and tracks all write calls.
function createFakeClient(initial: {
  links: LinkItem[];
  collections: LinkCollection[];
  tags?: LinkTag[];
  failCreateCollectionWith?: AppError;
}): { client: FakeLinkwardenClient; state: FakeState } {
  const state: FakeState = {
    links: initial.links.map((link) => ({ ...link })),
    collections: initial.collections.map((collection) => ({ ...collection })),
    tags: (initial.tags ?? []).map((tag) => ({ ...tag })),
    createCollectionCalls: [],
    createTagCalls: [],
    updateLinkCalls: [],
    failCreateCollectionWith: initial.failCreateCollectionWith
  };

  const client: FakeLinkwardenClient = {
    async getLink(id: number): Promise<LinkItem> {
      const found = state.links.find((link) => link.id === id);
      if (!found) {
        throw new AppError(404, 'link_not_found', `Link ${id} was not found.`);
      }
      return {
        ...found,
        tags: found.tags.map((tag) => ({ ...tag })),
        collection: found.collection ? { ...found.collection } : null
      };
    },
    async getCollection(id: number): Promise<LinkCollection> {
      const found = state.collections.find((collection) => collection.id === id);
      if (!found) {
        throw new AppError(404, 'collection_not_found', `Collection ${id} was not found.`);
      }
      return { ...found };
    },
    async listAllCollections(): Promise<LinkCollection[]> {
      return state.collections.map((collection) => ({ ...collection }));
    },
    async createCollection(input: { name: string; parentId?: number | null }): Promise<LinkCollection> {
      if (state.failCreateCollectionWith) {
        throw state.failCreateCollectionWith;
      }
      state.createCollectionCalls.push({ ...input });
      const nextId = state.collections.length > 0 ? Math.max(...state.collections.map((collection) => collection.id)) + 1 : 1;
      const created: LinkCollection = {
        id: nextId,
        name: input.name,
        parentId: input.parentId ?? null
      };
      state.collections.push(created);
      return { ...created };
    },
    async listAllTags(): Promise<LinkTag[]> {
      return state.tags.map((tag) => ({ ...tag }));
    },
    async createTag(name: string): Promise<LinkTag> {
      state.createTagCalls.push(name);
      const nextId = state.tags.length > 0 ? Math.max(...state.tags.map((tag) => tag.id)) + 1 : 1;
      const created = { id: nextId, name };
      state.tags.push(created);
      return { ...created };
    },
    async updateLink(
      id: number,
      updates: { collectionId?: number; tagIds?: number[]; archived?: boolean }
    ): Promise<LinkItem> {
      state.updateLinkCalls.push({
        id,
        updates: {
          collectionId: updates.collectionId,
          tagIds: updates.tagIds ? [...updates.tagIds] : undefined,
          archived: updates.archived
        }
      });
      const index = state.links.findIndex((link) => link.id === id);
      if (index === -1) {
        throw new AppError(404, 'link_not_found', `Link ${id} was not found.`);
      }
      const existing = state.links[index];
      state.links[index] = {
        ...existing,
        collection: typeof updates.collectionId === 'number'
          ? { id: updates.collectionId, name: `Collection ${updates.collectionId}`, parentId: null }
          : existing.collection,
        tags: Array.isArray(updates.tagIds) ? updates.tagIds.map((tagId) => ({ id: tagId, name: `tag-${tagId}` })) : existing.tags,
        archived: updates.archived ?? existing.archived
      };
      const updated = state.links[index];
      return {
        ...updated,
        tags: updated.tags.map((tag) => ({ ...tag })),
        collection: updated.collection ? { ...updated.collection } : null
      };
    }
  };

  return { client, state };
}

afterEach(() => {
  activeClient = null;
  for (const dir of tempDirs.splice(0, tempDirs.length)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe('archive collection resolution', () => {
  it('creates missing archive collection with per-user name and parent and applies soft delete tagging', async () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'archive-create-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: true
    });
    store.setUserChatControlSettings(userId, {
      archiveCollectionName: 'Archive Team',
      archiveCollectionParentId: 88
    });

    const fake = createFakeClient({
      links: [makeLink(11, 5)],
      collections: [{ id: 5, name: 'Inbox', parentId: null }],
      tags: []
    });
    activeClient = fake.client;

    const result = await executeTool(
      'linkwarden_delete_links',
      {
        ids: [11],
        mode: 'soft',
        dryRun: false
      },
      createContext(store, userId)
    );

    const payload = result.structuredContent as any;
    expect(payload.ok).toBe(true);
    expect(payload.data.archiveCollectionResolution.created).toBe(true);
    expect(payload.data.archiveCollectionResolution.strategy).toBe('created_new');
    expect(payload.data.archiveCollectionResolution.archiveCollectionName).toBe('Archive Team');
    expect(fake.state.createCollectionCalls).toEqual([{ name: 'Archive Team', parentId: 88 }]);
    expect(fake.state.createTagCalls).toEqual(['to-delete']);
    expect(fake.state.updateLinkCalls).toHaveLength(1);
    expect(fake.state.updateLinkCalls[0].updates.collectionId).toBe(payload.data.archiveCollection.id);
    expect(fake.state.updateLinkCalls[0].updates.archived).toBe(true);
    expect(fake.state.updateLinkCalls[0].updates.tagIds).toEqual([1]);
  });

  it('uses existing single exact-name match without creating a new archive collection', async () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'archive-single-match-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: true
    });
    store.setUserChatControlSettings(userId, {
      archiveCollectionName: 'Archive Team',
      archiveCollectionParentId: null
    });

    const fake = createFakeClient({
      links: [makeLink(12, 5)],
      collections: [
        { id: 5, name: 'Inbox', parentId: null },
        { id: 55, name: 'Archive Team', parentId: 7 }
      ],
      tags: [{ id: 2, name: 'to-delete' }]
    });
    activeClient = fake.client;

    const result = await executeTool(
      'linkwarden_delete_links',
      {
        ids: [12],
        mode: 'soft',
        dryRun: true
      },
      createContext(store, userId)
    );

    const payload = result.structuredContent as any;
    expect(payload.ok).toBe(true);
    expect(payload.data.archiveCollection.id).toBe(55);
    expect(payload.data.archiveCollectionResolution.created).toBe(false);
    expect(payload.data.archiveCollectionResolution.strategy).toBe('existing_name_match');
    expect(fake.state.createCollectionCalls).toHaveLength(0);
  });

  it('prefers root match with smallest id when multiple exact-name collections exist', async () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'archive-multi-root-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: true
    });
    store.setUserChatControlSettings(userId, {
      archiveCollectionName: 'Archive',
      archiveCollectionParentId: null
    });

    const fake = createFakeClient({
      links: [makeLink(13, 5)],
      collections: [
        { id: 5, name: 'Inbox', parentId: null },
        { id: 70, name: 'Archive', parentId: 2 },
        { id: 30, name: 'Archive', parentId: null },
        { id: 20, name: 'Archive', parentId: null }
      ],
      tags: [{ id: 9, name: 'to-delete' }]
    });
    activeClient = fake.client;

    const result = await executeTool(
      'linkwarden_delete_links',
      {
        ids: [13],
        mode: 'soft',
        dryRun: true
      },
      createContext(store, userId)
    );

    const payload = result.structuredContent as any;
    expect(payload.ok).toBe(true);
    expect(payload.data.archiveCollection.id).toBe(20);
    expect(payload.data.archiveCollectionResolution.strategy).toBe('existing_name_match');
  });

  it('chooses smallest id when multiple exact-name matches exist without root collections', async () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'archive-multi-non-root-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: true
    });
    store.setUserChatControlSettings(userId, {
      archiveCollectionName: 'Archive',
      archiveCollectionParentId: null
    });

    const fake = createFakeClient({
      links: [makeLink(14, 5)],
      collections: [
        { id: 5, name: 'Inbox', parentId: null },
        { id: 30, name: 'Archive', parentId: 2 },
        { id: 22, name: 'Archive', parentId: 3 },
        { id: 50, name: 'Archive', parentId: 7 }
      ],
      tags: [{ id: 9, name: 'to-delete' }]
    });
    activeClient = fake.client;

    const result = await executeTool(
      'linkwarden_delete_links',
      {
        ids: [14],
        mode: 'soft',
        dryRun: true
      },
      createContext(store, userId)
    );

    const payload = result.structuredContent as any;
    expect(payload.ok).toBe(true);
    expect(payload.data.archiveCollection.id).toBe(22);
    expect(payload.data.archiveCollectionResolution.strategy).toBe('existing_name_match');
  });

  it('returns dry-run warning instead of failing when archive collection is missing', async () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'archive-dry-run-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: true
    });
    store.setUserChatControlSettings(userId, {
      archiveCollectionName: 'Archive Missing',
      archiveCollectionParentId: null
    });

    const fake = createFakeClient({
      links: [makeLink(15, 5)],
      collections: [{ id: 5, name: 'Inbox', parentId: null }],
      tags: []
    });
    activeClient = fake.client;

    const result = await executeTool(
      'linkwarden_delete_links',
      {
        ids: [15],
        mode: 'soft',
        dryRun: true
      },
      createContext(store, userId)
    );

    const payload = result.structuredContent as any;
    expect(payload.ok).toBe(true);
    expect(payload.data.archiveCollection).toBeNull();
    expect(payload.data.archiveCollectionResolution.wouldCreate).toBe(true);
    expect(payload.warnings).toContain('archive_collection_missing: "Archive Missing" would be created on apply.');
  });

  it('surfaces genuine upstream permission errors while creating missing archive collections', async () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'archive-api-error-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: true
    });
    store.setUserChatControlSettings(userId, {
      archiveCollectionName: 'Archive Secure',
      archiveCollectionParentId: null
    });

    const fake = createFakeClient({
      links: [makeLink(16, 5)],
      collections: [{ id: 5, name: 'Inbox', parentId: null }],
      tags: [],
      failCreateCollectionWith: new AppError(403, 'forbidden', 'Permission denied for create collection.')
    });
    activeClient = fake.client;

    await expect(
      executeTool(
        'linkwarden_delete_links',
        {
          ids: [16],
          mode: 'soft',
          dryRun: false
        },
        createContext(store, userId)
      )
    ).rejects.toMatchObject({
      statusCode: 403,
      code: 'forbidden'
    });
  });
});
