// This test suite validates chat-link capture hierarchy resolution, dedupe, tagging toggles, and write-mode gating.

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AppError } from '../src/utils/errors.js';
import { SqliteStore } from '../src/db/database.js';
import type { LinkCollection, LinkItem, LinkTag } from '../src/types/domain.js';

let activeClient: FakeLinkwardenClient | null = null;

// This mock routes runtime client creation to one deterministic in-memory fake per test case.
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
  listAllCollections: () => Promise<LinkCollection[]>;
  createCollection: (input: { name: string; parentId?: number | null }) => Promise<LinkCollection>;
  listLinksByCollection: (collectionId: number) => Promise<LinkItem[]>;
  listAllTags: () => Promise<LinkTag[]>;
  createTag: (name: string) => Promise<LinkTag>;
  createLink: (input: {
    url: string;
    title?: string;
    description?: string;
    collectionId?: number;
    tagIds?: number[];
    archived?: boolean;
  }) => Promise<LinkItem>;
}

interface FakeState {
  collections: LinkCollection[];
  linksByCollection: Map<number, LinkItem[]>;
  tags: LinkTag[];
  createCollectionCalls: Array<{ name: string; parentId?: number | null }>;
  createTagCalls: string[];
  createLinkCalls: Array<{ url: string; collectionId: number; tagIds?: number[] }>;
  failCreateLinkForUrl?: string;
  failCreateLinkWithTagsForUrl?: string;
}

// This helper creates one isolated SQLite store for each test case.
function createStore(): SqliteStore {
  const dir = mkdtempSync(join(tmpdir(), 'linkwarden-mcp-capture-chat-links-'));
  tempDirs.push(dir);
  return new SqliteStore(join(dir, 'state.db'));
}

// This helper creates one standard MCP runtime context bound to a concrete user.
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
      username: 'capture-user',
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

// This helper creates one deterministic fake Linkwarden client with mutable in-memory state.
function createFakeClient(initial?: {
  collections?: LinkCollection[];
  linksByCollection?: Record<number, LinkItem[]>;
  tags?: LinkTag[];
  failCreateLinkForUrl?: string;
  failCreateLinkWithTagsForUrl?: string;
}): { client: FakeLinkwardenClient; state: FakeState } {
  const state: FakeState = {
    collections: (initial?.collections ?? []).map((collection) => ({ ...collection })),
    linksByCollection: new Map(
      Object.entries(initial?.linksByCollection ?? {}).map(([collectionId, links]) => [
        Number(collectionId),
        links.map((link) => ({
          ...link,
          tags: link.tags.map((tag) => ({ ...tag })),
          collection: link.collection ? { ...link.collection } : null
        }))
      ])
    ),
    tags: (initial?.tags ?? []).map((tag) => ({ ...tag })),
    createCollectionCalls: [],
    createTagCalls: [],
    createLinkCalls: [],
    failCreateLinkForUrl: initial?.failCreateLinkForUrl,
    failCreateLinkWithTagsForUrl: initial?.failCreateLinkWithTagsForUrl
  };

  const client: FakeLinkwardenClient = {
    async listAllCollections(): Promise<LinkCollection[]> {
      return state.collections.map((collection) => ({ ...collection }));
    },
    async createCollection(input: { name: string; parentId?: number | null }): Promise<LinkCollection> {
      state.createCollectionCalls.push({ ...input });
      const nextId =
        state.collections.length > 0
          ? Math.max(...state.collections.map((collection) => collection.id)) + 1
          : 1;
      const created: LinkCollection = {
        id: nextId,
        name: input.name,
        parentId: input.parentId ?? null
      };
      state.collections.push(created);
      return { ...created };
    },
    async listLinksByCollection(collectionId: number): Promise<LinkItem[]> {
      const links = state.linksByCollection.get(collectionId) ?? [];
      return links.map((link) => ({
        ...link,
        tags: link.tags.map((tag) => ({ ...tag })),
        collection: link.collection ? { ...link.collection } : null
      }));
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
    async createLink(input: {
      url: string;
      title?: string;
      description?: string;
      collectionId?: number;
      tagIds?: number[];
      archived?: boolean;
    }): Promise<LinkItem> {
      const collectionId = Number(input.collectionId);
      state.createLinkCalls.push({
        url: input.url,
        collectionId,
        tagIds: input.tagIds ? [...input.tagIds] : undefined
      });

      if (state.failCreateLinkForUrl && input.url === state.failCreateLinkForUrl) {
        throw new AppError(403, 'forbidden', 'Link create blocked by fake policy.');
      }
      if (
        state.failCreateLinkWithTagsForUrl &&
        input.url === state.failCreateLinkWithTagsForUrl &&
        Array.isArray(input.tagIds) &&
        input.tagIds.length > 0
      ) {
        throw new AppError(
          400,
          'linkwarden_api_error',
          '{"response":"Error: Invalid input: expected object, received number [tags, 0]"}'
        );
      }

      const nextId =
        [...state.linksByCollection.values()].flat().length > 0
          ? Math.max(...[...state.linksByCollection.values()].flat().map((link) => link.id)) + 1
          : 1;
      const created: LinkItem = {
        id: nextId,
        title: input.title ?? input.url,
        url: input.url,
        description: null,
        tags: (input.tagIds ?? []).map((tagId) => ({ id: tagId, name: `tag-${tagId}` })),
        collection: {
          id: collectionId,
          name: `Collection ${collectionId}`,
          parentId: null
        },
        pinned: false,
        archived: false,
        createdAt: '2026-02-20T12:00:00.000Z',
        updatedAt: '2026-02-20T12:00:00.000Z'
      };

      const existing = state.linksByCollection.get(collectionId) ?? [];
      existing.push(created);
      state.linksByCollection.set(collectionId, existing);
      return {
        ...created,
        tags: created.tags.map((tag) => ({ ...tag })),
        collection: created.collection ? { ...created.collection } : null
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

describe('capture chat links', () => {
  it('creates missing hierarchy and applies both default tags on apply', async () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'capture-default-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: true
    });
    const fake = createFakeClient();
    activeClient = fake.client;

    const result = await executeTool(
      'linkwarden_capture_chat_links',
      {
        urls: ['https://example.com/a', 'https://example.com/b'],
        aiName: 'ChatGPT',
        chatName: 'Thread 1',
        dryRun: false
      },
      createContext(store, userId)
    );

    const payload = result.structuredContent as any;
    expect(payload.ok).toBe(true);
    expect(payload.summary.created).toBe(2);
    expect(fake.state.createCollectionCalls).toEqual([
      { name: 'AI Chats', parentId: null },
      { name: 'ChatGPT', parentId: 1 },
      { name: 'Thread 1', parentId: 2 }
    ]);
    expect(fake.state.createTagCalls).toEqual(['AI Chat', 'ChatGPT']);
    expect(fake.state.createLinkCalls).toHaveLength(2);
    expect(fake.state.createLinkCalls[0].tagIds).toEqual([1, 2]);
  });

  it('uses deterministic smallest-id matches within hierarchy and avoids duplicate writes in dry-run', async () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'capture-match-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: true
    });
    const fake = createFakeClient({
      collections: [
        { id: 20, name: 'AI Chats', parentId: null },
        { id: 10, name: 'AI Chats', parentId: null },
        { id: 40, name: 'ChatGPT', parentId: 10 },
        { id: 30, name: 'ChatGPT', parentId: 10 },
        { id: 99, name: 'Thread 1', parentId: 30 },
        { id: 50, name: 'Thread 1', parentId: 30 }
      ],
      linksByCollection: {
        50: [
          {
            id: 501,
            title: 'Existing',
            url: 'https://example.com/a?utm_source=x',
            description: null,
            tags: [],
            collection: { id: 50, name: 'Thread 1', parentId: 30 },
            pinned: false,
            archived: false
          }
        ]
      }
    });
    activeClient = fake.client;

    const result = await executeTool(
      'linkwarden_capture_chat_links',
      {
        chatText: 'A https://example.com/a and duplicate https://example.com/a plus https://example.com/b',
        aiName: 'ChatGPT',
        chatName: 'Thread 1',
        dryRun: true
      },
      createContext(store, userId)
    );

    const payload = result.structuredContent as any;
    expect(payload.ok).toBe(true);
    expect(payload.data.hierarchy.rootCollection.id).toBe(10);
    expect(payload.data.hierarchy.aiCollection.id).toBe(30);
    expect(payload.data.hierarchy.chatCollection.id).toBe(50);
    expect(payload.summary.duplicatesWithinInput).toBeGreaterThanOrEqual(1);
    expect(payload.summary.duplicatesInTargetCollection).toBe(1);
    expect(fake.state.createCollectionCalls).toHaveLength(0);
    expect(fake.state.createLinkCalls).toHaveLength(0);
  });

  it('reuses existing hierarchy with case-insensitive name matching and avoids duplicate collection creation', async () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'capture-case-insensitive-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: true
    });
    const fake = createFakeClient({
      collections: [
        { id: 9, name: 'AI chats', parentId: null },
        { id: 21, name: 'chatgpt', parentId: 9 },
        { id: 33, name: 'mx server mit ai spam', parentId: 21 }
      ]
    });
    activeClient = fake.client;

    const result = await executeTool(
      'linkwarden_capture_chat_links',
      {
        urls: ['https://example.com/case-match'],
        aiName: 'ChatGPT',
        chatName: 'MX Server mit AI Spam',
        dryRun: false
      },
      createContext(store, userId)
    );

    const payload = result.structuredContent as any;
    expect(payload.ok).toBe(true);
    expect(payload.summary.created).toBe(1);
    expect(fake.state.createCollectionCalls).toHaveLength(0);
    expect(fake.state.createLinkCalls).toHaveLength(1);
    expect(fake.state.createLinkCalls[0].collectionId).toBe(33);
  });

  it('applies only configured static chat tag when AI-name tagging is disabled', async () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'capture-toggle-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: true
    });
    store.setUserChatControlSettings(userId, {
      chatCaptureTagName: 'My Static Tag',
      chatCaptureTagAiChatEnabled: true,
      chatCaptureTagAiNameEnabled: false
    });

    const fake = createFakeClient();
    activeClient = fake.client;

    const result = await executeTool(
      'linkwarden_capture_chat_links',
      {
        urls: ['https://example.com/c'],
        aiName: 'Claude',
        chatName: 'Session A',
        dryRun: false
      },
      createContext(store, userId)
    );

    const payload = result.structuredContent as any;
    expect(payload.ok).toBe(true);
    expect(payload.data.appliedTagNames).toEqual(['My Static Tag']);
    expect(fake.state.createTagCalls).toEqual(['My Static Tag']);
    expect(fake.state.createLinkCalls[0].tagIds).toEqual([1]);
  });

  it('creates links without tags when both tag toggles are disabled', async () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'capture-no-tags-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: true
    });
    store.setUserChatControlSettings(userId, {
      chatCaptureTagAiChatEnabled: false,
      chatCaptureTagAiNameEnabled: false
    });

    const fake = createFakeClient();
    activeClient = fake.client;

    const result = await executeTool(
      'linkwarden_capture_chat_links',
      {
        urls: ['https://example.com/d'],
        aiName: 'AnyAI',
        chatName: 'No Tags',
        dryRun: false
      },
      createContext(store, userId)
    );

    const payload = result.structuredContent as any;
    expect(payload.ok).toBe(true);
    expect(payload.data.appliedTagNames).toEqual([]);
    expect(fake.state.createTagCalls).toEqual([]);
    expect(fake.state.createLinkCalls[0].tagIds).toBeUndefined();
  });

  it('keeps dry-run side-effect free and reports missing hierarchy creation as warnings', async () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'capture-dry-run-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: true
    });
    const fake = createFakeClient();
    activeClient = fake.client;

    const result = await executeTool(
      'linkwarden_capture_chat_links',
      {
        urls: ['https://example.com/e'],
        aiName: 'ChatGPT',
        chatName: 'Preview',
        dryRun: true
      },
      createContext(store, userId)
    );

    const payload = result.structuredContent as any;
    expect(payload.ok).toBe(true);
    expect(payload.warnings.some((warning: string) => warning.includes('would be created on apply'))).toBe(true);
    expect(fake.state.createCollectionCalls).toHaveLength(0);
    expect(fake.state.createTagCalls).toHaveLength(0);
    expect(fake.state.createLinkCalls).toHaveLength(0);
  });

  it('reports explicit warning when chatName is missing and fallback is used', async () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'capture-chatname-warning-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: true
    });
    const fake = createFakeClient();
    activeClient = fake.client;

    const result = await executeTool(
      'linkwarden_capture_chat_links',
      {
        chatText: 'https://example.com/fallback-chat-name',
        aiName: 'ChatGPT',
        dryRun: true
      },
      createContext(store, userId)
    );

    const payload = result.structuredContent as any;
    expect(payload.ok).toBe(true);
    expect(payload.data.chatName).toBe('Current Chat');
    expect(
      payload.warnings.some((warning: string) =>
        warning.includes('chatName not provided, fallback "Current Chat" was used')
      )
    ).toBe(true);
  });

  it('uses conversation-title alias when chatName is missing', async () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'capture-chat-title-alias-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: true
    });
    const fake = createFakeClient();
    activeClient = fake.client;

    const result = await executeTool(
      'linkwarden_capture_chat_links',
      {
        chatText: 'https://example.com/alias-chat-title',
        aiName: 'ChatGPT',
        conversationTitle: 'MX Server mit AI Spam',
        dryRun: true
      },
      createContext(store, userId)
    );

    const payload = result.structuredContent as any;
    expect(payload.ok).toBe(true);
    expect(payload.data.chatName).toBe('MX Server mit AI Spam');
    expect(payload.warnings.some((warning: string) => warning.includes('resolved from alias "conversationTitle"'))).toBe(
      true
    );
    expect(
      payload.warnings.some((warning: string) =>
        warning.includes('chatName not provided, fallback "Current Chat" was used')
      )
    ).toBe(false);
  });

  it('enforces write-mode gating for apply requests and surfaces per-link create failures', async () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'capture-write-mode-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: false
    });
    const fake = createFakeClient();
    activeClient = fake.client;

    await expect(
      executeTool(
        'linkwarden_capture_chat_links',
        {
          urls: ['https://example.com/f'],
          dryRun: false
        },
        createContext(store, userId)
      )
    ).rejects.toMatchObject({
      code: 'write_mode_disabled'
    });

    store.setUserWriteMode(userId, true);
    const failingFake = createFakeClient({
      failCreateLinkForUrl: 'https://example.com/g'
    });
    activeClient = failingFake.client;

    const result = await executeTool(
      'linkwarden_capture_chat_links',
      {
        urls: ['https://example.com/g', 'https://example.com/h'],
        dryRun: false
      },
      createContext(store, userId)
    );
    const payload = result.structuredContent as any;
    expect(payload.ok).toBe(true);
    expect(payload.summary.failed).toBe(1);
    expect(payload.summary.created).toBe(1);
    expect(payload.failures).toHaveLength(1);
  });

  it('retries once without tags when create fails with tag validation and keeps link creation successful', async () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'capture-tag-fallback-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: true
    });

    const fake = createFakeClient({
      failCreateLinkWithTagsForUrl: 'https://example.com/retry'
    });
    activeClient = fake.client;

    const result = await executeTool(
      'linkwarden_capture_chat_links',
      {
        urls: ['https://example.com/retry'],
        aiName: 'ChatGPT',
        chatName: 'Retry',
        dryRun: false
      },
      createContext(store, userId)
    );

    const payload = result.structuredContent as any;
    expect(payload.ok).toBe(true);
    expect(payload.summary.created).toBe(1);
    expect(payload.summary.failed).toBe(0);
    expect(payload.summary.createdWithoutTags).toBe(1);
    expect(payload.warnings.some((warning: string) => warning.includes('created without tags'))).toBe(true);
    expect(fake.state.createLinkCalls).toHaveLength(2);
    expect(fake.state.createLinkCalls[0].tagIds).toEqual([1, 2]);
    expect(fake.state.createLinkCalls[1].tagIds).toBeUndefined();
  });
});
