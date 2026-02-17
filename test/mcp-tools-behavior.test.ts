// This test suite verifies MCP tool behavior for partial access failures and link-health status classification.

import { afterEach, describe, expect, it, vi } from 'vitest';
import { executeTool } from '../src/mcp/tools.js';

function makeContext(overrides?: Record<string, unknown>): any {
  const logger = {
    info: () => undefined,
    error: () => undefined,
    warn: () => undefined,
    debug: () => undefined,
    child: () => logger
  };

  return {
    actor: 'eric#key1',
    principal: {
      userId: 2,
      username: 'eric',
      role: 'user',
      apiKeyId: 'key1'
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
    db: {
      getLinkwardenTarget: () => ({
        baseUrl: 'http://linkwarden.local'
      }),
      getUserLinkwardenToken: () => 'encrypted-token',
      getUserSettings: () => ({
        userId: 2,
        writeModeEnabled: true,
        offlineDays: 14,
        offlineMinConsecutiveFailures: 3,
        offlineAction: 'archive',
        offlineArchiveCollectionId: null,
        updatedAt: new Date().toISOString()
      }),
      listLinkHealthStates: () => [],
      upsertLinkHealthState: () => undefined,
      insertAudit: () => undefined
    },
    logger,
    ...(overrides ?? {})
  };
}

describe('mcp tool behavior', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('keeps clean_link_urls dry-run successful when one link is inaccessible', async () => {
    // This mock returns one inaccessible link and one valid link to verify partial-result behavior.
    const fetchMock = vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = String(input);

      if (url.endsWith('/api/v1/links/1') && init?.method === 'GET') {
        return {
          ok: false,
          status: 403,
          text: async () => '{"response":"Collection is not accessible."}'
        };
      }

      if (url.endsWith('/api/v1/links/1171') && init?.method === 'GET') {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            response: {
              id: 1171,
              name: 'Tracked Link',
              url: 'https://example.com/path?utm_source=test&utm_medium=email',
              description: '',
              tags: [],
              collection: {
                id: 10,
                ownerId: 2
              }
            }
          })
        };
      }

      throw new Error(`Unexpected fetch call in test: ${url}`);
    });

    vi.stubGlobal('fetch', fetchMock);

    const result = await executeTool(
      'linkwarden_clean_link_urls',
      {
        linkIds: [1, 1171],
        dryRun: true
      },
      makeContext()
    );
    const payload = result.structuredContent as any;

    expect(payload.summary.total).toBe(2);
    expect(payload.summary.accessible).toBe(1);
    expect(payload.summary.skipped).toBe(1);
    expect(payload.summary.changed).toBe(1);
    expect(Array.isArray(payload.skipped)).toBe(true);
    expect(payload.skipped[0]).toMatchObject({ linkId: 1 });
  });

  it('classifies HTTP 404 as down in monitor_offline_links dry-run', async () => {
    // This mock emulates one search result and one 404 probe target.
    const fetchMock = vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = String(input);

      if (url.includes('/api/v1/search') && init?.method === 'GET') {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            data: {
              links: [
                {
                  id: 50,
                  name: 'Missing link',
                  url: 'https://invalid.example/not-found',
                  tags: [],
                  collection: null
                }
              ],
              nextCursor: null
            }
          })
        };
      }

      if (url === 'https://invalid.example/not-found') {
        return {
          ok: false,
          status: 404
        };
      }

      throw new Error(`Unexpected fetch call in test: ${url}`);
    });

    vi.stubGlobal('fetch', fetchMock);

    const result = await executeTool(
      'linkwarden_monitor_offline_links',
      {
        limit: 1,
        dryRun: true,
        timeoutMs: 1000
      },
      makeContext()
    );
    const payload = result.structuredContent as any;

    expect(payload.summary.scanned).toBe(1);
    expect(payload.summary.down).toBe(1);
    expect(payload.summary.up).toBe(0);
    expect(payload.checked[0]).toMatchObject({
      linkId: 50,
      status: 'down',
      httpStatus: 404
    });
  });

  it('applies offset before limit in monitor_offline_links dry-run', async () => {
    // This mock returns three links so the tool must page locally using offset+limit.
    const fetchMock = vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = String(input);

      if (url.includes('/api/v1/search') && init?.method === 'GET') {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            data: {
              links: [
                {
                  id: 10,
                  name: 'Link 10',
                  url: 'https://probe.example/10',
                  tags: [],
                  collection: null
                },
                {
                  id: 11,
                  name: 'Link 11',
                  url: 'https://probe.example/11',
                  tags: [],
                  collection: null
                },
                {
                  id: 12,
                  name: 'Link 12',
                  url: 'https://probe.example/12',
                  tags: [],
                  collection: null
                }
              ],
              nextCursor: null
            }
          })
        };
      }

      if (url === 'https://probe.example/11') {
        return {
          ok: true,
          status: 200
        };
      }

      throw new Error(`Unexpected fetch call in test: ${url}`);
    });

    vi.stubGlobal('fetch', fetchMock);

    const result = await executeTool(
      'linkwarden_monitor_offline_links',
      {
        offset: 1,
        limit: 1,
        dryRun: true,
        timeoutMs: 1000
      },
      makeContext()
    );
    const payload = result.structuredContent as any;

    expect(payload.summary.scanned).toBe(1);
    expect(payload.paging).toMatchObject({
      offset: 1,
      limit: 1,
      totalMatched: 3
    });
    expect(payload.checked[0]).toMatchObject({
      linkId: 11,
      status: 'up',
      httpStatus: 200
    });
  });
});
