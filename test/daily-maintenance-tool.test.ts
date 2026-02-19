// This test suite verifies alpha rule-run guard behavior and saved-query persistence tool paths.

import { describe, expect, it } from 'vitest';
import { executeTool } from '../src/mcp/tools.js';
import { AppError } from '../src/utils/errors.js';

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
    db: {
      getUserSettings: () => ({
        userId: 2,
        writeModeEnabled: true,
        taggingStrictness: 'very_strict',
        fetchMode: 'optional',
        queryTimeZone: null,
        offlineDays: 14,
        offlineMinConsecutiveFailures: 3,
        offlineAction: 'archive',
        offlineArchiveCollectionId: 123,
        updatedAt: new Date().toISOString()
      }),
      acquireMaintenanceLock: () => true,
      releaseMaintenanceLock: () => undefined,
      listRules: () => [],
      createSavedQuery: () => undefined,
      listSavedQueries: () => [],
      getSavedQuery: () => null
    },
    logger,
    ...(overrides ?? {})
  };
}

describe('rule and saved-query guards (alpha)', () => {
  it('rejects rules-now when another lock is active', async () => {
    const context = makeContext({
      db: {
        getUserSettings: () => ({
          userId: 2,
          writeModeEnabled: true,
          taggingStrictness: 'very_strict',
          fetchMode: 'optional',
          queryTimeZone: null,
          offlineDays: 14,
          offlineMinConsecutiveFailures: 3,
          offlineAction: 'archive',
          offlineArchiveCollectionId: 123,
          updatedAt: new Date().toISOString()
        }),
        acquireMaintenanceLock: () => false,
        releaseMaintenanceLock: () => undefined,
        listRules: () => []
      }
    });

    await expect(
      executeTool(
        'linkwarden_run_rules_now',
        {},
        context
      )
    ).rejects.toBeInstanceOf(AppError);
  });

  it('creates and lists saved queries through db adapter methods', async () => {
    const savedQueries: any[] = [];
    const context = makeContext({
      db: {
        getUserSettings: () => ({
          userId: 2,
          writeModeEnabled: true,
          taggingStrictness: 'very_strict',
          fetchMode: 'optional',
          queryTimeZone: null,
          offlineDays: 14,
          offlineMinConsecutiveFailures: 3,
          offlineAction: 'archive',
          offlineArchiveCollectionId: 123,
          updatedAt: new Date().toISOString()
        }),
        acquireMaintenanceLock: () => true,
        releaseMaintenanceLock: () => undefined,
        listRules: () => [],
        createSavedQuery: (query: any) => {
          savedQueries.push(query);
        },
        listSavedQueries: () => savedQueries,
        getSavedQuery: () => null
      }
    });

    const createResult = await executeTool(
      'linkwarden_create_saved_query',
      {
        name: 'Important',
        selector: {},
        fields: []
      },
      context
    );
    expect((createResult.structuredContent as any).ok).toBe(true);

    const listResult = await executeTool(
      'linkwarden_list_saved_queries',
      {},
      context
    );
    expect((listResult.structuredContent as any).ok).toBe(true);
    expect(Array.isArray((listResult.structuredContent as any).data.savedQueries)).toBe(true);
  });
});
