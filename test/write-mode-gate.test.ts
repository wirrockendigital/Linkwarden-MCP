// This test suite verifies that alpha write tools are blocked when per-user write mode is disabled.

import { describe, expect, it } from 'vitest';
import { executeTool } from '../src/mcp/tools.js';
import { AppError } from '../src/utils/errors.js';

describe('mcp write-mode gate (alpha)', () => {
  it('blocks mutating tool execution when write mode is disabled', async () => {
    const context = {
      actor: 'alice#key1',
      principal: {
        userId: 1,
        username: 'alice',
        role: 'user',
        apiKeyId: 'key1',
        toolScopes: ['*'],
        collectionScopes: []
      },
      configStore: {
        getRuntimeConfig: () => ({
          requestTimeoutMs: 10000,
          maxRetries: 1,
          retryBaseDelayMs: 100,
          planTtlHours: 24
        })
      },
      db: {
        getUserSettings: () => ({
          userId: 1,
          writeModeEnabled: false,
          taggingStrictness: 'very_strict',
          fetchMode: 'optional',
          queryTimeZone: null,
          offlineDays: 14,
          offlineMinConsecutiveFailures: 3,
          offlineAction: 'archive',
          offlineArchiveCollectionId: 5,
          updatedAt: new Date().toISOString()
        })
      },
      logger: {
        info: () => undefined,
        error: () => undefined,
        warn: () => undefined,
        debug: () => undefined
      }
    } as any;

    await expect(
      executeTool(
        'linkwarden_mutate_links',
        {
          ids: [123],
          updates: {
            title: 'blocked'
          },
          dryRun: false
        },
        context
      )
    ).rejects.toBeInstanceOf(AppError);

    await expect(
      executeTool(
        'linkwarden_delete_links',
        {
          ids: [123],
          dryRun: false
        },
        context
      )
    ).rejects.toBeInstanceOf(AppError);

    await expect(
      executeTool(
        'linkwarden_governed_tag_links',
        {
          linkIds: [123],
          dryRun: false
        },
        context
      )
    ).rejects.toBeInstanceOf(AppError);

    await expect(
      executeTool(
        'linkwarden_create_tag',
        {
          name: 'Security'
        },
        context
      )
    ).rejects.toBeInstanceOf(AppError);

    await expect(
      executeTool(
        'linkwarden_create_rule',
        {
          name: 'Rule',
          selector: {
            query: 'security'
          },
          action: {
            type: 'pin',
            pinned: true
          }
        },
        context
      )
    ).rejects.toBeInstanceOf(AppError);

    await expect(
      executeTool(
        'linkwarden_create_saved_query',
        {
          name: 'Saved',
          selector: {},
          fields: []
        },
        context
      )
    ).rejects.toBeInstanceOf(AppError);

    await expect(
      executeTool(
        'linkwarden_delete_rule',
        {
          id: '11111111-1111-1111-1111-111111111111'
        },
        context
      )
    ).rejects.toBeInstanceOf(AppError);
  });
});
