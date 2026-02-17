// This test suite verifies that MCP write tools are blocked when user write mode is disabled.

import { describe, expect, it } from 'vitest';
import { executeTool } from '../src/mcp/tools.js';
import { AppError } from '../src/utils/errors.js';

describe('mcp write-mode gate', () => {
  it('blocks write tool execution when per-user write mode is disabled', async () => {
    const context = {
      actor: 'alice#key1',
      principal: {
        userId: 1,
        username: 'alice',
        role: 'user',
        apiKeyId: 'key1'
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
        'linkwarden_update_link',
        {
          id: 123,
          updates: {
            title: 'blocked'
          }
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
        'linkwarden_create_collection',
        {
          name: 'Service'
        },
        context
      )
    ).rejects.toBeInstanceOf(AppError);
  });
});
