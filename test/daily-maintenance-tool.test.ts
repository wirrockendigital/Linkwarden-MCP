// This test suite verifies guardrail behavior for the daily maintenance orchestration tool.

import { afterEach, describe, expect, it, vi } from 'vitest';
import { executeTool } from '../src/mcp/tools.js';
import { AppError } from '../src/utils/errors.js';

function makeBaseContext(overrides?: Record<string, unknown>): any {
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
        maxRetries: 1,
        retryBaseDelayMs: 100,
        planTtlHours: 24
      })
    },
    db: {
      getUserSettings: () => ({
        userId: 2,
        writeModeEnabled: true,
        offlineDays: 14,
        offlineMinConsecutiveFailures: 3,
        offlineAction: 'archive',
        offlineArchiveCollectionId: 123,
        updatedAt: new Date().toISOString()
      }),
      acquireMaintenanceLock: () => true,
      releaseMaintenanceLock: () => undefined,
      createMaintenanceRun: () => 1,
      setMaintenanceRunReorgPlanId: () => undefined,
      insertMaintenanceRunItems: () => undefined,
      finishMaintenanceRun: () => undefined
    },
    logger: {
      info: () => undefined,
      error: () => undefined,
      warn: () => undefined,
      debug: () => undefined
    },
    ...(overrides ?? {})
  };
}

describe('daily maintenance tool guards', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('rejects calls without reorg and offline sections', async () => {
    const context = makeBaseContext();

    await expect(
      executeTool(
        'linkwarden_run_daily_maintenance',
        {
          apply: false
        },
        context
      )
    ).rejects.toBeInstanceOf(AppError);
  });

  it('rejects apply mode when confirm token is missing', async () => {
    const context = makeBaseContext();

    await expect(
      executeTool(
        'linkwarden_run_daily_maintenance',
        {
          apply: true,
          offline: {
            limit: 10,
            offlineDays: 14,
            minConsecutiveFailures: 3,
            archiveCollectionId: 123
          }
        },
        context
      )
    ).rejects.toBeInstanceOf(AppError);
  });

  it('rejects maintenance run when another active lock exists', async () => {
    const context = makeBaseContext({
      db: {
        getUserSettings: () => ({
          userId: 2,
          writeModeEnabled: true,
          offlineDays: 14,
          offlineMinConsecutiveFailures: 3,
          offlineAction: 'archive',
          offlineArchiveCollectionId: 123,
          updatedAt: new Date().toISOString()
        }),
        acquireMaintenanceLock: () => false,
        getActiveMaintenanceLock: () => ({
          lockToken: 'lock-1',
          expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString()
        }),
        releaseMaintenanceLock: () => undefined
      }
    });

    await expect(
      executeTool(
        'linkwarden_run_daily_maintenance',
        {
          apply: false,
          offline: {
            limit: 10
          }
        },
        context
      )
    ).rejects.toBeInstanceOf(AppError);
  });

  it('enforces write-mode gate for apply mode in daily maintenance', async () => {
    const context = makeBaseContext({
      db: {
        getUserSettings: () => ({
          userId: 2,
          writeModeEnabled: false,
          offlineDays: 14,
          offlineMinConsecutiveFailures: 3,
          offlineAction: 'archive',
          offlineArchiveCollectionId: 123,
          updatedAt: new Date().toISOString()
        })
      }
    });

    await expect(
      executeTool(
        'linkwarden_run_daily_maintenance',
        {
          apply: true,
          confirm: 'APPLY',
          offline: {
            limit: 10,
            offlineDays: 14,
            minConsecutiveFailures: 3,
            archiveCollectionId: 123
          }
        },
        context
      )
    ).rejects.toBeInstanceOf(AppError);
  });

  it('forwards offline offset into monitor execution', async () => {
    // This mock provides three scoped links and expects only the offset-selected link probe.
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
                  id: 20,
                  name: 'Link 20',
                  url: 'https://probe.example/20',
                  tags: [],
                  collection: null
                },
                {
                  id: 21,
                  name: 'Link 21',
                  url: 'https://probe.example/21',
                  tags: [],
                  collection: null
                },
                {
                  id: 22,
                  name: 'Link 22',
                  url: 'https://probe.example/22',
                  tags: [],
                  collection: null
                }
              ],
              nextCursor: null
            }
          })
        };
      }

      if (url === 'https://probe.example/21') {
        return {
          ok: true,
          status: 200
        };
      }

      throw new Error(`Unexpected fetch call in test: ${url}`);
    });

    vi.stubGlobal('fetch', fetchMock);

    const context = makeBaseContext();
    Object.assign(context.configStore, {
      decryptSecret: () => 'token-value'
    });
    Object.assign(context.db, {
      getLinkwardenTarget: () => ({
        baseUrl: 'http://linkwarden.local'
      }),
      getUserLinkwardenToken: () => 'encrypted-token',
      listLinkHealthStates: () => [],
      upsertLinkHealthState: () => undefined,
      markLinkHealthArchived: () => undefined,
      insertAudit: () => undefined
    });
    Object.assign(context.logger, {
      child: () => context.logger
    });

    const result = await executeTool(
      'linkwarden_run_daily_maintenance',
      {
        apply: false,
        offline: {
          offset: 1,
          limit: 1,
          timeoutMs: 1000
        }
      },
      context
    );
    const payload = result.structuredContent as any;
    expect(payload.offline.summary.scanned).toBe(1);
    expect(payload.offline.paging).toMatchObject({
      offset: 1,
      limit: 1,
      totalMatched: 3
    });
    expect(payload.offline.checked[0]).toMatchObject({
      linkId: 21,
      status: 'up',
      httpStatus: 200
    });
  });
});
