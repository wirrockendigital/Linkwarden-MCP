// This test suite verifies alpha MCP behavior for scope checks, envelope output, and cursor validation.

import { describe, expect, it } from 'vitest';
import { executeTool } from '../src/mcp/tools.js';
import { AppError } from '../src/utils/errors.js';

function makeBaseContext(overrides?: Record<string, unknown>): any {
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
      getQuerySnapshot: () => null
    },
    logger,
    ...(overrides ?? {})
  };
}

describe('mcp tools behavior (alpha)', () => {
  it('returns standardized envelope for server metadata tool', async () => {
    const result = await executeTool('linkwarden_get_server_info', {}, makeBaseContext());
    expect(result.structuredContent).toMatchObject({
      ok: true,
      error: null
    });
    expect((result.structuredContent as any).data.name).toBe('linkwarden-mcp');
    expect(typeof (result.structuredContent as any).data.version).toBe('string');
  });

  it('enforces tool scope restrictions before handler execution', async () => {
    const context = makeBaseContext({
      principal: {
        userId: 2,
        username: 'eric',
        role: 'user',
        apiKeyId: 'key1',
        toolScopes: ['linkwarden_get_server_info'],
        collectionScopes: []
      }
    });

    await expect(
      executeTool(
        'linkwarden_get_stats',
        {},
        context
      )
    ).rejects.toBeInstanceOf(AppError);
  });

  it('rejects invalid query cursor format deterministically', async () => {
    await expect(
      executeTool(
        'linkwarden_query_links',
        {
          cursor: 'invalid-cursor',
          limit: 10
        },
        makeBaseContext()
      )
    ).rejects.toBeInstanceOf(AppError);
  });
});
