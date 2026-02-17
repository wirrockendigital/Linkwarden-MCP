// This test suite verifies refresh-token flow safety for client validation and token rotation ordering.

import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';
import { registerOAuthRoutes } from '../src/http/oauth.js';

const VALID_REFRESH_TOKEN = 'lwr_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';

// This helper builds one valid refresh record fixture used by token endpoint tests.
function makeRefreshRecord(clientId: string) {
  return {
    tokenId: 'tok_1',
    userId: 2,
    username: 'eric',
    role: 'user',
    clientId,
    scope: 'mcp.read offline_access',
    resource: 'https://lwmcp.rocken.digital/mcp',
    accessExpiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
    refreshExpiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
  };
}

describe('oauth token refresh flow', () => {
  it('does not consume refresh token when client binding mismatches', async () => {
    const refreshRecord = makeRefreshRecord('client-a');
    let consumeCalls = 0;

    const app = Fastify({ logger: false });
    registerOAuthRoutes(app, {
      configStore: {
        isInitialized: () => true,
        isUnlocked: () => true,
        getRuntimeConfig: () => ({})
      } as any,
      db: {
        getOAuthRefreshToken: () => refreshRecord,
        consumeOAuthRefreshToken: () => {
          consumeCalls += 1;
          return refreshRecord;
        },
        getOAuthClient: (clientId: string) => ({
          clientId,
          clientName: 'dynamic-client',
          redirectUris: ['https://client.example/callback'],
          tokenEndpointAuthMethod: 'none',
          clientSecretHash: undefined,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        }),
        createOAuthToken: () => undefined
      } as any
    });

    await app.ready();
    try {
      const response = await app.inject({
        method: 'POST',
        url: '/token',
        payload: {
          grant_type: 'refresh_token',
          client_id: 'client-b',
          refresh_token: VALID_REFRESH_TOKEN
        }
      });

      expect(response.statusCode).toBe(400);
      expect(response.json()).toMatchObject({
        error: 'invalid_grant'
      });
      expect(consumeCalls).toBe(0);
    } finally {
      await app.close();
    }
  });

  it('accepts refresh requests without client_id and uses token-bound client identity', async () => {
    const refreshRecord = makeRefreshRecord('client-a');
    let consumeExpectedClientId: string | undefined;
    let createdTokens = 0;

    const app = Fastify({ logger: false });
    registerOAuthRoutes(app, {
      configStore: {
        isInitialized: () => true,
        isUnlocked: () => true,
        getRuntimeConfig: () => ({})
      } as any,
      db: {
        getOAuthRefreshToken: () => refreshRecord,
        consumeOAuthRefreshToken: (_tokenHash: string, expectedClientId?: string) => {
          consumeExpectedClientId = expectedClientId;
          return refreshRecord;
        },
        getOAuthClient: (clientId: string) => ({
          clientId,
          clientName: 'dynamic-client',
          redirectUris: ['https://client.example/callback'],
          tokenEndpointAuthMethod: 'none',
          clientSecretHash: undefined,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        }),
        createOAuthToken: () => {
          createdTokens += 1;
        }
      } as any
    });

    await app.ready();
    try {
      const response = await app.inject({
        method: 'POST',
        url: '/token',
        payload: {
          grant_type: 'refresh_token',
          refresh_token: VALID_REFRESH_TOKEN
        }
      });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toMatchObject({
        token_type: 'Bearer',
        scope: refreshRecord.scope
      });
      expect(consumeExpectedClientId).toBe('client-a');
      expect(createdTokens).toBe(1);
    } finally {
      await app.close();
    }
  });
});
